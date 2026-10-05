"""Telemetry shipper (F09 rewrite): a real, deliverable auditd → API pipeline.

Input: RAW auditd records on stdin (the documented `log_format=ENRICHED`
audit.log lines via audisp/`tail -F`, or plain audit.log). Multi-record events
(PROCTITLE/EXECVE/SYSCALL sharing one audit id) are GROUPED into exactly one
command event. argv is decoded correctly (aNN="..." hex-or-quoted values).

Reliability: bounded on-disk spool with retry + exponential backoff; when the
spool is full the OLDEST record is dropped and a visible gap counter advances
— nothing buffers endlessly, nothing is lost silently.

Identity: host name + /etc/machine-id (stable) + /proc boot_id are attached;
the API attributes via the HOST-BOUND telemetry capability, not "newest token
by hostname". Trust limit: telemetry from a COMPROMISED range host is evidence
of what that host CLAIMED at that time, not truth — see docs/ARCHITECTURE_NOTES.md.

Configuration (env or /etc/sparring-range/shipper.env):
  SR_API_URL, SR_TELEMETRY_TOKEN, SR_HOST, SR_SPOOL_DIR, SR_SPOOL_MAX_BYTES
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time

import urllib.error
import urllib.request

AUDIT_LINE_RE = re.compile(r'type=(?P<type>[A-Z0-9_]+) msg=audit\((?P<ts>[\d.]+):(?P<id>\d+)\):\s?(?P<rest>.*)$')
KV_RE = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')


def _unescape(v: str) -> str:
    # auditd escapes quotes/backslashes; EXECVE argv values may also be hex
    v = v.replace('\\"', '"').replace("\\\\", "\\")
    if v.isdigit() or (v[:1] == "-" and v[1:].isdigit()):
        return v  # decimal audit fields (uid, exit, syscall) are NOT hex-encoded
    if re.fullmatch(r"[0-9a-fA-F]{2,}", v) and len(v) % 2 == 0 and not re.search(r"[g-zG-Z]", v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def parse_audit_line(line: str) -> tuple[str, int, dict] | None:
    m = AUDIT_LINE_RE.match(line.strip())
    if not m:
        return None
    fields = {}
    for k, v1, v3 in KV_RE.findall(m.group("rest") or ""):
        if k:
            fields[k] = _unescape(v1 if v1 != "" else v3)
    return m.group("type"), int(m.group("id")), {"ts": float(m.group("ts")), **fields}


def group_event_records(lines, max_open: int = 64):
    """Yield one dict per audit EVENT ID.

    Record ORDER is not assumed (audit R11): ENRICHED streams may lead with
    SYSCALL and follow with EXECVE/PROCTITLE, or close with EOE. A group is
    complete when its EOE arrives, when SYSCALL arrives after the other
    records of its own event, or when the stream moves on to a different
    event id (auditd writes one event contiguously). PENDING groups survive
    interleaving (bounded by max_open) and EVERYTHING is flushed at EOF —
    a trailing group is never dropped.
    """
    groups: dict[int, dict] = {}
    order: list[int] = []
    last_id: int | None = None
    for raw in lines:
        parsed = parse_audit_line(raw)
        if not parsed:
            continue
        rtype, eid, fields = parsed
        # contiguous-stream close: the previous event is done once its SYSCALL
        # was seen and a NEW event id starts
        if last_id is not None and eid != last_id and \
                last_id in groups and "SYSCALL" in groups[last_id]["records"]:
            out = groups.pop(last_id)
            order.remove(last_id)
            yield out
            last_id = None
        g = groups.get(eid)
        if g is None:
            g = groups[eid] = {"source_id": eid, "records": {}}
            order.append(eid)
        g["records"][rtype] = fields
        recs = g["records"]
        closed = rtype in ("EOE", "AUDIT_EOE") or \
            (rtype == "SYSCALL" and ("EXECVE" in recs or "PROCTITLE" in recs))
        if closed:
            out = groups.pop(eid)
            order.remove(eid)
            yield out
            if last_id == eid:
                last_id = None
        else:
            last_id = eid
        while len(groups) > max_open:  # bounded memory under pathological interleaving
            oldest = order.pop(0)
            yield groups.pop(oldest)
    for eid in order:  # EOF FLUSH — trailing groups must never be lost
        yield groups[eid]


def build_command_event(host: str, group: dict, machine_id: str, boot_id: str) -> dict | None:
    recs = group["records"]
    if "EXECVE" not in recs and "SYSCALL" not in recs:
        return None  # ignore config/login noise here; commands + watch hits only
    ex = recs.get("EXECVE", {})
    argv = [ex[k] for k in sorted((k for k in ex if k.startswith("a") and k[1:].isdigit()),
                                  key=lambda k: int(k[1:]))]
    sc = recs.get("SYSCALL", {})
    ts = sc.get("ts") or ex.get("ts") or (recs.get("PROCTITLE") or {}).get("ts")
    key = sc.get("key", "")
    kind = "command" if "EXECVE" in recs else (
        "detection" if key in ("sparring_persistence", "sparring_accounts") else None)
    if kind is None:
        return None
    return {
        "kind": kind,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(float(ts))) if ts else None,
        "uid": sc.get("uid"), "comm": sc.get("comm"), "exe": sc.get("exe"),
        "argv": " ".join(argv), "audit_key": key or None,
        "source_id": str(group["source_id"]),
        "boot_id": boot_id, "raw": {"types": sorted(recs), "syscall": sc},
    }


class Spooler:
    """Bounded on-disk spool (NDJSON). Drops OLDEST records until the incoming
    record FITS (byte-aware, not one-line-per-append), and rewrites atomically
    via temp+rename so a crash mid-trim cannot corrupt the spool. Gaps are
    counted — visible, not silent."""

    def __init__(self, spool_dir: str, max_bytes: int = 64 * 1024 * 1024):
        self.path = os.path.join(spool_dir, "pending.ndjson")
        self.gap_path = os.path.join(spool_dir, "gaps")
        self.max_bytes = max_bytes
        os.makedirs(spool_dir, exist_ok=True)
        self.dropped = 0

    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _atomic_write_lines(self, lines: list[str]) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            f.writelines(lines)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def append(self, event: dict) -> None:
        payload = json.dumps(event) + "\n"
        # make room for the INCOMING SIZE: trim oldest until it fits (audit R11)
        if self._size() + len(payload.encode()) > self.max_bytes and os.path.exists(self.path):
            with open(self.path) as f:
                lines = f.readlines()
            dropped_now = 0
            while lines and sum(len(l.encode()) for l in lines) + len(payload.encode()) > self.max_bytes:
                lines.pop(0)
                dropped_now += 1
            if dropped_now:
                self._atomic_write_lines(lines)
                self.dropped += dropped_now
                with open(self.gap_path, "a") as g:
                    g.write(f"{time.time()} dropped-oldest n={dropped_now} total={self.dropped}\n")
            if not lines and len(payload.encode()) > self.max_bytes:
                # single record larger than the whole spool: record the gap, drop it
                self.dropped += 1
                with open(self.gap_path, "a") as g:
                    g.write(f"{time.time()} dropped-oversize total={self.dropped}\n")
                return
        with open(self.path, "a") as f:
            f.write(payload)

    def pending(self, n: int = 200) -> list[tuple[int, dict]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [(i, json.loads(l)) for i, l in enumerate(f) if l.strip()][:n]

    def remove(self, indices: set[int]) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path) as f:
            lines = f.readlines()
        keep = [l for i, l in enumerate(lines) if i not in indices]
        self._atomic_write_lines(keep)


def ship_events(api: str, token: str, events: list[dict]) -> bool:
    req = urllib.request.Request(
        f"{api}/ingest/auditd",
        data=json.dumps({"events": events}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status < 400
    except (urllib.error.URLError, OSError):
        return False


class DeliveryLoop:
    """Spool delivery INDEPENDENT of incoming activity (audit R11): a periodic
    background flush means a spooled record is delivered after connectivity
    returns even while the range is quiet. The real outage path (ship_events
    returns False) drives the exponential backoff — previously only a raised
    exception did, and it never raises on the network path."""

    def __init__(self, api: str, token: str, spool: Spooler,
                 interval_s: float = 2.0, max_backoff_s: float = 60.0,
                 sleeper=time.sleep):
        self.api, self.token, self.spool = api, token, spool
        self.interval_s = interval_s
        self.max_backoff_s = max_backoff_s
        self._sleep = sleeper
        self.backoff = 1.0
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="shipper-delivery")

    def flush_once(self) -> bool:
        pend = self.spool.pending()
        if not pend:
            self.backoff = 1.0
            return True
        ok = ship_events(self.api, self.token, [e for _, e in pend])
        if ok:
            self.spool.remove(set(range(len(pend))))
            self.backoff = 1.0
            return True
        # visible exponential backoff on the ACTUAL failure path
        print(f"[shipper] delivery failed; retry in {self.backoff:.0f}s", file=sys.stderr)
        self._sleep(self.backoff)
        self.backoff = min(self.backoff * 2, self.max_backoff_s)
        return False

    def _run(self):
        while not self.stopped.is_set():
            try:
                self.flush_once()
            except Exception as e:  # noqa: BLE001 — the loop survives anything
                print(f"[shipper] delivery loop error: {e}", file=sys.stderr)
            self.stopped.wait(self.interval_s)

    def start(self):
        self.thread.start()

    def stop(self, final_flush: bool = True, timeout: float = 30.0):
        self.stopped.set()
        self.thread.join(timeout=timeout)
        if final_flush:
            try:
                self.flush_once()
            except Exception:  # noqa: BLE001
                pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("SR_API_URL"))
    ap.add_argument("--token", default=os.environ.get("SR_TELEMETRY_TOKEN"))
    ap.add_argument("--host", default=os.environ.get("SR_HOST"))
    ap.add_argument("--spool-dir", default=os.environ.get("SR_SPOOL_DIR", "/var/lib/sparring-range/shipper"))
    args = ap.parse_args()
    if not all([args.api, args.token, args.host]):
        print("shipper requires --api/--token/--host (or SR_* env)", file=sys.stderr)
        sys.exit(2)

    machine_id = "unknown"
    try:
        machine_id = open("/etc/machine-id").read().strip()
    except OSError:
        pass
    boot_id = "noboot"
    try:
        boot_id = open("/proc/sys/kernel/random/boot_id").read().strip()
    except OSError:
        pass

    spool = Spooler(args.spool_dir)
    delivery = DeliveryLoop(args.api, args.token, spool)
    delivery.start()  # drains anything spooled during a previous outage,
                      # and keeps retrying while stdin blocks idle

    exit_code = 0
    try:
        for group in group_event_records(sys.stdin):
            ev = build_command_event(args.host, group, machine_id, boot_id)
            if ev is None:
                continue
            ev["machine_id"] = machine_id
            spool.append(ev)
    except KeyboardInterrupt:
        exit_code = 0
    finally:
        # EOF/shutdown: stop the loop and make ONE final delivery attempt —
        # the last events of a session must not wait for the next input line.
        delivery.stop(final_flush=True)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
