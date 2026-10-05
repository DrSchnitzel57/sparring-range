#!/usr/bin/env python3
"""Telemetry shipper (F09 rewrite): a real, deliverable auditd → API pipeline.

Input: RAW auditd records on stdin (the documented `log_format=ENRICHED`
audit.log lines via audisp/`tail -F`, or plain audit.log). Multi-record events
(PROCTITLE/EXECVE/SYSCALL sharing one audit id) are GROUPED into exactly one
command event. argv is decoded correctly: QUOTED values keep their literal
text; only UNQUOTED hex-encoded values are hex-decoded (audit N08).

Group completion (audit N08): an event closes on its EOE record or after a
BOUNDED completion timeout (no further records for that id) — never merely
because a different event id appeared or because SYSCALL arrived. For live
streams the timeout is enforced with a wall clock while input is idle, so the
FINAL event of a quiet session is deliverable without closing the input.
Repeated/chunked EXECVE records are CONCATENATED in arrival order and the
event is visibly marked — never silently replaced.

Reliability (audit N08): the spool is a durable queue with STABLE RECORD
IDENTITIES (monotonic sequence numbers), an exclusive lock around
append/trim/acknowledge, byte limits enforced INCLUDING the first oversized
record, delivery that acknowledges exactly the ids it sent (records created
while a batch is in flight survive), visible persisted gap counters, and
tolerant recovery from interrupted writes and malformed trailing data.

Identity: host name + /etc/machine-id (stable) + /proc boot_id are attached;
the API attributes via the HOST-BOUND, SESSION-BOUND telemetry capability,
not "newest token by hostname". Trust limit: telemetry from a COMPROMISED
range host is evidence of what that host CLAIMED at that time, not truth —
see docs/ARCHITECTURE_NOTES.md.

Configuration (env or /etc/sparring-range/shipper.env):
  SR_API_URL, SR_TELEMETRY_TOKEN, SR_HOST, SR_SPOOL_DIR, SR_SPOOL_MAX_BYTES
"""
from __future__ import annotations

import argparse
import fcntl
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


def _unescape_quoted(v: str) -> str:
    """QUOTED audit fields are literal text with backslash escapes only.
    Hex-looking content ("636174" as an actual argument) must NOT be
    hex-decoded (audit N08: preserve source encoding semantics)."""
    return v.replace('\\"', '"').replace("\\\\", "\\")


def _decode_unquoted(v: str, argv_field: bool = False) -> str:
    """UNQUOTED audit fields may be hex-encoded by auditd (non-printable
    values). DECIMAL fields (uid, exit, syscall numbers) are never hex. For
    EXECVE argv fields (aN) an all-digit string is ambiguous — decode hex
    only when the result is printable text, else keep the literal."""
    if v.isdigit() or (v[:1] == "-" and v[1:].isdigit()):
        if argv_field and len(v) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", v):
            try:
                dec = bytes.fromhex(v).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return v
            if dec and all(c.isprintable() or c == " " for c in dec):
                return dec
        return v
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
    for k, vq, vu in KV_RE.findall(m.group("rest") or ""):
        if k:
            argv_field = m.group("type") == "EXECVE" and bool(re.fullmatch(r"a\d+", k))
            fields[k] = _unescape_quoted(vq) if vq != "" \
                else _decode_unquoted(vu, argv_field=argv_field)
    return m.group("type"), int(m.group("id")), {"ts": float(m.group("ts")), **fields}


class LiveGrouper:
    """Event assembly for interleaved and LIVE streams (audit N08).

    Groups are keyed by (machine/boot source, event id) — ids are only unique
    per source. A group closes on:
      * its EOE record, or
      * the bounded completion timeout: no new record for that id while the
        stream clock (record timestamps, or the wall clock passed to
        flush_stale for idle live streams) advances past close_after_s.
    A group is NEVER closed merely because another event id appeared or
    because SYSCALL arrived. Repeated records of the same type within a group
    are KEPT (chunked EXECVE concatenation), never silently replaced.
    """

    def __init__(self, close_after_s: float = 2.0, max_open: int = 64,
                 source: str = "default"):
        self.close_after_s = close_after_s
        self.max_open = max_open
        self.source = source
        self._groups: dict[tuple, dict] = {}
        self._order: list[tuple] = []

    def add(self, line: str) -> list[dict]:
        parsed = parse_audit_line(line)
        if not parsed:
            return []
        rtype, eid, fields = parsed
        key = (self.source, eid)
        closed: list[dict] = []
        # timestamp-driven completion: any newer record advances the stream
        # clock; groups idle past the timeout close (bounded, not id-driven)
        closed.extend(self._timed_out(fields.get("ts", 0.0)))
        g = self._groups.get(key)
        if g is None:
            g = self._groups[key] = {"source_id": eid, "records": {},
                                     "duplicates": [], "last_ts": fields.get("ts", 0.0)}
            self._order.append(key)
        g["last_ts"] = max(g["last_ts"], fields.get("ts", 0.0))
        if rtype in g["records"]:
            # repeated record for the same type: KEEP both (chunked EXECVE /
            # PROCTITLE), record the duplication visibly
            g["duplicates"].append(rtype)
            if isinstance(g["records"][rtype], list):
                g["records"][rtype].append(fields)
            else:
                g["records"][rtype] = [g["records"][rtype], fields]
        else:
            g["records"][rtype] = fields
        if rtype in ("EOE", "AUDIT_EOE"):
            closed.append(self._pop(key))
        while len(self._groups) > self.max_open:  # bounded memory
            closed.append(self._pop(self._order[0]))
        return closed

    def _timed_out(self, now_ts: float) -> list[dict]:
        closed = []
        for key in list(self._order):
            g = self._groups.get(key)
            if g and (now_ts - g["last_ts"]) >= self.close_after_s:
                closed.append(self._pop(key))
        return closed

    def flush_stale(self, now_wall: float) -> list[dict]:
        """For LIVE idle streams: close groups whose LAST RECORD was seen at
        least close_after_s ago in wall-clock time — the final event of a
        quiet session becomes deliverable while input stays open."""
        closed = []
        for key in list(self._order):
            g = self._groups.get(key)
            if g and (now_wall - g.get("seen_wall", now_wall)) >= self.close_after_s:
                closed.append(self._pop(key))
        return closed

    def flush_all(self) -> list[dict]:
        return [self._pop(key) for key in list(self._order)]

    def _pop(self, key) -> dict:
        g = self._groups.pop(key)
        if key in self._order:
            self._order.remove(key)
        return g

    # keep add() recording wall-clock arrival for flush_stale
    def _touch(self, g: dict) -> None:
        g["seen_wall"] = time.time()


def _add_with_wall(grouper: LiveGrouper, line: str) -> list[dict]:
    closed = grouper.add(line)
    for g in grouper._groups.values():
        g["seen_wall"] = time.time()
    return closed


def group_event_records(lines, max_open: int = 64, close_after_s: float = 2.0,
                        source: str = "default"):
    """Yield one dict per audit EVENT (batch form; EOF flushes everything —
    a trailing group is never dropped)."""
    grouper = LiveGrouper(close_after_s=close_after_s, max_open=max_open,
                          source=source)
    for raw in lines:
        for g in grouper.add(raw):
            yield g
    for g in grouper.flush_all():
        yield g


def _rec_list(recs: dict, rtype: str) -> list[dict]:
    v = recs.get(rtype)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def build_command_event(host: str, group: dict, machine_id: str, boot_id: str) -> dict | None:
    recs = group["records"]
    if "EXECVE" not in recs and "SYSCALL" not in recs:
        return None  # ignore config/login noise here; commands + watch hits only
    # chunked/repeated EXECVE records concatenate in arrival order (audit N08)
    argv: list[str] = []
    for ex in _rec_list(recs, "EXECVE"):
        argv.extend(ex[k] for k in sorted((k for k in ex if k.startswith("a") and k[1:].isdigit()),
                                          key=lambda k: int(k[1:])))
    sc_list = _rec_list(recs, "SYSCALL")
    sc = sc_list[0] if sc_list else {}
    ts = None
    for r in sc_list + _rec_list(recs, "EXECVE") + _rec_list(recs, "PROCTITLE"):
        if r.get("ts"):
            ts = r["ts"]
            break
    key = sc.get("key", "")
    kind = "command" if "EXECVE" in recs else (
        "detection" if key in ("sparring_persistence", "sparring_accounts") else None)
    if kind is None:
        return None
    ev = {
        "kind": kind,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(float(ts))) if ts else None,
        "uid": sc.get("uid"), "comm": sc.get("comm"), "exe": sc.get("exe"),
        "argv": " ".join(argv), "audit_key": key or None,
        "source_id": str(group["source_id"]),
        "boot_id": boot_id, "raw": {"types": sorted(recs), "syscall": sc},
    }
    if group.get("duplicates"):
        ev["raw"]["duplicate_records"] = sorted(set(group["duplicates"]))
    return ev


class Spooler:
    """Durable queue with STABLE RECORD IDENTITIES (audit N08):

    * every record carries a monotonic `_seq` (persisted counter);
    * append/trim/acknowledge run under an exclusive flock — no torn state
      even across crashes or concurrent instances;
    * acknowledge removes records BY ID, so records appended while an HTTP
      batch was in flight are never removed by that batch's ack;
    * the byte limit is enforced for EVERY append including the first
      oversized record of an empty spool (visible drop, never silent);
    * gap/drop counters are PERSISTED and reloaded on restart;
    * readers are tolerant: a torn trailing line from an interrupted write is
      skipped and counted as a visible gap, never a crash.
    """

    def __init__(self, spool_dir: str, max_bytes: int = 64 * 1024 * 1024):
        self.path = os.path.join(spool_dir, "pending.ndjson")
        self.gap_path = os.path.join(spool_dir, "gaps")
        self.lock_path = os.path.join(spool_dir, "spool.lock")
        self.seq_path = os.path.join(spool_dir, "seq")
        self.max_bytes = max_bytes
        os.makedirs(spool_dir, exist_ok=True)
        self.dropped = self._load_dropped()

    # ---- durable counters -----------------------------------------------------
    def _load_dropped(self) -> int:
        try:
            with open(self.gap_path) as f:
                for line in reversed(f.readlines()[-64:]):
                    m = re.search(r"total=(\d+)", line)
                    if m:
                        return int(m.group(1))
        except OSError:
            pass
        return 0

    def _gap(self, reason: str, n: int = 1) -> None:
        self.dropped += n
        with open(self.gap_path, "a") as g:
            g.write(f"{time.time()} {reason} n={n} total={self.dropped}\n")

    # ---- locking ---------------------------------------------------------------
    class _Lock:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            self.f = open(self.path, "a+")
            fcntl.flock(self.f, fcntl.LOCK_EX)
            return self

        def __exit__(self, *a):
            fcntl.flock(self.f, fcntl.LOCK_UN)
            self.f.close()
            return False

    def _lock(self):
        return Spooler._Lock(self.lock_path)

    # ---- storage ---------------------------------------------------------------
    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _read_lines(self) -> list[str]:
        """Tolerant read: malformed/trailing torn lines are skipped and
        counted as a visible gap (interrupted-write recovery)."""
        if not os.path.exists(self.path):
            return []
        out, bad = [], 0
        with open(self.path) as f:
            for l in f:
                if not l.strip():
                    continue
                try:
                    json.loads(l)
                    out.append(l if l.endswith("\n") else l + "\n")
                except json.JSONDecodeError:
                    bad += 1
        if bad:
            self._gap("dropped-malformed", bad)
        return out

    def _atomic_write_lines(self, lines: list[str]) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            f.writelines(lines)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def _next_seq(self) -> int:
        try:
            cur = int(open(self.seq_path).read().strip() or "0")
        except (OSError, ValueError):
            cur = 0
        n = cur + 1
        with open(self.seq_path, "w") as f:
            f.write(str(n))
            f.flush()
            os.fsync(f.fileno())
        return n

    # ---- queue operations --------------------------------------------------------
    def append(self, event: dict) -> int | None:
        """Stable-identity append with byte-limit enforcement (returns the
        record id, or None when the record itself exceeds the spool — a
        VISIBLE drop, including as the very first record)."""
        with self._lock():
            seq = self._next_seq()
            payload = json.dumps({**event, "_seq": seq}) + "\n"
            size = len(payload.encode())
            if size > self.max_bytes:
                self._gap("dropped-oversize")
                return None
            lines = self._read_lines()
            cur = sum(len(l.encode()) for l in lines)
            trimmed = 0
            while lines and cur + size > self.max_bytes:
                cur -= len(lines.pop(0).encode())
                trimmed += 1
            if trimmed:
                self._atomic_write_lines(lines)
                self._gap("dropped-oldest", trimmed)
            with open(self.path, "a") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            return seq

    def pending(self, n: int = 200) -> list[tuple[int, dict]]:
        with self._lock():
            out = []
            for l in self._read_lines()[:n]:
                rec = json.loads(l)
                out.append((rec.get("_seq", 0), rec))
            return out

    def ack(self, ids: set[int]) -> None:
        """Acknowledge BY STABLE ID: records created while the delivered
        batch was in flight are NOT in `ids` and survive."""
        with self._lock():
            lines = self._read_lines()
            keep = [l for l in lines if json.loads(l).get("_seq", 0) not in ids]
            if len(keep) != len(lines):
                self._atomic_write_lines(keep)

    # previous positional API kept as a thin shim for any external caller
    def remove(self, ids: set[int]) -> None:
        self.ack(ids)


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
    returns False) drives the exponential backoff. Acknowledges exactly the
    ids it sent (audit N08) — records appended during the HTTP round trip
    remain queued for the next flush."""

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
        sent_ids = {i for i, _ in pend}
        ok = ship_events(self.api, self.token, [e for _, e in pend])
        if ok:
            self.spool.ack(sent_ids)
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
    ap.add_argument("--close-after-s", type=float, default=2.0,
                    help="bounded completion timeout: an event with no further "
                         "records for this long is deliverable while input stays open")
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
        # LIVE stream (audit N08): read stdin in a thread; the main loop uses
        # a queue timeout so an IDLE stream still closes its last event after
        # the bounded completion timeout — the final command of a quiet
        # session is deliverable without EOF.
        import queue
        q: queue.Queue = queue.Queue()

        def _reader():
            for line in sys.stdin:
                q.put(line)
            q.put(None)  # EOF sentinel

        threading.Thread(target=_reader, daemon=True, name="shipper-stdin").start()
        grouper = LiveGrouper(close_after_s=args.close_after_s, source=machine_id)
        eof = False
        while not eof:
            try:
                line = q.get(timeout=args.close_after_s)
            except queue.Empty:
                line = ""
                closed = grouper.flush_stale(time.time())
            else:
                if line is None:
                    eof = True
                    closed = grouper.flush_all()
                else:
                    closed = grouper.add(line)
                    for g in grouper._groups.values():
                        g["seen_wall"] = time.time()
            for group in closed:
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
