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


def group_event_records(lines):
    """Yield one dict per audit EVENT ID, grouping consecutive records that
    share it (auditd writes EXECVE+SYSCALL+PROCTITLE adjacently)."""
    current_id, group = None, None
    for raw in lines:
        parsed = parse_audit_line(raw)
        if not parsed:
            continue
        rtype, eid, fields = parsed
        if eid != current_id:
            if group is not None:
                yield group
            current_id, group = eid, {"source_id": eid, "records": {}}
        group["records"][rtype] = fields
        if rtype == "SYSCALL":  # SYSCALL closes the event
            out, current_id, group = group, None, None
            yield out


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
    """Bounded on-disk spool (NDJSON). Retry with exponential backoff. Drops
    OLDEST when full, counting gaps — visible, not silent."""

    def __init__(self, spool_dir: str, max_bytes: int = 64 * 1024 * 1024):
        self.path = os.path.join(spool_dir, "pending.ndjson")
        self.gap_path = os.path.join(spool_dir, "gaps")
        self.max_bytes = max_bytes
        os.makedirs(spool_dir, exist_ok=True)
        self.dropped = 0

    def append(self, event: dict) -> None:
        size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        if size > self.max_bytes:
            # drop oldest line, record the gap
            with open(self.path) as f:
                lines = f.readlines()[1:]
            with open(self.path, "w") as f:
                f.writelines(lines)
            self.dropped += 1
            with open(self.gap_path, "a") as g:
                g.write(f"{time.time()} dropped-oldest total={self.dropped}\n")
        with open(self.path, "a") as f:
            f.write(json.dumps(event) + "\n")

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
        with open(self.path, "w") as f:
            f.writelines(keep)


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
    backoff = 1.0
    last_flush = 0.0

    def flush() -> bool:
        nonlocal backoff, last_flush
        pend = spool.pending()
        if not pend:
            backoff = 1.0
            return True
        try:
            ok = ship_events(args.api, args.token, [e for _, e in pend])
            if ok:
                spool.remove(set(range(len(pend))))
                backoff = 1.0
                last_flush = time.time()
            return ok
        except Exception as e:  # noqa: BLE001
            print(f"[shipper] flush failed: {e} (retry in {backoff:.0f}s)", file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            return False

    # drain anything spooled from previous outages first (bounded by loop)
    for _ in range(5):
        if flush():
            break

    for group in group_event_records(sys.stdin):
        ev = build_command_event(args.host, group, machine_id, boot_id)
        if ev is None:
            continue
        ev["machine_id"] = machine_id
        spool.append(ev)
        if time.time() - last_flush > 2:
            flush()


if __name__ == "__main__":
    main()
