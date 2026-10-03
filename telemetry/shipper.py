"""~100-line telemetry shipper (Part 2): tail-and-POST into the API ingest
endpoint. Runs on each Linux range host; the auditd rules live in
telemetry/auditd.rules. This exists because auditd writes to a log file and the
platform wants structured events — Vector would be the drop-in alternative; this
keeps the dependency count at zero and is easy to debug.

Reads auditd's ENRICHED/JSON output (audispd → this script, or `ausearch -i -i
--format json` stream) and forwards execve-related records to the API, tagging
each with the host so the API can resolve the live session.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import httpx

FORWARDED_TYPES = {"EXECVE", "SYSCALL", "PROCTITLE", "CWD", "USER_CMD"}


def forward_line(client: httpx.Client, base_url: str, host: str, line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return  # raw audit format is handled by audispd-json plugin upstream
    if rec.get("type") not in FORWARDED_TYPES:
        return
    body = {
        "host": host,
        "ts": rec.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "uid": (rec.get("message", {}).get("uid") or rec.get("uid")),
        "comm": rec.get("comm") or rec.get("a0") or (rec.get("message", {}).get("comm")),
        "exe": rec.get("exe") or rec.get("path"),
        "argv": rec.get("argv") or rec.get("a0", ""),
        "raw": rec,
    }
    r = client.post(f"{base_url}/ingest/auditd", json=body, timeout=10)
    r.raise_for_status()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True, help="platform API base URL")
    ap.add_argument("--host", required=True, help="this host's name (matches scenario topology)")
    args = ap.parse_args()

    with httpx.Client() as client, (sys.stdin if len(sys.argv) else sys.stdin) as _:
        for line in sys.stdin:  # audisp-remote/af_unix plugin pipes JSON lines to us
            try:
                forward_line(client, args.api, args.host, line)
            except Exception as e:  # never die on one bad event — telemetry is firehose
                print(f"[shipper] drop: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
