#!/usr/bin/env python3
"""Delete every live lab (releases VMs/lease) — appliance helper."""
from __future__ import annotations

import sys
import time

from infra.dev.lab_gate import _call, _token


def main() -> int:
    token = _token()
    labs = _call("GET", "/labs", token)["labs"]
    for lab in labs:
        print("deleting", lab["lab_id"], lab["state"])
        _call("DELETE", f"/labs/{lab['lab_id']}", token, timeout=900)
    left = _call("GET", "/labs", token)["labs"]
    print("labs left:", [(x["lab_id"], x["state"]) for x in left])
    time.sleep(2)
    return 0 if not left else 1


if __name__ == "__main__":
    sys.exit(main())
