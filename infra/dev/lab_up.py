#!/usr/bin/env python3
"""Bring a lab UP and print how to get in (Underpressure step 3, stopgap CLI).

Run on the appliance (same env rules as `lab_gate.py`). Unlike the gate this
REUSES an existing live lab and never tears it down: provision if needed,
wait for readiness, then print the captain's own SSH capabilities for every
guest (bastion logins issued by the readiness workflow; they expire with the
usual token TTL and are revoked by a reset).

Usage (appliance):
    sudo bash -c '. /etc/sparring-range/control-plane.derived.env;
        . /etc/sparring-range/control-plane.env; set -a;
        cd /opt/sparring-range && .venv/bin/python -m infra.dev.lab_up'
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"
ENV_ID = "underpressure-range"
SCENARIO = "underpressure-range-01"


def _token() -> str:
    from srplatform.api.auth import issue_user_token
    from srplatform.db.models import User
    from srplatform.db.session import db
    from srplatform.settings import get_settings

    from sqlalchemy import select

    with db() as s:
        user = s.execute(select(User).where(
            User.username == "lab-gate-operator")).scalar_one_or_none()
        if user is None:
            user = User(username="lab-gate-operator", role="operator")
            s.add(user)
            s.flush()
        return issue_user_token(s, user, get_settings().web_token_ttl_hours)


def _call(method: str, path: str, token: str, body: dict | None = None,
          *, timeout: float = 1800.0) -> dict:
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        text = e.read().decode(errors="replace")
        raise SystemExit(f"HTTP {e.code} {method} {path}: {text[:1200]}") from None


def _wait(token: str, lab_id: str, cap_s: int = 1200) -> dict:
    end = time.time() + cap_s
    last = {}
    while time.time() < end:
        last = _call("GET", f"/labs/{lab_id}/operation", token, timeout=60)
        if last.get("state") in ("succeeded", "failed", "interrupted"):
            return last
        time.sleep(5)
    raise SystemExit(f"operation did not finish: {json.dumps(last)[:400]}")


def main() -> int:
    token = _token()
    labs = _call("GET", "/labs", token, timeout=60)["labs"]
    lab = labs[0] if labs else None
    if lab is None or lab.get("state") not in ("provisioning", "degraded"):
        lab = _call("POST", "/labs", token,
                    {"environment_id": ENV_ID, "scenario_id": SCENARIO,
                     "name": "practice lab"}, timeout=120)
        print(f"created lab {lab['lab_id']}", file=sys.stderr)
        _call("POST", f"/labs/{lab['lab_id']}/provision", token, timeout=120)
    lab_id = lab["lab_id"]
    op = _wait(token, lab_id)
    if op.get("state") != "succeeded":
        raise SystemExit(f"provision failed: {json.dumps(op)[:2000]}")
    lab = _call("GET", f"/labs/{lab_id}", token, timeout=60)
    out = {
        "lab_id": lab_id,
        "state": lab["state"],
        "guests": [{"guest": g["guest"], "generation": g["generation"],
                    "state": g["state"], "vmid": g.get("vmid")}
                   for g in lab["guests"]],
    }
    result = op.get("result") or {}
    connections = result.get("connections") or []
    print(json.dumps(out, indent=2, sort_keys=True))
    if connections:
        print("\n# SSH from the operator box (bastion logins, token TTL):")
        for c in connections:
            print(f"#   {c['host']:<14} {c.get('ip', '')}   {c.get('ssh')}")
        print("\n# (the token is the ssh -l value; `ssh -p`/host appear above)")
    else:
        print("\n# no connections in the operation result — check the lab's "
              "guest states above")
    return 0


if __name__ == "__main__":
    sys.exit(main())
