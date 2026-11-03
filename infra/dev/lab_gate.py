#!/usr/bin/env python3
"""Live lab API gate (Underpressure step 3) — run ON the appliance.

Drives the real HTTP surface against real VMs through the private broker:

  1. creates a lab for the Underpressure environment,
  2. provisions it through the supervised executor (12 blueprint guests),
  3. requires the lab to become `active` with every guest `ready`,
  4. plans a single-guest reset (dependencies shown), approves it, and
     requires the SELECTIVE executor to bump ONLY that guest's generation
     while every preserved guest keeps its vmid/generation,
  5. deletes the lab and requires a verified teardown.

A temporary operator account is minted in the DB and its bearer token is
returned; nothing is printed that contains the password (only a token id).
Everything else is evidence JSON.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "http://127.0.0.1:8000"
ENV_ID = "underpressure-range"
SCENARIO = "underpressure-range-01"
GUEST = "ubuntu-wkst"


def _token() -> str:
    """Mint a short-lived operator token directly in the DB (no password
    needed; the gate runs on the appliance itself)."""
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
        tok = issue_user_token(s, user, get_settings().web_token_ttl_hours)
        return tok


def _call(method: str, path: str, token: str, body: dict | None = None,
          *, timeout: float = 120.0) -> dict:
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
        raise SystemExit(f"HTTP {e.code} {method} {path}: {text[:800]}") from None


def _wait_operation(token: str, lab_id: str, timeout_s: int = 1200) -> dict:
    deadline = time.time() + timeout_s
    last = {}
    while time.time() < deadline:
        last = _call("GET", f"/labs/{lab_id}/operation", token)
        state = last.get("state")
        if state in ("succeeded", "failed", "interrupted"):
            return last
        time.sleep(5)
    raise SystemExit(f"operation did not finish: {json.dumps(last)[:400]}")


def main() -> int:
    token = _token()
    for lab in _call("GET", "/labs", token)["labs"]:
        print("cleaning previous lab", lab["lab_id"], file=sys.stderr)
        _call("DELETE", f"/labs/{lab['lab_id']}", token, timeout=600)

    lab = _call("POST", "/labs", token, {"environment_id": ENV_ID,
                                         "scenario_id": SCENARIO,
                                         "name": "live lab gate"})
    lab_id = lab["lab_id"]
    print(f"lab {lab_id} created, {len(lab['guests'])} guests", file=sys.stderr)

    _call("POST", f"/labs/{lab_id}/provision", token)
    op = _wait_operation(token, lab_id)
    if op.get("state") != "succeeded":
        raise SystemExit(f"provision did not succeed: {json.dumps(op)[:1500]}")
    lab = _call("GET", f"/labs/{lab_id}", token)
    guests = {g["guest"]: g for g in lab["guests"]}
    assert lab["state"] == "active", f"lab state {lab['state']}"
    assert len(guests) == 12 and all(g["state"] == "ready"
                                     for g in guests.values()), \
        json.dumps(lab["guests"], indent=1)
    before = {name: (g["generation"], g["vmid"])
              for name, g in guests.items()}
    print("all 12 guests ready; planning a single-guest reset",
          file=sys.stderr)

    planned = _call("POST", f"/labs/{lab_id}/reset-plans", token,
                    {"selected": [GUEST]})
    plan = planned["plan"]
    if not plan["ok"]:
        raise SystemExit(f"plan blocked: {plan['blockers']}")
    assert plan["rebuild"] == [GUEST], plan["rebuild"]
    _call("POST", f"/labs/{lab_id}/reset-plans/{planned['plan_id']}"
                  f"/approve", token)
    op = _wait_operation(token, lab_id)
    if op.get("state") != "succeeded":
        raise SystemExit(f"reset did not succeed: {json.dumps(op)[:1500]}")
    lab = _call("GET", f"/labs/{lab_id}", token)
    guests = {g["guest"]: g for g in lab["guests"]}
    assert lab["state"] == "active", lab["state"]
    assert guests[GUEST]["generation"] == before[GUEST][0] + 1
    for name, (gen, vmid) in before.items():
        if name == GUEST:
            continue
        assert guests[name]["generation"] == gen, name
        assert guests[name]["vmid"] == vmid, name
    print(f"selective reset bumped only {GUEST}", file=sys.stderr)

    deleted = _call("DELETE", f"/labs/{lab_id}", token, timeout=900)
    assert deleted["state"] == "deleted"
    print(json.dumps({
        "gate": "lab-api-live",
        "lab_id": lab_id,
        "guests_ready": 12,
        "reset_guest": GUEST,
        "generation_before": before[GUEST][0],
        "generation_after": guests[GUEST]["generation"],
        "preserved_guests": len(before) - 1,
        "deleted": deleted["state"],
        "removed": len(deleted.get("removed") or []),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
