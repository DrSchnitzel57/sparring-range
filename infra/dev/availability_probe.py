#!/usr/bin/env python3
"""Live availability probe: run the check registry from the SCORING VANTAGE.

Dev tool (appliance): resolves the lab's deployment, builds the vetted plans,
executes them over SSH on the scoring-vantage guest, and prints the
dependency-aware evidence. Credentials resolve to None here, so every
credentialed check honestly reports `unknown` (scorer material is not wired
to a protected store yet) — only the checks that need no secret can prove
the executor end to end.

Usage (appliance, control-plane env sourced):
    cd /opt/sparring-range && .venv/bin/python -m infra.dev.availability_probe
"""
from __future__ import annotations

import json
import sys

ENV_ID = "underpressure-range"


def _main() -> int:
    from sqlalchemy import select

    from srplatform import lab_service, verification_service
    from srplatform.availability_runner import SshVantage, sample_window
    from srplatform.db.models import Deployment, Lab
    from srplatform.db.session import db
    from srplatform.environment_specs import load_environment
    from srplatform.settings import get_settings

    s = get_settings()
    env = load_environment(ENV_ID)
    with db() as session:
        lab = session.execute(select(Lab).where(
            Lab.environment_id == ENV_ID,
            Lab.deleted_at.is_(None))).scalars().first()
        if lab is None:
            print("no live lab", file=sys.stderr)
            return 2
        home = lab_service.home_session(session, lab)
        dep = verification_service.active_deployment(session, home.session_id)
        if dep is None:
            print(f"lab {lab.lab_id} has no READY deployment", file=sys.stderr)
            return 2
        by_host = {r["host"]: r for r in (dep.resources or [])
                   if r.get("state") == "created"}
        guest_states = {g.guest: g.state for g in lab_service._guests(session, lab)}
    vantage = by_host.get("scoring-vantage")
    if vantage is None:
        print("no scoring-vantage in the deployment", file=sys.stderr)
        return 2
    key = s.runner_ssh_key_path or s.verifier_ssh_key_path
    known = s.runner_ssh_known_hosts or s.verifier_ssh_known_hosts
    print(f"vantage {vantage['host']} {vantage['ip']}  lab {lab.lab_id} "
          f"state {lab.state}")
    transport = SshVantage(host=vantage["ip"], user="sr", key_path=key,
                           known_hosts=known or None)
    evidence = sample_window(env.checks, env.blueprint,
                             transport=transport,
                             credentials=lambda name: None,
                             guest_states=guest_states)
    rows = {cid: row["state"] for cid, row in evidence["checks"].items()}
    print(json.dumps({"states": rows, "coverage": evidence["coverage"],
                      "tasks": {tid: t["state"] for tid, t in evidence["tasks"].items()}},
                     indent=2, sort_keys=True))
    # A check is PROVEN only if it really ran on the vantage (not credential-
    # blocked): report which ones those were.
    ran = [cid for cid, row in evidence["checks"].items()
           if row["state"] in ("ok", "failed")]
    print("ran on vantage:", sorted(ran))
    return 0 if ran else 1


if __name__ == "__main__":
    sys.exit(_main())
