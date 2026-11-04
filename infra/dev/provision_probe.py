#!/usr/bin/env python3
"""Run per-role provisioning against the LIVE lab, from the operator gate.

Two processes by design, because the two authorities disagree:

  * the protected credential store is root:0600, so ROOT reads it;
  * the broker socket accepts only the `srrange` identity, so SRRANGE runs
    the guest commands.

The outer (root) process resolves the environment's credentials, hands them
to the inner process as `SR_CRED_*` environment variables (visible to root
alone; never argv), and the inner process calls the broker. That is the same
shape the availability gate uses — one secret at one boundary.

Usage (appliance):
    sudo bash -c '. /etc/sparring-range/control-plane.derived.env;
        . /etc/sparring-range/control-plane.env; set -a;
        cd /opt/sparring-range && .venv/bin/python -m infra.dev.provision_probe'

Exit: 0 when every guest that declares services has provisioning_ready,
1 when any implemented service failed or any service is unimplemented,
2 when there is no live deployment to provision.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

ENV_ID = "underpressure-range"


def _inner() -> int:
    from srplatform import lab_service, verification_service
    from srplatform.api.deps import get_broker
    from srplatform.db.models import Lab
    from srplatform.db.session import db
    from srplatform.environment_specs import load_environment
    from srplatform.labs.pki import LabPKI, pki_directory
    from srplatform.scenario_engine import env_provision
    from srplatform.settings import get_settings
    from sqlalchemy import select

    s = get_settings()
    with db() as session:
        lab = session.execute(select(Lab).where(
            Lab.environment_id == ENV_ID,
            Lab.deleted_at.is_(None))).scalars().first()
        if lab is None:
            print("no lab for", ENV_ID)
            return 2
        home = lab_service.home_session(session, lab)
        if home is None:
            print("lab has no home session")
            return 2
        dep = verification_service.active_deployment(session, home.session_id)
        if dep is None:
            print("no READY deployment for session", home.session_id)
            return 2
        bp = load_environment(ENV_ID).blueprint
        resolver = lambda name: os.environ.get(name)  # noqa: E731

        result = env_provision.provision_deployment(
            session, home.session_id, dep, bp, get_broker(),
            node=s.deploy_node, resolver=resolver,
            pki=LabPKI(pki_directory(s)))
    print(json.dumps(result, indent=2, sort_keys=True))
    return _verdict(result)


def _verdict(result: dict) -> int:
    bad = 0
    for guest, services in result.items():
        for service, state in services.items():
            if state == "failed":
                print(f"FAILED  {guest}.{service}")
                bad = 1
            elif state == "unimplemented":
                print(f"PENDING {guest}.{service} (no handler yet)")
                bad = 1
    if not bad:
        print("all declared services provisioned")
    return bad


def _outer() -> int:
    from srplatform.credentials import DEFAULT_PATH, load
    from srplatform.settings import get_settings

    s = get_settings()
    path = s.environment_credentials_file or DEFAULT_PATH
    try:
        values = load(path).get(ENV_ID, {})
    except Exception as exc:  # noqa: BLE001 — a bad store is loud, not silent
        print(f"credential store unreadable ({type(exc).__name__}): {exc}")
        values = {}
    env = dict(os.environ)
    env.update(values)
    print(f"store {path}: {len(values)} credential names resolved "
          f"(values withheld)")
    inner_env = {k: v for k, v in env.items()}
    inner_env["PYTHONPATH"] = os.getcwd()
    proc = subprocess.run(
        ["sudo", "-u", "srrange", "-E", sys.executable, "-m",
         "infra.dev.provision_probe", "--inner"],
        env=inner_env, capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    if proc.stderr.strip():
        sys.stderr.write(proc.stderr[-2000:])
    return proc.returncode if proc.returncode is not None else 1


def main() -> int:
    if "--inner" in sys.argv:
        return _inner()
    return _outer()


if __name__ == "__main__":
    sys.exit(main())
