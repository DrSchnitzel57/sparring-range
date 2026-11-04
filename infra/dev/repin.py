#!/usr/bin/env python3
"""Re-pin Linux guests that missed the first-boot window (appliance dev tool).

The env lane pins each Linux guest's SSH host key after its clone; a heavy
image (Kali base, desktop) can still be booting when the boot-marker window
closes, so its pin is honestly recorded as `unenforced-environment-guest`.
The resume path re-pins a created guest that has no pin — by now the guest has
finished booting, so the read succeeds and the EXISTING bastion tokens start
working (the token route reads the pin at request time).
"""
from __future__ import annotations

import sys

ENV_ID = "underpressure-range"
SCENARIO = "underpressure-range-01"


def main() -> int:
    from sqlalchemy import select

    from srplatform import lab_service
    from srplatform.api.deps import get_broker
    from srplatform.db.models import Deployment, Lab
    from srplatform.db.session import db
    from srplatform.scenario_engine.env_deploy import deploy_environment

    broker = get_broker()
    with db() as session:
        lab = session.execute(select(Lab).where(
            Lab.environment_id == ENV_ID,
            Lab.deleted_at.is_(None))).scalars().first()
        if lab is None:
            print("no live lab", file=sys.stderr)
            return 2
        home = lab_service.home_session(session, lab)
        sid = home.session_id
        out = deploy_environment(session, sid, SCENARIO,
                                 {"environment": ENV_ID}, broker, resume=True)
        print("resume hosts:", len(out["hosts"]))
        dep = session.execute(select(Deployment).where(
            Deployment.session_id == sid).order_by(
                Deployment.created_at.desc())).scalars().first()
        for r in sorted(dep.resources, key=lambda x: x["host"]):
            if r.get("host_key") == "pinned":
                continue
            print(f"  still unpinned: {r['host']} "
                  f"{str(r.get('host_key_pin_error'))[:90]}")
        pinned = [r["host"] for r in dep.resources if r.get("host_key") == "pinned"]
        print("pinned:", sorted(pinned))
    return 0


if __name__ == "__main__":
    sys.exit(main())
