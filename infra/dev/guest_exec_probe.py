#!/usr/bin/env python3
"""Live probe: typed guest_exec on Linux and Windows guests (appliance).

Dev tool. Resolves the live lab's deployment rows, then runs one harmless
command through the agent on a Linux and a Windows guest - the two halves of
the verification lane. Prints the raw result so the exit code and identity
are evidence, not a claim.
"""
from __future__ import annotations

import json
import sys

ENV_ID = "underpressure-range"


def _main() -> int:
    from sqlalchemy import select

    from srplatform import lab_service, verification_service
    from srplatform.api.deps import get_broker
    from srplatform.db.models import Deployment, Lab
    from srplatform.db.session import db

    broker = get_broker()
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
            print("no ready deployment", file=sys.stderr)
            return 2
        rows = {r["host"]: dict(r) for r in (dep.resources or [])
                if r.get("state") == "created"}
        node = dep.resources[0].get("node") if dep.resources else None
        session_id, generation = home.session_id, str(dep.deployment_id)

    cases = [
        ("ecomm", ["hostname"], "linux"),
        ("ad-dns", ["C:\\Windows\\system32\\cmd.exe", "/c", "hostname"],
         "windows"),
    ]
    failures = 0
    for host, argv, os_name in cases:
        row = rows.get(host)
        if row is None:
            print(f"{host}: not in the deployment")
            failures += 1
            continue
        try:
            out = broker.guest_exec(node, int(row["vmid"]), argv,
                                    session_id=str(session_id),
                                    generation=generation)
        except Exception as exc:  # noqa: BLE001 - report, never hide
            print(f"{host} ({os_name}) vmid={row['vmid']}: FAILED "
                  f"{type(exc).__name__}: {exc}")
            failures += 1
            continue
        print(f"{host} ({os_name}) vmid={row['vmid']}: rc={out['returncode']} "
              f"stdout={out['stdout'].strip()!r} stderr={out['stderr'].strip()!r}")
        if out["returncode"] != 0 or not out["stdout"].strip():
            failures += 1
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
