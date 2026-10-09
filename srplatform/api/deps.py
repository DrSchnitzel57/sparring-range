"""Injectable dependencies for the API (proxmox connection, DB session).

In prod: real proxmoxer wrapper (token from .env). In tests: FakeProxmox via
set_proxmox(). The API process is the only thing that talks to Postgres, and the
only thing that talks to Proxmox.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from srplatform.db.session import db as _db_ctx

# -------------------------------------------------------------------------- #
# ONE shared request DB session, pinned to the FUNCTION dependency scope.     #
#                                                                              #
# FastAPI >= 0.142 runs generator dependencies with the DEFAULT ("request")    #
# scope AFTER the response has been sent to the client (verified against the   #
# installed stack: the commit landed ~300 ms after the client's next request   #
# was already in flight). A write committed there is invisible to the very     #
# next request — the intermittent CI handoff failures (login 401 after         #
# bootstrap 201, launch 404 after create 201, M01-R4, compose "401 after      #
# login") were exactly that race. scope="function" closes (commits) the        #
# session BEFORE the response is sent: a 2xx response is only observable once  #
# its writes are durable, and a failed commit is a 500, never a false 2xx.     #
# -------------------------------------------------------------------------- #


def get_db():
    with _db_ctx() as s:
        yield s


DbSession = Annotated[Session, Depends(get_db, scope="function")]

_proxmox = None


def get_proxmox():
    global _proxmox
    if _proxmox is None:
        import os

        from srplatform.settings import get_settings

        s = get_settings()
        if os.environ.get("SR_DEMO_FAKE_PROXMOX") == "1" and s.sr_env != "production":
            # Explicit DEV-ONLY demo double (browser/dev without a PVE).
            from infra.proxmox_client import FakePVEHttp, ProxmoxClient

            http = FakePVEHttp()
            for vmid in (9001, 9002, 9003, 9004):
                http.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid,
                                  "status": "stopped"}
            _proxmox = ProxmoxClient(api=http)
            return _proxmox
        from infra.proxmox_client import ProxmoxClient

        _proxmox = ProxmoxClient()
    return _proxmox


def set_proxmox(p) -> None:
    global _proxmox
    _proxmox = p
