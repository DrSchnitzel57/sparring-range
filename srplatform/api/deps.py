"""Injectable dependencies for the API (broker client, DB session).

In prod: mutual-TLS BrokerClient (client cert from .env). In tests and the
isolated synthetic fixtures: set_broker(). The API process is the only thing
that talks to Postgres, and it reaches the deployment boundary ONLY through
the broker — it holds no PVE credentials and cannot construct PVE paths
(milestone 02). There is no direct-PVE fallback to remove, because there is
no longer any path to one from this process.
"""
from __future__ import annotations

import os
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

_broker = None


def get_broker():
    global _broker
    if _broker is None:
        from srplatform.settings import get_settings

        s = get_settings()
        if os.environ.get("SR_BROKER_FIXTURE") == "1" and s.sr_env != "production":
            # Explicit FIXTURE-ONLY in-process broker over the synthetic PVE
            # double (compose demo / browser acceptance). Never selectable
            # in production; production requires BROKER_URL + client TLS.
            from infra.broker.testing import make_fake_broker, policy_from_settings

            _broker, _svc, _http = make_fake_broker(policy=policy_from_settings(s))
            return _broker
        if not s.broker_url:
            from infra.broker.errors import BrokerUnavailable

            raise BrokerUnavailable(
                "broker not configured (BROKER_URL + mutual-TLS client material "
                "required) — the API has no direct Proxmox path")
        from infra.broker.client import BrokerClient, HttpTransport

        _broker = BrokerClient(HttpTransport(s.broker_url, s.broker_tls_ca_file,
                                             s.broker_client_cert,
                                             s.broker_client_key))
    return _broker


def set_broker(b) -> None:
    global _broker
    _broker = b
