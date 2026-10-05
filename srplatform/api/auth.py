"""Authentication + authorization (F04).

Real member authentication with operator-provisioned passwords; server-side
token expiry and revocation; distinct capability scopes for members, the
bastion, telemetry hosts and red workers. Username knowledge is NOT
authentication; a token alone identifies an actor; routes declare the minimum
capability they need.

Password storage: stdlib scrypt (memory-hard KDF). Justified instead of adding
a hashing dependency: no new supply chain, appropriate for LAN-scale account
counts, parameters recorded in the hash string for future upgrades.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from srplatform.db.models import Run, ServiceToken, User, WebToken

# scrypt parameters (interactive login: ~100ms class costs)
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**15, 8, 1
# N*r needs ~32MiB; Python's OpenSSL default maxmem is exactly 32MiB -> pass an
# explicit ceiling or hashing dies with "memory limit exceeded" on some builds.
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32, maxmem=_SCRYPT_MAXMEM)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64),
                            n=int(n), r=int(r), p=int(p), dklen=len(base64.b64decode(hash_b64)),
                            maxmem=_SCRYPT_MAXMEM)
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- principals
@dataclass(frozen=True)
class Principal:
    """Any authenticated actor."""
    kind: str                 # member | operator | service
    username: str | None = None
    user_id: object = None
    scope: str | None = None  # service scopes: bastion|telemetry|runner|score
    session_id: object = None  # service-bound session (runner/telemetry)
    host: str | None = None    # telemetry host identity

    @property
    def is_operator(self) -> bool:
        return self.kind == "operator"

    def require(self, *kinds: str) -> None:
        if self.kind not in kinds:
            raise HTTPException(403, "insufficient capability")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _live(row) -> bool:
    if getattr(row, "revoked_at", None) is not None:
        return False
    exp = getattr(row, "expires_at", None)
    if exp is not None and exp < _now():
        return False
    return True


def issue_user_token(db: Session, user: User, ttl_hours: int) -> str:
    tok = secrets.token_urlsafe(32)
    db.add(WebToken(token=tok, user_id=user.user_id,
                    expires_at=_now() + timedelta(hours=ttl_hours)))
    return tok


def revoke_token(db: Session, token: str) -> None:
    wt = db.get(WebToken, token)
    if wt and wt.revoked_at is None:
        wt.revoked_at = _now()


def _principal_from_token(db: Session, token: str) -> Principal:
    # user tokens first, then scoped service capabilities
    wt = db.get(WebToken, token)
    if wt:
        if not _live(wt):
            raise HTTPException(401, "token expired or revoked")
        u = db.get(User, wt.user_id)
        if not u:
            raise HTTPException(401, "bad token")
        return Principal(kind="operator" if u.role == "operator" else "member",
                         username=u.username, user_id=u.user_id)
    st = db.get(ServiceToken, token)
    if st:
        if not _live(st):
            raise HTTPException(401, "service token expired or revoked")
        return Principal(kind="service", scope=st.scope, session_id=st.session_id, host=st.host)
    # run-scoped red-worker credential (audit R01): the run manager stores ONLY
    # the sha256 of the token the worker was spawned with. It authenticates as
    # the `runner` capability bound to that run's session, and dies with the
    # run: a finished/cancelled/failed run's credential is REVOKED here.
    digest = hashlib.sha256(token.encode()).hexdigest()
    run = db.execute(select(Run).where(Run.worker_token == digest)).scalars().first()
    if run is not None:
        if run.status not in ("queued", "running"):
            raise HTTPException(401, "run credential revoked (run is no longer active)")
        return Principal(kind="service", scope="runner", session_id=run.session_id)
    raise HTTPException(401, "authentication required")


def extract_token(authorization: str | None, x_token: str | None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if x_token:
        return x_token.strip()
    raise HTTPException(401, "missing credential (Authorization: Bearer <token> or X-Token)")


def require_session_access(db: Session, p: Principal, session) -> None:
    """Members may only touch their own sessions; operators may manage all."""
    if p.is_operator:
        return
    if p.kind != "member" or session is None or str(session.user_id) != str(p.user_id):
        raise HTTPException(403, "not your session")


def make_auth_dependencies(get_db):
    """Build auth dependencies bound to a router's get_db."""

    def principal(authorization: str | None = Header(default=None),
                  x_token: str | None = Header(default=None),
                  db: Session = Depends(get_db)) -> Principal:
        token = extract_token(authorization, x_token)
        return _principal_from_token(db, token)

    def any_member(p: Principal = Depends(principal)) -> Principal:
        p.require("member", "operator")
        return p

    def operator(p: Principal = Depends(principal)) -> Principal:
        p.require("operator")
        return p

    def service(*scopes: str):
        def dep(p: Principal = Depends(principal)) -> Principal:
            if p.kind != "service" or p.scope not in scopes:
                raise HTTPException(403, f"requires service scope in {scopes}")
            return p
        return dep

    return principal, any_member, operator, service
