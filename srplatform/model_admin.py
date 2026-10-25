"""Model administration (plan 19): versioned named profiles, role
overrides, per-session pins, rotation/revocation and bootstrap.

Trust model:
* The profile row is the ONLY holder of a provider credential, and the
  API process is its only reader. Nothing here returns a key: masked
  shapes only (``ModelProfile.masked`` / ``public_config``), so no API
  response, event payload, log line or export can carry one.
* Editing a profile creates a NEW version and demotes the old one —
  versions are never rewritten. A session PINS the version that served
  its first use and keeps it for its whole life: replacement or
  revocation can only invalidate (visibly, cancelling affected jobs and
  references), never silently swap the model or key underneath a match.
* Role overrides live in their own table and select a profile NAME;
  they never touch the process environment (explicitly NOT a global
  settings change).
* Bootstrap mirrors the existing environment configuration into a
  profile exactly once at upgrade, reading the env-held credential only
  to move it behind the profile store — the key never travels through
  an API request to get there.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from srplatform.db.models import (Event, ModelProfile, ModelRoleOverride,
                                  SessionModelPin)

BOOTSTRAP_NAME = "environment"
ROLES = ("attacker", "coach", "summarizer")
THINKING_LEVELS = ("none", "low", "medium", "high")

#: generation kwargs the operator may pin, with validators. Anything
#: else — messages, tools, auth, model, stream destinations, secret
#: redirects — is refused by name. The generation plane cannot be
#: overridden beyond these scalar sampling knobs.
_KWARG_RANGES = {
    "temperature": (0.0, 2.0),
    "top_p": (0.0, 1.0),
    "presence_penalty": (-2.0, 2.0),
    "frequency_penalty": (-2.0, 2.0),
}
_KWARG_DENY = ("messages", "tools", "tool_choice", "functions", "model",
               "api_key", "authorization", "stream", "user", "n",
               "max_tokens", "response_format", "stop", "seed",
               "base_url", "extra_body", "extra_headers")


class ProfileProblem(ValueError):
    """Validation or lifecycle refusal — always visible to the caller."""


class ProfileUnavailable(ProfileProblem):
    """A pinned profile was revoked/retired (or a role has no active
    profile): the session's work FAILS visibly. Never substituted."""
    retryable = False


def validate_generation_kwargs(kwargs) -> dict:
    if not isinstance(kwargs, dict):
        raise ProfileProblem("generation_kwargs must be an object")
    out: dict = {}
    for key, value in kwargs.items():
        if key in _KWARG_DENY:
            raise ProfileProblem(
                f"generation kwarg {key!r} is not permitted — it controls "
                "messages, tools, auth, destinations or the request "
                "envelope, which profiles must never override")
        if key not in _KWARG_RANGES:
            raise ProfileProblem(f"generation kwarg {key!r} is not allowlisted")
        lo, hi = _KWARG_RANGES[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not (lo <= float(value) <= hi):
            raise ProfileProblem(f"generation kwarg {key!r} must be a number "
                                 f"between {lo} and {hi}")
        out[key] = value
    return out


def validate_base_url(url: str) -> str:
    from urllib.parse import urlsplit
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ProfileProblem("base_url must be an absolute http(s) URL")
    if parts.username or parts.password:
        raise ProfileProblem(
            "base_url must not embed credentials — the credential lives "
            "only in the profile's write-only key field")
    return url


def validate_profile_fields(*, base_url: str, model_name: str,
                            thinking_level: str | None,
                            thinking_map: dict | None,
                            generation_kwargs: dict | None,
                            context_window: int | None,
                            max_completion_tokens: int | None,
                            timeout_s: int | None) -> dict:
    out = {"base_url": validate_base_url(base_url),
           "model_name": (model_name or "").strip()}
    if not out["model_name"] or len(out["model_name"]) > 200:
        raise ProfileProblem("model_name must be a non-empty short string")
    level = thinking_level or "none"
    if level not in THINKING_LEVELS:
        raise ProfileProblem(f"thinking_level must be one of "
                             f"{'/'.join(THINKING_LEVELS)}")
    out["thinking_level"] = level
    tmap = thinking_map or {}
    if not isinstance(tmap, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or len(v) > 64
            for k, v in tmap.items()):
        raise ProfileProblem("thinking_map must map names to short strings")
    out["thinking_map"] = dict(tmap)
    out["generation_kwargs"] = validate_generation_kwargs(
        generation_kwargs or {})
    cw = 262144 if context_window is None else context_window
    mc = 32768 if max_completion_tokens is None else max_completion_tokens
    ts = 900 if timeout_s is None else timeout_s
    for name, value, lo, hi in (
            ("context_window", cw, 4096, 4_000_000),
            ("max_completion_tokens", mc, 1, 262144),
            ("timeout_s", ts, 5, 900)):
        if isinstance(value, bool) or not isinstance(value, int) \
                or not (lo <= value <= hi):
            raise ProfileProblem(f"{name} must be an integer between {lo} "
                                 f"and {hi}")
    if mc >= cw:
        raise ProfileProblem("max_completion_tokens must leave room in the "
                             "context window (completion < context)")
    out.update({"context_window": cw, "max_completion_tokens": mc,
                "timeout_s": ts})
    return out


def _append_admin_note(db: Session, action: str, payload: dict) -> None:
    """Admin actions are auditable: events.session_id is nullable, so a
    global note is a SESSIONLESS event — honest provenance rather than a
    fake session. Session-scoped actions (rebind) carry their session."""
    db.add(Event(session_id=None, ts=datetime.now(timezone.utc),
                 actor="operator", action_type=f"model_admin.{action}",
                 payload=payload))


# --------------------------------------------------------------------------- #
# bootstrap                                                                    #
# --------------------------------------------------------------------------- #

def env_bootstrap_source() -> dict:
    """What the environment currently says the model is (never raises;
    an unusable environment yields None fields and bootstrap is simply
    skipped — role bindings then fail visibly with 'no active profile').
    The key is READ here solely to move it behind the profile store; it
    never appears in any return value that leaves this module."""
    from srplatform.settings import get_settings, model_api_key
    s = get_settings()
    if not s.llm_base_url:
        return {}
    try:
        key = model_api_key(s)
    except OSError:
        key = ""
    return {
        "base_url": s.llm_base_url,
        "api_key": key,
        "red_model": s.llm_model_red,
        "coach_model": s.llm_model_coach,
        "red_max_tokens": s.llm_max_tokens_red,
        "coach_max_tokens": s.llm_max_tokens_coach,
        "timeout_s": max(5, min(900, int(s.llm_timeout_s))),
    }


def ensure_bootstrap_profile(db: Session) -> bool:
    """Create the bootstrap profiles exactly once (idempotent — never
    re-reads env after the first call). Two profiles mirror the two
    env models; role defaults preserve pre-19 behavior: the red loop
    and the summarizer ran on the red model, the coach on the coach
    model. The credential is copied from the env-held credential into
    the profile store here and ONLY here."""
    if db.execute(select(ModelProfile).limit(1)).first() is not None:
        return False
    src = env_bootstrap_source()
    if not src:
        return False
    base = {"base_url": validate_base_url(src["base_url"]),
            "api_key": src["api_key"],
            "context_window": 262144, "timeout_s": src["timeout_s"]}
    red = ModelProfile(name=f"{BOOTSTRAP_NAME}-red", version=1,
                       status="active", model_name=src["red_model"],
                       max_completion_tokens=src["red_max_tokens"],
                       note="bootstrapped from environment configuration",
                       **base)
    coach = ModelProfile(name=f"{BOOTSTRAP_NAME}-coach", version=1,
                         status="active", model_name=src["coach_model"],
                         max_completion_tokens=src["coach_max_tokens"],
                         note="bootstrapped from environment configuration",
                         **base)
    db.add_all([red, coach])
    db.flush()
    db.add_all([
        ModelRoleOverride(role="attacker", profile_name=red.name),
        ModelRoleOverride(role="coach", profile_name=coach.name),
        # Pre-19, compression rode the red route with the red model — the
        # default keeps history comparable; operators may override.
        ModelRoleOverride(role="summarizer", profile_name=red.name),
    ])
    _append_admin_note(db, "bootstrap",
                       {"profiles": [red.name, coach.name]})
    return True


# --------------------------------------------------------------------------- #
# profile CRUD (versioned)                                                     #
# --------------------------------------------------------------------------- #

def active_profile(db: Session, name: str) -> ModelProfile | None:
    return db.execute(select(ModelProfile).where(
        ModelProfile.name == name,
        ModelProfile.status == "active")).scalar_one_or_none()


def create_profile(db: Session, *, name: str, base_url: str, model_name: str,
                   api_key: str, thinking_level: str | None = None,
                   thinking_map: dict | None = None,
                   generation_kwargs: dict | None = None,
                   context_window: int | None = None,
                   max_completion_tokens: int | None = None,
                   timeout_s: int | None = None,
                   actor: str = "operator",
                   note: str | None = None,
                   _status: str = "active") -> ModelProfile:
    """Create the NEXT version of a profile (version 1 when the name is
    new). ``api_key`` is write-only by construction: this is the only
    function that accepts it and it is never echoed. An empty key on a
    NEW version means 'replace with no credential' — callers who mean
    'keep the current one' (rotation of everything except the key) must
    use :func:`revise`."""
    if not name or len(name) > 64 or any(c in name for c in " \t/"):
        raise ProfileProblem("profile name must be a short token")
    fields = validate_profile_fields(
        base_url=base_url, model_name=model_name,
        thinking_level=thinking_level, thinking_map=thinking_map,
        generation_kwargs=generation_kwargs, context_window=context_window,
        max_completion_tokens=max_completion_tokens, timeout_s=timeout_s)
    from sqlalchemy import func as _func
    top = db.execute(select(_func.coalesce(_func.max(ModelProfile.version), 0))
                     .where(ModelProfile.name == name)).scalar_one()
    prof = ModelProfile(name=name, version=int(top) + 1, status=_status,
                        api_key=api_key or "", note=note, **fields)
    db.add(prof)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ProfileProblem(f"profile {name!r} could not be created: "
                             "another version won the race") from exc
    _append_admin_note(db, "profile.create",
                       {"name": name, "version": prof.version,
                        "model_name": prof.model_name, "by": actor})
    return prof


def revise(db: Session, name: str, *, api_key: str | None = None,
           actor: str = "operator", **changes) -> ModelProfile:
    """Rotation = create the next version from the current active one,
    overriding only what the operator supplied, then DEMOTE the old
    version and CANCEL everything that referenced it — visibly.
    ``api_key=None`` keeps the previous credential (rotation of a
    non-secret field); a supplied key replaces it. Sessions pinned to
    the previous version fail visibly afterwards; resuming requires the
    explicit operator rebind, never a silent swap."""
    current = active_profile(db, name)
    if current is None:
        raise ProfileProblem(f"no active profile named {name!r}")
    merged = {
        "base_url": changes.get("base_url", current.base_url),
        "model_name": changes.get("model_name", current.model_name),
        "thinking_level": changes.get("thinking_level", current.thinking_level),
        "thinking_map": changes.get("thinking_map", current.thinking_map),
        "generation_kwargs": changes.get("generation_kwargs",
                                         current.generation_kwargs),
        "context_window": changes.get("context_window", current.context_window),
        "max_completion_tokens": changes.get("max_completion_tokens",
                                             current.max_completion_tokens),
        "timeout_s": changes.get("timeout_s", current.timeout_s),
    }
    unknown = set(changes) - set(merged)
    if unknown:
        raise ProfileProblem(f"unknown profile fields: {sorted(unknown)}")
    # demote FIRST: the one-ACTIVE partial index forbids two active rows
    # even mid-transaction, and the visible cancellation duty over the old
    # version's queued jobs must be established before its replacement.
    demote(db, current, reason="replaced by rotation", actor=actor)
    new = create_profile(db, name=name,
                         api_key=current.api_key if api_key is None else api_key,
                         actor=actor,
                         note=changes.get("note", f"rotation of {name} v{current.version}"),
                         **merged)
    return new


def demote(db: Session, prof: ModelProfile, *, reason: str,
           actor: str = "operator", revoked: bool = False) -> None:
    """Visible lifecycle transition + the cancellation duty: queued jobs
    bound to this version are cancelled before they run; running ones
    get a cancellation request (the slot releases only when the live
    call actually returns — no overlapping requests)."""
    if prof.status != "active":
        raise ProfileProblem(f"profile {prof.name} v{prof.version} is "
                             f"already {prof.status}")
    prof.status = "revoked" if revoked else "retired"
    prof.retired_at = datetime.now(timezone.utc)
    db.flush()
    _cancel_jobs_for(db, prof, reason=reason)


def _cancel_jobs_for(db: Session, prof: ModelProfile, *, reason: str) -> None:
    from srplatform.db.models import ModelJob
    queued = db.execute(select(ModelJob).where(
        ModelJob.profile_id == prof.profile_id,
        ModelJob.state == "queued")).scalars().all()
    for job in queued:
        job.state = "cancelled"
        job.error = f"profile {prof.name} v{prof.version} replaced: {reason}"
        job.finished_at = datetime.now(timezone.utc)
    running = db.execute(select(ModelJob).where(
        ModelJob.profile_id == prof.profile_id,
        ModelJob.state == "running")).scalars().all()
    for job in running:
        job.cancel_requested = True
        job.error = (f"profile {prof.name} v{prof.version} replaced: {reason} "
                     "— slot held until the live call returns")


def revoke(db: Session, profile_id: uuid.UUID, *, actor: str = "operator",
           reason: str = "revoked") -> ModelProfile:
    from srplatform.db.models import ModelJob
    prof = db.get(ModelProfile, profile_id)
    if prof is None:
        raise ProfileProblem("profile version not found")
    if prof.status == "revoked":
        raise ProfileProblem("profile version is already revoked")
    if prof.status == "active":
        demote(db, prof, reason=reason, actor=actor, revoked=True)
    else:
        prof.status = "revoked"
        prof.retired_at = datetime.now(timezone.utc)
        db.flush()
    # References are cancelled too: every not-yet-terminal job bound to
    # this version (any state except the terminal ones) fails visibly.
    jobs = db.execute(select(ModelJob).where(
        ModelJob.profile_id == prof.profile_id,
        ModelJob.state.in_(("queued", "running")))).scalars().all()
    for job in jobs:
        if job.state == "queued":
            job.state = "cancelled"
            job.error = f"profile {prof.name} v{prof.version} revoked: {reason}"
            job.finished_at = datetime.now(timezone.utc)
        else:
            job.cancel_requested = True
            job.error = (f"profile {prof.name} v{prof.version} revoked: "
                         f"{reason} — slot held until the live call returns")
    _append_admin_note(db, "profile.revoke",
                       {"name": prof.name, "version": prof.version,
                        "by": actor, "reason": reason})
    return prof


# --------------------------------------------------------------------------- #
# role overrides and session pins                                              #
# --------------------------------------------------------------------------- #

def set_role_override(db: Session, role: str, profile_name: str, *,
                      actor: str = "operator") -> None:
    if role not in ROLES:
        raise ProfileProblem(f"role must be one of {', '.join(ROLES)}")
    if active_profile(db, profile_name) is None:
        raise ProfileProblem(f"no active profile named {profile_name!r}")
    row = db.get(ModelRoleOverride, role)
    if row is None:
        db.add(ModelRoleOverride(role=role, profile_name=profile_name,
                                 updated_by=actor))
    else:
        row.profile_name = profile_name
        row.updated_by = actor
    _append_admin_note(db, "role.set",
                       {"role": role, "profile_name": profile_name,
                        "by": actor})


def role_overrides(db: Session) -> dict[str, str]:
    return {r.role: r.profile_name
            for r in db.execute(select(ModelRoleOverride)).scalars()}


def bind_for(db: Session, session_id, role: str) -> tuple[SessionModelPin, ModelProfile]:
    """The profile version THIS session runs on: the pin is created on
    first use and honored for the session's whole life. A pin whose
    version was retired/revoked raises :class:`ProfileUnavailable` —
    the session's model work FAILS visibly until an operator rebinds
    it; nothing is ever substituted."""
    if role not in ROLES:
        raise ProfileProblem(f"role must be one of {', '.join(ROLES)}")
    pin = db.execute(select(SessionModelPin).where(
        SessionModelPin.session_id == session_id,
        SessionModelPin.role == role)).scalar_one_or_none()
    if pin is None:
        name = role_overrides(db).get(role) or _default_role_profile(db, role)
        if not name:
            raise ProfileUnavailable(
                f"no active profile is bound to role {role!r} — configure "
                "one via the model admin")
        prof = active_profile(db, name)
        if prof is None:
            raise ProfileUnavailable(
                f"role {role!r} selects {name!r}, which has no active version")
        pin = SessionModelPin(session_id=session_id, role=role,
                              profile_id=prof.profile_id,
                              config=prof.public_config())
        db.add(pin)
        try:
            db.flush()
        except IntegrityError:      # concurrent first use: honor the winner
            db.rollback()
            pin = db.execute(select(SessionModelPin).where(
                SessionModelPin.session_id == session_id,
                SessionModelPin.role == role)).scalar_one()
    prof = db.get(ModelProfile, pin.profile_id)
    if prof is None or prof.status != "active":
        state = "missing" if prof is None else prof.status
        raise ProfileUnavailable(
            f"session is pinned to {pin.config.get('name')} "
            f"v{pin.config.get('version')} ({state}) — no substitution is "
            "made; an operator must rebind the session explicitly")
    return pin, prof


def _default_role_profile(db: Session, role: str) -> str | None:
    # Without overrides (fresh bootstrap), fall back to the bootstrap
    # names so a first session works before any operator visit.
    bootstrap = db.execute(select(ModelProfile).where(
        ModelProfile.status == "active",
        ModelProfile.name.like(f"{BOOTSTRAP_NAME}%")).limit(1)).scalars().first()
    if bootstrap is None:
        return None
    if role == "coach":
        return f"{BOOTSTRAP_NAME}-coach"
    return f"{BOOTSTRAP_NAME}-red"


def rebind(db: Session, session_id, role: str, *, actor: str = "operator") -> SessionModelPin:
    """Explicit operator rebind: after a replacement/revocation, the
    ONLY way a session continues on models — pin the role's CURRENT
    active version. Never automatic."""
    if role not in ROLES:
        raise ProfileProblem(f"role must be one of {', '.join(ROLES)}")
    name = role_overrides(db).get(role) or _default_role_profile(db, role)
    if not name:
        raise ProfileProblem(f"role {role!r} has no profile to rebind to")
    prof = active_profile(db, name)
    if prof is None:
        raise ProfileProblem(f"no active profile named {name!r}")
    pin = db.execute(select(SessionModelPin).where(
        SessionModelPin.session_id == session_id,
        SessionModelPin.role == role)).scalar_one_or_none()
    if pin is None:
        pin = SessionModelPin(session_id=session_id, role=role,
                              profile_id=prof.profile_id,
                              config=prof.public_config())
        db.add(pin)
    else:
        pin.profile_id = prof.profile_id
        pin.config = prof.public_config()
        pin.bound_at = datetime.now(timezone.utc)
    db.flush()
    db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc),
                 actor="operator", action_type="model_admin.rebind",
                 payload={"role": role, "profile": prof.name,
                          "version": prof.version, "by": actor}))
    return pin


def resolve_credential(prof: ModelProfile) -> str:
    """The ONLY accessor for the provider credential — module-private by
    contract: callers are the provider layer in this process, and the
    value is never logged, returned over HTTP, or handed to a worker."""
    return prof.api_key or ""


def masked(prof: ModelProfile) -> dict:
    return prof.masked()
