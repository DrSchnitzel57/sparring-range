"""Model administration (plan 19): versioned named profiles, role
overrides, per-session pins, rotation/revocation and bootstrap.

Trust model:
* The provider credential lives ONLY in the secret store (separate
  minimal DB identity — migration 0021); the profile row never holds or
  echoes a key. Nothing here returns a key: masked shapes only
  (``ModelProfile.masked`` / ``public_config``), so no API response,
  event payload, log line or export can carry one.
* Editing a profile creates a NEW version. A NON-secret edit marks the
  old version ``superseded`` and sessions already pinned to it KEEP
  running on it; only credential replacement/revocation invalidates
  (visibly, cancelling affected jobs). A session PINS the whole role
  set at first use and keeps it for its whole life.
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


#: levels with a built-in wire encoding (see conversation.thinking_encoding)
THINKING_LEVELS = ("none", "low", "medium", "high")

#: request fields a custom thinking level may shape (finding 6) — and
#: their value bounds. Anything outside this surface is refused at
#: validation, so a thinking_map can never smuggle messages, tools,
#: auth or destination overrides onto the request.
_EFFORT_WORDS = ("minimal", "low", "medium", "high", "xhigh", "none")


def validate_thinking_map(thinking_map, level: str) -> dict:
    """Custom named levels must DECLARE how they reach the wire
    (review finding 6): a level maps to standard level-alias string or
    to a bounded request-field mapping. No arbitrary provider
    overrides, and no level whose encoding is unknown."""
    if not isinstance(thinking_map, dict):
        raise ProfileProblem("thinking_map must be an object")
    out: dict = {}
    for name, target in thinking_map.items():
        if not isinstance(name, str) or not name or len(name) > 64:
            raise ProfileProblem("thinking_map level names must be short "
                                 "strings")
        if isinstance(target, str):
            if target not in THINKING_LEVELS:
                raise ProfileProblem(
                    f"thinking_map[{name!r}] may alias only "
                    f"{'/'.join(THINKING_LEVELS)}")
            out[name] = target
            continue
        if not isinstance(target, dict) or not target:
            raise ProfileProblem(
                f"thinking_map[{name!r}] must be a standard level or a "
                "request-field mapping (reasoning_effort and/or "
                "chat_template_kwargs)")
        for field, value in target.items():
            if field == "reasoning_effort":
                if value not in _EFFORT_WORDS:
                    raise ProfileProblem(
                        f"thinking_map[{name!r}].reasoning_effort must be "
                        f"one of {'/'.join(_EFFORT_WORDS)}")
            elif field == "chat_template_kwargs":
                if (not isinstance(value, dict) or not value
                        or len(value) > 8):
                    raise ProfileProblem(
                        f"thinking_map[{name!r}].chat_template_kwargs must "
                        "be a small object")
                for k, v in value.items():
                    if not isinstance(k, str) or len(k) > 64:
                        raise ProfileProblem("chat_template_kwargs keys "
                                             "must be short strings")
                    if isinstance(v, bool) or isinstance(v, int):
                        continue
                    if not isinstance(v, str) or len(v) > 200:
                        raise ProfileProblem(
                            "chat_template_kwargs values must be bool, "
                            "int, or short strings")
            else:
                raise ProfileProblem(
                    f"thinking_map[{name!r}] field {field!r} is not "
                    "permitted — only reasoning_effort and "
                    "chat_template_kwargs reach the wire through a mapping")
        out[name] = dict(target)
    if (level not in THINKING_LEVELS and level not in out):
        raise ProfileProblem(
            f"thinking_level {level!r} has no mapping: custom levels must "
            f"declare how they encode (standard levels: "
            f"{'/'.join(THINKING_LEVELS)})")
    return out


def validate_capabilities(capabilities) -> dict:
    """Bounded, labeled discovery facts (admin GUI, finding 6). Shapes
    are enforced shallowly; CONTENT remains an operator/endpoint claim,
    never authority over routing or auth."""
    if not isinstance(capabilities, dict) or len(capabilities) > 16:
        raise ProfileProblem("capabilities must be a small object")
    out: dict = {}
    for key, value in capabilities.items():
        if not isinstance(key, str) or len(key) > 64:
            raise ProfileProblem("capabilities keys must be short strings")
        blob = str(value)
        if len(blob) > 2000:
            raise ProfileProblem("capabilities values are too large")
        out[key] = value
    think = out.get("thinking")
    if isinstance(think, dict):
        levels = think.get("supported_levels")
        if levels is not None and (
                not isinstance(levels, list)
                or any(not isinstance(x, str) or len(x) > 64
                       for x in levels) or len(levels) > 32):
            raise ProfileProblem(
                "capabilities.thinking.supported_levels must be a list "
                "of short strings")
    return out


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
                            timeout_s: int | None,
                            compaction_ratio: float | None = None,
                            capabilities: dict | None = None) -> dict:
    out = {"base_url": validate_base_url(base_url),
           "model_name": (model_name or "").strip()}
    if not out["model_name"] or len(out["model_name"]) > 200:
        raise ProfileProblem("model_name must be a non-empty short string")
    level = thinking_level or "none"
    if not isinstance(level, str) or len(level) > 64:
        raise ProfileProblem("thinking_level must be a short string")
    out["thinking_level"] = level
    tmap = validate_thinking_map(thinking_map or {}, level)
    out["thinking_map"] = tmap
    caps = validate_capabilities(capabilities or {})
    declared = (caps.get("thinking") or {}).get("supported_levels") \
        if isinstance(caps.get("thinking"), dict) else None
    if declared and level not in declared:
        raise ProfileProblem(
            f"thinking_level {level!r} is not among the profile's declared "
            f"supported levels {sorted(declared)}")
    out["capabilities"] = caps
    out["generation_kwargs"] = validate_generation_kwargs(
        generation_kwargs or {})
    cw = 262144 if context_window is None else context_window
    mc = 32768 if max_completion_tokens is None else max_completion_tokens
    ts = 900 if timeout_s is None else timeout_s
    cr = 0.8 if compaction_ratio is None else compaction_ratio
    for name, value, lo, hi in (
            ("context_window", cw, 4096, 4_000_000),
            ("max_completion_tokens", mc, 1, 262144),
            ("timeout_s", ts, 5, 900)):
        if isinstance(value, bool) or not isinstance(value, int) \
                or not (lo <= value <= hi):
            raise ProfileProblem(f"{name} must be an integer between {lo} "
                                 f"and {hi}")
    if isinstance(cr, bool) or not isinstance(cr, (int, float)) \
            or not (0.05 <= float(cr) <= 0.99):
        raise ProfileProblem("compaction_ratio must be between 0.05 and 0.99")
    if mc >= cw:
        raise ProfileProblem("max_completion_tokens must leave room in the "
                             "context window (completion < context)")
    out.update({"context_window": cw, "max_completion_tokens": mc,
                "compaction_ratio": float(cr), "timeout_s": ts})
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
    model. The credential is moved from the env-held value into the
    SECRET STORE here and ONLY here — it never appears in any return
    value. If the secret identity is not configured, bootstrap refuses
    (audited, visible) rather than storing a key anywhere the ingestion
    role could read it."""
    if db.execute(select(ModelProfile).limit(1)).first() is not None:
        return False
    src = env_bootstrap_source()
    if not src:
        return False
    from srplatform import secret_store
    try:
        secret_store.has_key(uuid.uuid4())      # probe: is it configured?
    except Exception:  # noqa: BLE001 — a refusal, loudly audited
        _append_admin_note(db, "bootstrap.refused", {
            "reason": "postgres_url_secret is not configured: provider "
                      "credentials cannot be isolated from the ingestion "
                      "role; configure the secret identity first"})
        return False
    base = {"base_url": validate_base_url(src["base_url"]),
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
    try:
        db.flush()
    except IntegrityError:
        # first start of TWO processes at once: the unique indexes pick the
        # winner; the loser contributes nothing and the database is correct
        db.rollback()
        return False
    for prof in (red, coach):
        if src["api_key"]:
            secret_store.set_key(prof.profile_id, src["api_key"])
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
                   compaction_ratio: float | None = None,
                   capabilities: dict | None = None,
                   actor: str = "operator",
                   note: str | None = None,
                   _status: str = "active") -> ModelProfile:
    """Create the NEXT version of a profile (version 1 when the name is
    new). ``api_key`` is write-only by construction: it goes straight
    into the secret store and is never echoed. An empty key means "no
    credential yet" — the profile exists but every call on it fails
    visibly until a credential is supplied (callers who mean "keep the
    current one" must use :func:`revise` with ``api_key=None``)."""
    if not name or len(name) > 64 or any(c in name for c in " \t/"):
        raise ProfileProblem("profile name must be a short token")
    fields = validate_profile_fields(
        base_url=base_url, model_name=model_name,
        thinking_level=thinking_level, thinking_map=thinking_map,
        generation_kwargs=generation_kwargs, context_window=context_window,
        max_completion_tokens=max_completion_tokens, timeout_s=timeout_s,
        compaction_ratio=compaction_ratio, capabilities=capabilities)
    from sqlalchemy import func as _func
    top = db.execute(select(_func.coalesce(_func.max(ModelProfile.version), 0))
                     .where(ModelProfile.name == name)).scalar_one()
    prof = ModelProfile(name=name, version=int(top) + 1, status=_status,
                        note=note, **fields)
    db.add(prof)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ProfileProblem(f"profile {name!r} could not be created: "
                             "another version won the race") from exc
    if api_key:
        from srplatform import secret_store
        try:
            secret_store.set_key(prof.profile_id, api_key)
        except Exception as exc:  # noqa: BLE001 — row must not lie
            db.delete(prof)
            db.flush()
            raise ProfileProblem(
                "the credential could not be stored in the secret store; "
                "the profile was not created") from exc
    _append_admin_note(db, "profile.create",
                       {"name": name, "version": prof.version,
                        "model_name": prof.model_name, "by": actor,
                        "key_set": bool(api_key)})
    return prof


def revise(db: Session, name: str, *, api_key: str | None = None,
           actor: str = "operator", **changes) -> ModelProfile:
    """Create the next version from the current active one, overriding
    only what the operator supplied. The SECRET axis decides the old
    version's fate (review finding 9):

    * ``api_key=None`` (non-secret edit — thinking, timeouts, budgets):
      the old version becomes ``superseded``. Sessions PINNED to it
      KEEP working (that is what makes a thinking-level edit safe to
      make mid-match); new sessions get the new version. No job is
      cancelled, nothing is interrupted.
    * a supplied key (credential replacement): the old version becomes
      ``revoked`` and its stored credential is DELETED immediately —
      pinned sessions' work then FAILS visibly until an operator
      rebinds. Queued jobs are cancelled; running ones get a visible
      cessation request.
    """
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
        "compaction_ratio": changes.get("compaction_ratio",
                                        current.compaction_ratio),
        "capabilities": changes.get("capabilities", current.capabilities),
    }
    unknown = set(changes) - set(merged)
    if unknown:
        raise ProfileProblem(f"unknown profile fields: {sorted(unknown)}")
    rotating_key = api_key is not None
    # demote FIRST: the one-ACTIVE partial index forbids two active rows
    # even mid-transaction.
    demote(db, current,
           reason="credential replaced" if rotating_key
                  else "non-secret edit; pinned sessions continue",
           actor=actor, revoked=rotating_key)
    new = create_profile(db, name=name,
                         api_key=(api_key or "") if rotating_key else "",
                         actor=actor,
                         note=changes.get("note",
                                          f"rotation of {name} v{current.version}"
                                          if rotating_key else
                                          f"edit of {name} v{current.version}"),
                         **merged)
    if not rotating_key:
        # carry the credential forward for NEW sessions (the old version
        # keeps its own until it is revoked; both point at the same
        # secret value but rows are independent so revocation later
        # cannot orphan a replacement mid-flight)
        from srplatform import secret_store
        existing = secret_store.get_key(current.profile_id)
        if existing:
            secret_store.set_key(new.profile_id, existing)
        _append_admin_note(db, "profile.supersede", {
            "name": name, "old_version": current.version,
            "new_version": new.version,
            "effect": "new sessions use the new version; sessions pinned "
                      "to the old version continue on it", "by": actor})
    return new


def demote(db: Session, prof: ModelProfile, *, reason: str,
           actor: str = "operator", revoked: bool = False) -> None:
    """Visible lifecycle transition. Revocation carries the CANCELLATION
    duty over the version's references: queued jobs die, running jobs
    get a cessation request (the slot releases only when the live call
    actually returns). Supersession (a non-secret edit) cancels NOTHING
    — pinned sessions keep running on the version they started with,
    which is exactly the freeze finding 9 demanded."""
    if prof.status != "active":
        raise ProfileProblem(f"profile {prof.name} v{prof.version} is "
                             f"already {prof.status}")
    prof.status = "revoked" if revoked else "superseded"
    prof.retired_at = datetime.now(timezone.utc)
    db.flush()
    if revoked:
        from srplatform import secret_store
        secret_store.delete_key(prof.profile_id)
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
    # queued descendants (retry children, gated turns) must not survive
    # their parent's cancellation — cascade one visible level at a time
    cancelled_ids = {j.job_id for j in queued}
    while cancelled_ids:
        children = db.execute(select(ModelJob).where(
            ModelJob.parent_job.in_(cancelled_ids),
            ModelJob.state == "queued")).scalars().all()
        cancelled_ids = set()
        for child in children:
            child.state = "cancelled"
            child.error = (f"cancelled with its parent job: {reason}")
            child.finished_at = datetime.now(timezone.utc)
            cancelled_ids.add(child.job_id)
        db.flush()


def revoke(db: Session, profile_id: uuid.UUID, *, actor: str = "operator",
           reason: str = "revoked") -> ModelProfile:
    from srplatform.db.models import ModelJob
    prof = db.get(ModelProfile, profile_id)
    if prof is None:
        raise ProfileProblem("profile version not found")
    if prof.status == "revoked":
        raise ProfileProblem("profile version is already revoked")
    from srplatform import secret_store
    if prof.status == "active":
        demote(db, prof, reason=reason, actor=actor, revoked=True)
    else:
        prof.status = "revoked"
        prof.retired_at = datetime.now(timezone.utc)
        db.flush()
        # revocation of an already-superseded/retired version invalidates
        # its credential too — that is the whole point of revoking it
        secret_store.delete_key(prof.profile_id)
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


def _resolve_role_profile(db: Session, role: str) -> ModelProfile:
    name = role_overrides(db).get(role) or _default_role_profile(db, role)
    if not name:
        raise ProfileUnavailable(
            f"no active profile is bound to role {role!r} — configure "
            "one via the model admin")
    prof = active_profile(db, name)
    if prof is None:
        raise ProfileUnavailable(
            f"role {role!r} selects {name!r}, which has no active version")
    return prof


def bind_for(db: Session, session_id, role: str
             ) -> tuple[SessionModelPin, ModelProfile]:
    """The profile version THIS session runs on.

    WHOLE-SESSION FREEZE (review finding 9): the first use of ANY role
    pins ALL resolvable role profiles in one transaction — a session
    can never pick up a role override that an operator made after the
    session started (the old per-role first-use binding allowed a
    late override to silently change what an in-flight session used).

    A pin on a ``superseded`` version (non-secret edit) KEEPS SERVING;
    a pin on a ``revoked``/``retired`` version raises
    :class:`ProfileUnavailable` — the session's model work FAILS
    visibly until an operator rebinds. Nothing is ever substituted."""
    if role not in ROLES:
        raise ProfileProblem(f"role must be one of {', '.join(ROLES)}")
    pin = db.execute(select(SessionModelPin).where(
        SessionModelPin.session_id == session_id,
        SessionModelPin.role == role)).scalar_one_or_none()
    if pin is None:
        pins = _freeze_all_roles(db, session_id)
        pin = pins.get(role)
        if pin is None:
            raise ProfileUnavailable(
                f"no active profile is bound to role {role!r} — configure "
                "one via the model admin")
    prof = db.get(ModelProfile, pin.profile_id)
    if prof is None or prof.status not in ("active", "superseded"):
        state = "missing" if prof is None else prof.status
        raise ProfileUnavailable(
            f"session is pinned to {pin.config.get('name')} "
            f"v{pin.config.get('version')} ({state}) — no substitution is "
            "made; an operator must rebind the session explicitly")
    return pin, prof


def _freeze_all_roles(db: Session, session_id) -> dict[str, SessionModelPin]:
    """Pin every resolvable role at once. Roles with no resolvable
    profile are skipped HERE and fail visibly at their own first use —
    refusing to freeze one role must not silently unfreeze the others
    later, which is why resolution happens before any pin is written."""
    existing = {p.role: p for p in db.execute(
        select(SessionModelPin).where(
            SessionModelPin.session_id == session_id)).scalars()}
    if len(existing) == len(ROLES):
        return existing
    resolved: dict[str, ModelProfile] = {}
    problems: list[str] = []
    for role in ROLES:
        if role in existing:
            continue
        try:
            resolved[role] = _resolve_role_profile(db, role)
        except ProfileUnavailable as exc:
            problems.append(f"{role}: {exc}")
    if not resolved:
        raise ProfileUnavailable("; ".join(problems)
                                 or "no profiles resolvable for binding")
    for role, prof in resolved.items():
        db.add(SessionModelPin(session_id=session_id, role=role,
                               profile_id=prof.profile_id,
                               config=prof.public_config()))
    try:
        db.flush()
    except IntegrityError:      # concurrent first use: honor the winner
        db.rollback()
    return {p.role: p for p in db.execute(
        select(SessionModelPin).where(
            SessionModelPin.session_id == session_id)).scalars()}


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
    active version. Never automatic, and NEVER mid-generation: while
    the session has queued or running model work the rebind is refused,
    so no call can flip models under a live request (finding 9)."""
    if role not in ROLES:
        raise ProfileProblem(f"role must be one of {', '.join(ROLES)}")
    from srplatform.db.models import ModelJob
    busy = db.execute(select(ModelJob.job_id).where(
        ModelJob.session_id == session_id,
        ModelJob.state.in_(("queued", "running")))).first()
    if busy is not None:
        raise ProfileProblem(
            "session has queued or running model work — rebind is refused "
            "until it finishes (no mid-match substitution)")
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
    value is never logged, returned over HTTP, or handed to a worker.

    Since 0021 the value lives in the SECRET STORE (its own minimal DB
    role), not in the profile row the app role can read (finding 8). A
    missing secret row means the credential was revoked/never set:
    FAIL CLOSED — the work stops visibly, no substitute is tried."""
    from srplatform import secret_store
    key = secret_store.get_key(prof.profile_id)
    if key is None:
        raise ProfileUnavailable(
            f"no provider credential is stored for {prof.name} "
            f"v{prof.version} — it was revoked or never set; work stops "
            "until an operator configures a credential")
    return key


def masked(prof: ModelProfile, *, key_present: bool | None = None) -> dict:
    return prof.masked(key_present=key_present)
