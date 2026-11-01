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

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from srplatform.db.models import (Event, ModelProfile, ModelRoleOverride,
                                  SessionModelPin)

BOOTSTRAP_NAME = "environment"
ROLES = ("attacker", "coach", "summarizer")

_SAFE_CODE_RE = re.compile(r"\A[0-9A-Za-z]{5}\Z")


def safe_error_shape(exc: BaseException | None) -> str:
    """The SECRET-SAFE structural identity of an exception (round-5
    review): class names plus SQLSTATE-style codes, nothing else.

    Raw exception text must never be persisted into evidence. Real
    PostgreSQL diagnostics quote the failing row's VALUES in the message
    (``DETAIL: Failing row contains (...)``), so a failed operation
    against the secret store can copy a provider credential VERBATIM
    into app-role-readable events, logs or exports. Class names and
    5-character codes are library-defined structure and cannot carry a
    value; text, ``args``, ``params``, statements, row details,
    tracebacks and provider bodies are never read, and NO pattern-based
    redaction is trusted — short opaque keys defeat every pattern.
    The failure itself stays fully recorded (this is not a silencer).
    """
    segments: list[str] = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    while isinstance(cur, BaseException) and len(segments) < 4:
        if id(cur) in seen:
            break
        seen.add(id(cur))
        codes: list[str] = []
        hops = [cur]
        orig = getattr(cur, "orig", None)
        if isinstance(orig, BaseException):
            hops.append(orig)
        for hop in hops:
            for attr in ("pgcode", "sqlstate"):
                code = getattr(hop, attr, None)
                if (isinstance(code, str) and _SAFE_CODE_RE.fullmatch(code)
                        and code not in codes):
                    codes.append(code)
        segments.append(type(cur).__name__
                        + (f"[{','.join(sorted(codes))}]" if codes else ""))
        cur = cur.__cause__ if cur.__cause__ is not None else cur.__context__
    return " <- ".join(segments) or "unknown"


def _credential_digest(api_key: str | None) -> str | None:
    """Non-reversible identity of a credential VALUE (round-2 finding 2).
    A one-way digest of a high-entropy key leaks nothing, and it is what
    makes "replace this credential" mean "invalidate EVERY version that
    carries this credential" — not just whichever version happens to be
    active when the operator rotates. Versions created before digests
    existed carry NULL and never match (no false revocations)."""
    if not api_key:
        return None
    return "sha256:" + hashlib.sha256(api_key.encode()).hexdigest()


def _record_compensation_failure(op: str, profile_id, exc: Exception) -> None:
    """A FAILED best-effort compensation is a durable repair obligation,
    not a swallowed log line: the secret store and the profile database
    are separate stores, and this guard is honest in-process
    compensation — NOT crash-atomicity. When even the compensation
    fails, an operator must be able to SEE the divergence (an admin
    event written through a fresh session, since the failed transaction
    is being discarded).

    Round-5 review: the record names the failure STRUCTURALLY ONLY
    (``safe_error_shape``). A real PostgreSQL diagnostic can quote the
    failing row's values — for a secret-store operation that is the
    provider credential itself — and these events are app-role
    evidence. Honest obligation, zero secret: never raw diagnostics,
    text, params, row details, causes-as-text or tracebacks, and no
    pattern "redaction" that could miss a short opaque key.
    """
    try:
        from srplatform.db.session import db as db_ctx
        with db_ctx() as s:
            _append_admin_note(s, "profile.secret_compensation_failed", {
                "op": op, "profile_id": str(profile_id),
                "error": safe_error_shape(exc),
                "action_needed": ("provider credential store and profile "
                                  "database diverge; inspect and re-align "
                                  "this profile version's credential")})
            s.commit()
    except Exception as note_exc:  # noqa: BLE001 — last resort, see below
        # The durable obligation itself could not be written (the DB may
        # be wedged or rejecting rows). Nothing remains that is both
        # available and secret-safe EXCEPT this process's own log — so
        # record the safe shapes loudly there. The divergence then has
        # no durable record by force of the environment, which is
        # exactly why the line says so in words; we never fake success.
        logging.getLogger("srplatform.model_admin").error(
            "secret compensation FAILED op=%s profile=%s error=%s; "
            "durable obligation NOT recorded (note write failed: %s) — "
            "manual credential re-alignment required",
            op, profile_id, safe_error_shape(exc),
            safe_error_shape(note_exc))


def _track_secret_writes_against_rollback(db: Session, profile_id) -> None:
    """Compensation across the protected store (round-2 finding 11,
    round-3 audit): the secret store is a SEPARATE database and commits
    immediately, so a profile row whose transaction later rolls back
    would leave an unowned secret. Register a per-request rollback guard
    ONCE that deletes secrets written for rows the transaction discarded
    and restores secrets whose delete was discarded with it.

    Round-3 audit fixes to the guard itself:
    * ``after_commit`` clears the pending lists — a COMMITTED unit of
      work owns its secrets legitimately, and a later rollback on the
      SAME session (session reuse, or any exception after a mid-request
      commit) must never re-fire compensation for it;
    * a restore re-checks the profile's COMMITTED status first: a
      concurrent revocation that already deleted the credential is
      never undone by our rollback (no resurrection of a compromised
      lineage through the wrong window);
    * a failing compensation records the durable repair obligation
      (see :func:`_record_compensation_failure`) instead of vanishing.

    Keys RESTORED as compensation target pre-existing rows and are
    deliberately not tracked as cleanups."""
    if profile_id is not None:
        db.info.setdefault("sr_secret_rollback_cleanups", []).append(
            profile_id)
    if db.info.get("sr_secret_guard_installed"):
        return
    from sqlalchemy import event as sa_event

    def _cleanup(session: Session) -> None:
        # SQLAlchemy 2.1 dispatches after_rollback with ONE argument
        # (proven empirically: a two-argument listener makes
        # Session.rollback() itself raise TypeError before the handler
        # runs, silently killing this exact compensation)
        from srplatform import secret_store
        cleanups = session.info.get("sr_secret_rollback_cleanups", [])
        session.info["sr_secret_rollback_cleanups"] = []
        restores = session.info.get("sr_secret_rollback_restores", [])
        session.info["sr_secret_rollback_restores"] = []
        for pid in cleanups:
            try:
                secret_store.delete_key(pid)
            except Exception as exc:  # noqa: BLE001 — already failing
                _record_compensation_failure("delete-rolled-back-write",
                                             pid, exc)
        for pid, value in restores:
            try:
                # the row's COMMITTED status decides: restoring under a
                # concurrent revocation would resurrect a deleted
                # credential for a version an operator just killed.
                # A STATUS CHECK ALONE IS NOT SERIALIZATION (round-4
                # finding 1): between a check and the write a revoke
                # could commit (delete the credential) and we would
                # recreate it for a revoked profile. The restore
                # therefore takes the SAME row lock a revocation takes
                # to change status — FOR UPDATE on the profile row —
                # and holds it ACROSS the secret write, committing
                # after. Ordering is then total: either our restore
                # lands first and the later revoke deletes the secret,
                # or the revoke lands first and our lock waits, sees
                # 'revoked', and skips. A bounded lock_timeout keeps a
                # wedged writer from hanging the compensation: a
                # timeout is a FAILED compensation — recorded as the
                # durable repair obligation, never a silent success.
                # Fresh session because a session inside its own
                # after_rollback is 'inactive' and refuses SQL (proven
                # by this guard's own regression).
                from sqlalchemy import text as _text
                from srplatform.db.session import app_engine
                with Session(app_engine()) as chk:
                    chk.execute(_text("SET LOCAL lock_timeout = '10s'"))
                    status = chk.execute(
                        select(ModelProfile.status)
                        .where(ModelProfile.profile_id == pid)
                        .with_for_update()).first()
                    if status is None or status[0] == "revoked":
                        continue
                    secret_store.set_key(pid, value)
                    chk.commit()
            except Exception as exc:  # noqa: BLE001 — already failing
                _record_compensation_failure("restore-deleted", pid, exc)

    def _settled(session: Session) -> None:
        # committed work is legitimate ownership: compensation entries
        # only ever concern THIS transaction's discarded effects, and a
        # commit ends that transaction. Without this, a later rollback
        # on a reused session would delete the committed profile's live
        # secret (round-3 audit: the guard lacked after-commit cleanup).
        session.info["sr_secret_rollback_cleanups"] = []
        session.info["sr_secret_rollback_restores"] = []

    sa_event.listen(db, "after_rollback", _cleanup)
    sa_event.listen(db, "after_commit", _settled)
    db.info["sr_secret_guard_installed"] = True


def _track_secret_delete_against_rollback(db: Session, profile_id,
                                          value: str | None) -> None:
    """A COMMITTED secret delete whose profile-status transaction later
    rolls back would destroy a working credential (round-2 finding 11).
    Record the value so the rollback guard puts it back; the guard is
    the SAME one that removes rolled-back writes, so one request sees
    one consistent compensation story no matter where the rollback
    happens (inside revise, or at the route after revise returned)."""
    if value is not None:
        db.info.setdefault("sr_secret_rollback_restores", []).append(
            (profile_id, value))
    if not db.info.get("sr_secret_guard_installed"):
        _track_secret_writes_against_rollback(db, None)

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
            # the env-held key MOVES here: digest recorded, value behind
            # the secret identity, rollback-guarded like every other
            # credential write
            prof.credential_digest = _credential_digest(src["api_key"])
            secret_store.set_key(prof.profile_id, src["api_key"])
            _track_secret_writes_against_rollback(db, prof.profile_id)
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
                   credential_digest: str | None = None,
                   _status: str = "active") -> ModelProfile:
    """Create the NEXT version of a profile (version 1 when the name is
    new). ``api_key`` is write-only by construction: it goes straight
    into the secret store and is never echoed. An empty key means "no
    credential yet" — the profile exists but every call on it fails
    visibly until a credential is supplied (callers who mean "keep the
    current one" must use :func:`revise` with ``api_key=None``).

    Round-2 finding 11: ALL validation happens before ANY effect; the
    secret write is the LAST step after the row is flushed, a failed
    secret write removes the row, and a rolled-back request transaction
    removes the secret again through the rollback guard — a version can
    never persist without its (intended) secret, and no secret can
    outlive its version."""
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
                        note=note,
                        credential_digest=(credential_digest
                                           if credential_digest is not None
                                           else _credential_digest(api_key)),
                        **fields)
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
        _track_secret_writes_against_rollback(db, prof.profile_id)
    _append_admin_note(db, "profile.create",
                       {"name": name, "version": prof.version,
                        "model_name": prof.model_name, "by": actor,
                        "key_set": bool(api_key)})
    return prof


def revise(db: Session, name: str, *, api_key: str | None = None,
           actor: str = "operator", note: str | None = None,
           **changes) -> ModelProfile:
    """Create the next version from the current active one, overriding
    only what the operator supplied. The SECRET axis decides the old
    versions' fate (review finding 9 + round-2 finding 2):

    * ``api_key=None`` (non-secret edit — thinking, timeouts, budgets):
      the old version becomes ``superseded``. Sessions PINNED to it
      KEEP working (that is what makes a thinking-level edit safe to
      make mid-match); new sessions get the new version. No job is
      cancelled, nothing is interrupted. The credential VALUE carries
      over (same digest — the lineage stays traceable).
    * a supplied key (credential replacement): every version that
      carries the REPLACED credential — the active one AND every
      superseded version a non-secret edit copied it forward to — is
      REVOKED at once, its stored credential deleted, its queued jobs
      cancelled and its running jobs asked to cease. Pinned sessions
      then FAIL visibly until an operator rebinds. Replacing a
      credential because it is compromised must not leave a live copy
      behind in an older version.

    Round-2 finding 11: validation completes BEFORE any secret or
    status effect, and every effect is compensated on failure — an
    invalid rotation can never destroy the working credential."""
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
    # ---- validate EVERYTHING before any effect (finding 11) ----------
    fields = validate_profile_fields(**merged)
    from srplatform import secret_store
    old_secret = secret_store.get_key(current.profile_id)  # read only
    replaced_digest = current.credential_digest
    if rotating_key:
        # Round-3 finding 5: a resubmitted credential whose VALUE is
        # unchanged is not a replacement. The GUI (and curl habit) can
        # resave the whole form, key included; treating that as a
        # rotation once revoked the brand-new version its own sweep was
        # performing and deleted the secret seconds after writing it —
        # a 200 response for an unusable profile. Same value means the
        # secret axis DID NOT change: it is a non-secret edit, the
        # lineage stays traceable, and no revocation duty arises. (A
        # GENUINE replacement still invalidates the whole replaced
        # lineage immediately, and a revoked version is never revived
        # — sibling sweeps skip revoked rows and will skip this new
        # version structurally too, below.)
        new_digest_now = _credential_digest(api_key)
        if ((replaced_digest is not None
             and new_digest_now == replaced_digest)
                or (old_secret is not None and api_key == old_secret)):
            rotating_key = False
    new_digest = _credential_digest(api_key) if rotating_key \
        else current.credential_digest
    demote(db, current,
           reason="credential replaced" if rotating_key
                  else "non-secret edit; pinned sessions continue",
           actor=actor, revoked=rotating_key)
    try:
        new = create_profile(db, name=name,
                             api_key=(api_key or "") if rotating_key else
                                      (old_secret or ""),
                             credential_digest=new_digest,
                             actor=actor,
                             note=note or (
                                 f"rotation of {name} v{current.version}"
                                 if rotating_key else
                                 f"edit of {name} v{current.version}"),
                             **fields)
        if rotating_key and replaced_digest:
            # invalidate the WHOLE replaced-credential lineage, not just
            # the version that was active (finding 2)
            siblings = db.execute(select(ModelProfile).where(
                ModelProfile.credential_digest == replaced_digest,
                ModelProfile.status != "revoked")).scalars().all()
            for sib in siblings:
                if sib.profile_id == current.profile_id:
                    continue
                if sib.profile_id == new.profile_id:
                    # structural guard (round-3 finding 5): THIS
                    # request's own new version is never a "sibling
                    # carrying the replaced credential" — sweeping it
                    # would revoke the replacement it just created
                    continue
                sib.status = "revoked"
                sib.retired_at = datetime.now(timezone.utc)
                _delete_secret_tracked(db, sib.profile_id)
                _cancel_jobs_for(db, sib, reason="credential replaced")
            _append_admin_note(db, "profile.lineage_revoke", {
                "name": name, "new_version": new.version,
                "revoked_versions": [s.version for s in siblings
                                     if s.profile_id not in
                                     (current.profile_id, new.profile_id)],
                "effect": "every version carrying the replaced credential "
                          "is revoked; pinned sessions fail visibly until "
                          "an operator rebinds", "by": actor})
    except Exception:
        # No manual compensation is needed — and none would be correct:
        # the transaction rolls back (restoring every status change,
        # even at route level after this function returned), and the
        # SAME rollback guard deletes the new version's written secret
        # and restores every secret this request deleted with its
        # recorded value. One consistent story for every failure point
        # (round-2 finding 11). HONEST SCOPE (round-3 audit): this is
        # in-process compensation across two stores, NOT crash
        # atomicity — a power loss between the secret-store commit and
        # this transaction's end can leave a bounded divergence, and a
        # FAILED compensation records a durable admin obligation rather
        # than vanishing. Genuine XA over both stores is not on this
        # release's dependency list; the divergence is documented and
        # auditable, not hidden.
        raise
    if not rotating_key:
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
        _delete_secret_tracked(db, prof.profile_id)
        _cancel_jobs_for(db, prof, reason=reason)


def _delete_secret_tracked(db: Session, profile_id) -> None:
    """Delete a stored credential WITH rollback compensation (finding 11):
    the secret store commits immediately, so the value is captured first
    and the transaction's rollback guard restores it if the status
    change that justified the delete never commits."""
    from srplatform import secret_store
    value = secret_store.get_key(profile_id)
    secret_store.delete_key(profile_id)
    _track_secret_delete_against_rollback(db, profile_id, value)


def _cancel_jobs_for(db: Session, prof: ModelProfile, *, reason: str) -> None:
    """Revocation carries the FULL cancellation duty (round-3 finding 4):
    every affected logical request goes through the ONE durable protocol
    — lock, stamp intent, transition conditionally, cascade, and persist
    the member-visible outcome exactly once — instead of hand-writing
    row states here and bypassing the outcome claim (the reviewer's
    repro: cancelled rows, outcome_persisted false, ZERO events)."""
    from srplatform import model_jobs
    from srplatform.db.models import ModelJob
    jobs = db.execute(select(ModelJob).where(
        ModelJob.profile_id == prof.profile_id,
        ModelJob.state.in_(("queued", "running")))).scalars().all()
    for job in jobs:
        try:
            model_jobs.cancel(
                db, job.job_id,
                actor=f"profile {prof.name} v{prof.version} ({reason})")
        except model_jobs.JobProblem:
            continue                       # row vanished under us


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
        # revocation of an already-superseded/retired version invalidates
        # its credential too — that is the whole point of revoking it
        _delete_secret_tracked(db, prof.profile_id)
    # References are cancelled too: every still-live job bound to this
    # version dies through the logical-request protocol (intent, cascade
    # and ONE durable outcome per chain — round-3 finding 4), never by
    # a hand-written state that skips the member's evidence.
    jobs = db.execute(select(ModelJob).where(
        ModelJob.profile_id == prof.profile_id,
        ModelJob.state.in_(("queued", "running")))).scalars().all()
    for job in jobs:
        try:
            from srplatform import model_jobs
            model_jobs.cancel(db, job.job_id,
                              actor=f"revocation: {reason}")
        except model_jobs.JobProblem:
            continue
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
