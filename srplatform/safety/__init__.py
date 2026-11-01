"""Safety supervisor (hard constraints #1, #2 — audit F02 rewrite).

Properties the old module violated, now enforced:

  * Fail-closed: the default state is NOT safe. Starting a run requires
    (a) not latched, (b) a fresh, identity-matched baseline check record,
    (c) a fresh operator datapath proof, and (d) a configured, reachable
    isolated runner. A handwritten success string is not attestation; records
    are made by THIS code or by an authenticated operator endpoint.
  * Durable latch: engagement is persisted (file + mirrored to DB when
    available) and survives API/worker restart. While latched, new commands
    and runs are rejected. Release is explicit, operator-only, removes only
    this application's emergency rules, and invalidates the evidence (a new
    start needs fresh checks).
  * Independent layers, honest results: worker termination and the datapath
    operation are attempted INDEPENDENTLY; each failure is reported truthfully
    (partial failure ≠ "engaged" success). A worker-signal failure never
    blocks the network operation, and a network failure is never silent.
  * Process identity: no arbitrary PIDs. Workers live in their own process
    groups; termination targets recorded groups with an identity guard that
    refuses to signal the API's own group.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from srplatform.safety.datapath import (
    DatapathController, config_identity, get_datapath)
from srplatform.safety.runregistry import run_registry
from srplatform.settings import Settings, get_settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


# -------------------------------------------------------------------------- #
# Datapath-proof attestation schema (audit R04)                              #
# The operator endpoint stays a trust boundary, but the SCHEMA distinguishes #
# "isolation observed" from "egress reachable": observations that describe  #
# working connectivity are structurally rejected, not silently recorded.     #
# -------------------------------------------------------------------------- #
# -------------------------------------------------------------------------- #
# Plan 22 LIVE-07: qualification versus admission health.                    #
# The three commissioning kinds below are QUALIFICATION evidence: collected  #
# once per configuration/contract, valid while that configuration and the    #
# safety latches are unchanged, with age shown as an advisory only. A fourth,#
# machine-written kind records the bounded non-disruptive ADMISSION probes   #
# the controller runs itself at every start — evidence of health now, never  #
# a renewed qualification. `qualification_contract` marks the schema version #
# a record was collected under; earlier accepted releases wrote the same    #
# kinds without a marker and are classified "legacy-compatible".             #
# -------------------------------------------------------------------------- #
QUALIFICATION_KINDS = ("baseline_check", "datapath_proof", "killswitch_test")
ADMISSION_KIND = "admission_probe"
QUALIFICATION_CONTRACT = 1


class SafetyStoreUnavailable(RuntimeError):
    """The AUTHORITATIVE append-only safety-record store cannot be used.
    Fencing-sensitive writes (reclassification) refuse rather than publish
    an unfenced fallback; observation-time resolution refuses to guess."""


class SafetyProvenanceError(ValueError):
    """A recognized classification's provenance cannot be VERIFIED (the
    source row is absent, a digest disagrees, the chain is cyclic or
    unresolvable, or a claimed time is not a finite, plausible,
    non-future instant). Such a record is INCOMPATIBLE evidence — never a
    new passed observation, and never defaulted to "now". It subclasses
    ValueError: publication refuses with it, readers mark it unusable."""


# THE shared publication boundary (plan 22 review round 4, owner contract):
# every safety_records writer — ordinary observation appends AND operator
# classifications — takes this same advisory transaction lock inside its
# one read-validate-append transaction, so a classifier and an observation
# can never interleave outside it. The table's grants are deliberately
# SELECT/INSERT-only (append-only doctrine), so an advisory lock, not a
# row FOR UPDATE, provides the serialization.
_SAFETY_PUBLISH_LOCK_SQL = (
    "SELECT pg_advisory_xact_lock(hashtext('sr.safety_records.cas.v1'))")
_SAFETY_NEWEST_SQL = (
    "SELECT record_id, ok, detail, config_identity,"
    " extract(epoch from recorded_at) AS at"
    " FROM safety_records WHERE kind = :k"
    " ORDER BY record_id DESC LIMIT 1")
_SAFETY_BY_ID_SQL = (
    "SELECT record_id, kind, ok, detail, config_identity,"
    " extract(epoch from recorded_at) AS at"
    " FROM safety_records WHERE record_id = :r")

# provenance time sanity: no pre-2001 epochs, small clock tolerance,
# nothing from the future — a future "observation" is a defect, never a
# head start on validity.
_PROVENANCE_MIN_EPOCH = 1_000_000_000.0
_PROVENANCE_FUTURE_TOLERANCE_S = 300.0
_PROVENANCE_MAX_HOPS = 64
_PROVENANCE_AGREEMENT_S = 1.0


def _detail_digest(detail) -> str:
    return hashlib.sha256(json.dumps(detail, sort_keys=True,
                                     default=str).encode()).hexdigest()[:16]


def _valid_observation_time(value, now: float | None = None) -> float | None:
    """A finite, plausible, NON-FUTURE epoch as a float — or None. Bools,
    NaN, Infinity, strings, missing values, pre-2001 and future stamps all
    fail; nothing here coerces a bad value into a passed observation."""
    if value is None or isinstance(value, bool):
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(ts) or ts < _PROVENANCE_MIN_EPOCH:
        return None
    if ts > (time.time() if now is None else now) \
            + _PROVENANCE_FUTURE_TOLERANCE_S:
        return None
    return ts


def _is_recognized_classification(det) -> bool:
    return (isinstance(det, dict)
            and det.get("qualification_contract") == QUALIFICATION_CONTRACT
            and det.get("one_time_reclassification") is True)


def _pending_failure_blocker(kind: str, untrusted: bool, pts: float,
                             pass_ts: float, audit_ts: float | None,
                             recon_pass: bool) -> str:
    """TRUTHFUL, actionable blocker for a retained failed observation
    that no reconciliation supersedes (plan 22 review round 6). The text
    must never send an operator to a command that cannot work: what
    clears the block is named exactly, and a failure that cannot be
    superseded says so."""
    if untrusted:
        return (
            f"an UNTRUSTED FAILED {kind} record exists (its claimed "
            "authoritative sequence resolves to nothing) — the failure is "
            "never lost; once the check holds authoritatively, close it "
            "with the audited recovery: `rangectl safety reconcile-outage "
            f"{kind} --reason \"...\"`")
    if recon_pass and pts >= pass_ts:
        return (
            f"an unreconciled FAILED {kind} record is envelope-stamped at "
            f"{pts:.0f}, NOT older than the newest authoritative pass "
            f"({pass_ts:.0f}) — it may be a NEWER failure or a clock "
            "defect and cannot be superseded by that pass; investigate "
            "it, then re-run the check so a fresh committed observation "
            "orders the truth")
    if audit_ts is not None:
        return (
            f"an unreconciled FAILED {kind} record is newer than the last "
            f"audited reconciliation ({audit_ts:.0f}) — investigate that "
            "failure; only a fresh authoritative observation or a newer "
            "audited reconciliation can order it")
    return (
        f"an unreconciled FAILED {kind} record exists whose order against "
        "the current evidence cannot be proven — re-run the check with "
        "working storage; the fresh committed pass supersedes it")
# Bounded freshness for the real runner health probe (SSHRunner.health through
# the transport the dispatcher itself uses): one probe per TTL window, never a
# connection storm behind the safety-page poll.
RUNNER_PROBE_TTL_S = 15.0

ISOLATION_MARKERS = (
    "100% packet loss", "100.0% packet loss", "unreachable", "fail", "failures",
    "timed out", "timeout", "no route to host", "no default route", "no answer",
    "no servers could be reached", "server fail", "nxdomain", "servfail",
    "network is unreachable", "could not resolve", "no such device",
)
# regexes, NOT substrings: "0% packet loss" is a substring of "100% packet loss"
REACHABILITY_MARKERS = (
    r"(?<!\d)0(\.0)?% packet loss", r"bytes from", r"default via",
    r"answers:", r"status: resolved", r"connected to", r"established",
)


def _legacy_scope_attested(kind: str, detail: dict) -> tuple[bool, str]:
    """Did an unmarked (pre-contract) record's detail PROVE its scope?

    The shapes below are what the accepted operator endpoints have always
    been REQUIRED to write for each kind (audit R04/N07 schemas). A record
    carrying that content describes what it observed and can be classified
    "legacy-compatible"; anything else — empty, missing the bound
    observations, or hand-written prose — proves nothing about what config
    it covered and must NOT default into compatibility (plan 22 review).
    """
    if kind == "datapath_proof":
        probes = detail.get("probes")
        if not isinstance(probes, dict) or not probes:
            return False, "no probe observations recorded"
        if not detail.get("vm"):
            return False, "probe host not recorded"
        ok, reasons = probes_attest_isolation(probes)
        return (True, "") if ok else (False, "; ".join(reasons)[:200])
    if kind == "killswitch_test":
        if "commands_stopped" not in detail or "datapath_isolated" not in detail:
            return False, "cessation/isolation observations not recorded"
        if not (detail.get("commands_stopped") and detail.get("datapath_isolated")):
            return False, ("a stop test that did not observe both cessation "
                           "and isolation never qualified anything")
        return True, ""
    if kind == "baseline_check":
        live = detail.get("live")
        if not isinstance(live, dict):
            return False, "no live verification status recorded"
        if not detail.get("source"):
            return False, "no attestation source recorded"
        return True, ""
    return False, f"unknown qualification kind {kind!r}"


def probes_attest_isolation(probes: dict) -> tuple[bool, list[str]]:
    """True only when EVERY probe observation describes FAILED egress and at
    least one probe exists. Ambiguous observations are rejected (fail closed)."""
    import re as _re
    reasons: list[str] = []
    if not probes:
        return False, ["no probe observations supplied"]
    for name, value in probes.items():
        v = str(value).lower()
        reach = [m for m in REACHABILITY_MARKERS if _re.search(m, v)]
        if reach:
            reasons.append(f"probe '{name}' describes REACHABLE egress ({reach[0]!r}) — "
                           "this endpoint records successful ISOLATION only")
            continue
        if not any(m in v for m in ISOLATION_MARKERS):
            reasons.append(f"probe '{name}' observation {str(value)[:80]!r} does not clearly "
                           "attest failed egress (quote the tool output, e.g. '100% packet loss')")
    return (not reasons), reasons


def _runner_file_identity(path: str) -> str:
    """Trust/security identity of a runner credential/trust file for the
    health memo (review F3): CONTENT DIGEST + MODE + OWNER, never content.
    OpenSSH enforces the MODE (it refuses group/other-accessible private
    keys), so a chmod that changes usability must invalidate a cached
    health verdict exactly like a byte change; unreadable and absent are
    distinct identities. Modes/uid only — no secret material."""
    if not path:
        return "unset"
    p = Path(path)
    try:
        st = p.stat()
        mode = stat.S_IMODE(st.st_mode)
    except OSError:
        return "absent"
    try:
        digest = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    except OSError:
        digest = "unreadable"
    return f"{digest}:m{mode:o}:u{st.st_uid}"


def _runner_health_probe(settings) -> tuple[bool, str]:
    """REAL bounded health of the isolated runner RIGHT NOW (plan 22 review):
    one supervised health round through ``get_runner(settings).health()`` —
    the exact transport, pinned host trust, BatchMode identity and
    runner-side supervisor the dispatcher itself will use for the next
    command. Configured strings and file existence are NOT a usable runner;
    this opens the connection. Fixed-shape (no model-selected destinations,
    no shell of its own beyond the transport's, no root, bounded by the
    transport's own timeouts)."""
    from srplatform.red_agent.runner import RunnerUnavailable, get_runner
    try:
        return get_runner(settings).health()
    except RunnerUnavailable as exc:      # not configured / trust file absent
        return False, str(exc)
    except Exception as exc:              # noqa: BLE001 — unknown is not healthy
        return False, f"runner health probe could not run: {str(exc)[:200]}"


class Supervisor:
    def __init__(self, datapath: DatapathController | None = None,
                 settings: Settings | None = None,
                 state_file: str | None = None,
                 broker=None):
        self.settings = settings or get_settings()
        self.datapath = datapath if datapath is not None else get_datapath(self.settings)
        self.state_file = Path(state_file or self.settings.safety_state_file)
        # milestone 02: independent VM cessation authority (BrokerClient).
        # Set by the app at startup; None in unit tests means the layer is
        # reported as NOT CONFIGURED — never silently "ok".
        self.broker = broker
        self._mirror_dh = None  # test hook: shared dict mirroring DB records
        self._records_reader = None  # test hook: callable -> DB record dicts

    # ---------------------------------------------------------------- latch ---
    def _read_state(self) -> tuple[dict, str | None]:
        """(state, error). error is set for CORRUPT/UNREADABLE files — a missing
        file is the legitimate fresh-install state (not latched)."""
        try:
            return json.loads(self.state_file.read_text()), None
        except FileNotFoundError:
            return {}, None
        except (OSError, json.JSONDecodeError) as e:
            return {}, f"state file unreadable: {e}"

    def _write_state(self, state: dict) -> tuple[str | None, str | None]:
        """Persist the latch to BOTH durable stores. Returns
        (file_error, db_error): the FILE is the primary durable store — its
        failure means the latch may not survive; the DB mirror failure must
        still be EXPOSED, never swallowed (audit R04)."""
        state = dict(state, updated_at=_now().isoformat())
        tmp = self.state_file.with_suffix(".tmp")
        file_err: str | None = None
        try:
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(state))
            os.replace(tmp, self.state_file)
        except OSError as e:
            file_err = f"state file write failed: {e}"
        return file_err, self._db_write_state(state)

    def _db_write_state(self, state: dict) -> str | None:
        try:
            from srplatform.db.models import SafetyState
            from srplatform.db.session import db
            with db() as s:
                row = s.get(SafetyState, 1)
                if row is None:
                    row = SafetyState(id=1)  # mirror must EXIST to be consulted
                    s.add(row)
                row.latched = bool(state.get("latched"))
                row.latched_at = _now() if state.get("latched") else None
                row.reason = state.get("reason")
            return None
        except Exception as e:  # noqa: BLE001 — reported, never silent
            return f"state DB mirror write failed: {e}"

    def _db_read_state(self) -> tuple[dict | None, str | None]:
        """(row-or-None, error). None means 'no mirror row', not 'not latched'
        when the read itself failed."""
        try:
            from srplatform.db.models import SafetyState
            from srplatform.db.session import db
            with db() as s:
                row = s.get(SafetyState, 1)
                if row is None:
                    return None, None
                return ({"latched": bool(row.latched),
                         "latched_at": row.latched_at.isoformat() if row.latched_at else None,
                         "reason": row.reason}), None
        except Exception as e:  # noqa: BLE001
            return None, f"state DB mirror unreadable: {e}"

    def latch_status(self) -> dict:
        """CONSERVATIVE reconciliation of the durable stores (audit N04/N07):
        latched if EITHER store says so; if BOTH are unreadable, FAIL CLOSED.
        A MISSING file is only a legitimate fresh-install when the DB mirror
        positively confirms it (a row with latched=False, or a recorded
        release). Missing file + unreadable DB = LOST STATE, not 'not
        latched' — losing the file during a DB outage must not forget an
        engagement."""
        st, file_err = self._read_state()
        db_st, db_err = self._db_read_state()
        problems = [p for p in (file_err, db_err) if p]
        if file_err and db_err:
            return {"latched": True, "latched_at": None,
                    "reason": "safety state stores unreadable — failing closed",
                    "persistence_error": "; ".join(problems)}
        file_missing = not st and not file_err
        db_missing = db_st is None and not db_err
        if file_missing and db_err:
            return {"latched": True, "latched_at": None,
                    "reason": "state file missing and DB mirror unreadable — "
                              "cannot prove release; failing closed",
                    "persistence_error": "; ".join(problems)}
        if file_missing and db_missing:
            # neither store has ANY evidence — first install or lost state.
            # Fail closed until an operator initializes explicitly.
            return {"latched": True, "latched_at": None,
                    "reason": "no safety state in any durable store — first install "
                              "or lost state; run the documented safety initialization",
                    "persistence_error": "no affirmative release evidence"}
        db_latched = bool((db_st or {}).get("latched"))
        latched = bool(st.get("latched")) or db_latched
        out = {"latched": latched,
               "latched_at": st.get("latched_at") or (db_st or {}).get("latched_at"),
               "reason": st.get("reason") or (db_st or {}).get("reason")}
        if problems:
            out["persistence_error"] = "; ".join(problems)
        return out

    def initialize_state(self, reason: str = "documented first-install initialization") -> dict:
        """Explicit first-install bootstrap (audit N07: define explicit
        first-install initialization instead of treating missing state as a
        healthy fresh store). Writes an affirmative NOT-latched record to
        BOTH durable stores."""
        file_err, mirror_err = self._write_state({"latched": False, "reason": reason,
                                                  "initialized": True})
        self.record("state_initialize", not file_err, {"reason": reason,
                                                       "file_error": file_err,
                                                       "mirror_error": mirror_err})
        return {"ok": not file_err, "file_error": file_err, "mirror_error": mirror_err}

    # --------------------------------------------------------------- records ---
    def _record_by_id(self, rid: int):
        """Authoritative FULL-ROW lookup for provenance resolution (reader
        side): returns the complete record (record_id, kind, strict ok,
        detail, config_identity, recorded_at) or None. None NEVER means
        "trustworthy" — an unresolvable source is incompatible."""
        try:
            from sqlalchemy import text

            from srplatform.db.session import db
            with db() as s:
                row = s.execute(text(_SAFETY_BY_ID_SQL),
                                {"r": int(rid)}).first()
            if row is None:
                return None
            return {"record_id": int(row[0]), "kind": row[1],
                    "ok": row[2] is True,
                    "detail": row[3] if isinstance(row[3], dict) else {},
                    "config_identity": row[4], "recorded_at": float(row[5])}
        except Exception:  # noqa: BLE001 — unreachable store = unverifiable
            return None

    def _resolve_provenance(self, detail, recorded_at, fetch,
                            *, kind: str | None = None,
                            self_row: dict | None = None,
                            now: float | None = None) -> float:
        """THE OBSERVATION-PROVENANCE CONTRACT (plan 22 rounds 4-5).

        An UNMARKED original observation derives its effective observation
        time from its AUTHORITATIVE RECORD TIMESTAMP — an arbitrary
        ``detail.observed_at`` injected into an ordinary record has no
        authority and is ignored (a stored field cannot retroactively move
        when the test ran).

        A recognized classification resolves hop by hop through
        ``source_record_id`` + ``original_detail_digest`` to the ORIGINAL
        record, and EVERY link must satisfy the FULL authoritative record
        contract (round 5): the source row exists, is of the SAME
        qualification kind, PASSED (strict ``ok is True``), matches the
        carried detail digest, and is scope-bound — the classification's
        ``record_identity_was`` equals its SOURCE row's config identity
        and its ``bound_identity`` equals the config identity of the row
        carrying it. Unknown markers, malformed persisted rows (a
        classification flag without a marker, a missing scope binding),
        cross-kind or failed sources, cycles, and carried times that
        disagree with the terminal resolution raise SafetyProvenanceError
        — INCOMPATIBLE evidence, never a usable current pass, never a
        "now" fallback. Age advisories for genuinely compatible evidence
        stay as they were; no daily re-commissioning is reintroduced."""
        now = time.time() if now is None else now
        det = detail if isinstance(detail, dict) else {}
        if not _is_recognized_classification(det):
            ts = _valid_observation_time(recorded_at, now)
            if ts is None:
                raise SafetyProvenanceError(
                    "record timestamp is not a finite, plausible, "
                    "non-future observation time")
            return ts
        carried = _valid_observation_time(det.get("observed_at"), now)
        if carried is None:
            raise SafetyProvenanceError(
                "classification observed_at is missing, non-finite or from "
                "the future — no defensible observation time")
        src_id = det.get("source_record_id")
        want_digest = det.get("original_detail_digest")
        if not isinstance(src_id, int) or isinstance(src_id, bool) \
                or not isinstance(want_digest, str) or not want_digest:
            raise SafetyProvenanceError(
                "classification does not carry an immutable source record "
                "id + detail digest — its derived time cannot resolve")
        expected_kind = kind
        own_identity = (self_row or {}).get("config_identity")
        riw = det.get("record_identity_was")
        if not isinstance(riw, str) or not riw:
            raise SafetyProvenanceError(
                "classification carries no record_identity_was source-scope "
                "binding — malformed persisted provenance")
        if own_identity is not None and det.get("bound_identity") != own_identity:
            raise SafetyProvenanceError(
                "classification's bound_identity does not match the config "
                "identity of the record carrying it — scope-inconsistent "
                "chain")
        visited: set[int] = set()
        self_id = (self_row or {}).get("record_id")
        if isinstance(self_id, int):
            visited.add(self_id)
        while True:
            if src_id in visited:
                raise SafetyProvenanceError(
                    "classification provenance chain is cyclic")
            visited.add(src_id)
            if len(visited) > _PROVENANCE_MAX_HOPS:
                raise SafetyProvenanceError(
                    "classification provenance chain is unboundedly deep")
            row = fetch(src_id)
            if row is None:
                raise SafetyProvenanceError(
                    f"classification names source record {src_id}, which "
                    "the authoritative store cannot resolve")
            if expected_kind is not None and row.get("kind") != expected_kind:
                raise SafetyProvenanceError(
                    f"source record {src_id} is kind {row.get('kind')!r}, "
                    f"not {expected_kind!r} — a classification may only "
                    "reference the same qualification kind")
            if row.get("ok") is not True:
                raise SafetyProvenanceError(
                    f"source record {src_id} did not PASS — a failed "
                    "record can never be classified into passing")
            src_detail = row.get("detail")
            src_detail = (src_detail if isinstance(src_detail, dict)
                          else {})
            if _detail_digest(src_detail) != want_digest:
                raise SafetyProvenanceError(
                    f"source record {src_id} does not match the "
                    "classification's immutable detail digest — the "
                    "provenance is forged or stale")
            src_identity = row.get("config_identity")
            if riw != src_identity:
                raise SafetyProvenanceError(
                    f"classification's record_identity_was {riw!r} is not "
                    f"source record {src_id}'s config identity — the chain "
                    "crosses a configuration/scope boundary")
            src_marker = src_detail.get("qualification_contract")
            src_onetime = src_detail.get("one_time_reclassification")
            if src_marker is None and src_onetime is not None:
                raise SafetyProvenanceError(
                    f"source record {src_id} carries a classification "
                    "flag without a contract marker — malformed "
                    "persisted provenance")
            if src_marker is not None \
                    and src_marker != QUALIFICATION_CONTRACT:
                raise SafetyProvenanceError(
                    f"source record {src_id} carries unknown "
                    f"qualification contract {src_marker!r} — this build "
                    "cannot verify its chain")
            if src_marker == QUALIFICATION_CONTRACT and src_onetime is True:
                nxt = src_detail.get("source_record_id")
                nd = src_detail.get("original_detail_digest")
                n_riw = src_detail.get("record_identity_was")
                if not isinstance(nxt, int) or isinstance(nxt, bool) \
                        or not isinstance(nd, str) or not nd:
                    raise SafetyProvenanceError(
                        f"nested classification {src_id} carries no "
                        "resolvable source chain")
                if not isinstance(n_riw, str) or not n_riw:
                    raise SafetyProvenanceError(
                        f"nested classification {src_id} carries no "
                        "source-scope binding — malformed chain")
                if src_detail.get("bound_identity") != src_identity:
                    raise SafetyProvenanceError(
                        f"nested classification {src_id} is not bound to "
                        "its own row's config identity — scope-forged "
                        "chain")
                src_id, want_digest, riw = nxt, nd, n_riw
                continue
            if src_marker == QUALIFICATION_CONTRACT and src_onetime not in (
                    None, False):
                raise SafetyProvenanceError(
                    f"source record {src_id} carries a malformed "
                    "one_time_reclassification flag — unknown marker")
            terminal = _valid_observation_time(row.get("recorded_at"), now)
            if terminal is None:
                raise SafetyProvenanceError(
                    f"original record {src_id} carries no plausible "
                    "observation time")
            if abs(terminal - carried) > _PROVENANCE_AGREEMENT_S:
                raise SafetyProvenanceError(
                    f"classification carries observed_at {carried!r} but "
                    f"its source chain resolves to {terminal!r} — "
                    "inconsistent provenance")
            return terminal

    def _authoritative_publish(self, kind: str, ok: bool, identity: str,
                               detail: dict, *,
                               validate=None) -> tuple[bool, int | None]:
        """ONE shared read-validate-append boundary for safety_records
        (plan 22 review rounds 4-5, owner contract). Every writer —
        ordinary baseline/proof/killswitch/engage/release observations AND
        operator classifications — appends through this transaction, and
        every one of them FIRST acquires the same advisory transaction
        lock. A classifier therefore cannot validate against a source
        snapshot while a fresh observation commits in between: the
        observation queues on the lock and becomes the newest row the next
        reader sees. ``validate(row, session)`` runs AFTER the source
        read, inside the lock, must be pure local computation plus reads
        on the SAME connection (no network waits, ever), and returns the
        final detail dict. Returns ``(published, seq)``: whether the
        append COMMITTED, and the COMMITTED authoritative APPEND SEQUENCE
        (record_id) — the identity every mirror envelope must carry so
        delayed copies order by the authoritative sequence, never by
        their own write clock. seq is None when the committed store
        exposes no sequence (legacy stub lanes; a real store always
        assigns one); published is False when the store is missing or
        failed (callers decide: observations fall back to the durable
        file ledger EXPLICITLY UNRECONCILED with the failure retained;
        classifications refuse — an unfenced append cannot honor the
        CAS)."""
        from sqlalchemy.exc import SQLAlchemyError

        from srplatform.db.session import db
        try:
            from sqlalchemy import text

            from srplatform.db.models import SafetyRecord
            with db() as s:
                s.execute(text(_SAFETY_PUBLISH_LOCK_SQL))
                if validate is not None:
                    row = s.execute(text(_SAFETY_NEWEST_SQL),
                                    {"k": kind}).first()
                    hook = getattr(self, "_test_after_source_read", None)
                    if hook is not None:
                        hook()
                    final = validate(row, s)
                    if isinstance(final, dict):
                        detail = final
                obj = SafetyRecord(kind=kind, ok=ok,
                                   config_identity=identity, detail=detail)
                s.add(obj)
                s.flush()
                seq = int(getattr(obj, "record_id", 0) or 0) or None
                # COMMIT happens as the session context exits — the
                # advisory lock is held until this very point, so exactly
                # one append can follow each validated source read.
            return True, seq
        except (ValueError, SafetyStoreUnavailable):
            raise                      # truthful refusals propagate as-is
        except SQLAlchemyError:
            return False, None
        except Exception:  # noqa: BLE001 — no store configured, or down
            return False, None

    def reclassify_qualification(self, kind: str, *, reason: str,
                                 actor: str,
                                 expect_recorded_at: float | None = None) -> dict:
        """ONE-TIME operator classification of pre-contract evidence (plan 22
        review): a legacy record whose detail cannot prove its scope is not
        silently honored and not silently thrown away — an operator who has
        verified the record's provenance states so, and this is appended as
        an AUDIT event bound to today's configuration.

        It mints NO fresh observation and launders NOTHING: the appended
        record carries the SOURCE's effective observation time, resolved
        through the immutable source chain under the OBSERVATION-PROVENANCE
        CONTRACT (`_resolve_provenance`) — an unmarked original's time is
        its authoritative record timestamp, never an injected detail
        field — so age and engage/release invalidation behave exactly as
        the original test would. The decision's own time is stored
        separately (``classification_decided_at``), the source row stays
        byte-identical (id + detail digest recorded), and a
        failed/already-contracted/unresolvable-provenance source is
        refused. Age-only expiry is NOT reintroduced.

        PUBLICATION goes through the SAME shared serialization boundary
        every safety writer uses (`_authoritative_publish`): advisory
        lock, newest-row read, validation, append, commit — one database
        transaction, no network waits inside. Concurrent classifiers AND
        interleaved observations serialize; only one append can follow a
        validated source, losers get the truthful conflict. If the
        authoritative store is unavailable the classification FAILS (no
        unfenced file-only publish exists); mirrors are written only
        after the commit, never independently."""
        if kind not in QUALIFICATION_KINDS:
            raise ValueError(f"{kind} is not a qualification kind")
        if not str(reason or "").strip():
            raise ValueError("a reclassification requires the reason the "
                             "operator verified this record's provenance")
        want: float | None = None
        if expect_recorded_at is not None:
            try:
                want = float(expect_recorded_at)
            except (TypeError, ValueError):
                raise ValueError("expect_recorded_at must be the source "
                                 "record's recorded_at value") from None
        identity = config_identity(self.settings)
        resolved: dict = {}

        def _validate(row, s) -> dict:
            if row is None:
                raise ValueError(f"no {kind} record exists to classify")
            src_id = int(row[0])
            src_ok = bool(row[1])
            src_detail = row[2] if isinstance(row[2], dict) else {}
            src_identity = row[3]
            src_at = float(row[4])
            if want is not None and abs(src_at - want) > 1e-6:
                raise ValueError(
                    f"the newest {kind} record is no longer the one "
                    f"being classified (recorded_at {src_at!r} != "
                    f"{want!r}) — re-examine the current record before "
                    "classifying")
            if src_detail.get("qualification_contract") is not None:
                raise ValueError(
                    f"the newest {kind} record already carries a "
                    "qualification contract — re-collect the evidence "
                    "instead of reclassifying")
            if not src_ok:
                raise ValueError(f"the newest {kind} record FAILED — a "
                                 "failed check cannot be classified "
                                 "into passing")

            def _fetch(rid: int, _s=s):
                from sqlalchemy import text
                r = _s.execute(text(_SAFETY_BY_ID_SQL),
                               {"r": int(rid)}).first()
                if r is None:
                    return None
                return {"record_id": int(r[0]), "kind": r[1],
                        "ok": r[2] is True,
                        "detail": r[3] if isinstance(r[3], dict) else {},
                        "config_identity": r[4],
                        "recorded_at": float(r[5])}

            effective = self._resolve_provenance(
                src_detail, src_at, _fetch, kind=kind,
                self_row={"record_id": src_id,
                          "config_identity": src_identity})
            decided = time.time()
            detail = {"qualification_contract": QUALIFICATION_CONTRACT,
                      "one_time_reclassification": True,
                      "observed_at": effective,
                      "classification_decided_at": decided,
                      "source_record_id": src_id,
                      "reclassified_record_at": src_at,
                      "record_identity_was": src_identity,
                      "bound_identity": identity,
                      "original_detail_digest": _detail_digest(src_detail),
                      "reason": str(reason)[:500], "operator": actor}
            resolved["effective"] = effective
            resolved["src_id"] = src_id
            resolved["detail"] = detail
            return detail

        published, seq = self._authoritative_publish(kind, True, identity,
                                                     {},
                                                     validate=_validate)
        if not published:
            raise SafetyStoreUnavailable(
                "the authoritative safety-record store is unavailable — "
                "a classification without it would be an unfenced append "
                "(reclassification refused)")
        # ROUND 5 CONTRACT: mirrors of a committed record carry the
        # AUTHORITATIVE SEQUENCE (the envelope below), so a delayed copy
        # orders by its commit identity — never by the clock on the wall
        # of whatever process copies it late. The test barrier sits exactly
        # in the post-commit / pre-mirror window (review F1).
        barrier = getattr(self, "_test_after_commit_before_mirror", None)
        if barrier is not None:
            barrier(kind)
        # durable audit mirrors AFTER the committed authoritative append
        # (never a substitute for it, never written for a loser); file
        # mirror failures stay visible exactly like record()'s are
        detail = resolved["detail"]
        if self._mirror_dh is not None:
            self._mirror_dh.append({"kind": kind, "ok": True,
                                    "config_identity": identity,
                                    "detail": detail, "seq": seq,
                                    "recorded_at": detail[
                                        "classification_decided_at"]})
        ferr = self._append_file_record(kind, True, identity, detail,
                                        seq=seq)
        if ferr:
            self._record_failures = list(
                getattr(self, "_record_failures", [])) + [ferr]
        return {"ok": True, "kind": kind, "bound_identity": identity,
                "observed_at": resolved["effective"],
                "source_record_id": resolved["src_id"]}

    OUTAGE_AUDIT_KIND = "outage_reconciliation"

    def reconcile_outage(self, kind: str, *, reason: str,
                         actor: str) -> dict:
        """AUDITED operator reconciliation of retained outage evidence
        (plan 22 review round 6, owner contract 2). A fresh committed
        pass of a kind ALREADY supersedes older order-unprovable failed
        observations automatically; this is the supported surface for
        the remainder — UNTRUSTED failed evidence (whose sequence claim
        resolves to nothing) and failures stamped during the recovery
        window. It launders nothing:

        * the newest AUTHORITATIVE record of that kind must be a PASSED
          observation under the CURRENT configuration identity — refused
          while a failure is current, after a configuration change, or
          with no resolvable record;
        * the append runs through the SAME shared CAS boundary
          (`_authoritative_publish`): advisory lock, validation, append,
          commit — and REFUSES outright when the store is unavailable
          (no unfenced audit exists);
        * it records an AUDIT event, never a new observation: actor,
          reason, and the passing record it vouches for are persisted;
        * failures are NEVER deleted or forgotten — ledger lines stay
          byte-identical; readers supersede only evidence stamped
          EARLIER than this audit, so a failure observed afterwards
          (or on a future clock) keeps blocking, truthfully."""
        if kind not in QUALIFICATION_KINDS:
            raise ValueError(f"{kind} is not a qualification kind")
        if not str(reason or "").strip():
            raise ValueError("an audited reconciliation requires the "
                             "operator's reason")
        identity = config_identity(self.settings)

        def _validate(row, s) -> dict:
            from sqlalchemy import text
            t = s.execute(text(_SAFETY_NEWEST_SQL), {"k": kind}).first()
            if t is None:
                raise ValueError(f"no {kind} record exists — there is "
                                 "nothing to reconcile; record the check "
                                 "with working storage first")
            if t[1] is not True:
                raise ValueError(
                    f"the newest authoritative {kind} record FAILED — an "
                    "outage reconciliation cannot launder a current "
                    "failure; make the check pass first")
            if t[3] != identity:
                raise ValueError(
                    f"the newest authoritative {kind} record carries a "
                    "different configuration identity — reconcile a "
                    "passing CURRENT observation, not one from another "
                    "scope")
            detail["vouched_record_id"] = int(t[0])
            detail["vouched_record_at"] = float(t[4])
            return detail

        detail = {"target_kind": kind, "reason": str(reason)[:500],
                  "operator": actor, "bound_identity": identity}
        published, seq = self._authoritative_publish(
            self.OUTAGE_AUDIT_KIND, True, identity, detail,
            validate=_validate)
        if not published:
            raise SafetyStoreUnavailable(
                "the authoritative safety-record store is unavailable — "
                "an audited reconciliation without it would be an "
                "unfenced append (refused; nothing was recorded)")
        # this committed audit demonstrates the store works — the
        # process-local outage debts for it must not outlive the proof
        self._record_failures = [
            f for f in getattr(self, "_record_failures", [])
            if not f.startswith("db record ")]
        barrier = getattr(self, "_test_after_commit_before_mirror", None)
        if barrier is not None:
            barrier(self.OUTAGE_AUDIT_KIND)
        if self._mirror_dh is not None:
            self._mirror_dh.append({"kind": self.OUTAGE_AUDIT_KIND,
                                    "ok": True, "config_identity": identity,
                                    "detail": detail, "seq": seq,
                                    "recorded_at": time.time()})
        ferr = self._append_file_record(self.OUTAGE_AUDIT_KIND, True,
                                        identity, detail, seq=seq)
        if ferr:
            self._record_failures = list(
                getattr(self, "_record_failures", [])) + [ferr]
        return {"ok": True, "kind": kind, "audit_record_id": seq,
                "bound_identity": identity,
                "vouched_record_id": detail.get("vouched_record_id"),
                "note": "audit recorded under the authoritative CAS "
                        "boundary; retained failure evidence is kept and "
                        "only evidence stamped earlier is superseded"}

    def record(self, kind: str, ok: bool, detail: dict | None = None) -> None:
        """Append a safety record (baseline_check|datapath_proof|killswitch_test|
        engage|release). Records are never rewritten; validity is derived from
        the newest ones. Persistence failures are RETAINED for start_gate
        (audit N07: a record that could not be persisted must deny starts,
        not silently vanish).

        ROUND 4 CONTRACT: the append goes through the SAME shared
        serialization boundary as classifications (`_authoritative_publish`),
        so a fresh observation can never slip between a classifier's source
        read and its append — whichever commits first is simply the newest
        row, and the newest row is what readers honor. Mirrors are written
        only AFTER the authoritative attempt, consistently with it: when a
        store is configured and commits, the mirror follows the commit;
        when the store failed, the durable file record still lands (the
        N07 outage ledger) with the failure retained — an observation is
        never silently dropped, and nothing republishes a stale pass."""
        identity = config_identity(self.settings)
        if kind in QUALIFICATION_KINDS:
            # new qualifications carry the contract marker; older accepted
            # records without one are classified, not rewritten (the record
            # you recorded is the record that stays — append-only)
            detail = {**(detail or {}),
                      "qualification_contract": QUALIFICATION_CONTRACT}
        self._record_failures = list(getattr(self, "_record_failures", []))
        published, seq = self._authoritative_publish(kind, ok, identity,
                                                     detail or {})
        if not published:
            self._record_failures.append(
                f"db record '{kind}': authoritative safety-record store "
                "unavailable — recorded to the durable file ledger only")
        elif any(f.startswith("db record ")
                 for f in self._record_failures):
            # ROUND 6 CONTRACT 2: a COMMITTED append demonstrates the
            # authoritative store is working again — the stale outage
            # debts ("store unavailable") must not keep denying starts
            # after the very observation that proved storage restored.
            # File-write debts stay until the write actually succeeds.
            self._record_failures = [
                f for f in self._record_failures
                if not f.startswith("db record ")]
        # ROUND 5: the mirror envelope carries the authoritative sequence
        # when publication committed (None = EXPLICITLY UNRECONCILED
        # outage-only record, conservative-only for readers). The test
        # barrier marks the post-commit / pre-mirror window.
        barrier = getattr(self, "_test_after_commit_before_mirror", None)
        if barrier is not None:
            barrier(kind)
        if self._mirror_dh is not None:
            self._mirror_dh.append({"kind": kind, "ok": ok, "config_identity": identity,
                                    "detail": detail or {}, "seq": seq,
                                    "recorded_at": time.time()})
        ferr = self._append_file_record(kind, ok, identity, detail, seq=seq)
        if ferr:
            self._record_failures.append(ferr)
        if published and ok and seq is not None:
            self._append_reconcile_audit(kind, seq, identity)

    def _append_reconcile_audit(self, kind: str, via_seq: int,
                                identity: str) -> None:
        """Durable LINK (round 6, contract 2): when an authoritative PASS
        commits while the file ledger still holds same-kind outage-window
        failures (sequence-less), record what that commit reconciles —
        same kind, same config scope, the passing sequence, and a count.
        This is an audit line, NEVER an observation: readers skip it, it
        authorizes nothing on its own, and it changes no retained
        failure; the committed pass is the authority, the failure lines
        stay byte-identical."""
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            stale = 0
            linked = 0
            for line in p.read_text().splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict) or rec.get("kind") != kind:
                    continue
                if rec.get("audit"):
                    n = rec.get("superseded_unreconciled")
                    if isinstance(n, int) and not isinstance(n, bool):
                        linked = max(linked, n)
                elif (rec.get("seq") is None and rec.get("ok")
                      is not True):
                    stale += 1
            if stale <= linked:
                return  # already linked durably (this or an earlier process)
            with p.open("a") as f:
                f.write(json.dumps({"audit": "outage_reconciliation",
                                    "kind": kind, "via_seq": via_seq,
                                    "config_identity": identity,
                                    "superseded_unreconciled": stale,
                                    "recorded_at": time.time()}) + "\n")
        except OSError:
            pass  # audit link only; the committed pass is the authority

    def _append_file_record(self, kind, ok, identity, detail,
                            seq: int | None = None) -> str | None:
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(json.dumps({"kind": kind, "ok": ok,
                                    "config_identity": identity,
                                    "detail": detail or {}, "seq": seq,
                                    "recorded_at": time.time()}) + "\n")
            return None
        except OSError as e:
            return f"file record '{kind}' write failed: {e}"

    def _latest_records(self) -> dict:
        """Newest record per kind, MERGING the DB and the file mirror
        under the ROUND 5 ORDERING CONTRACT:

        * DB-published observations and classifications are ordered by
          their AUTHORITATIVE APPEND SEQUENCE (record_id), carried in
          every mirror envelope as ``seq`` — a delayed file copy can
          NEVER become a newer observation by its write clock.
        * A record whose envelope carries no sequence while the
          environment demonstrably HAS an authoritative store is
          EXPLICITLY UNRECONCILED (a genuine outage-only observation or
          audit line): it is retained and honored CONSERVATIVELY — it can
          never authorize admission as a pass and never overrides a
          known authoritative FAILED state — but it never disappears and
          its failures are not lost.
        * With no authoritative sequence seen anywhere (legacy dev/file
          installs predating this contract) the ledger falls back to the
          historical timestamp append order — N07 semantics preserved.

        Readers receive the unreconciled lines under the reserved
        ``__unreconciled__`` key; selection itself never mixes it in.
        A mirror line that POSITIVELY MATCHES an authoritative record
        (kind + outcome + config identity + detail digest — never a
        timestamp guess) IS that record's copy: the committed row wins
        its data and order, so replayed or delayed duplicates can
        neither reorder history nor masquerade as outage evidence.

        ROUND 6 CONTRACT 1 — a claimed sequence is a REFERENCE, never
        authority: every non-authoritative line claiming a ``seq`` must
        resolve to an actual committed record whose content POSITIVELY
        matches it. An unknown, bool, negative or mismatched claim
        becomes EXPLICIT UNTRUSTED evidence: never a pass that
        authorizes, never an ordering advantage, never silently lost.
        A reconciliation audit line (top-level ``audit`` key) is a
        durable link, never an observation: readers skip it."""
        out: dict[str, dict] = {}
        pending: list[dict] = []
        authority = {"seen": False}
        untrusted = {"seen": False}

        def content_key(rec: dict):
            det = rec.get("detail")
            try:
                digest = hashlib.sha256(json.dumps(
                    det if det is not None else {}, sort_keys=True,
                    default=str).encode()).hexdigest()[:16]
            except (TypeError, ValueError):
                return None
            return (rec.get("kind"), bool(rec.get("ok")),
                    rec.get("config_identity"), digest)

        def db_records() -> list[dict]:
            try:
                from sqlalchemy import select
                from srplatform.db.models import SafetyRecord
                from srplatform.db.session import db
                with db() as s:
                    rows = s.execute(select(SafetyRecord).order_by(
                        SafetyRecord.record_id)).scalars().all()
                    return [{"kind": r.kind, "ok": r.ok,
                             "config_identity": r.config_identity,
                             "detail": r.detail, "seq": r.record_id,
                             "recorded_at": r.recorded_at.timestamp() if r.recorded_at else 0}
                            for r in rows]
            except Exception:
                return []  # file mirror below still contributes

        authoritative: list[dict] = []
        if self._records_reader is not None:
            try:
                authoritative = [dict(r) for r in self._records_reader()]
            except Exception:
                pass
        else:
            authoritative = db_records()
        # POSITIVE reconciliation maps: content → authoritative sequence,
        # and sequence → the committed row itself (the ONLY thing a
        # claimed reference may resolve against).
        seq_by_content: dict = {}
        seq_rows: dict[int, dict] = {}
        for r in authoritative:
            raw = r.get("seq")
            if raw is None or isinstance(raw, bool):
                continue
            try:
                s = int(raw)
            except (TypeError, ValueError):
                continue
            if s < 0:
                continue
            seq_rows[s] = r
            key = content_key(r)
            if key is not None:
                prev = seq_by_content.get(key)
                if prev is None or s >= prev:
                    seq_by_content[key] = s

        def consider(rec: dict, *, authoritative_src: bool = False) -> None:
            kind = rec.get("kind")
            if not kind:
                return
            rec = dict(rec)
            if rec.get("audit"):
                return  # durable reconciliation link, never an observation
            claimed = rec.get("seq")
            if authoritative_src:
                # A row read from the authoritative store IS the authority;
                # nothing validates it here — it validates everything else.
                if claimed is not None:
                    authority["seen"] = True
            elif claimed is not None:
                # ROUND 6 CONTRACT 1: a mirror/file line CLAIMING a
                # sequence must resolve to that committed row of matching
                # content — the row's data and order win, never the
                # line's envelope. Anything else (unknown id, bool or
                # negative claim, foreign kind, mismatched outcome/
                # identity/detail) is UNTRUSTED: stripped of its ordering
                # advantage, retained, and never able to authorize.
                row = None
                if isinstance(claimed, int) and not isinstance(claimed, bool) \
                        and claimed >= 0:
                    row = seq_rows.get(claimed)
                if row is not None:
                    key = content_key(rec)
                    if key is not None and content_key(row) == key:
                        return  # THIS is that row's delayed copy; row won
                rec["untrusted"] = True
                rec["seq"] = None
                untrusted["seen"] = True
            else:
                key = content_key(rec)
                if key is not None and key in seq_by_content:
                    rec["seq"] = seq_by_content[key]  # that record's copy
            rec_seq = rec.get("seq")
            if rec_seq is not None:
                authority["seen"] = True
            else:
                pending.append(rec)
            cur = out.get(kind)
            if cur is None:
                out[kind] = rec
                return
            cur_seq = cur.get("seq")
            if cur_seq is not None and rec_seq is not None:
                # Same sequence = the SAME authoritative event mirrored:
                # the row first seen (the authoritative one) keeps its
                # envelope — a mirror copy's write clock never becomes
                # the record's observation time.
                if rec_seq > cur_seq:
                    out[kind] = rec
                return
            if rec_seq is not None:       # authoritative beats unreconciled
                out[kind] = rec
                return
            if cur_seq is not None:       # a delayed copy never supersedes
                return
            # both unreconciled: append-order timestamps (legacy fallback)
            if float(rec.get("recorded_at", 0)) >= float(
                    cur.get("recorded_at", 0)):
                out[kind] = rec

        for r in authoritative:
            consider(r, authoritative_src=True)
        if self._mirror_dh is not None:
            for r in self._mirror_dh:
                consider(r)
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            for line in p.read_text().splitlines():
                consider(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
        # EXPLICIT unreconciled classification (round 5, owner contract):
        # only once an authoritative sequence was demonstrably seen does a
        # sequence-less record become "unreconciled" — an outage-only
        # mirror/copy that may NEVER authorize a pass on its own clock.
        # Where no authority has ever been seen (legacy file-only installs)
        # the historical timestamp semantics simply continue. An UNTRUSTED
        # line (round 6) is corrupt/forged evidence wherever it appeared —
        # it is exposed even on a legacy install, where a sequence claim
        # resolves to nothing by definition.
        if authority["seen"]:
            for rec in out.values():
                if rec.get("seq") is None and not rec.get("untrusted"):
                    rec["unreconciled"] = True
            out["__unreconciled__"] = pending
        elif untrusted["seen"]:
            out["__unreconciled__"] = [p for p in pending
                                       if p.get("untrusted")]
        return out

    def _qualification(self, kind: str,
                       recs: dict | None = None) -> dict:
        """Classify the newest record of one kind (plan 22 LIVE-07).

        A qualification is COMMISSIONING evidence: it stays usable for the
        exact configuration/contract it was collected under, and its AGE
        ALONE is an advisory, never a failed test. What DOES invalidate it:
        a failed newest record, a changed config identity, a safety
        engage/release transition after it, or evidence this build cannot
        classify (unknown provenance fails closed). Legacy records written
        by accepted earlier releases — same kinds, structured detail — are
        classified "legacy-compatible" and honored; that re-classifies old
        truth, it never mints a new passed observation.
        """
        recs = self._latest_records() if recs is None else recs
        out: dict = {"kind": kind, "usable": False, "provenance": "missing",
                     "problems": [], "advisories": [], "age_h": None}
        rec = recs.get(kind)
        if not rec:
            out["problems"] = [f"no {kind} record"]
            return out
        if rec.get("untrusted"):
            # ROUND 6 CONTRACT 1: the newest line for this kind CLAIMED an
            # authoritative sequence that resolves to no matching
            # committed record — unknown id, forged reference or
            # content-mismatched copy. Such evidence never authorizes
            # admission and never gains an ordering advantage; it stays
            # visible until an authoritative record supersedes it.
            problems = [
                f"{kind} evidence is UNTRUSTED: the authoritative sequence "
                "it claims resolves to no matching committed record "
                "(unknown, forged or content-mismatched) — it cannot "
                "authorize admission; record a fresh authoritative check"]
            if not rec.get("ok"):
                problems.insert(0, f"latest {kind} FAILED (untrusted "
                                   "record) — the failure stands")
            out["provenance"] = "untrusted"
            out["problems"] = problems
            return out
        if rec.get("unreconciled"):
            # Round 5, owner contract: the newest selected line for this
            # kind exists only in a mirror WITHOUT an authoritative
            # sequence while the authoritative store is demonstrably in
            # use. It is retained and honored CONSERVATIVELY — never a
            # pass that authorizes admission, never a lost failure — and
            # it reconciles only by a fresh authoritative record, never
            # by a timestamp. Round 6 contract 2: that fresh record is
            # now actually the recovery — once it commits, it supersedes
            # this unreconciled evidence for ordering.
            problems = [
                f"{kind} evidence is UNRECONCILED: it has no authoritative "
                "append sequence (a delayed mirror copy or an outage-only "
                "observation), so it cannot be ordered against committed "
                "records and cannot authorize admission — re-run the "
                "check with working storage; the fresh committed pass "
                "supersedes this unreconciled evidence"]
            if not rec.get("ok"):
                problems.insert(0, f"latest {kind} FAILED (unreconciled "
                                   "record) — the failure stands")
            out["provenance"] = "unreconciled"
            out["problems"] = problems
            return out
        detail = rec.get("detail")
        if detail is not None and not isinstance(detail, dict):
            out["provenance"] = "incompatible"
            out["problems"] = [
                f"{kind} record detail is not structured — this build "
                "cannot classify its scope; re-collect through the "
                "supported operator flow"]
            return out
        marker = (detail or {}).get("qualification_contract")
        if marker is None:
            # Plan 22 review: an unmarked QUALIFICATION record is "legacy"
            # only if its detail actually PROVES its scope. The
            # kind-specific shape a record was required to carry is
            # re-validated here; an empty or unclassifiable detail proves
            # nothing and is NOT made compatible by default (fail closed,
            # with an explicit one-time operator classification as the
            # recovery path). Lifecycle markers (engage/release/…) carry
            # no qualification scope — there is nothing to attest.
            if kind not in QUALIFICATION_KINDS:
                out["provenance"] = "legacy-compatible"
            else:
                scope_ok, scope_why = _legacy_scope_attested(kind, detail or {})
                if scope_ok:
                    out["provenance"] = "legacy-compatible"
                else:
                    out["provenance"] = "legacy-unclassified"
                    out["problems"] = [
                        f"{kind} record predates qualification contracts and "
                        f"its detail does not attest its scope ({scope_why}) — "
                        "an operator must either re-collect the evidence or "
                        "classify the existing record ONCE for the current "
                        "configuration: `rangectl safety reclassify "
                        f"{kind} --reason \"...\"`"]
                    return out
        elif marker != QUALIFICATION_CONTRACT:
            out["provenance"] = "incompatible"
            out["problems"] = [
                f"{kind} record carries qualification contract "
                f"{marker!r}, this build understands "
                f"{QUALIFICATION_CONTRACT} — re-collect"]
            return out
        else:
            out["provenance"] = "current"
        if not rec.get("ok"):
            out["problems"] = [f"latest {kind} FAILED"]
        identity = config_identity(self.settings)
        if rec.get("config_identity") != identity:
            out.setdefault("problems", []).append(
                f"{kind} record predates a configuration/network change "
                "(identity mismatch) — re-collect for the current "
                "configuration")
        raw_ts = float(rec.get("recorded_at", 0))
        det = rec.get("detail") if isinstance(rec.get("detail"), dict) else {}
        # Round-4 system contract: QUALIFICATION AGE AND TRANSITION
        # INVALIDATION run on the EFFECTIVE OBSERVATION TIME, established
        # by the OBSERVATION-PROVENANCE CONTRACT (_resolve_provenance): an
        # ordinary record's own authoritative timestamp; a recognized
        # classification's time only through its verified immutable source
        # chain — never an arbitrary detail field, never the audit
        # decision's wall clock. Unverifiable provenance is INCOMPATIBLE:
        # it does not pass, and it does not default to "now".
        try:
            rec_ts = self._resolve_provenance(
                det, raw_ts, self._record_by_id, kind=kind,
                self_row={"record_id": rec.get("seq"),
                          "config_identity": rec.get("config_identity")})
        except SafetyProvenanceError as exc:
            out["provenance"] = "incompatible"
            out["problems"] = [
                f"{kind} record carries no verifiable observation "
                f"provenance ({exc}) — incompatible evidence, never a new "
                "passed observation"]
            return out
        if kind not in ("engage", "release"):
            for gate in ("engage", "release"):
                g = recs.get(gate)
                if g and float(g.get("recorded_at", 0)) >= rec_ts:
                    out.setdefault("problems", []).append(
                        f"{kind} record predates the last {gate} — "
                        "evidence invalidated, re-run the check")
        # CONSERVATIVE pending-row handling (rounds 5-6, owner contract
        # 2): an unreconciled or UNTRUSTED same-kind FAILED is never lost.
        # It is superseded ONLY by a durable reconciliation, never by a
        # timestamp guess or a restart:
        #  * AUTO — the selected record is itself a genuine authoritative
        #    PASSED observation of THIS kind under the CURRENT identity
        #    (a classification never reconciles: an old classification
        #    cannot clear a fresh failure), and the pending failure's
        #    envelope time is strictly older than that pass. A committed
        #    pass IS the publication/CAS-boundary reconciliation; the
        #    decision is derived from durable state, so it survives
        #    restarts unchanged and never needs a ledger edit.
        #  * AUDIT — an operator reconciled this kind through the audited
        #    authority (`reconcile_outage`, appended under the same CAS
        #    boundary, current identity); pending failures envelope-stamped
        #    before that audit record are superseded.
        # A failure newer than every reconciliation — or carrying a
        # future/unprovable envelope clock nothing precedes — keeps
        # blocking, truthfully. An unreconciled engage/release transition
        # is honored under the same gate rule as a selected one.
        recon_pass = (rec.get("seq") is not None
                      and not rec.get("untrusted")
                      and not rec.get("unreconciled")
                      and rec.get("ok") is True
                      and rec.get("config_identity") == identity
                      and not _is_recognized_classification(det))
        audit_ts: float | None = None
        aud = recs.get("outage_reconciliation")
        if (aud is not None and not aud.get("untrusted")
                and not aud.get("unreconciled") and aud.get("ok") is True
                and aud.get("seq") is not None
                and aud.get("config_identity") == identity):
            adet = aud.get("detail") if isinstance(aud.get("detail"),
                                                   dict) else {}
            if adet.get("target_kind") == kind:
                at = float(aud.get("recorded_at", 0))
                if at > 0:
                    audit_ts = at
        for p in recs.get("__unreconciled__") or ():
            pk = p.get("kind")
            if pk == kind and not p.get("ok"):
                p_untr = bool(p.get("untrusted"))
                pts = float(p.get("recorded_at", 0))
                if audit_ts is not None and 0 < pts < audit_ts:
                    continue  # the audited reconciliation supersedes this
                if recon_pass and not p_untr and 0 < pts < rec_ts:
                    continue  # the committed pass supersedes this
                out.setdefault("problems", []).append(
                    _pending_failure_blocker(kind, p_untr, pts, rec_ts,
                                             audit_ts, recon_pass))
            elif kind not in ("engage", "release") and pk in (
                    "engage", "release") and float(
                        p.get("recorded_at", 0)) >= rec_ts:
                out.setdefault("problems", []).append(
                    f"an unreconciled {pk} transition cannot be ordered "
                    "before this evidence — re-run the check with "
                    "working storage")
        out["recorded_at"] = rec_ts
        out["observed_at"] = rec_ts
        if _is_recognized_classification(det):
            # the UI must distinguish the observation date from the day
            # an operator made the compatibility decision (audit time)
            out["classified_at"] = raw_ts
        if rec_ts:
            age_h = (time.time() - rec_ts) / 3600
            out["age_h"] = round(age_h, 1)
            if age_h > self.settings.safety_evidence_max_age_h:
                out["advisories"] = [
                    f"{kind} qualification is {age_h:.0f}h old (advisory "
                    f"lifetime {self.settings.safety_evidence_max_age_h}h); "
                    "still valid for this unchanged configuration — renewal "
                    "is optional, age alone does not reprove or disprove "
                    "isolation"]
        out["usable"] = not out["problems"]
        return out

    def _record_fresh(self, kind: str) -> tuple[bool, str]:
        """Compatibility wrapper: (usable, why). LIVE-07 changed AGE to an
        advisory; usability now means provenance-compatible, newest-passed,
        config-bound and not invalidated by a safety transition."""
        v = self._qualification(kind)
        if v["usable"]:
            return True, "fresh"
        return False, "; ".join(v["problems"]) or "unusable"

    # ------------------------------------------------------- admission health ---
    def _runner_check(self) -> dict:
        """Config gate PLUS a real, bounded health probe through the
        EXISTING runner authority.

        Checking configured strings and file existence is NOT a verified
        usable runner (plan 22 review): the probe runs the platform's own
        ``get_runner(settings).health()`` — one supervised round-trip (supervisor
        start + containment status) through the exact pinned identity the
        dispatcher uses, proving transport, host trust, key acceptance and
        the cessation control channel, not just a TCP handshake. Results
        are memoized for a short TTL so the safety page and the Begin
        poll cannot hammer it.
        """
        s = self.settings
        ok_cfg, why_cfg = self.runner_available()
        if s.runner_transport != "ssh":
            return {"check": "runner", "ok": ok_cfg, "detail": why_cfg}
        if not ok_cfg:
            return {"check": "runner", "ok": False, "detail": why_cfg}
        # Review F2: the memo key must be the TRANSPORT TRUST IDENTITY, not
        # the file NAMES. Re-pinning a foreign host key or rotating the key
        # IN PLACE keeps the paths identical while the authority behind
        # them changes completely — a path-keyed cache then replays the old
        # success for the TTL even though the direct probe would (correctly)
        # refuse the foreign pin. Fingerprints are content digests
        # (key contents never enter the key; a missing file is its own
        # distinct identity, as are empty vs unreadable).
        key = (s.runner_transport, str(s.runner_ssh_target or ""),
               _runner_file_identity(str(s.runner_ssh_key_path or "")),
               _runner_file_identity(str(s.runner_ssh_known_hosts or "")))
        cache = getattr(self, "_runner_probe_cache", None)
        if cache and cache["key"] == key and time.monotonic() < cache["until"]:
            ok, why = cache["res"]
        else:
            ok, why = _runner_health_probe(s)
            self._runner_probe_cache = {
                "key": key, "res": (ok, why),
                "until": time.monotonic() + RUNNER_PROBE_TTL_S}
        return {"check": "runner", "ok": ok, "detail": why}

    def _broker_check(self) -> dict:
        """The VM-cessation authority answers RIGHT NOW (or it does not).
        An unconfigured authority is only non-applicable where the
        configuration carries no VMs to stop (the noop-fixture exemption
        the qualification applies); anywhere else its absence fails closed.

        Review F1 (HIGH): answering is not the same as ANSWERING THE
        CONTRACT. The broker's latch record is exactly
        ``{latched: strict bool, reason, latched_at}`` (ledger.get_latch);
        anything else — a missing key, a null/zero/string "latched", a bare
        list or None, a wrong authority speaking another protocol — is
        UNKNOWN and must block, never launder itself into "no engagement
        active". The check validates the typed shape first and only then
        reads the boolean; NO falsy value is ever treated as release, and
        no exception escapes as a trace."""
        if self.broker is None:
            if self.settings.sr_env != "production":
                return {"check": "broker_authority", "ok": True,
                        "applicable": False,
                        "detail": "broker authority NOT configured "
                                  "(non-production configuration) — no VM "
                                  "cessation authority to probe"}
            return {"check": "broker_authority", "ok": False,
                    "detail": "broker authority NOT configured — current "
                              "VM cessation cannot be proven"}
        try:
            st = self.broker.latch_status()
        except Exception as exc:  # noqa: BLE001 — unknown is not healthy
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker authority unreachable: {str(exc)[:160]}"}
        if not isinstance(st, dict):
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reply UNTRUSTED: expected the latch "
                              f"record object, got {type(st).__name__} — "
                              "starts stay refused until it answers the "
                              "contract"}
        missing = [f for f in ("latched", "reason", "latched_at")
                   if f not in st]
        if missing:
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reply UNTRUSTED: latch record missing "
                              f"field(s) {', '.join(missing)} — starts stay "
                              "refused until it answers the contract"}
        if not isinstance(st["latched"], bool):
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reply UNTRUSTED: latched must be the "
                              f"strict boolean the contract defines, got "
                              f"{type(st['latched']).__name__} — starts "
                              "stay refused"}
        # Review F4: the metadata fields carry their own types in the real
        # ledger contract (get_latch returns reason as TEXT|NULL and
        # latched_at as a numeric epoch|NULL). Malformed metadata is a
        # malformed answer — a dict/number reason or a string/NaN/Inf
        # timestamp means this authority does not speak the contract, and
        # its "not latched" cannot be trusted. Legitimate NULLs pass.
        if not (st["reason"] is None or isinstance(st["reason"], str)):
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reply UNTRUSTED: reason must be text "
                              f"or null per the latch contract, got "
                              f"{type(st['reason']).__name__} — starts stay "
                              "refused"}
        lat = st["latched_at"]
        if not (lat is None
                or (isinstance(lat, (int, float))
                    and not isinstance(lat, bool) and math.isfinite(lat))):
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reply UNTRUSTED: latched_at must be a "
                              f"finite numeric epoch or null per the latch "
                              f"contract, got {type(lat).__name__} — starts "
                              "stay refused"}
        if st["latched"]:
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reports emergency engagement ACTIVE "
                              f"({str(st.get('reason') or 'no reason recorded')[:120]}) "
                              "— starts stay refused"}
        return {"check": "broker_authority", "ok": True,
                "detail": "broker authority answers the latch contract; "
                          "no engagement active"}

    def admission_probes(self) -> dict:
        """Bounded, NON-DESTRUCTIVE, authoritative health of RIGHT NOW
        (plan 22 LIVE-07, sharpened by review): fixed typed checks through
        authorities the platform already holds — the runner's own SSH
        identity, the broker client, the datapath controller. No host
        shell, no model-selected destinations, no killswitch exercise.

        Three honest outcomes are distinguished: FAILED (blocks), UNKNOWN
        (blocks — unknown health is not health), and a live check the
        datapath DECLARED UNSUPPORTED (never counted as a passed probe and
        never disguised as "not applicable because production": isolation
        in that mode is carried by the config-bound commissioning
        qualification, and the page says exactly that)."""
        checks: list[dict] = [self._runner_check(), self._broker_check()]
        mechanism = getattr(self.datapath, "mechanism", None)
        if mechanism == "nft":
            from srplatform.safety.firewall import validate_port_coverage
            cov_ok, cov_why = validate_port_coverage(self.settings)
            checks.append({"check": "bridge_port_coverage", "ok": cov_ok,
                           "detail": cov_why})
        if mechanism == "noop" and not self._evidence_required():
            checks.append({"check": "isolation_live", "ok": True,
                           "applicable": False,
                           "detail": "noop datapath outside production — "
                                     "no isolation exists to probe"})
        else:
            try:
                base = self.datapath.baseline_status()
                if base.get("ok") is None:
                    checks.append({
                        "check": "isolation_live", "ok": None,
                        "declared_unsupported": True,
                        "detail": str(base.get("detail", base))[:300]})
                else:
                    checks.append({"check": "isolation_live",
                                   "ok": bool(base.get("ok")),
                                   "detail": str(base.get("detail", base))[:300]})
            except Exception as exc:  # noqa: BLE001 — unknown is not healthy
                checks.append({"check": "isolation_live", "ok": False,
                               "detail": f"controller error: {exc}"[:300]})
        health = all(c["ok"] is not False
                     and not (c["ok"] is None and not c.get("declared_unsupported"))
                     for c in checks)
        return {"ok": health, "checks": checks,
                "config_identity": config_identity(self.settings),
                "at": time.time()}

    def _evidence_required(self) -> bool:
        """Non-production noop datapaths (plain dev) carry no isolation to
        qualify — same exemption the historical start_gate applied."""
        return (getattr(self.datapath, "mechanism", None) != "noop"
                or self.settings.sr_env == "production")

    def qualification_report(self) -> dict:
        """ONE classification shared by readiness, stages, the safety page
        and Begin (plan 22 LIVE-07: UI/readiness/stages/Begin must agree).
        Read-only: performs no writes and records nothing."""
        recs = self._latest_records()
        quals = [self._qualification(k, recs) for k in QUALIFICATION_KINDS]
        probes = self.admission_probes()
        st = self.latch_status()
        reasons: list[str] = []
        if st["latched"]:
            reasons.append(
                f"SAFETY LATCHED since {st['latched_at']} ({st['reason']}) — "
                "operator release required")
        if st.get("persistence_error"):
            reasons.append(f"safety state persistence problem: "
                           f"{st['persistence_error']}")
        if getattr(self, "_record_failures", []):
            reasons.append("safety record persistence failed since startup: "
                           + "; ".join(self._record_failures[-3:])
                           + " — re-run the checks with working storage")
        advisories: list[str] = []
        for c in probes["checks"]:
            if c["ok"] is False or (c["ok"] is None
                                    and not c.get("declared_unsupported")):
                label = {"runner": "runner unavailable",
                         # the accepted pre-22 gate worded this blocker as
                         # "live bridge topology" — keep operator-recognized
                         # wording for the identical check
                         "bridge_port_coverage":
                             "live bridge topology",
                         "isolation_live": "live isolation check",
                         "broker_authority": "broker authority"}.get(
                    c["check"], c["check"])
                reasons.append(f"{label}: {c['detail']}")
            elif c["ok"] is None and c.get("declared_unsupported"):
                advisories.append(
                    "live isolation check DECLARED UNSUPPORTED by this "
                    "datapath — Begin is carried by the config-bound "
                    "commissioning qualification, never by a simulated "
                    "live probe")
        if self._evidence_required():
            for q in quals:
                if not q["usable"]:
                    label = {"baseline_check": "baseline verification",
                             "datapath_proof": "operator datapath proof",
                             "killswitch_test":
                                 "killswitch stop/isolation test"}[q["kind"]]
                    for p in q["problems"]:
                        reasons.append(f"{label}: {p}")
                advisories.extend(q["advisories"])
        return {"qualifications": quals, "admission": probes,
                "latch": st, "advisories": advisories,
                "config_identity": config_identity(self.settings),
                "begin_allowed": not reasons, "begin_blockers": reasons}

    # ------------------------------------------------------------ operations ---
    def kill_workers(self, extra_groups: list[tuple] | None = None) -> dict:
        """Terminate all supervised worker process groups. extra_groups lets
        the caller pass groups recovered from durable run state after an API
        restart — as (run_id, pgid) or (run_id, pgid, pgid_pstart) tuples."""
        results = []
        for h in run_registry.active():
            r = run_registry.terminate_group(h.pgid, expected_pstart=h.pgid_pstart)
            results.append({"run_id": h.run_id, **r})
        for entry in (extra_groups or []):
            run_id, pgid = entry[0], int(entry[1])
            pstart = entry[2] if len(entry) > 2 else None
            if any(h.run_id == run_id for h in run_registry.active()):
                continue
            r = run_registry.terminate_group(pgid, expected_pstart=pstart)
            results.append({"run_id": run_id, **r})
        ok = all(r["ok"] for r in results) if results else True
        return {"ok": ok, "results": results,
                "detail": f"{sum(1 for r in results if not r['ok'])} of {len(results)} worker terminations failed"}

    def engage(self, reason: str = "killswitch",
               extra_groups: list[tuple] | None = None) -> dict:
        """The killswitch (hard constraint #2). Each layer attempted independently
        and reported truthfully; the latch is persisted FIRST so a crash in the
        middle cannot forget the engagement. An exception in worker termination
        can NEVER prevent the datapath half from executing (audit R03)."""
        file_err, mirror_err = self._write_state({"latched": True, "reason": reason})
        persist_err = file_err or mirror_err

        # (a) stop red agent workers (live registry + groups recovered from
        #     durable run rows for cross-restart coverage)
        try:
            workers = self.kill_workers(extra_groups=extra_groups)
        except Exception as e:  # noqa: BLE001 — must not block the datapath half
            workers = {"ok": False, "results": [],
                       "detail": f"worker termination raised: {e}"}

        # (b) drop the range datapath — independent of (a)
        try:
            datapath = self.datapath.apply_emergency()
        except Exception as e:  # noqa: BLE001
            datapath = {"ok": False, "detail": f"datapath controller raised: {e}", "mechanism": "unknown"}

        # (c) milestone 02: INDEPENDENT VM cessation through the broker —
        # hard-stops every owned attacker/target VM (latch-first, read-back
        # confirmed, obligations retained on failure). Attempted regardless
        # of how (a) and (b) went.
        if self.broker is None:
            broker_stop = {"ok": self.settings.sr_env != "production", "configured": False,
                           "detail": "no broker configured (unit/dev scope)"}
        else:
            try:
                report = self.broker.hard_stop_all(f"killswitch: {reason}")
                failed = report.get("failed") or []
                broker_stop = {"ok": not failed, "configured": True,
                               "detail": f"{len(report.get('stopped', []))} stopped, "
                                         f"{len(report.get('already-stopped', []))} already "
                                         f"stopped, {len(report.get('absent', []))} absent, "
                                         f"{len(failed)} UNCONFIRMED",
                               "report": report}
            except Exception as e:  # noqa: BLE001 — must not block reporting
                broker_stop = {"ok": False, "configured": True,
                               "detail": f"broker cessation failed: {e} — the "
                                         "control-lease watchdog must stop the range"}

        # the LATCH ITSELF failing to persist durably (file) is a layer failure;
        # a DB-mirror-only failure is exposed as a warning, not a false "partial"
        full_ok = workers["ok"] and datapath["ok"] and broker_stop["ok"] and not file_err
        self.record("engage", full_ok, {"workers": workers, "datapath": datapath,
                                        "broker": broker_stop, "reason": reason,
                                        **({"state_persistence": persist_err} if persist_err else {})})
        result = {
            "killswitch": "engaged" if full_ok else "engaged-partial",
            "latched": True,
            "workers": workers,
            "datapath": datapath,
            "broker": broker_stop,
            "actions": [f"{r['run_id']}: {r['detail']}" for r in workers["results"]]
                       + [f"datapath: {datapath['detail']}",
                          f"broker: {broker_stop['detail']}"],
        }
        if persist_err:
            result["state_persistence_error"] = persist_err
        if not full_ok:
            result["warning"] = ("PARTIAL engagement — at least one layer failed. "
                                 + (f"LATCH PERSISTENCE PROBLEM: {persist_err}. " if persist_err else "")
                                 + (f"Broker cessation incomplete ({broker_stop['detail']}) — "
                                    "VMs may still be running; check brokerctl status. "
                                    if not broker_stop["ok"] else "")
                                 + ("Worker termination incomplete. " if not workers["ok"] else "")
                                 + ("Static isolation is not a network-disconnect action; "
                                    "verify broker VM cessation."
                                    if datapath.get("mechanism") == "static" else
                                    "Emergency datapath action confirmed."
                                    if datapath["ok"] else
                                    "Datapath action FAILED; use the operator's "
                                    "independent appliance power-off procedure."))
        return result

    def release(self) -> dict:
        """Operator release: remove ONLY the emergency ruleset, preserve the
        baseline deny, then invalidate evidence (fresh checks required — the
        release RECORD is the cutoff that `_record_fresh` enforces)."""
        try:
            datapath = self.datapath.remove_emergency()
        except Exception as e:  # noqa: BLE001
            datapath = {"ok": False, "detail": f"datapath controller raised: {e}", "mechanism": "unknown"}
        if datapath["ok"]:
            file_err, mirror_err = self._write_state({"latched": False})
            persist_err = file_err or mirror_err
            self.record("release", not file_err,
                        {"datapath": datapath,
                         **({"state_persistence": persist_err} if persist_err else {})})
            out = {"killswitch": "released", "datapath": datapath,
                   "note": "baseline egress-deny must still be active (verified above); "
                           "evidence invalidated — run baseline check + datapath proof before the next start"}
            if persist_err:
                out["state_persistence_error"] = persist_err
                out["warning"] = f"released, but state persistence reported: {persist_err}"
            return out
        self.record("release", False, {"datapath": datapath})
        return {"killswitch": "still-engaged", "datapath": datapath,
                "warning": "emergency ruleset removal FAILED — remaining latched"}

    # ------------------------------------------------------------------ gate ---
    def runner_available(self) -> tuple[bool, str]:
        """DETERMINISTIC config-readiness of the runner (NOT its live health):
        the transport is named and every input the transport will NEED is
        actually present and usable. Review F3: this is what /readyz reports,
        so it must never be a misleading positive. A configured-but-absent
        private key or an EMPTY host-trust file cannot authenticate a runner
        — the live probe and the Begin classifier both refuse them — so
        config readiness says NO too, and the two surfaces agree. This does
        not probe the network (readiness stays side-effect-free); the actual
        health is the SEPARATE admission probe, so installation readiness is
        still satisfied without an attacker or guest being active."""
        s = self.settings
        t = s.runner_transport
        if t == "ssh":
            if not (s.runner_ssh_target and s.runner_ssh_key_path and s.runner_ssh_known_hosts):
                return False, "isolated runner not fully configured (target/key/known_hosts)"
            if not Path(s.runner_ssh_known_hosts).is_file():
                return False, f"runner host-key file missing: {s.runner_ssh_known_hosts}"
            try:
                trust_lines = [
                    ln for ln in Path(s.runner_ssh_known_hosts)
                    .read_text(errors="replace").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
            except OSError:
                trust_lines = []
            if not trust_lines:
                # an empty trust file authenticates NO host: every pinning
                # connection is refused, so this is not a ready runner
                return False, (f"runner host-key file is EMPTY "
                               f"({s.runner_ssh_known_hosts}) — no pinned "
                               "host to trust; the runner cannot be reached")
            if not Path(s.runner_ssh_key_path).is_file():
                return False, f"runner private key missing: {s.runner_ssh_key_path}"
            # Review F3: readiness is ALSO the transport's own security
            # gate — OpenSSH refuses a private key that group/other can
            # access, so such a key is NOT a usable configuration no
            # matter what a cached probe once said. Refuse before any
            # cache/probe path; never suggest widening permissions.
            try:
                kmode = stat.S_IMODE(Path(s.runner_ssh_key_path).stat().st_mode)
            except OSError:
                return False, (f"runner private key cannot be inspected: "
                               f"{s.runner_ssh_key_path}")
            if kmode & 0o077:
                return False, (f"runner private key permissions are "
                               f"group/other-accessible ({kmode:04o}) — "
                               "OpenSSH refuses it; tighten to 0600 "
                               "(never loosen the transport)")
            if not os.access(s.runner_ssh_key_path, os.R_OK):
                return False, (f"runner private key is unreadable by the "
                               f"API service user: {s.runner_ssh_key_path}")
            return True, "ssh runner configured (key + non-empty host trust present)"
        if t == "local-dev":
            if s.sr_env == "production":
                return False, "local-dev runner forbidden in production"
            if not s.allow_local_dev_fixture:
                return False, ("local-dev runner is fixture-only (isolated synthetic "
                               "acceptance fixtures; ALLOW_LOCAL_DEV_FIXTURE=1) — "
                               "normal development uses the isolated runner")
            return True, "local-dev runner (isolated fixture only — NOT isolated)"
        return False, f"unknown runner transport '{t}'"

    def start_gate(self) -> tuple[bool, list[str]]:
        """Every /run passes through this. Returns (allowed, reasons).

        Audit N07: a start additionally requires a SUCCESSFUL killswitch test
        (command cessation + datapath isolation observed during an actual
        engagement) bound to the current configuration identity — baseline
        and proof records alone never proved the stop/isolation mechanism
        works. Persistence failures also deny (state/evidence that cannot be
        established cannot authorize a start).

        Plan 22 LIVE-07: the decision is exactly the shared
        ``qualification_report()`` — commissioning qualification
        (config-bound, provenance-classified, age advisory) PLUS the bounded
        automatic admission probes. Before deciding, the probes' outcome is
        appended as an ``admission_probe`` record: what the machine checked
        at admission is durable evidence, never dressed up as a renewed
        baseline/proof/killswitch qualification."""
        report = self.qualification_report()
        self.record(ADMISSION_KIND, bool(report["admission"]["ok"]),
                    {"checks": report["admission"]["checks"],
                     "begin_allowed": report["begin_allowed"],
                     "blockers": report["begin_blockers"][:10]})
        return report["begin_allowed"], report["begin_blockers"]

    # -------------------------------------------------------------- verify ----
    def verify(self) -> dict:
        """Config-state verification + the operator live-probe instructions."""
        base_ok, base_why = self._record_fresh("baseline_check")
        proof_ok, proof_why = self._record_fresh("datapath_proof")
        live_base = None
        try:
            live_base = self.datapath.baseline_status()
        except Exception as e:  # noqa: BLE001
            live_base = {"ok": False, "detail": f"controller error: {e}"}
        return {
            "latch": self.latch_status(),
            "config_identity": config_identity(self.settings),
            "baseline_check": {"fresh": base_ok, "why": base_why},
            "datapath_proof": {"fresh": proof_ok, "why": proof_why},
            "live_baseline_table": live_base,
            "policy": f"default-deny on {self.settings.range_bridge}; explicit allows only",
            "live_check": "from a range VM: ping -c1 1.1.1.1 (must FAIL); "
                          "getent hosts example.com (must FAIL); ip -6 route (must have no default)",
        }


_supervisor: Supervisor | None = None


def get_supervisor() -> Supervisor:
    global _supervisor
    if _supervisor is None:
        _supervisor = Supervisor()
    return _supervisor


def set_supervisor(s: Supervisor | None) -> None:
    global _supervisor
    _supervisor = s
