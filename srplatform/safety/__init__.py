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
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from srplatform.safety.datapath import DatapathController, config_identity, get_datapath
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
    def reclassify_qualification(self, kind: str, *, reason: str,
                                 actor: str) -> dict:
        """ONE-TIME operator classification of pre-contract evidence (plan 22
        review): a legacy record whose detail cannot prove its scope is not
        silently honored and not silently thrown away — an operator who has
        verified the record's provenance states so, and this is appended as
        a NEW current-contract record bound to today's configuration.

        This mints no fresh observation: the appended record says exactly
        what happened (the operator classified the <date> record; original
        content quoted by digest), keeps the original append-only line
        untouched, and names the actor. Age-only manual retests stay
        removed — this is the explicit compatibility decision, made once
        per record, not a daily ritual."""
        if kind not in QUALIFICATION_KINDS:
            raise ValueError(f"{kind} is not a qualification kind")
        if not str(reason or "").strip():
            raise ValueError("a reclassification requires the reason the "
                             "operator verified this record's provenance")
        rec = self._latest_records().get(kind)
        if not rec:
            raise ValueError(f"no {kind} record exists to classify")
        if (rec.get("detail") or {}).get("qualification_contract") is not None:
            raise ValueError(
                f"the newest {kind} record already carries a qualification "
                "contract — re-collect the evidence instead of reclassifying")
        if not rec.get("ok"):
            raise ValueError(f"the newest {kind} record FAILED — a failed "
                             "check cannot be classified into passing")
        identity = config_identity(self.settings)
        detail = {"qualification_contract": QUALIFICATION_CONTRACT,
                  "one_time_reclassification": True,
                  "reclassified_record_at": float(rec.get("recorded_at", 0)),
                  "record_identity_was": rec.get("config_identity"),
                  "bound_identity": identity,
                  "original_detail_digest": hashlib.sha256(json.dumps(
                      rec.get("detail") or {}, sort_keys=True,
                      default=str).encode()).hexdigest()[:16],
                  "reason": str(reason)[:500], "operator": actor}
        self.record(kind, True, detail)
        return {"ok": True, "kind": kind, "bound_identity": identity}

    def record(self, kind: str, ok: bool, detail: dict | None = None) -> None:
        """Append a safety record (baseline_check|datapath_proof|killswitch_test|
        engage|release). Records are never rewritten; validity is derived from
        the newest ones. Persistence failures are RETAINED for start_gate
        (audit N07: a record that could not be persisted must deny starts,
        not silently vanish)."""
        identity = config_identity(self.settings)
        if kind in QUALIFICATION_KINDS:
            # new qualifications carry the contract marker; older accepted
            # records without one are classified, not rewritten (the record
            # you recorded is the record that stays — append-only)
            detail = {**(detail or {}),
                      "qualification_contract": QUALIFICATION_CONTRACT}
        if self._mirror_dh is not None:
            self._mirror_dh.append({"kind": kind, "ok": ok, "config_identity": identity,
                                    "detail": detail or {}, "recorded_at": time.time()})
        self._record_failures = list(getattr(self, "_record_failures", []))
        try:
            from srplatform.db.models import SafetyRecord
            from srplatform.db.session import db
            with db() as s:
                s.add(SafetyRecord(kind=kind, ok=ok, config_identity=identity,
                                   detail=detail or {}))
        except Exception as e:  # noqa: BLE001 — observable, never swallowed
            self._record_failures.append(f"db record '{kind}': {e}")
        ferr = self._append_file_record(kind, ok, identity, detail)
        if ferr:
            self._record_failures.append(ferr)

    def _append_file_record(self, kind, ok, identity, detail) -> str | None:
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(json.dumps({"kind": kind, "ok": ok, "config_identity": identity,
                                    "detail": detail or {}, "recorded_at": time.time()}) + "\n")
            return None
        except OSError as e:
            return f"file record '{kind}' write failed: {e}"

    def _latest_records(self) -> dict:
        """Newest record per kind by TIMESTAMP, MERGING the DB and the file
        mirror (audit N07: preferring the DB whenever any row exists let an
        engage/release recorded only to the file during a DB outage be
        forgotten once the DB became reachable again)."""
        out: dict[str, dict] = {}

        def consider(rec: dict) -> None:
            kind = rec.get("kind")
            if not kind:
                return
            cur = out.get(kind)
            if cur is None or float(rec.get("recorded_at", 0)) >= float(cur.get("recorded_at", 0)):
                out[kind] = rec

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
                             "detail": r.detail,
                             "recorded_at": r.recorded_at.timestamp() if r.recorded_at else 0}
                            for r in rows]
            except Exception:
                return []  # file mirror below still contributes
        if self._records_reader is not None:
            try:
                for r in self._records_reader():
                    consider(r)
            except Exception:
                pass
        else:
            for r in db_records():
                consider(r)
        if self._mirror_dh is not None:
            for r in self._mirror_dh:
                consider(r)
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            for line in p.read_text().splitlines():
                consider(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
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
        rec_ts = float(rec.get("recorded_at", 0))
        if kind not in ("engage", "release"):
            for gate in ("engage", "release"):
                g = recs.get(gate)
                if g and float(g.get("recorded_at", 0)) >= rec_ts:
                    out.setdefault("problems", []).append(
                        f"{kind} record predates the last {gate} — "
                        "evidence invalidated, re-run the check")
        out["recorded_at"] = rec_ts
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
        key = (s.runner_ssh_target, s.runner_ssh_key_path,
               s.runner_ssh_known_hosts)
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
        the qualification applies); anywhere else its absence fails
        closed."""
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
        if isinstance(st, dict) and st.get("latched"):
            return {"check": "broker_authority", "ok": False,
                    "detail": f"broker reports emergency engagement ACTIVE "
                              f"({str(st.get('reason') or 'no reason recorded')[:120]}) "
                              "— starts stay refused"}
        return {"check": "broker_authority", "ok": True,
                "detail": "broker authority answers; no engagement active"}

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
        s = self.settings
        t = s.runner_transport
        if t == "ssh":
            if not (s.runner_ssh_target and s.runner_ssh_key_path and s.runner_ssh_known_hosts):
                return False, "isolated runner not fully configured (target/key/known_hosts)"
            if not Path(s.runner_ssh_known_hosts).exists():
                return False, f"runner host-key file missing: {s.runner_ssh_known_hosts}"
            return True, "ssh runner configured"
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
