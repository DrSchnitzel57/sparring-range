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


class Supervisor:
    def __init__(self, datapath: DatapathController | None = None,
                 settings: Settings | None = None,
                 state_file: str | None = None):
        self.settings = settings or get_settings()
        self.datapath = datapath if datapath is not None else get_datapath(self.settings)
        self.state_file = Path(state_file or self.settings.safety_state_file)
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
    def record(self, kind: str, ok: bool, detail: dict | None = None) -> None:
        """Append a safety record (baseline_check|datapath_proof|killswitch_test|
        engage|release). Records are never rewritten; validity is derived from
        the newest ones. Persistence failures are RETAINED for start_gate
        (audit N07: a record that could not be persisted must deny starts,
        not silently vanish)."""
        identity = config_identity(self.settings)
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
                    return [{"kind": r.kind, "ok": r.ok, "config_identity": r.config_identity,
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

    def _record_fresh(self, kind: str) -> tuple[bool, str]:
        recs = self._latest_records()
        rec = recs.get(kind)
        if not rec:
            return False, f"no {kind} record"
        if not rec.get("ok"):
            return False, f"latest {kind} FAILED"
        identity = config_identity(self.settings)
        if rec.get("config_identity") != identity:
            return False, f"{kind} record predates a configuration/network change (identity mismatch)"
        # ENGAGE/RELEASE INVALIDATE PRIOR EVIDENCE (audit R04): a killswitch
        # engagement or release means the datapath changed — every baseline
        # check / datapath proof recorded BEFORE that event says nothing about
        # the current state and must not re-authorize a start.
        rec_ts = float(rec.get("recorded_at", 0))
        if kind not in ("engage", "release"):
            for gate in ("engage", "release"):
                g = recs.get(gate)
                if g and float(g.get("recorded_at", 0)) >= rec_ts:
                    return False, (f"{kind} record predates the last {gate} — "
                                   "evidence invalidated, re-run the check")
        age_h = (time.time() - rec_ts) / 3600
        if age_h > self.settings.safety_evidence_max_age_h:
            return False, f"{kind} record is stale ({age_h:.0f}h > {self.settings.safety_evidence_max_age_h}h)"
        return True, "fresh"

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

        # the LATCH ITSELF failing to persist durably (file) is a layer failure;
        # a DB-mirror-only failure is exposed as a warning, not a false "partial"
        full_ok = workers["ok"] and datapath["ok"] and not file_err
        self.record("engage", full_ok, {"workers": workers, "datapath": datapath, "reason": reason,
                                        **({"state_persistence": persist_err} if persist_err else {})})
        result = {
            "killswitch": "engaged" if full_ok else "engaged-partial",
            "latched": True,
            "workers": workers,
            "datapath": datapath,
            "actions": [f"{r['run_id']}: {r['detail']}" for r in workers["results"]]
                       + [f"datapath: {datapath['detail']}"],
        }
        if persist_err:
            result["state_persistence_error"] = persist_err
        if not full_ok:
            result["warning"] = ("PARTIAL engagement — at least one layer failed. "
                                 + (f"LATCH PERSISTENCE PROBLEM: {persist_err}. " if persist_err else "")
                                 + ("Worker termination failed; network IS severed." if datapath["ok"] else
                                    "Datapath drop FAILED — range traffic may still flow; "
                                    "run infra/firewall/killswitch.sh on the Proxmox host NOW."))
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
            return True, "local-dev runner (dev mode only — NOT isolated)"
        return False, f"unknown runner transport '{t}'"

    def start_gate(self) -> tuple[bool, list[str]]:
        """Every /run passes through this. Returns (allowed, reasons).

        Audit N07: a start additionally requires a SUCCESSFUL killswitch test
        (command cessation + datapath isolation observed during an actual
        engagement) bound to the current configuration identity — baseline
        and proof records alone never proved the stop/isolation mechanism
        works. Persistence failures also deny (state/evidence that cannot be
        established cannot authorize a start)."""
        reasons: list[str] = []
        st = self.latch_status()
        if st["latched"]:
            reasons.append(f"SAFETY LATCHED since {st['latched_at']} ({st['reason']}) — "
                           "operator release required")
        if st.get("persistence_error"):
            reasons.append(f"safety state persistence problem: {st['persistence_error']}")
        if getattr(self, "_record_failures", []):
            reasons.append("safety record persistence failed since startup: "
                           + "; ".join(self._record_failures[-3:]) +
                           " — re-run the checks with working storage")
        runner_ok, why = self.runner_available()
        if not runner_ok:
            reasons.append(f"runner unavailable: {why}")
        dp_available = getattr(self.datapath, "mechanism", None) != "noop" or self.settings.sr_env == "production"
        for kind, label in (("baseline_check", "baseline verification"),
                            ("datapath_proof", "operator datapath proof"),
                            ("killswitch_test", "killswitch stop/isolation test")):
            ok, why_r = self._record_fresh(kind)
            if not ok and dp_available:
                reasons.append(f"{label}: {why_r}")
        return (len(reasons) == 0), reasons

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
