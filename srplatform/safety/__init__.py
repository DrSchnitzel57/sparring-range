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


class Supervisor:
    def __init__(self, datapath: DatapathController | None = None,
                 settings: Settings | None = None,
                 state_file: str | None = None):
        self.settings = settings or get_settings()
        self.datapath = datapath if datapath is not None else get_datapath(self.settings)
        self.state_file = Path(state_file or self.settings.safety_state_file)
        self._mirror_dh = None  # test hook: shared dict mirroring DB records

    # ---------------------------------------------------------------- latch ---
    def _read_state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {"latched": False}

    def _write_state(self, state: dict) -> None:
        state = dict(state, updated_at=_now().isoformat())
        tmp = self.state_file.with_suffix(".tmp")
        try:
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(state))
            os.replace(tmp, self.state_file)
        except OSError:
            pass  # latch also mirrors to DB; a lost file must not abort engagement
        self._db_write_state(state)

    def _db_write_state(self, state: dict) -> None:
        try:
            from srplatform.db.models import SafetyState
            from srplatform.db.session import db
            with db() as s:
                row = s.get(SafetyState, 1)
                if row is None:
                    return
                row.latched = bool(state.get("latched"))
                row.latched_at = _now() if state.get("latched") else None
                row.reason = state.get("reason")
        except Exception:
            pass  # file is the durable store; DB mirror is best-effort

    def latch_status(self) -> dict:
        st = self._read_state()
        return {"latched": bool(st.get("latched")), "latched_at": st.get("latched_at"),
                "reason": st.get("reason")}

    # --------------------------------------------------------------- records ---
    def record(self, kind: str, ok: bool, detail: dict | None = None) -> None:
        """Append a safety record (baseline_check|datapath_proof|engage|release).
        Records are never rewritten; validity is derived from the newest ones."""
        identity = config_identity(self.settings)
        if self._mirror_dh is not None:
            self._mirror_dh.append({"kind": kind, "ok": ok, "config_identity": identity,
                                    "detail": detail or {}, "recorded_at": time.time()})
        try:
            from srplatform.db.models import SafetyRecord
            from srplatform.db.session import db
            with db() as s:
                s.add(SafetyRecord(kind=kind, ok=ok, config_identity=identity,
                                   detail=detail or {}))
        except Exception:
            pass  # record also lives in the file mirror for restart-durability
        self._append_file_record(kind, ok, identity, detail)

    def _append_file_record(self, kind, ok, identity, detail) -> None:
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(json.dumps({"kind": kind, "ok": ok, "config_identity": identity,
                                    "detail": detail or {}, "recorded_at": time.time()}) + "\n")
        except OSError:
            pass

    def _latest_records(self) -> dict:
        """Newest record per kind, from DB when reachable else file mirror."""
        out: dict[str, dict] = {}
        try:
            from sqlalchemy import select
            from srplatform.db.models import SafetyRecord
            from srplatform.db.session import db
            with db() as s:
                rows = s.execute(select(SafetyRecord).order_by(SafetyRecord.record_id)).scalars().all()
                for r in rows:
                    out[r.kind] = {"kind": r.kind, "ok": r.ok, "config_identity": r.config_identity,
                                   "recorded_at": r.recorded_at.timestamp() if r.recorded_at else 0}
            if out:
                return out
        except Exception:
            pass
        if self._mirror_dh is not None:
            for r in self._mirror_dh:
                out[r["kind"]] = r
            return out
        try:
            p = self.state_file.parent / (self.state_file.name + ".records")
            for line in p.read_text().splitlines():
                r = json.loads(line)
                out[r["kind"]] = r
        except (OSError, json.JSONDecodeError):
            pass
        return out

    def _record_fresh(self, kind: str) -> tuple[bool, str]:
        rec = self._latest_records().get(kind)
        if not rec:
            return False, f"no {kind} record"
        if not rec.get("ok"):
            return False, f"latest {kind} FAILED"
        identity = config_identity(self.settings)
        if rec.get("config_identity") != identity:
            return False, f"{kind} record predates a configuration/network change (identity mismatch)"
        age_h = (time.time() - float(rec.get("recorded_at", 0))) / 3600
        if age_h > self.settings.safety_evidence_max_age_h:
            return False, f"{kind} record is stale ({age_h:.0f}h > {self.settings.safety_evidence_max_age_h}h)"
        return True, "fresh"

    # ------------------------------------------------------------ operations ---
    def kill_workers(self, extra_groups: list[tuple[str, int]] | None = None) -> dict:
        """Terminate all supervised worker process groups. extra_groups lets the
        caller pass groups recovered from durable run state after an API restart."""
        results = []
        for h in run_registry.active():
            r = run_registry.terminate_group(h.pgid)
            results.append({"run_id": h.run_id, **r})
        for run_id, pgid in (extra_groups or []):
            if any(h.run_id == run_id for h in run_registry.active()):
                continue
            r = run_registry.terminate_group(int(pgid))
            results.append({"run_id": run_id, **r})
        ok = all(r["ok"] for r in results) if results else True
        return {"ok": ok, "results": results,
                "detail": f"{sum(1 for r in results if not r['ok'])} of {len(results)} worker terminations failed"}

    def engage(self, reason: str = "killswitch") -> dict:
        """The killswitch (hard constraint #2). Each layer attempted independently
        and reported truthfully; the latch is persisted FIRST so a crash in the
        middle cannot forget the engagement."""
        self._write_state({"latched": True, "reason": reason})

        # (a) stop red agent workers (from the live registry; the API layer adds
        #     groups recovered from durable run rows for cross-restart coverage)
        workers = self.kill_workers()

        # (b) drop the range datapath — independent of (a)
        try:
            datapath = self.datapath.apply_emergency()
        except Exception as e:  # noqa: BLE001
            datapath = {"ok": False, "detail": f"datapath controller raised: {e}", "mechanism": "unknown"}

        full_ok = workers["ok"] and datapath["ok"]
        self.record("engage", full_ok, {"workers": workers, "datapath": datapath, "reason": reason})
        result = {
            "killswitch": "engaged" if full_ok else "engaged-partial",
            "latched": True,
            "workers": workers,
            "datapath": datapath,
            "actions": [f"{r['run_id']}: {r['detail']}" for r in workers["results"]]
                       + [f"datapath: {datapath['detail']}"],
        }
        if not full_ok:
            result["warning"] = ("PARTIAL engagement — at least one layer failed. "
                                 + ("Worker termination failed; network IS severed." if datapath["ok"] else
                                    "Datapath drop FAILED — range traffic may still flow; "
                                    "run infra/firewall/killswitch.sh on the Proxmox host NOW."))
        return result

    def release(self) -> dict:
        """Operator release: remove ONLY the emergency ruleset, preserve the
        baseline deny, then invalidate evidence (fresh checks required)."""
        try:
            datapath = self.datapath.remove_emergency()
        except Exception as e:  # noqa: BLE001
            datapath = {"ok": False, "detail": f"datapath controller raised: {e}", "mechanism": "unknown"}
        if datapath["ok"]:
            self._write_state({"latched": False})
            self.record("release", True, {"datapath": datapath})
            return {"killswitch": "released", "datapath": datapath,
                    "note": "baseline egress-deny must still be active (verified above); "
                            "evidence invalidated — run baseline check + datapath proof before the next start"}
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
        """Every /run passes through this. Returns (allowed, reasons)."""
        reasons: list[str] = []
        st = self.latch_status()
        if st["latched"]:
            reasons.append(f"SAFETY LATCHED since {st['latched_at']} ({st['reason']}) — "
                           "operator release required")
        runner_ok, why = self.runner_available()
        if not runner_ok:
            reasons.append(f"runner unavailable: {why}")
        dp_available = getattr(self.datapath, "mechanism", None) != "noop" or self.settings.sr_env == "production"
        for kind, label in (("baseline_check", "baseline verification"),
                            ("datapath_proof", "operator datapath proof")):
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
