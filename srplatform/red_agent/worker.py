"""Red worker process (F01/F02 boundary).

Spawned by the API's run manager as a subprocess in its own process group.
Holds ONLY: the API URL + a run-scoped token (evidence plane), and the runner
channel from configuration. It never receives the database, Proxmox, or
verifier/management credentials — verifier execution happens in the trusted
backend, requested over the API. Model calls go through the bounded gateway.
"""
from __future__ import annotations

import json
import os
import sys

import httpx


def main() -> int:
    api = os.environ.get("SR_API_BASE")
    session_id = os.environ.get("SR_SESSION_ID")
    scenario_id = os.environ.get("SR_SCENARIO_ID")
    run_id = os.environ.get("SR_RUN_ID")
    token = os.environ.get("SR_WORKER_TOKEN")
    if not all([api, session_id, scenario_id, run_id, token]):
        print("[worker] missing SR_* environment — refusing to run", file=sys.stderr)
        return 2

    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.runner import get_runner, install_cancellation_handlers
    from srplatform.red_agent.transport import HttpTransport

    # Stopping THIS worker (process-group SIGTERM from the API) must also stop
    # the command currently running in the runner's own group (audit R03).
    install_cancellation_handlers()

    transport = HttpTransport(api, token=token, run_id=run_id)

    # Runner is resolved NOW — no local fallback, hard failure if unavailable.
    try:
        runner = get_runner()
    except Exception as e:  # noqa: BLE001
        _report(api, run_id, token, {"outcome": "worker_failure", "error": f"runner: {e}"})
        print(f"[worker] runner unavailable: {e}", file=sys.stderr)
        return 3

    # Model calls go through the API's ONE SHARED SCHEDULER (audit Stage 5):
    # the run capability posts to /internal/model/complete and the API's
    # gateway orders it against interactive hints/AARs across processes. The
    # worker holds NO model endpoint credential at all.
    class ApiModel:
        def complete(self, system, user):
            r = httpx.post(f"{api}/internal/model/complete",
                           json={"name": "red-turn", "system": system, "user": user},
                           headers={"Authorization": f"Bearer {token}"}, timeout=900)
            r.raise_for_status()
            return r.json()["text"]

    loop = RedAgentLoop(session_id, scenario_id, transport, ApiModel(), runner,
                        throttle_s=_pace_seconds(),
                        deadline_utc=_match_deadline())
    try:
        result = loop.run()
    except Exception as e:  # noqa: BLE001 — the API needs a truthful failure
        _report(api, run_id, token, {"outcome": "worker_failure", "error": str(e)[:1000]})
        print(f"[worker] failed: {e}", file=sys.stderr)
        return 1
    if not _report(api, run_id, token, result):
        # The supervisor retains the assignment and reports this exit through
        # its fenced callback. Never present an unacknowledged completion as 0.
        return 1
    print(json.dumps({"run_id": run_id, **{k: result[k] for k in
                                           ("steps", "phase", "achieved", "complete", "outcome")
                                           if k in result}}))
    if result.get("outcome") == "cancel_unconfirmed":
        # audit T01: remote cessation could not be confirmed — distinct exit
        # status so "stopped cleanly" is never confused with "unknown"
        return 4
    return 0


def _pace_seconds() -> float:
    """Per-action dispatch throttle from the SESSION SNAPSHOT (start_run
    exports SR_ATTACK_PACE_S at worker spawn): 30 s default, 0 = no
    intentional delay. Never re-read live mid-match."""
    raw = os.environ.get("SR_ATTACK_PACE_S", "30")
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 30.0


def _match_deadline():
    """Server-clock match deadline (SR_MATCH_DEADLINE_UTC, ISO) set at Begin;
    absent = no server deadline (legacy CLI practice ends via stop/budget)."""
    from datetime import datetime, timezone
    raw = os.environ.get("SR_MATCH_DEADLINE_UTC")
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _report(api: str, run_id: str, token: str, result: dict) -> bool:
    try:
        response = httpx.post(f"{api}/internal/runs/{run_id}/complete", json=result,
                              headers={"X-Worker-Token": token}, timeout=15)
        response.raise_for_status()
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[worker] could not report completion: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    sys.exit(main())
