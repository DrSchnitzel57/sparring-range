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

    from srplatform.model_gateway import PRIORITY_RED, get_model_gateway
    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.runner import get_runner, install_cancellation_handlers
    from srplatform.red_agent.transport import HttpTransport

    # Stopping THIS worker (process-group SIGTERM from the API) must also stop
    # the command currently running in the runner's own group (audit R03).
    install_cancellation_handlers()

    transport = HttpTransport(api, token=token)

    # Runner is resolved NOW — no local fallback, hard failure if unavailable.
    try:
        runner = get_runner()
    except Exception as e:  # noqa: BLE001
        _report(api, run_id, token, {"outcome": "worker_failure", "error": f"runner: {e}"})
        print(f"[worker] runner unavailable: {e}", file=sys.stderr)
        return 3

    # Model through the bounded gateway (priority: red turn)
    from srplatform.red_agent.llm import LLM
    llm = LLM()
    gateway = get_model_gateway()

    class GatewayLLM:
        def complete(self, system, user):
            fut = gateway.submit(PRIORITY_RED, "red-turn", llm.complete, system, user)
            return gateway.wait(fut, timeout=600)

    loop = RedAgentLoop(session_id, scenario_id, transport, GatewayLLM(), runner)
    try:
        result = loop.run()
    except Exception as e:  # noqa: BLE001 — the API needs a truthful failure
        _report(api, run_id, token, {"outcome": "worker_failure", "error": str(e)[:1000]})
        print(f"[worker] failed: {e}", file=sys.stderr)
        return 1
    _report(api, run_id, token, result)
    print(json.dumps({"run_id": run_id, **{k: result[k] for k in
                                           ("steps", "phase", "achieved", "complete", "outcome")
                                           if k in result}}))
    return 0


def _report(api: str, run_id: str, token: str, result: dict) -> None:
    try:
        httpx.post(f"{api}/internal/runs/{run_id}/complete", json=result,
                   headers={"X-Worker-Token": token}, timeout=15)
    except Exception as e:  # noqa: BLE001
        print(f"[worker] could not report completion: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
