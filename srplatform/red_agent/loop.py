"""The red agent: a hand-rolled loop, not a framework (Part 2).

  load agent_state + recent events → build prompt → one model call →
  parse JSON tool call → execute (in the Kali sandbox) → log event →
  run relevant verifiers → compress old history into agent_state → advance phase

Trust model (hard constraint #3): the model may CLAIM anything; only verifier
events flip objectives to achieved. This is what makes a mediocre local model
trustworthy (Part 6.4). Resume after kill/restart comes from agent_state +
events — the loop never relies on the model remembering.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from srplatform.red_agent.phases import PhaseMachine
from srplatform.red_agent.schema import TOOL_SCHEMA_DOC, parse_tool_call
from srplatform.safety import get_supervisor
from srplatform.scenario_engine.loader import load_scenario
from verifiers import registry
from verifiers.base import Context

SYSTEM_PROMPT = """You are the RED agent in an isolated CCDC sparring range (no internet, lab only).
You have ONE tool: shell, executed in your Kali container against the range network.
{schema}

Scenario: {name}
Objectives (verifier-confirmed — never self-declare):
{objectives}
Current phase: {phase}
SITUATION REPORT (compressed memory):
{summary}
RECENT EVENTS:
{recent}

Command targets via their scenario hostnames/IPs. When you believe every
objective is verifier-confirmed, send {{"tool":"shell","args":{{"command":"DONE"}}}}."""

SUMMARIZER_PROMPT = """Compress the following red-agent event log into a situation report
(under 200 words): what is known about targets, what worked, what failed,
current phase. Plain text, no JSON.

{events}"""


class RedAgentKilled(Exception):
    pass


class RedAgentLoop:
    def __init__(self, session_id: str, scenario_id: str, transport, llm, sandbox,
                 max_steps: int = 20, compress_after: int = 8, keep_recent: int = 6):
        self.session_id = session_id
        self.scenario = load_scenario(scenario_id)
        self.transport = transport
        self.llm = llm  # needs .complete(system, user) -> str
        self.sandbox = sandbox
        self.max_steps = max_steps
        self.compress_after = compress_after
        self.keep_recent = keep_recent
        self.verifier_ctx = Context(exec=sandbox.verifier_exec, hosts={})
        self.achieved: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def _log(self, actor, action_type, payload, phase=None, mitre=None, raw_ref=None, host=None,
             raw_output_hash=None):
        self.transport.log_event({
            "session_id": self.session_id, "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor, "host": host, "action_type": action_type, "phase": phase,
            "mitre_technique": mitre, "payload": payload,
            "raw_ref": raw_ref, "raw_output_hash": raw_output_hash,
        })

    def _red_objectives(self):
        return self.scenario.get("red", {}).get("objectives", [])

    def _check_objectives(self, phase: str) -> bool:
        """Run every red objective's verifier against real state. Returns True
        when all pass. Only these results mark objectives achieved."""
        newly = False
        for obj in self._red_objectives():
            if obj["id"] in self.achieved:
                continue
            v = registry.get(obj["verifier"])
            res = v.check(self.verifier_ctx, **(obj.get("args") or {}))
            self._log("system", "verifier", {
                "objective": obj["id"], "verifier": obj["verifier"], "passed": res.passed,
                "evidence": res.evidence,
            }, phase=phase, mitre=(v.mitre or [None])[0])
            if res.passed:
                self.achieved.add(obj["id"])
                newly = True
        return newly

    def compress(self, upto_event_id: int, events: list[dict], phase: str) -> tuple[str, int]:
        blob = "\n".join(f"[{e['event_id']}] {e['actor']}/{e['action_type']} @{e.get('host')}: "
                         f"{str(e['payload'])[:200]}" for e in events)
        summary = self.llm.complete(SUMMARIZER_PROMPT.format(events=blob), "summarize")
        return summary, upto_event_id

    # --------------------------------------------------------------------- run
    def run(self, stop_after_steps: int | None = None) -> dict:
        # register with the killswitch supervisor (hard constraint #2) — both the
        # in-process supervisor and (best effort) the API's, for cross-process runs
        try:
            get_supervisor().register_red_agent(os.getpid())
        except Exception:
            pass
        try:
            import httpx

            from srplatform.settings import get_settings
            httpx.post(f"{get_settings().api_base_url}/safety/register-pid",
                       json={"pid": os.getpid()}, timeout=3)
        except Exception:
            pass  # no supervisor reachable (pure test)

        objectives_desc = "\n".join(f"- {o['id']}: {o['verifier']} {o.get('args', {})}"
                                    for o in self._red_objectives())
        pm = PhaseMachine(self.scenario.get("red", {}).get("start_phase", "recon"))

        # RESUME: restore phase/summary from agent_state; re-derive achieved
        # objectives from verifier events (the log is the truth, not memory).
        state = self.transport.get_agent_state(self.session_id) or {}
        if state.get("current_phase"):
            pm.advance_to(state["current_phase"])
        summary = state.get("summary") or ""
        summary_upto = state.get("summary_upto") or 0
        for e in self.transport.events_since(self.session_id, 0):
            p = e.get("payload") or {}
            if e["action_type"] == "verifier" and p.get("passed"):
                self.achieved.add(p.get("objective"))

        all_ids = {o["id"] for o in self._red_objectives()}
        steps_run = 0
        done_claims = 0

        while True:
            if all_ids and self.achieved >= all_ids:
                break
            limit = stop_after_steps if stop_after_steps is not None else self.max_steps
            if steps_run >= limit:
                break

            recent = self.transport.events_since(self.session_id, summary_upto)
            recent_tail = recent[-self.keep_recent:]
            recent_txt = "\n".join(
                f"[{e['event_id']}] {e['actor']}/{e['action_type']} {str(e['payload'])[:200]}"
                for e in recent_tail) or "(none yet)"

            prompt = SYSTEM_PROMPT.format(
                schema=TOOL_SCHEMA_DOC, name=self.scenario.get("name", "?"),
                objectives=objectives_desc, phase=pm.phase,
                summary=summary or "(no summary yet)", recent=recent_txt)

            # ONE model call; strict parse with a single retry (Part 6.4 tuning)
            raw = self.llm.complete(prompt, "next action")
            try:
                tc = parse_tool_call(raw)
            except ValueError:
                raw = self.llm.complete(prompt + "\n\nREMINDER: JSON ONLY, exact schema.", "next action")
                try:
                    tc = parse_tool_call(raw)
                except ValueError as e:
                    self._log("system", "tool_call", {"error": f"model output rejected twice: {e}",
                                                      "raw": raw[:500]}, phase=pm.phase)
                    steps_run += 1
                    continue

            # DONE is only true if the VERIFIERS say so (anti-hallucination gate)
            if tc.command.strip() == "DONE":
                if self._check_objectives(pm.phase) or (all_ids and self.achieved >= all_ids):
                    break
                done_claims += 1
                self._log("system", "verifier", {
                    "note": "red agent claimed completion but verifiers did not confirm",
                    "achieved": sorted(self.achieved), "needed": sorted(all_ids)}, phase=pm.phase)
                if done_claims >= 3:
                    break  # stop thrashing on a false claim
                steps_run += 1
                continue

            # execute in the sandbox (Kali, range-only network)
            code, out = self.sandbox.run(tc.command)
            self._log("red", "tool_call",
                      {"command": tc.command, "thought": tc.thought, "exit_code": code,
                       "output": out[:4000]},
                      phase=pm.phase,
                      raw_output_hash=hashlib.sha256(out.encode()).hexdigest()[:16])

            # deterministic verification after every action; verifier truth
            # advances the kill-chain phase machine
            if self._check_objectives(pm.phase):
                remaining = [o for o in self._red_objectives() if o["id"] not in self.achieved]
                # simple forward advance: one step per achieved objective
                order = ["recon", "initial-access", "priv-esc", "lateral", "persistence", "objectives"]
                idx = order.index(pm.phase)
                if idx < len(order) - 1:
                    pm.advance_to(order[idx + 1])

            # rolling memory: compress events beyond the keep-recent window
            all_new = self.transport.events_since(self.session_id, summary_upto)
            if len(all_new) > self.compress_after:
                window = all_new[: len(all_new) - self.keep_recent]
                summary, summary_upto = self.compress(window[-1]["event_id"], window, pm.phase)

            self.transport.save_agent_state(self.session_id, summary, summary_upto, pm.phase)
            steps_run += 1

        self.transport.save_agent_state(self.session_id, summary, summary_upto, pm.phase)
        complete = bool(all_ids) and self.achieved >= all_ids
        return {"steps": steps_run, "phase": pm.phase, "achieved": sorted(self.achieved),
                "complete": complete}


if __name__ == "__main__":  # dev entrypoint: run the loop against the live API
    import argparse

    from srplatform.red_agent.llm import LLM
    from srplatform.red_agent.sandbox import KaliSandbox
    from srplatform.red_agent.transport import HttpTransport
    from srplatform.settings import get_settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--session", required=True)
    a = ap.parse_args()
    s = get_settings()
    loop = RedAgentLoop(a.session, a.scenario, HttpTransport(s.api_base_url), LLM(), KaliSandbox())
    print(loop.run())
