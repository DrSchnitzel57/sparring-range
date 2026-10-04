"""The red agent: a hand-rolled loop, not a framework (Part 2).

  load agent_state + recent events (cursor) → build prompt WITH topology →
  one model call → strict-parse tool call → append action INTENT → execute on
  the isolated runner → append action RESULT → request trusted verification
  (backend runs the verifiers; the loop never holds management credentials) →
  compress old history INTO the next summary → advance phase from verifier facts.

Trust model (hard constraint #3): the model may CLAIM anything; only verifier
results (executed by the trusted backend, recorded with actor 'system') flip
objectives. Crash safety (F14): intents are appended before dispatch, results
after — on restart, unresolved intents are marked unknown, never blindly
replayed. DONE is only success when ALL objectives are verifier-confirmed
(F15); false claims get bounded retries and end as explicit no-progress.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from srplatform.red_agent.phases import PhaseMachine
from srplatform.red_agent.schema import TOOL_SCHEMA_DOC, parse_tool_call

SYSTEM_PROMPT = """You are the RED agent in an isolated CCDC sparring range (no internet, lab only).
You have ONE tool: shell, executed on your isolated Kali runner against the range network.
{schema}

Scenario: {name}
Target inventory (scenario hostnames/IPs on the range network):
{topology}
Objectives (verifier-confirmed — never self-declare):
{objectives}
Current phase: {phase}
SITUATION REPORT (compressed memory):
{summary}
RECENT EVENTS:
{recent}

Command targets via their scenario hostnames/IPs. When you believe EVERY
objective is verifier-confirmed, send {{"tool":"shell","args":{{"command":"DONE"}}}}."""

SUMMARIZER_PROMPT = """You maintain a rolling situation report for a red-agent session.

PREVIOUS SITUATION REPORT (facts already established — every fact in it MUST
survive, with its supporting event ids):
{previous}

NEW EVENTS to fold in:
{events}

Output the NEW complete situation report (under 250 words): what is known
about targets, what worked, what failed, what is in flight, current phase.
Plain text, no JSON."""


class RedAgentKilled(Exception):
    pass


class RedAgentLoop:
    def __init__(self, session_id: str, scenario_id: str, transport, llm, runner,
                 max_steps: int = 20, compress_after: int = 8, keep_recent: int = 6):
        from srplatform.scenario_engine.loader import load_scenario

        self.session_id = session_id
        self.scenario = load_scenario(scenario_id)
        self.transport = transport
        self.llm = llm  # needs .complete(system, user) -> str
        self.runner = runner  # isolated runner adapter: .run(cmd) -> RunResult|(code,out)
        self.max_steps = max_steps
        self.compress_after = compress_after
        self.keep_recent = keep_recent
        self.achieved: set[str] = set()
        self._op_seq = 0

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

    def _topology_text(self) -> str:
        hosts = (self.scenario.get("topology") or {}).get("hosts") or []
        lines = [f"- {h.get('name')}: ip {h.get('ip')} services {h.get('services', [])}"
                 for h in hosts]
        return "\n".join(lines) or "(no inventory — abort: scenario has no hosts)"

    def _check_objectives(self, phase: str) -> bool:
        """Ask the TRUSTED BACKEND to run every unconfirmed red objective's
        verifier against real host state and append the evidence itself.
        Returns True when anything newly passed."""
        newly = False
        for obj in self._red_objectives():
            if obj["id"] in self.achieved:
                continue
            res = self.transport.verify_objective(self.session_id, obj["id"])
            if not res or res.get("error"):
                continue  # unavailable stays unavailable — never a silent pass
            if res.get("passed"):
                self.achieved.add(obj["id"])
                newly = True
        return newly

    def compress(self, previous: str, upto_event_id: int, events: list[dict]) -> tuple[str, int] | None:
        """Carry the PREVIOUS report forward into every compression (F14).
        Returns None on model failure so the checkpoint never advances
        over unfactored events."""
        blob = "\n".join(f"[{e['event_id']}] {e['actor']}/{e['action_type']} @{e.get('host')}: "
                         f"{str(e['payload'])[:200]}" for e in events)
        try:
            summary = self.llm.complete(
                SUMMARIZER_PROMPT.format(previous=previous or "(none yet)", events=blob),
                "summarize")
        except Exception:
            return None
        return summary, upto_event_id

    # --------------------------------------------------------------------- run
    def run(self, stop_after_steps: int | None = None) -> dict:
        objectives_desc = "\n".join(f"- {o['id']}: {o.get('description', o['verifier'])} "
                                    f"(phase {o.get('phase', 'any')})"
                                    for o in self._red_objectives())
        pm = PhaseMachine(self.scenario.get("red", {}).get("start_phase", "recon"))

        # RESUME: restore phase/summary from agent_state; re-derive achieved
        # objectives from verifier events (the log is the truth, not memory).
        state = self.transport.get_agent_state(self.session_id) or {}
        if state.get("current_phase"):
            pm.advance_to(state["current_phase"])
        summary = state.get("summary") or ""
        summary_upto = state.get("summary_upto") or 0

        history = self.transport.events_since(self.session_id, 0)
        unresolved_intents: set[int] = set()
        for e in history:
            p = e.get("payload") or {}
            if e["action_type"] == "verifier" and p.get("passed"):
                self.achieved.add(p.get("objective"))
            elif e["action_type"] == "action_intent":
                unresolved_intents.add(p.get("op_id"))
                self._op_seq = max(self._op_seq, p.get("op_id", 0))
            elif e["action_type"] == "action_result":
                unresolved_intents.discard(p.get("op_id"))
        # reconcile: an intent that never got a result had an UNKNOWN outcome —
        # record that truthfully and move on; never blindly replay it (F14).
        for op in sorted(unresolved_intents):
            self._log("red", "agent_note",
                      {"op_id": op, "note": "intent without result after worker restart — "
                                            "outcome unknown, command NOT replayed"}, phase=pm.phase)

        all_ids = {o["id"] for o in self._red_objectives()}
        steps_run = 0
        done_claims = 0
        outcome = "incomplete"

        while True:
            if all_ids and self.achieved >= all_ids:
                outcome = "complete"
                break
            limit = stop_after_steps if stop_after_steps is not None else self.max_steps
            if steps_run >= limit:
                outcome = "incomplete"  # budget exhausted, explicitly not complete
                break

            recent = self.transport.events_since(self.session_id, summary_upto)
            recent_tail = recent[-self.keep_recent:]
            recent_txt = "\n".join(
                f"[{e['event_id']}] {e['actor']}/{e['action_type']} {str(e['payload'])[:200]}"
                for e in recent_tail) or "(none yet)"

            prompt = SYSTEM_PROMPT.format(
                schema=TOOL_SCHEMA_DOC, name=self.scenario.get("name", "?"),
                topology=self._topology_text(),
                objectives=objectives_desc, phase=pm.phase,
                summary=summary or "(no summary yet)", recent=recent_txt)

            # ONE model call; strict parse with a single retry (Part 6.4 tuning)
            try:
                raw = self.llm.complete(prompt, "next action")
            except Exception as e:  # model outage is a first-class outcome (F18)
                self._log("red", "agent_note", {"model_error": str(e)[:300]}, phase=pm.phase)
                outcome = "model_unavailable"
                break
            try:
                tc = parse_tool_call(raw)
            except ValueError:
                try:
                    raw = self.llm.complete(prompt + "\n\nREMINDER: JSON ONLY, exact schema.",
                                            "next action")
                    tc = parse_tool_call(raw)
                except ValueError as e:
                    self._log("system", "tool_call", {"error": f"model output rejected twice: {e}",
                                                      "raw": raw[:500]}, phase=pm.phase)
                    steps_run += 1
                    continue

            # DONE is only true if the VERIFIERS say ALL objectives hold (F15)
            if tc.command.strip() == "DONE":
                self._check_objectives(pm.phase)
                if all_ids and self.achieved >= all_ids:
                    outcome = "complete"
                    break
                done_claims += 1
                self._log("red", "agent_note", {
                    "note": "red agent claimed completion but verifiers did not confirm ALL objectives",
                    "achieved": sorted(self.achieved), "needed": sorted(all_ids)}, phase=pm.phase)
                if done_claims >= 3:
                    outcome = "no_progress"  # stop thrashing on a false claim
                    break
                steps_run += 1
                continue

            # --- intent BEFORE execution (F14): a crash cannot erase that we
            # --- dispatched this command, and restart will not replay it blind.
            self._op_seq += 1
            op_id = self._op_seq
            self._log("red", "action_intent", {"op_id": op_id, "command": tc.command,
                                               "thought": tc.thought}, phase=pm.phase)

            res = self.runner.run(tc.command)
            code, out = self._runner_result(res)

            self._log("red", "action_result",
                      {"op_id": op_id, "command": tc.command, "exit_code": code,
                       "output": out[:4000], "timed_out": getattr(res, "timed_out", False)},
                      phase=pm.phase,
                      raw_output_hash=hashlib.sha256(out.encode()).hexdigest()[:16])

            # trusted verification after every action; results come from the
            # backend (actor system) and drive phase advancement
            if self._check_objectives(pm.phase):
                newly_achieved = [o for o in self._red_objectives() if o["id"] in self.achieved]
                for o in newly_achieved:
                    if o.get("phase"):  # phase is a SCENARIO fact (F15)
                        pm.advance_to(o["phase"])

            # rolling memory: compress events beyond the keep-recent window,
            # carrying the previous summary forward; checkpoint only on success
            all_new = self.transport.events_since(self.session_id, summary_upto)
            if len(all_new) > self.compress_after:
                window = all_new[: len(all_new) - self.keep_recent]
                compressed = self.compress(summary, window[-1]["event_id"], window)
                if compressed:
                    summary, summary_upto = compressed

            self.transport.save_agent_state(self.session_id, summary, summary_upto, pm.phase)
            steps_run += 1

        self.transport.save_agent_state(self.session_id, summary, summary_upto, pm.phase)
        complete = bool(all_ids) and self.achieved >= all_ids
        if complete:
            outcome = "complete"
        return {"steps": steps_run, "phase": pm.phase, "achieved": sorted(self.achieved),
                "complete": complete, "outcome": outcome}

    @staticmethod
    def _runner_result(res):
        """Normalize RunnerResult or legacy (code, out) tuples."""
        if isinstance(res, tuple):
            return res[0], res[1]
        return res.exit_code, res.output


if __name__ == "__main__":  # dev entrypoint — normal path is the worker (see worker.py)
    raise SystemExit("run via `python -m srplatform.red_agent.worker` (requires run-scoped token)")
