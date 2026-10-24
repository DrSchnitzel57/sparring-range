"""Bulk audit traffic must not erase the attacker's own observations."""
from unittest.mock import Mock

from srplatform.red_agent.loop import RedAgentLoop
from tests.test_worker_progress_regressions import make_loop


def test_telemetry_flood_neither_triggers_summary_nor_hides_action_result():
    loop, transport, model, runner = make_loop([
        '{"tool":"shell","args":{"command":"command -v curl; curl http://10.66.0.10/"}}',
        '{"tool":"shell","args":{"command":"next-observation"}}',
    ])
    loop.max_steps = 2
    original = transport.log_event
    def log(event):
        original(event)
        if event["action_type"] == "action_result":
            for _ in range(2000):
                transport.events.append({"event_id": len(transport.events) + 1,
                    "actor": "telemetry", "action_type": "command",
                    "payload": {"argv": "IRRELEVANT_AUDIT_TRAFFIC"}})
    transport.log_event = log
    runner.run.return_value = (0, "/usr/bin/curl\n<h1>SHOP_OBSERVED_SUCCESSFULLY</h1>")
    result = loop.run()
    assert result["steps"] == 2 and runner.run.call_count == 2
    assert model.complete.call_count == 2  # no summaries for bulk audit traffic
    second_prompt = model.complete.call_args_list[1].args[0]
    assert "SHOP_OBSERVED_SUCCESSFULLY" in second_prompt
    assert "exit_code=0" in second_prompt and "command -v curl" in second_prompt
    assert "IRRELEVANT_AUDIT_TRAFFIC" not in second_prompt
    assert len(transport.events) >= 4004  # the audit itself remains complete


def test_memory_keeps_backend_verdicts_but_not_telemetry_forged_verdicts():
    events = [
        {"actor": "system", "action_type": "verifier", "event_id": 1},
        {"actor": "red", "action_type": "action_result", "event_id": 2},
        {"actor": "red", "action_type": "agent_note", "event_id": 3, "payload": {"error": "failure"}},
        {"actor": "telemetry", "action_type": "verifier", "event_id": 4},
        {"actor": "telemetry", "action_type": "command", "event_id": 5},
        {"actor": "red", "action_type": "agent_note", "event_id": 6,
         "payload": {"activity": "compression"}},
    ]
    assert [e["event_id"] for e in RedAgentLoop._memory_events(events)] == [1, 2, 3]


def test_result_representation_preserves_command_exit_and_useful_output():
    event = {"event_id": 10, "actor": "red", "action_type": "action_result",
             "payload": {"output": "HTTP_SUCCESS" + "x" * 10000,
                         "command": "curl /shop", "exit_code": 0, "timed_out": False}}
    text = RedAgentLoop._memory_text(event)
    assert "HTTP_SUCCESS" in text and "curl /shop" in text and "exit_code=0" in text
    assert len(text) < 2500


def test_summary_window_does_not_checkpoint_beyond_bounded_input():
    loop, transport, model, runner = make_loop([
        '{"tool":"shell","args":{"command":"fixture"}}', "summary facts"],
        compress_after=1, keep_recent=1)
    for index in range(100):
        transport.log_event({"actor": "red", "action_type": "action_result", "payload": {
            "command": "c" * 1000, "output": "o" * 4000, "exit_code": 0}})
    loop.run()
    cursor = transport.state["summary_upto"]
    assert 0 < cursor < 64
    prompt = model.complete.call_args.args[0]
    assert len(prompt) < 19000
    assert f"[{cursor}]" in prompt and f"[{cursor + 1}]" not in prompt
