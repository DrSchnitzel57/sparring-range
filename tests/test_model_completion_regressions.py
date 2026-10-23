"""No-network regressions for reasoning-model completion and honest coaching."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from srplatform.coach.aar import build_hint
from srplatform.red_agent.llm import CompletionRejected, LLM


def response(content="A useful answer", finish_reason="stop"):
    return SimpleNamespace(choices=[SimpleNamespace(
        finish_reason=finish_reason,
        message=SimpleNamespace(content=content, reasoning_content="private reasoning"))])


@pytest.fixture
def endpoint(monkeypatch):
    settings = SimpleNamespace(llm_model_red="red", llm_model_coach="coach",
                               llm_base_url="http://fixture.invalid/v1",
                               llm_api_key="synthetic", llm_timeout_s=60)
    monkeypatch.setattr("srplatform.red_agent.llm.get_settings", lambda: settings)
    client = Mock()
    client.chat.completions.create.return_value = response()
    factory = Mock(return_value=client)
    monkeypatch.setattr("openai.OpenAI", factory)
    return settings, factory, client


@pytest.mark.parametrize("kwargs,model,budget", [
    ({}, "red", 2048),
    ({"model": "coach"}, "coach", 3072),
    ({"role": "coach"}, "coach", 3072),
])
def test_role_budgets_preserve_existing_constructors(endpoint, kwargs, model, budget):
    _, factory, client = endpoint
    assert LLM(**kwargs).complete("system", "user") == "A useful answer"
    request = client.chat.completions.create.call_args.kwargs
    assert request["model"] == model
    assert request["max_tokens"] == budget
    assert request["messages"] == [{"role": "system", "content": "system"},
                                    {"role": "user", "content": "user"}]
    assert factory.call_args.kwargs["timeout"] == 60
    assert factory.call_args.kwargs["max_retries"] == 0


def test_settings_budgets_and_explicit_override(endpoint):
    settings, _, client = endpoint
    settings.llm_max_tokens_red = 1800
    settings.llm_max_tokens_coach = 2800
    LLM().complete("s", "u")
    assert client.chat.completions.create.call_args.kwargs["max_tokens"] == 1800
    coach = LLM(model="coach")
    coach.complete("s", "u")
    assert client.chat.completions.create.call_args.kwargs["max_tokens"] == 2800
    coach.complete("s", "u", 0.5, 400)
    assert client.chat.completions.create.call_args.kwargs["max_tokens"] == 400
    assert client.chat.completions.create.call_args.kwargs["temperature"] == 0.5


def test_explicit_role_disambiguates_shared_model_alias(endpoint):
    settings, _, client = endpoint
    settings.llm_model_coach = settings.llm_model_red
    LLM().complete("s", "u")
    assert client.chat.completions.create.call_args.kwargs["max_tokens"] == 2048
    LLM(model="red", role="coach").complete("s", "u")
    assert client.chat.completions.create.call_args.kwargs["max_tokens"] == 3072


@pytest.mark.parametrize("budget", [0, -1, True, "600"])
def test_invalid_budget_never_calls_endpoint(endpoint, budget):
    _, _, client = endpoint
    with pytest.raises(ValueError, match="positive integer"):
        LLM().complete("s", "u", max_tokens=budget)
    client.chat.completions.create.assert_not_called()


@pytest.mark.parametrize("content,reason,error", [
    (None, "length", "token budget exhausted"),
    ('{"command": "partial', "length", "token budget exhausted"),
    ("looks complete", "length", "token budget exhausted"),
    (None, "stop", "empty final content"),
    ("", "stop", "empty final content"),
    (" \n\t", "stop", "empty final content"),
    ("filtered text", "content_filter", "no normal stop"),
    ("tool call", "tool_calls", "no normal stop"),
    ("unfinished", None, "no normal stop"),
])
def test_rejected_completion_is_bounded_and_does_not_expose_content(
        endpoint, content, reason, error):
    _, _, client = endpoint
    client.chat.completions.create.return_value = response(content, reason)
    with pytest.raises(CompletionRejected, match=error) as exc:
        LLM().complete("s", "u")
    assert "private reasoning" not in str(exc.value)
    assert len(str(exc.value)) < 100
    assert client.chat.completions.create.call_count == 1


def test_missing_choice_is_explicit_failure(endpoint):
    _, _, client = endpoint
    client.chat.completions.create.return_value = SimpleNamespace(choices=[])
    with pytest.raises(CompletionRejected, match="no choices"):
        LLM().complete("s", "u")


@pytest.mark.parametrize("content,reason", [(None, "length"), ("partial", "length"),
                                            ("", "stop"), ("  ", "stop")])
def test_coach_rejection_produces_visible_nonempty_deterministic_hint(endpoint, content, reason):
    _, _, client = endpoint
    client.chat.completions.create.return_value = response(content, reason)
    result = build_hint([], "Where should I look?", LLM(model="coach"))
    assert "Model response was empty, incomplete, or rejected" in result["hint"]
    assert "not an AI-generated hint" in result["hint"]
    assert "second log source" in result["hint"]
    assert "No diagnosis or successful remediation is inferred" in result["hint"]
    assert result["context_events"] == []
    assert client.chat.completions.create.call_count == 1


def test_coach_alternative_adapter_empty_response_also_falls_back():
    result = build_hint([], "", Mock(complete=Mock(return_value="")))
    assert "deterministic guidance" in result["hint"]


def test_coach_without_model_is_honest():
    assert "No model available" in build_hint([], "", None)["hint"]


def test_coach_valid_text_is_preserved(endpoint):
    assert build_hint([], "", LLM(model="coach"))["hint"] == "A useful answer"


def test_transport_fault_still_reaches_gateway_retry_policy(endpoint):
    _, _, client = endpoint
    client.chat.completions.create.side_effect = TimeoutError("fixture timeout")
    with pytest.raises(TimeoutError, match="fixture timeout"):
        build_hint([], "", LLM(model="coach"))


def test_rejected_attacker_completion_stops_loop_without_dispatch(endpoint):
    from srplatform.red_agent.loop import RedAgentLoop
    from tests.test_pilot_sustained_attacker import (
        MemTransport, SeqRunner, _one_objective_scenario,
    )

    _, _, client = endpoint
    client.chat.completions.create.return_value = response('{"command": "id"}', "length")
    transport = MemTransport(_one_objective_scenario(), {})
    runner = SeqRunner()
    result = RedAgentLoop("s1", "sustain-01", transport, LLM(), runner).run()
    assert result["outcome"] == "model_unavailable"
    assert not runner.calls
    assert any("token budget exhausted" in e["payload"].get("model_error", "")
               for e in transport.events)
