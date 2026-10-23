"""LLM client (M3): openai SDK → LLM_BASE_URL. Model-server-agnostic (Part 6.1);
the harness only needs an OpenAI-compatible chat endpoint.
"""
from __future__ import annotations

from srplatform.settings import get_settings


class CompletionRejected(ValueError):
    """The endpoint answered, but did not supply a usable final completion."""

    retryable = False  # retrying the identical exhausted budget cannot repair it


class LLM:
    def __init__(self, model: str | None = None, base_url: str | None = None,
                 api_key: str | None = None, *, role: str | None = None):
        s = get_settings()
        from openai import OpenAI

        # Existing coach callers select its model explicitly. An explicit role
        # also supports deployments using the same model alias for both roles.
        role = role or ("coach" if model is not None and model == s.llm_model_coach else "red")
        if role not in {"red", "coach"}:
            raise ValueError("completion role must be red or coach")
        self.model = model or getattr(s, f"llm_model_{role}")
        # Reasoning tokens consume the same output budget as visible text on
        # compatible servers. Leave headroom under the 60 s call policy rather
        # than requesting 8192 tokens (~126 s at 65 tokens/s). No local retries:
        # the gateway remains the single bounded retry authority.
        self.max_tokens = getattr(s, f"llm_max_tokens_{role}",
                                  3072 if role == "coach" else 2048)
        # Bounded call timeout (60 s default per the gateway policy); the SDK's
        # own implicit retries are DISABLED so the single bounded retry policy
        # lives in the model gateway (no hidden multiplication of attempts).
        self.client = OpenAI(base_url=base_url or s.llm_base_url,
                             api_key=api_key or s.llm_api_key,
                             timeout=s.llm_timeout_s, max_retries=0)

    def complete(self, system: str, user: str, temperature: float = 0.2,
                 max_tokens: int | None = None) -> str:
        budget = self.max_tokens if max_tokens is None else max_tokens
        if isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0:
            raise ValueError("completion token budget must be a positive integer")
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=temperature,
            max_tokens=budget,
        )
        if not resp.choices:
            raise CompletionRejected("model completion rejected: no choices")
        choice = resp.choices[0]
        # Partial JSON and partial coaching are not successful completions.
        # Never include returned content/reasoning in these diagnostic errors.
        if choice.finish_reason == "length":
            raise CompletionRejected("model completion rejected: token budget exhausted")
        if choice.finish_reason != "stop":
            raise CompletionRejected("model completion rejected: no normal stop")
        text = choice.message.content
        if not isinstance(text, str) or not text.strip():
            raise CompletionRejected("model completion rejected: empty final content")
        return text
