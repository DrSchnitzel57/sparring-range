"""LLM client (M3): openai SDK → LLM_BASE_URL. Model-server-agnostic (Part 6.1);
the harness only needs an OpenAI-compatible chat endpoint.
"""
from __future__ import annotations

from srplatform.settings import get_settings


class LLM:
    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None):
        s = get_settings()
        from openai import OpenAI

        self.model = model or s.llm_model_red
        self.client = OpenAI(base_url=base_url or s.llm_base_url, api_key=api_key or s.llm_api_key)

    def complete(self, system: str, user: str, temperature: float = 0.2, max_tokens: int = 600) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""
