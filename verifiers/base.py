"""Verifier interface (plan Part 5/M4 shape) — the ONLY thing allowed to declare
red success or score blue (hard constraint #3: no self-reported success anywhere).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass
class VerifierResult:
    passed: bool
    evidence: dict = field(default_factory=dict)
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Context:
    """What a verifier may consult. `exec` runs a command on the named target
    host and returns (exit_code, stdout). In prod this is an exec channel from
    the platform into the range (management path); in tests it's a fake fs."""
    exec: Callable[[str, str], tuple[int, str]]
    hosts: dict[str, Any] = field(default_factory=dict)


class Verifier(ABC):
    id: str = ""
    description: str = ""
    mitre: list[str] = []

    @abstractmethod
    def check(self, ctx: Context, **args) -> VerifierResult:
        ...
