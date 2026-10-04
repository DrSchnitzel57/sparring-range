"""Verifier interface (plan Part 5/M4 shape) — the ONLY thing allowed to declare
red success or score blue (hard constraint #3: no self-reported success anywhere).

F10 fixes baked into the contract:
  * Three-valued outcomes: `passed` / `failed` / `unknown`. A failed command,
    timeout, unparsable output or missing tool is UNKNOWN — never a pass, and
    never silently a "confirmed clean".
  * Typed arguments (pydantic): required args, types and legal ranges are
    validated BEFORE anything runs; the loader can validate scenario args
    statically (F19).
  * Explicit polarity per use (`expect`): the same predicate can serve a red
    objective ("persistence present") or a blue check ("persistence absent")
    without awarding points for the wrong condition.
  * Command parameters are quoted by each verifier (shlex) — no injection into
    the management channel.
  * Stable identity: verifier id + version + args digest go into every result
    so historical evidence remains interpretable (F19).
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

TRUTHY_EXPECT = {"true", "present", "yes"}
FALSY_EXPECT = {"false", "absent", "no"}


@dataclass
class VerifierOutcome:
    status: str                      # passed | failed | unknown
    expected: str = "true"           # polarity applied
    evidence: dict = field(default_factory=dict)
    error: str | None = None
    args_digest: str | None = None
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Context:
    """What a verifier may consult. `exec` runs a command on the named target
    host and returns (exit_code, stdout). In prod this is an exec channel from
    the platform into the range (management path); in tests it's a fake."""
    exec: Callable[[str, str], tuple[int, str]]
    hosts: dict[str, Any] = field(default_factory=dict)


class Verifier(ABC):
    id: str = ""
    description: str = ""
    mitre: list[str] = []
    version: str = "1"
    #: condition this verifier OBSERVES, human-readable (documented semantics)
    observed_condition: str = "the named condition holds"
    #: pydantic model for typed args; None = no args beyond host
    args_model: type[BaseModel] | None = None

    @abstractmethod
    def observe(self, ctx: Context, **args) -> tuple[bool | None, dict, str | None]:
        """Return (predicate, evidence, error). predicate None => UNKNOWN.
        Implementations MUST NOT raise; convert every failure into None+error."""
        ...

    # ------------------------------------------------------------------ public
    def evaluate(self, ctx: Context, **raw_args: Any) -> VerifierOutcome:
        """Validate args, observe, apply polarity. The single entry point."""
        args = dict(raw_args)
        expect = str(args.pop("expect", "true")).lower()
        if expect not in TRUTHY_EXPECT | FALSY_EXPECT:
            return VerifierOutcome(status="unknown", expected=expect,
                                   error=f"invalid expect '{expect}' (use true/false)")
        want_true = expect in TRUTHY_EXPECT
        if self.args_model is not None:
            try:
                model = self.args_model.model_validate(args)
                args = model.model_dump()
            except ValidationError as e:
                return VerifierOutcome(status="unknown", expected=expect,
                                       error=f"invalid args: {e.errors()}",
                                       args_digest=self._digest(args))
        try:
            predicate, evidence, error = self.observe(ctx, **args)
        except Exception as e:  # noqa: BLE001 — defensive: never crash the caller
            return VerifierOutcome(status="unknown", expected=expect,
                                   error=f"verifier error: {e}", args_digest=self._digest(args))
        if predicate is None:
            return VerifierOutcome(status="unknown", expected=expect, evidence=evidence,
                                   error=error or "probe result indeterminate",
                                   args_digest=self._digest(args))
        passed = (predicate is True) == want_true
        return VerifierOutcome(status="passed" if passed else "failed",
                               expected=expect, evidence=evidence,
                               args_digest=self._digest(args))

    def validate_static(self, args: dict) -> str | None:
        """Loader-side validation of scenario args without executing anything.
        Returns an issue string or None."""
        a = {k: v for k, v in args.items() if k != "expect"}
        if self.args_model is None:
            return None
        try:
            self.args_model.model_validate(a)
            return None
        except ValidationError as e:
            return f"verifier '{self.id}' args invalid: {e.errors()}"

    @staticmethod
    def _digest(args: dict) -> str:
        try:
            blob = json.dumps(args, sort_keys=True, default=str)
        except TypeError:
            blob = str(args)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]
