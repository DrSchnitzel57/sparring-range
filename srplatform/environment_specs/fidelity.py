"""Fidelity / deviation ledger — labels every reconstructed value.

The supplied Underpressure replication spec is REPORTED evidence: its
screenshots, exports and disks were not independently inspected. A
blueprint line is therefore only as strong as its ledger entry. This
module validates the ledger shape; the loader additionally checks that
substituted/unknown roles are never presented as exact originals and that
every ledger path resolves inside the blueprint document.

Classifications:
  reported  — stated by the supplied spec/screenshots (not independently verified)
  observed  — verified first-hand on the original (only the operator can add these)
  inferred  — reasonable reading of partial evidence; the original may differ
  synthetic — deliberately generated (fictional identities, labs, budgets)
  substituted — legitimate stand-in for unavailable/proprietary media or hardware
  excluded  — known original artifact intentionally NOT reproduced (incident
              residue, original keys/malware, cosmetic damage)
  unverified — carried from a source that cannot be checked in this lab
"""
from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .blueprint import EnvironmentError  # noqa: F401 (re-raised errors)

SOURCE_RE = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
# JSON-pointer-like path: slash-separated tokens (array indices allowed).
PATH_RE = re.compile(r"^(/[A-Za-z0-9._-]+)+$")


class FidelityClass(str, Enum):
    REPORTED = "reported"
    OBSERVED = "observed"
    INFERRED = "inferred"
    SYNTHETIC = "synthetic"
    SUBSTITUTED = "substituted"
    EXCLUDED = "excluded"
    UNVERIFIED = "unverified"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FidelityEntry(Strict):
    path: str = Field(pattern=PATH_RE.pattern)
    classification: FidelityClass
    note: str = Field(min_length=1, max_length=600)
    # Which declared source document supports this value (environment-local
    # source id; raw screenshots/OSINT stay operator-local, never in Git).
    source: str = Field(pattern=SOURCE_RE.pattern)

    @field_validator("path")
    @classmethod
    def _norm(cls, v: str) -> str:
        return v.rstrip("/")


class FidelityLedger(Strict):
    schema_version: int = 1
    environment: str = Field(min_length=1, max_length=64)
    version: int = Field(ge=1)
    # Declared source ids this ledger may cite (documents, not content).
    sources: list[str] = Field(min_length=1)
    entries: list[FidelityEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_and_cited(self) -> "FidelityLedger":
        issues: list[str] = []
        seen: set[str] = set()
        for i, e in enumerate(self.entries):
            if e.path in seen:
                issues.append(f"fidelity: duplicate path {e.path}")
            seen.add(e.path)
            if e.source not in self.sources:
                issues.append(f"fidelity: entries[{i}] cites undeclared "
                              f"source {e.source!r}")
        for s in self.sources:
            if not re.fullmatch(SOURCE_RE.pattern, s):
                issues.append(f"fidelity: source id {s!r} invalid")
        if issues:
            raise ValueError("\n".join(issues))
        return self

    def classification_for(self, path: str) -> FidelityClass | None:
        """Exact-match classification (longest registered prefix on arrays is
        intentionally NOT guessed — callers register what they label)."""
        for e in self.entries:
            if e.path == path:
                return e.classification
        return None

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.classification.value] = out.get(e.classification.value, 0) + 1
        return out
