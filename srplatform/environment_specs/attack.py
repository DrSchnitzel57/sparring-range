"""Private attack configuration — AUTHORIZED scope, not management access.

What the offensive AI legitimately receives: the authorized target scope
(from the blueprint), known service context, and an OSINT-derived tactic
guide. What it must NEVER receive from this document: platform management
material, scorer secrets or expectations, hidden defender telemetry,
credential references, future activity, or an automatic foothold. The
loader rejects any of those appearing here; visibility views are built by
projection so a new field can only widen a view if its name is added to
the projection list deliberately.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TacticEntry(Strict):
    tactic: str = Field(min_length=4, max_length=80)
    guidance: str = Field(min_length=10, max_length=1200)
    # Which blueprint guests/segments this tactic concerns (validated by the
    # loader against the blueprint).
    concerns: list[str] = []


class AttackScope(Strict):
    entry_guest: str = Field(min_length=1, max_length=31)
    target_guests: list[str] = Field(min_length=1)
    allowed_segments: list[str] = []
    # The red entry must arrive through the replica's own routed/NAT path.
    entry_via: Literal["routed-nat"] = "routed-nat"
    deny_destructive_wiping: Literal[True] = True
    deny_real_secret_collection: Literal[True] = True
    deny_external_targets: Literal[True] = True
    # Bounded in-range persistence against synthetic assets is allowed;
    # persistence must never survive a generation change as "success".
    bounded_in_range_persistence: Literal[True] = True


class AttackGuide(Strict):
    schema_version: int = 1
    environment: str = Field(min_length=1, max_length=64)
    version: int = Field(ge=1)
    scope: AttackScope
    service_context: list[str] = []
    tactics: list[TacticEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _no_secrets(self) -> "AttackGuide":
        blob = self.model_dump_json()
        if re.search(r"credential:[A-Za-z0-9._-]+", blob):
            raise ValueError("attack guide must never reference scorer or "
                             "verifier credentials")
        if re.search(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S", blob):
            raise ValueError("attack guide contains credential-like material")
        return self
