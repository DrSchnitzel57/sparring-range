"""Red kill-chain phase state machine (M3).

recon → initial-access → priv-esc → lateral → persistence → objectives

Transitions are driven by VERIFIER results (objective completion), not by the
model's say-so; the model may propose a phase, but the machine only advances when
the scenario's objective verifier for that step passes.
"""
from __future__ import annotations

PHASES = ["recon", "initial-access", "priv-esc", "lateral", "persistence", "objectives"]


class PhaseMachine:
    def __init__(self, start: str = "recon"):
        assert start in PHASES, f"unknown phase {start}"
        self.phase = start

    def can_go(self, target: str) -> bool:
        # forward moves allowed (skipping e.g. lateral on a one-host scenario is fine);
        # never backward — progress is one-way.
        return target in PHASES and PHASES.index(target) >= PHASES.index(self.phase)

    def advance_to(self, target: str) -> str:
        if not self.can_go(target):
            return self.phase
        self.phase = target
        return self.phase

    @property
    def done(self) -> bool:
        return self.phase == "objectives"
