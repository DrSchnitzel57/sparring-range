"""Blue scoring (M4): the SAME verifiers that confirm red objectives score the
defender. A score is computed from real host state at score time (or from
logged verifier-result events for replay) — never from anyone's claims.
"""
from __future__ import annotations

from srplatform.scenario_engine.loader import load_scenario
from verifiers import registry
from verifiers.base import Context


def compute_blue_score(scenario_id: str, ctx: Context) -> dict:
    spec = load_scenario(scenario_id)
    checks = (spec.get("scoring") or {}).get("blue_checks", [])
    items, earned, total = [], 0, 0
    for chk in checks:
        points = int(chk.get("points", 0))
        total += points
        v = registry.get(chk["verifier"])
        args = {k: val for k, val in chk.items() if k not in ("verifier", "points")}
        res = v.check(ctx, **args)
        if res.passed:
            earned += points
        items.append({"verifier": chk["verifier"], "host": chk.get("host"), "points": points,
                      "awarded": points if res.passed else 0, "evidence": res.evidence})
    return {"scenario_id": scenario_id, "earned": earned, "total": total, "items": items}
