"""Implementation behind `rangectl score` (M4) — referee-side blue scoring using
the same verifiers that judge red objectives, against REAL host state."""
import httpx

from srplatform.settings import get_settings


def score(session_id: str) -> str:
    base = get_settings().api_base_url
    sess = next((s for s in httpx.get(f"{base}/sessions", timeout=30).json()
                 if s["session_id"] == session_id), None)
    if not sess:
        return "session not found"

    from srplatform.red_agent.sandbox import KaliSandbox
    from srplatform.scenario_engine.scoring import compute_blue_score
    from verifiers.base import Context

    result = compute_blue_score(sess["scenario_id"], Context(exec=KaliSandbox().verifier_exec))
    lines = []
    for item in result["items"]:
        mark = "PASS" if item["awarded"] else "FAIL"
        lines.append(f"  [{mark}] {item['verifier']}@{item['host']} +{item['awarded']}/{item['points']}")
    lines.append(f"score: {result['earned']}/{result['total']}")

    # record the scorecard in the append-only log (evidence for the AAR)
    httpx.post(f"{base}/events", json={
        "session_id": session_id, "actor": "system", "action_type": "verifier",
        "payload": {"scorecard": result},
    }, timeout=30)
    return "\n".join(lines)
