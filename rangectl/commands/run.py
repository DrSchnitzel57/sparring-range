"""Implementation behind `rangectl run` (M3)."""
import httpx

from srplatform.settings import get_settings


def run(scenario_id: str, username: str = "drew", no_start: bool = False) -> str:
    base = get_settings().api_base_url
    sid = httpx.post(f"{base}/sessions", json={"scenario_id": scenario_id, "username": username},
                     timeout=30).json()["session_id"]
    lines = [f"session {sid}"]
    if no_start:
        return "\n".join(lines)
    httpx.post(f"{base}/run/{scenario_id}", json={"session_id": sid}, timeout=30).raise_for_status()
    lines.append("red agent loop started (verifiers decide everything; watch with: rangectl status "
                 f"{sid})")
    return "\n".join(lines)
