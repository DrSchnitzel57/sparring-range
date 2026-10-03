"""Implementation behind `rangectl report` / `rangectl hint` (M5)."""
import httpx

from srplatform.settings import get_settings


def report(session_id: str) -> str:
    r = httpx.post(f"{get_settings().api_base_url}/sessions/{session_id}/aar",
                   json={"narrative": True}, timeout=300)
    r.raise_for_status()
    return r.json()["markdown"]


def hint(session_id: str, question: str = "") -> str:
    r = httpx.post(f"{get_settings().api_base_url}/sessions/{session_id}/hint",
                   json={"question": question}, timeout=120)
    r.raise_for_status()
    return r.json()["hint"]
