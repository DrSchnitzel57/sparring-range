"""Transport between the red agent loop and the platform.

The loop NEVER talks to Postgres — it goes through the API (front-door rule),
both in prod (httpx) and in tests (in-process TestClient). That keeps the loop's
state (events + agent_state) exactly where the plan wants it: in the DB, via the
single front door, so it survives kills and restarts.
"""
from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    def log_event(self, event: dict) -> None: ...
    def events_since(self, session_id: str, after_event_id: int) -> list[dict]: ...
    def get_agent_state(self, session_id: str) -> dict | None: ...
    def save_agent_state(self, session_id: str, summary: str | None, summary_upto: int | None,
                         current_phase: str | None) -> None: ...


class HttpTransport:
    def __init__(self, base_url: str):
        import httpx

        self.client = httpx.Client(base_url=base_url, timeout=30)

    def log_event(self, event: dict) -> None:
        self.client.post("/events", json=event).raise_for_status()

    def events_since(self, session_id: str, after_event_id: int) -> list[dict]:
        rows = self.client.get("/events", params={"session_id": session_id, "limit": 5000}).json()
        return [r for r in rows if r["event_id"] > after_event_id]

    def get_agent_state(self, session_id: str) -> dict | None:
        r = self.client.get(f"/agent_state/{session_id}")
        return r.json() if r.status_code == 200 else None

    def save_agent_state(self, session_id: str, summary, summary_upto, current_phase) -> None:
        self.client.put(f"/agent_state/{session_id}", json={
            "summary": summary, "summary_upto": summary_upto, "current_phase": current_phase,
        }).raise_for_status()


class TestClientTransport:
    """Same surface, in-process (tests) — hits the REAL endpoints and DB."""

    def __init__(self, test_client):
        self.c = test_client

    def log_event(self, event: dict) -> None:
        self.c.post("/events", json=event).raise_for_status()

    def events_since(self, session_id: str, after_event_id: int) -> list[dict]:
        rows = self.c.get("/events", params={"session_id": session_id, "limit": 5000}).json()
        return [r for r in rows if r["event_id"] > after_event_id]

    def get_agent_state(self, session_id: str) -> dict | None:
        r = self.c.get(f"/agent_state/{session_id}")
        return r.json() if r.status_code == 200 else None

    def save_agent_state(self, session_id: str, summary, summary_upto, current_phase) -> None:
        self.c.put(f"/agent_state/{session_id}", json={
            "summary": summary, "summary_upto": summary_upto, "current_phase": current_phase,
        }).raise_for_status()
