"""Transport between the red agent loop and the platform.

The loop NEVER talks to Postgres — it goes through the API (front-door rule).
Event reads use a SERVER-SIDE event-ID cursor (F14): deterministic ingestion
order, no 5,000-row head window, late-arriving telemetry is never lost. A
`latest_events` call backs CLI `status` / live UI tails.
"""
from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    def log_event(self, event: dict) -> None: ...
    def events_since(self, session_id: str, after_event_id: int) -> list[dict]: ...
    def latest_events(self, session_id: str, n: int = 50) -> list[dict]: ...
    def verify_objective(self, session_id: str, objective_id: str) -> dict: ...
    def scenario_spec(self, session_id: str) -> dict: ...
    def get_agent_state(self, session_id: str) -> dict | None: ...
    def save_agent_state(self, session_id: str, summary: str | None, summary_upto: int | None,
                         current_phase: str | None) -> None: ...


PAGE = 1000


def _fetch_since(client, session_id: str, after_event_id: int, max_rows: int = 50_000) -> list[dict]:
    """Page through the server-side cursor until exhausted (no head-window loss)."""
    rows: list[dict] = []
    cursor = after_event_id
    while True:
        page = client.get("/events", params={"session_id": session_id,
                                             "after_event_id": cursor, "limit": PAGE}).json()
        if not page:
            return rows
        rows.extend(page)
        cursor = page[-1]["event_id"]
        if len(page) < PAGE or len(rows) >= max_rows:
            return rows


def _save_state_sync(client, session_id: str, summary, summary_upto, current_phase) -> None:
    client.put(f"/agent_state/{session_id}", json={
        "summary": summary, "summary_upto": summary_upto, "current_phase": current_phase,
    }).raise_for_status()


class HttpTransport:
    def __init__(self, base_url: str, token: str | None = None):
        import httpx

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.client = httpx.Client(base_url=base_url, timeout=30, headers=headers)

    def log_event(self, event: dict) -> None:
        self.client.post("/events", json=event).raise_for_status()

    def events_since(self, session_id: str, after_event_id: int) -> list[dict]:
        return _fetch_since(self.client, session_id, after_event_id)

    def latest_events(self, session_id: str, n: int = 50) -> list[dict]:
        rows = self.client.get("/events", params={"session_id": session_id, "tail": n}).json()
        return rows

    def verify_objective(self, session_id: str, objective_id: str) -> dict:
        r = self.client.post(f"/sessions/{session_id}/verifier_checks", json={"objective_id": objective_id})
        return r.json() if r.status_code == 200 else {"error": f"verifier check rejected: {r.status_code}"}

    def scenario_spec(self, session_id: str) -> dict:
        """Session snapshot from the API (audit N10) — the worker never reads
        the mutable scenario file."""
        r = self.client.get(f"/sessions/{session_id}/scenario")
        r.raise_for_status()
        return r.json()["scenario"]

    def get_agent_state(self, session_id: str) -> dict | None:
        r = self.client.get(f"/agent_state/{session_id}")
        return r.json() if r.status_code == 200 else None

    def save_agent_state(self, session_id: str, summary, summary_upto, current_phase) -> None:
        _save_state_sync(self.client, session_id, summary, summary_upto, current_phase)


class TestClientTransport:
    """Same surface, in-process (tests) — hits the REAL endpoints and DB."""

    def __init__(self, test_client, token: str | None = None):
        self.c = test_client
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    def log_event(self, event: dict) -> None:
        self.c.post("/events", json=event, headers=self.headers).raise_for_status()

    def events_since(self, session_id: str, after_event_id: int) -> list[dict]:
        return _fetch_since(_AuthedClient(self.c, self.headers), session_id, after_event_id)

    def latest_events(self, session_id: str, n: int = 50) -> list[dict]:
        return self.c.get("/events", params={"session_id": session_id, "tail": n},
                          headers=self.headers).json()

    def verify_objective(self, session_id: str, objective_id: str) -> dict:
        r = self.c.post(f"/sessions/{session_id}/verifier_checks",
                        json={"objective_id": objective_id}, headers=self.headers)
        return r.json() if r.status_code == 200 else {"error": f"verifier check rejected: {r.status_code}"}

    def scenario_spec(self, session_id: str) -> dict:
        r = self.c.get(f"/sessions/{session_id}/scenario", headers=self.headers)
        r.raise_for_status()
        return r.json()["scenario"]

    def get_agent_state(self, session_id: str) -> dict | None:
        r = self.c.get(f"/agent_state/{session_id}", headers=self.headers)
        return r.json() if r.status_code == 200 else None

    def save_agent_state(self, session_id: str, summary, summary_upto, current_phase) -> None:
        self.c.put(f"/agent_state/{session_id}", json={
            "summary": summary, "summary_upto": summary_upto, "current_phase": current_phase},
            headers=self.headers).raise_for_status()


class _AuthedClient:
    """Adapter so the shared cursor pager (built for httpx) sends auth headers."""

    def __init__(self, client, headers):
        self._c, self._h = client, headers

    def get(self, path, params=None):
        return self._c.get(path, params=params, headers=self._h)
