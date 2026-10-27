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
    # durable command-operation inventory (audit T01) — implemented by the
    # real transports; the loop degrades visibly when absent (test doubles)
    def register_operation(self, op_uuid: str, kind: str = "remote") -> None: ...
    def complete_operation(self, op_uuid: str, state: str = "completed",
                           detail: str | None = None) -> None: ...
    # plan 20 timed output capture (implemented by the real transports; the
    # loop only builds a capture sink when append_output is present).
    # Returns the SERVER status string ("stored" | "duplicate" |
    # "conflict" | "quota") or "error"; it NEVER raises (finding 9).
    def append_output(self, op_uuid: str, seq: int, kind: str,
                      text: str | None = None,
                      dropped_bytes: int | None = None,
                      read_ts: float | None = None) -> str: ...


PAGE = 1000

# Capture delivery statuses (finding 9): the ONLY values the capture
# consumer trusts from the server; anything else is transport noise.
_DELIVERY_STATUSES = ("stored", "duplicate", "conflict", "quota")


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
    def __init__(self, base_url: str, token: str | None = None,
                 run_id: str | None = None):
        import httpx

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.client = httpx.Client(base_url=base_url, timeout=30, headers=headers)
        self.token = token
        self.run_id = run_id   # audit T01: durable operation plane binding

    # ---- durable command-operation inventory (audit T01) --------------------
    def register_operation(self, op_uuid: str, kind: str = "remote") -> None:
        """Persist BEFORE dispatch: the API records the operation against the
        run + deployment generation. A failure here is FATAL to the command —
        dispatching work the API cannot later recover/cancel is forbidden."""
        if not self.run_id:
            return
        self.client.post(f"/internal/runs/{self.run_id}/operations",
                         json={"op_id": op_uuid, "kind": kind},
                         headers={"X-Worker-Token": self.token or ""}).raise_for_status()

    def complete_operation(self, op_uuid: str, state: str = "completed",
                           detail: str | None = None) -> None:
        if not self.run_id:
            return
        self.client.post(f"/internal/runs/{self.run_id}/operations/{op_uuid}/done",
                         json={"state": state, "detail": detail},
                         headers={"X-Worker-Token": self.token or ""}).raise_for_status()

    def append_output(self, op_uuid: str, seq: int, kind: str,
                      text: str | None = None,
                      dropped_bytes: int | None = None,
                      read_ts: float | None = None,
                      absolute_timeout_s: float = 12.0) -> str:
        """Deliver one timed output chunk. NEVER raises: capture is
        additive evidence — a failed POST becomes the "error" status and
        the capture counts it honestly; the command and the stop path
        are never blocked by it. The server's status string
        (stored/duplicate/conflict/quota) is returned verbatim so the
        producer can distinguish an idempotent re-delivery from a real
        content conflict (finding 9).

        Review F4: a per-read timeout does NOT bound request AGE — an
        endpoint that dribbles one byte every timeout window holds a
        capture thread forever. The delivery therefore runs on a
        one-shot client that a timer CLOSES at the absolute deadline:
        worst-case thread lifetime is bounded by ``absolute_timeout_s``,
        and the interrupted delivery becomes an honest counted gap.
        """
        if not self.run_id:
            return "error"
        import httpx
        import threading as _threading
        one_shot = httpx.Client(base_url=self.client.base_url, timeout=10,
                                headers={"X-Worker-Token": self.token or ""})
        killer = _threading.Timer(max(1.0, float(absolute_timeout_s)),
                                  one_shot.close)
        killer.daemon = True
        killer.start()
        try:
            r = one_shot.post(
                f"/internal/runs/{self.run_id}/operations/{op_uuid}/output",
                json={"seq": seq, "kind": kind, "text": text,
                      "dropped_bytes": dropped_bytes, "read_ts": read_ts})
            if r.status_code in (200, 201):
                status = (r.json() or {}).get("status")
                return (status if status in _DELIVERY_STATUSES
                        else "stored")
            return "error"
        except Exception:  # noqa: BLE001 — honest gap, never an abort
            return "error"
        finally:
            killer.cancel()
            try:
                one_shot.close()
            except Exception:  # noqa: BLE001
                pass

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

    def __init__(self, test_client, token: str | None = None,
                 run_id: str | None = None):
        self.c = test_client
        self.token = token
        self.run_id = run_id
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    def register_operation(self, op_uuid: str, kind: str = "remote") -> None:
        if not self.run_id:
            return
        r = self.c.post(f"/internal/runs/{self.run_id}/operations",
                        json={"op_id": op_uuid, "kind": kind},
                        headers={"X-Worker-Token": self.token or ""})
        r.raise_for_status()

    def complete_operation(self, op_uuid: str, state: str = "completed",
                           detail: str | None = None) -> None:
        if not self.run_id:
            return
        r = self.c.post(f"/internal/runs/{self.run_id}/operations/{op_uuid}/done",
                        json={"state": state, "detail": detail},
                        headers={"X-Worker-Token": self.token or ""})
        r.raise_for_status()

    def append_output(self, op_uuid: str, seq: int, kind: str,
                      text: str | None = None,
                      dropped_bytes: int | None = None,
                      read_ts: float | None = None) -> str:
        if not self.run_id:
            return "error"
        try:
            r = self.c.post(
                f"/internal/runs/{self.run_id}/operations/{op_uuid}/output",
                json={"seq": seq, "kind": kind, "text": text,
                      "dropped_bytes": dropped_bytes, "read_ts": read_ts},
                headers={"X-Worker-Token": self.token or ""})
            if r.status_code in (200, 201):
                status = (r.json() or {}).get("status")
                return (status if status in _DELIVERY_STATUSES
                        else "stored")
            return "error"
        except Exception:  # noqa: BLE001 — capture never breaks the run
            return "error"

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
