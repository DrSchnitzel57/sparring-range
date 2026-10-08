"""M5 acceptance tests — Part 5/M5 'Accept when':

  * `report` emits a GRADED AAR that cites specific logged events by id with
    real timestamps — and is HONEST: correlation (not any-later-activity)
    counts as response; missing telemetry is a gap, never an accusation; and
    without a trusted scorecard the report says UNSCORED instead of inventing
    a grade (or an F) (F12).
  * hint returns a context-aware Socratic hint without stalling the queue:
    interactive priority jumps ahead of batch AAR work.
"""
import threading
import time

import pytest

from srplatform.api.coach_routes import set_coach_llm
from srplatform.coach.aar import build_aar, validate_narrative
from srplatform.coach.timeline import compress_timeline
from srplatform.model_gateway import get_model_gateway

# db layer membership derives from the fixture closure (milestone 01)


def ev(eid, ts, actor, kind, host=None, payload=None, **kw):
    return {"event_id": eid, "ts": f"2026-10-04T15:{ts:02d}:00+00:00", "actor": actor,
            "action_type": kind, "host": host, "payload": payload or {}, **kw}


# --- timeline: correlation, not magic ------------------------------------------------------------
def test_timeline_response_must_be_correlated_same_host_within_window():
    events = [
        ev(1, 0, "system", "verifier", "web01", {"objective": "foothold", "passed": True}),
        ev(2, 5, "drew", "bastion_session_end"),                 # disconnect != response
        ev(3, 10, "telemetry", "command", "db01", {"argv": "ps aux"}),  # wrong host
    ]
    _, idx = compress_timeline(events)
    assert len(idx["misses"]) == 0 and len(idx["telemetry_gaps"]) == 1
    assert "no telemetry received" in idx["telemetry_gaps"][0]["reason"]

    # Same-host telemetry closes the GAP (the host reports) but is UNATTRIBUTED
    # activity — it is NOT a defender response (Stage 5: the attacker's own
    # commands on the host must never earn blue credit).
    events.append(ev(4, 20, "telemetry", "command", "web01", {"argv": "cat /var/log/auth.log"}))
    _, idx = compress_timeline(events)
    assert len(idx["misses"]) == 1            # still uncorrelated: no defender attribution
    assert len(idx["telemetry_gaps"]) == 0    # telemetry coverage exists now
    # a defender-ATTRIBUTED action on the right host within the window correlates
    events.append(ev(5, 25, "blue:amy", "command", "web01", {"command": "ps aux"}))
    _, idx = compress_timeline(events)
    assert len(idx["misses"]) == 0

    # telemetry exists on this host but NO response AFTER the objective -> miss
    # (activity precedes the compromise — it cannot be the investigation)
    events2 = [
        ev(2, 55, "telemetry", "command", "web01", {"argv": "uptime"}),
        ev(1, 0, "system", "verifier", "web01", {"objective": "x", "passed": True}),
    ]
    _, idx2 = compress_timeline(sorted(events2, key=lambda e: e["event_id"]))
    assert len(idx2["misses"]) == 1
    assert "no correlated defender action" in idx2["misses"][0]["reason"]


def test_timeline_wins_are_explicit_remediations_only():
    events = [ev(1, 0, "blue:drew", "command", "web01", {"command": "ls"}),
              ev(2, 1, "blue:drew", "remediation", "web01", {"action": "removed cron"})]
    _, idx = compress_timeline(events)
    assert [e["event_id"] for e in idx["wins"]] == [2]


def test_timeline_response_outside_window_still_a_miss():
    events = [
        {"event_id": 1, "ts": "2026-10-04T10:00:00+00:00", "actor": "system",
         "action_type": "verifier", "host": "web01",
         "payload": {"objective": "x", "passed": True}},
        {"event_id": 2, "ts": "2026-10-04T12:00:00+00:00", "actor": "telemetry",
         "action_type": "command", "host": "web01", "payload": {"argv": "ls"}},
    ]
    _, idx = compress_timeline(events)
    assert len(idx["misses"]) == 1


# --- AAR honesty ---------------------------------------------------------------------------------
def test_aar_unscored_never_becomes_an_f():
    report = build_aar([ev(1, 0, "system", "session_start", payload={})],
                       {"name": "x", "techniques": []}, None)
    assert "UNSCORED" in report["markdown"] and "Grade: **" not in report["markdown"].replace(
        "Grade: **UNSCORED**", "")
    assert report["grade"] is None and report["score_status"] == "unscored"


def test_aar_grades_only_from_trusted_scorecard():
    card = {"status": "scored", "earned": 8, "total": 10, "items": [
        {"points": 10, "awarded": 8, "status": "passed"}], "rubric_version": 2}
    report = build_aar([ev(1, 0, "system", "session_start", payload={})],
                       {"name": "x", "techniques": ["T1190"]}, card)
    assert report["grade"] and f"{report['earned']}/{report['total']}" in report["markdown"]


def test_narrative_citations_are_validated_verbatim_kept():
    out = validate_narrative(
        "You missed the cron at #3. Also #999 never happened. Clear.", {1, 2, 3})
    assert "#3" in out and "#999" not in out
    assert "You missed the cron at #3." in out       # kept VERBATIM, not rewritten


# --- API: hint (priority scheduling) and AAR (persisted versions) --------------------------------
def test_hint_endpoint_is_context_aware(client, users):
    class FakeCoach:
        def __init__(self):
            self.n = 0
        def complete(self, system, user):
            self.n += 1
            assert "10.66.0.10" in user or "DEFENDER QUESTION" in user
            return "What changed on web01 since the scan?"
    fc = FakeCoach()
    set_coach_llm(fc)
    try:
        sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                          headers=users["member"]).json()["session_id"]
        r = client.post(f"/sessions/{sid}/hint", json={"question": "where next?"},
                        headers=users["member"])
        assert r.status_code == 200 and "web01" in r.json()["hint"]
        assert fc.n == 1
        # hint is evidence in the log
        logged = client.get("/events", params={"session_id": sid, "tail": 20},
                            headers=users["member"]).json()
        assert any(e["action_type"] == "hint" for e in logged)
    finally:
        set_coach_llm(None)


def test_aar_get_never_regenerates_post_persists_versions(client, users):
    class CountingLLM:
        def __init__(self):
            self.n = 0
        def complete(self, system, user):
            self.n += 1
            return "Narrative."
    llm = CountingLLM()
    set_coach_llm(llm)
    try:
        sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                          headers=users["member"]).json()["session_id"]
        r = client.get(f"/sessions/{sid}/aar", headers=users["member"])
        assert r.status_code == 200 and r.json()["status"] == "no-report"
        assert llm.n == 0                                     # GET spent nothing

        first = client.post(f"/sessions/{sid}/aar", json={"narrative": True},
                            headers=users["member"]).json()
        assert first["persisted"] and first["version"] == 1 and llm.n == 1

        again = client.get(f"/sessions/{sid}/aar", headers=users["member"]).json()
        assert again["version"] == 1 and llm.n == 1           # GET never regenerates

        second = client.post(f"/sessions/{sid}/aar",
                             json={"regenerate": True, "narrative": True},
                             headers=users["member"]).json()
        assert second["version"] == 2 and llm.n == 2          # explicit regen = new version
    finally:
        set_coach_llm(None)


def test_hint_jumps_the_queue_ahead_of_batch_work(client, users):
    gateway = get_model_gateway()
    release = threading.Event()
    completion_order: list[str] = []
    lock = threading.Lock()

    def job(name, sleep=0.0):
        def _f():
            release.wait(5)
            time.sleep(sleep)
            with lock:
                completion_order.append(name)
            return name
        return _f

    blocker = gateway.submit(9, "blocker", job("blocker"))
    time.sleep(0.1)                                # blocker now occupies the worker
    slow_batch = gateway.submit(9, "batch", job("batch", sleep=0.2))
    hint = gateway.submit(0, "hint", job("hint"))  # queued AFTER batch, priority ABOVE it
    release.set()
    assert hint.result(timeout=5) == "hint"
    assert slow_batch.result(timeout=5) == "batch"
    assert blocker.result(timeout=5) == "blocker"
    # the later-submitted batch job did NOT run before the interactive hint
    assert completion_order.index("hint") < completion_order.index("batch")
