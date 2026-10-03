"""M5 acceptance tests — Part 5/M5 'Accept when':

  * `report <session>` emits a graded AAR that cites specific logged events
    with timestamps ("Sysmon flagged the new service at 14:02 — you never
    investigated it")
  * hint returns a context-aware Socratic hint mid-session without stalling
    the red loop (priority queue: hints jump ahead of batch work)
"""
import time

import pytest
from fastapi.testclient import TestClient

from srplatform.api.app import app
from srplatform.api.coach_routes import set_coach_llm
from srplatform.coach.queue import coach_queue

TS = "2026-10-03T14:02:00+00:00"  # the plan's example moment


@pytest.fixture()
def seeded_session(migrated_db):
    c = TestClient(app)
    sid = c.post("/sessions", json={"scenario_id": "web-foothold-01"}).json()["session_id"]
    evs = [
        # red installed a persistence service at 14:02 — verifier confirmed it
        {"session_id": sid, "ts": TS, "actor": "red", "host": "web01", "action_type": "tool_call",
         "phase": "persistence", "payload": {"command": "systemctl enable backup-updater"}},
        {"session_id": sid, "ts": TS, "actor": "system", "host": "web01", "action_type": "verifier",
         "payload": {"objective": "persistence", "verifier": "service_present", "passed": True,
                     "evidence": {"service": "backup-updater"}}, "mitre_technique": "T1543.002"},
        # defender did nothing after — this must surface as a MISS
    ]
    for e in evs:
        assert c.post("/events", json=e).status_code == 201
    yield c, sid
    set_coach_llm(None)


def test_m5_report_cites_timestamped_events(seeded_session):
    c, sid = seeded_session
    # scorecard recorded by `rangectl score` (a verifier event with scorecard payload)
    c.post("/events", json={"session_id": sid, "ts": "2026-10-03T14:30:00+00:00", "actor": "system",
                            "action_type": "verifier",
                            "payload": {"scorecard": {"earned": 5, "total": 15}}})
    set_coach_llm(False)  # deterministic report path (no GPU needed)

    r = c.post(f"/sessions/{sid}/aar", json={"narrative": True})
    assert r.status_code == 200, r.text
    aar = r.json()
    md = aar["markdown"]
    assert "Grade" in md and aar["grade"] in "ABCDF"
    # THE acceptance line: cites the specific logged event with its timestamp
    assert "14:02" in md, "AAR must cite event timestamps"
    assert "never investigated" in md
    assert aar["cited_events"], "AAR must cite event ids"
    assert "T1543" in md or "T1190" in md  # MITRE mapping present
    assert "CSF" in md or "DE —" in md     # NIST CSF mapping present
    assert "study" in md.lower()


def test_m5_hint_is_context_aware(seeded_session):
    c, sid = seeded_session

    class FakeCoach:
        def __init__(self): self.prompts = []
        def complete(self, system, user):
            self.prompts.append((system, user))
            return "You saw a service change at 14:02 — what does an enable-only change suggest, and which log line proves the binary?"

    coach = FakeCoach()
    set_coach_llm(coach)
    r = c.post(f"/sessions/{sid}/hint", json={"question": "what should I look at?"})
    assert r.status_code == 200, r.text
    # context-aware: the coach prompt contains the real timeline (14:02 event)
    assert any("14:02" in u for (_, u) in coach.prompts)
    assert "14:02" in r.json()["hint"]
    # hint itself is logged (the log is the product)
    logged = c.get("/events", params={"session_id": sid}).json()
    assert any(e["action_type"] == "hint" for e in logged)


def test_m5_hint_jumps_the_queue_ahead_of_batch_work():
    """Interactive hints never starve behind the red agent's/AAR's long batch
    calls on the single GPU slot (Part 6.5)."""
    def slow(name, secs):
        time.sleep(secs)
        return name

    b1 = coach_queue.submit(9, "aar-batch-1", slow, "b1", 0.35)
    b2 = coach_queue.submit(9, "aar-batch-2", slow, "b2", 0.35)
    time.sleep(0.05)  # let b1 start the job
    hint = coach_queue.submit(0, "hint", slow, "hint", 0.02)

    hint.result(timeout=5)          # hint returns while batch work is mid-flight
    assert not b2.done(), "hint must not queue behind batch work"
    assert b1.result(timeout=5) and b2.result(timeout=5)
