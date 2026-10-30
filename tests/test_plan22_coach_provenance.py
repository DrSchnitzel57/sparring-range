"""Plan 22 LIVE-10 + retained F5: coaching provenance and canonical
citations.

F5: a citation is approved only against the canonical ids of events the
rendered evidence ACTUALLY shows. A command payload reading
``echo reference #99999999`` may mention any id it likes — a regex over
the rendered text must not launder it into the approved set (chat prompt
allow-list and the AAR narrative validator both consume the compressor's
own accounting now).

LIVE-10: before any red run exists there is NO attacker activity — a
READY session's commands are operator/member setup or background
telemetry. The prompt now carries phase/run state and per-line actor
classes (RED (agent) / MEMBER <user> via bastion / AUDITD unattributed),
member names survive compression, unknown attribution stays unknown, and
user corrections are acknowledged, not argued with.
"""
from __future__ import annotations

import pytest

from srplatform.coach.aar import validate_narrative
from srplatform.coach.chat import build_chat_prompt, validated_citations
from srplatform.coach.timeline import compress_timeline, session_context_note


def ev(eid, actor, kind, host=None, payload=None, phase=None):
    return {"event_id": eid, "ts": "2026-10-24T10:%02d:00+00:00" % (eid % 60),
            "actor": actor, "action_type": kind, "host": host,
            "payload": payload or {}, **({"phase": phase} if phase else {})}


FORGER = ev(10, "red", "tool_call", "web01",
            {"command": "echo reference #99999999"}, phase="recon")
REAL = ev(11, "system", "verifier", "web01",
          {"objective": "foothold", "passed": True})
SETUP = ev(12, "blue:amy", "command", "web01", {"command": "whoami"})


# ------------------------------------------------------------------ F5 -----
def test_shown_ids_are_canonical_never_payload_text():
    text, idx = compress_timeline([FORGER, REAL, SETUP])
    assert idx["shown_ids"] == [10, 11, 12]
    assert "#99999999" in text            # the forged token IS visible...
    assert 99999999 not in idx["shown_ids"]   # ...and is still not citable


def test_chat_allow_list_and_validation_reject_the_forgery():
    _sys, _user, _cut, allowed = build_chat_prompt([FORGER, REAL, SETUP], [], "q?")
    assert allowed == [10, 11, 12]
    # an answer citing both the real and the forged id keeps ONLY the real one
    assert validated_citations("see #99999999 and also #11", allowed) == [11]


def test_aar_narrative_forged_citation_dropped_real_kept():
    _text, idx = compress_timeline([FORGER, REAL, SETUP])
    valid = set(idx["shown_ids"])
    out = validate_narrative(
        "Solid response at #11. The recon at #99999999 was clever. Keep it up.",
        valid)
    assert "#11" in out and "#99999999" not in out


# ------------------------------------------ compressed-away citations ----- #
def _many(n):
    return [ev(i, "red", "tool_call", "web01", {"command": f"step {i}"},
               phase="recon") for i in range(1, n + 1)]


def test_trimmed_events_leave_the_chat_allow_list_and_the_prompt():
    """Plan 22 review: 60 events render as the LAST 40 lines. The FIRST
    twenty are compressed away — an allow-list that accumulated ids at
    emit time still counted them citable, so 'Evidence #1' validated even
    though the model was never shown event #1. The allowed set now comes
    from the exact final render: #1 is absent from BOTH the prompt and
    the allow-list; the visible head line (#21) is in both."""
    events = _many(60)
    text, idx = compress_timeline(events, max_lines=40)
    assert len(text.splitlines()) == 40
    assert idx["shown_ids"] == list(range(21, 61))
    assert "#1]" not in text and "#20]" not in text and "#21]" in text
    _sys, user, _c, allowed = build_chat_prompt(events, [], "q?",)
    assert allowed == list(range(21, 61))
    assert "#1]" not in user and "#21]" in user
    # an answer citing the trimmed-away first event is rejected exactly
    # like a forged one; a visible citation survives
    assert validated_citations("Evidence #1 explains it", allowed) == []
    assert validated_citations("Evidence #21 explains it", allowed) == [21]


def test_trimmed_events_leave_the_aar_narrative_allow_list():
    """Same rule on the AAR surface: with 100 events (render keeps 80),
    the narrative may cite what the report shows, and the compressed-
    away #1 citation is dropped from the persisted narrative just like a
    foreign id — the report text carries no #1 citation either."""
    from srplatform.coach.aar import build_aar
    events = _many(100)
    report = build_aar(events, {"techniques": []}, None,
                       narrative="Early #1 mattered. Late #99 mattered. "
                                 "Foreign #99999999 did not.")
    doc = report["markdown"]
    assert "Early #1 mattered" not in doc       # trimmed away: dropped
    assert "Late #99 mattered" in doc           # shown: kept
    assert "#99999999" not in doc
    approved = report["approved_citation_ids"]
    assert 1 not in approved and 99 in approved and 20 not in approved


# --------------------------------------------------------------- LIVE-10 ---
def test_member_and_agent_lines_keep_distinct_provenance():
    text, _ = compress_timeline([FORGER, SETUP, ev(
        13, "blue:drew", "remediation", "web01", {"action": "killed cron"})])
    assert "RED (agent)" in text
    assert "MEMBER amy" in text and "not the red agent" in text
    assert "MEMBER drew REMEDIATION" in text
    assert "whoami" in text          # the username/content survived compression


def test_context_note_states_the_only_truth_about_red_activity():
    ready = session_context_note({"session_status": "ready"})
    assert "NO red run has started" in ready
    assert "not attacker reconnaissance" in ready
    running = session_context_note({"session_status": "running",
                                    "red_run_state": "running",
                                    "phase": "recon"})
    assert "red run state: running" in running and "phase recon" in running
    assert session_context_note(None) == ""


def test_chat_prompt_carries_context_and_correction_rules():
    _sys, user, _c, _a = build_chat_prompt([SETUP], [], "what is happening?",
                                           context={"session_status": "ready"})
    assert "NO red run has started" in user
    _sys2, user2, _c2, _a2 = build_chat_prompt([SETUP], [], "q?")
    assert "Session context:" not in user2         # nothing claimed without state
    for rule in ("CORRECTIONS", "acknowledge the correction", "unknown"):
        assert rule in _sys


# ------------------------------------------------------------- API (db) ----
def test_operator_coach_jobs_are_invisible_to_member_job_surfaces(client, users):
    """F7: the model-jobs LIST, DETAIL and stream previously ignored
    audience — a member enumerated the operator's coach work (state and
    timing). The audience captured at enqueue is now enforced at every
    member job surface; operators still see the whole picture."""
    from tests.test_plan19_model_admin import _make_profile
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    _make_profile(client, users, "coachf7", "http://x/v1")
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "coach", "profile_name": "coachf7"})
    assert r.status_code == 200, r.text
    jop = client.post(f"/sessions/{sid}/coach/messages",
                      json={"text": "operator turn"},
                      headers=users["op"]).json()["job_id"]
    jmem = client.post(f"/sessions/{sid}/coach/messages",
                       json={"text": "member turn"},
                       headers=users["member"]).json()["job_id"]
    listing = client.get(f"/sessions/{sid}/model-jobs",
                         headers=users["member"]).json()
    ids = [j["job_id"] for j in listing["jobs"]]
    assert jmem in ids and jop not in ids
    assert client.get(f"/sessions/{sid}/model-jobs/{jop}",
                      headers=users["member"]).status_code == 404
    assert client.get(f"/sessions/{sid}/model-jobs/{jmem}",
                      headers=users["member"]).status_code == 200
    assert client.get(f"/sessions/{sid}/model-jobs/{jop}/stream",
                      headers=users["member"]).status_code == 404
    oids = [j["job_id"] for j in client.get(
        f"/sessions/{sid}/model-jobs", headers=users["op"]).json()["jobs"]]
    assert jop in oids and jmem in oids


@pytest.mark.db
def test_unclassified_audience_fails_closed_on_every_member_surface(
        client, users):
    """Plan 22 review: denial of the EXPLICIT operator audience was
    positive only in name — a coach-chat job whose stored audience is
    MISSING or unknown (a row written by no current producer, a partially
    upgraded queue) enumerated, opened and streamed for a member with
    200. Members are now AUTHORIZED by the explicit member stamp; every
    other value fails closed — while operators keep recovery visibility
    over the same rows."""
    import uuid as _uuid

    from srplatform.db.models import ModelJob
    from srplatform.db.session import db as db_ctx

    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    variants = {
        "missing-meta": {},
        "missing-audience": {"chat_meta": {"asked_by": "someone"}},
        "audience-null": {"chat_meta": {"audience": None}},
        "audience-junk": {"chat_meta": {"audience": "operatorx"}},
    }
    ids = {}
    with db_ctx() as s:
        for name, payload in variants.items():
            j = ModelJob(session_id=_uuid.UUID(sid), kind="coach-chat",
                         priority=50,
                         payload={"text": f"x-{name}", **payload})
            s.add(j)
            s.flush()
            ids[name] = str(j.job_id)
        s.commit()
    listing = client.get(f"/sessions/{sid}/model-jobs",
                         headers=users["member"]).json()
    mids = [j["job_id"] for j in listing["jobs"]]
    for name, jid in ids.items():
        assert jid not in mids, f"unclassified {name} leaked into the list"
        assert client.get(f"/sessions/{sid}/model-jobs/{jid}",
                          headers=users["member"]).status_code == 404, name
        assert client.get(f"/sessions/{sid}/model-jobs/{jid}/stream",
                          headers=users["member"]).status_code == 404, name
        # operator recovery visibility: the row exists and is openable
        assert client.get(f"/sessions/{sid}/model-jobs/{jid}",
                          headers=users["op"]).status_code == 200, name
    oids = [j["job_id"] for j in client.get(
        f"/sessions/{sid}/model-jobs", headers=users["op"]).json()["jobs"]]
    assert all(j["job_id"] in oids for j in listing["jobs"])
    for jid in ids.values():
        assert jid in oids
