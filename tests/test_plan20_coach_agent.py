"""Plan 20 coach chat — the FULL loop against a (fake) model endpoint.

Durable-contract behaviors live in test_plan20_coach.py; here nothing is
stubbed between the API and the wire: a real HTTP provider (the pinned
FakeModelServer), the real scheduler, the real job, the real result
handler. Proven: a genuine answer persists verbatim with only the
citations its own evidence window allowed and the enqueue-time cutoff;
an empty/rejected completion persists the honest fallback, never an
invented hint; the conversation never mints scores or audit events.
"""
from __future__ import annotations

import uuid as U

import pytest
from sqlalchemy import select

from srplatform.db.models import CoachMessage, Event
from srplatform.db.session import db as db_ctx

from tests.fake_model import FakeModelServer, text_response
from tests.test_plan19_model_admin import _make_profile, _wait_job

pytestmark = pytest.mark.agent


@pytest.fixture()
def srv():
    s = FakeModelServer().start()
    try:
        yield s
    finally:
        s.stop()


def _setup(client, users, srv, name):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    _make_profile(client, users, name, srv.base_url)
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "coach", "profile_name": name})
    assert r.status_code == 200, r.text
    return sid


def test_real_coach_answer_persists_with_validated_citations(client, users,
                                                             srv):
    from srplatform import model_jobs
    sid = _setup(client, users, srv, "p20ok")
    from datetime import datetime, timezone
    with db_ctx() as s:
        ev = Event(session_id=U.UUID(sid), ts=datetime.now(timezone.utc),
                   actor="blue", action_type="note",
                   payload={"text": "web01 responded"})
        s.add(ev)
        s.commit()
        eid = ev.event_id

    srv.script([text_response(
        f"Look at what web01 answered (#{eid}); you could also run "
        "`ss -tlnp` yourself. Ignore #424242 and #1 — never given.")])
    r = client.post(f"/sessions/{sid}/coach/messages",
                    json={"text": "what did the web server do?"},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    jid = U.UUID(r.json()["job_id"])
    model_jobs.start_model_jobs()
    job = _wait_job(jid)
    assert job.state == "succeeded", job.error

    with db_ctx() as s:
        msgs = s.execute(select(CoachMessage)
                         .where(CoachMessage.session_id == U.UUID(sid))
                         .order_by(CoachMessage.message_id)
                         ).scalars().all()
    assert [m.role for m in msgs] == ["user", "coach"]
    coach = msgs[1]
    assert coach.model_ok is True
    assert coach.model_job == jid
    # the answer persists VERBATIM (prose is never rewritten)…
    assert f"#{eid}" in coach.body and "#424242" in coach.body
    # …but only citations its own window allowed are recorded
    assert coach.citations == [eid]
    assert coach.context_cutoff_event_id == eid

    # the provider call really happened, carried the hints-first system
    # prompt and the member's question
    req = srv.requests[0]
    assert "practice coach" in req["body"]["messages"][0]["content"]
    assert "what did the web server do?" in req["body"]["messages"][1]["content"]

    # the conversation stays out of audit and out of scoring
    with db_ctx() as s:
        kinds = [e.action_type for e in s.execute(
            select(Event).where(Event.session_id == U.UUID(sid))
        ).scalars().all()]
    assert "note" in kinds  # the seeded evidence, untouched
    assert not [k for k in kinds if "coach" in k or "score" in k]


def test_empty_completion_persists_honest_fallback_not_invention(client,
                                                                 users,
                                                                 srv):
    from srplatform import model_jobs
    sid = _setup(client, users, srv, "p20empty")
    srv.script([text_response("", finish="stop")])  # rejected: empty
    r = client.post(f"/sessions/{sid}/coach/messages",
                    json={"text": "give me a hint"},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    jid = U.UUID(r.json()["job_id"])
    model_jobs.start_model_jobs()
    job = _wait_job(jid)
    assert job.state == "failed", job.state

    with db_ctx() as s:
        msgs = s.execute(select(CoachMessage)
                         .where(CoachMessage.session_id == U.UUID(sid))
                         .order_by(CoachMessage.message_id)
                         ).scalars().all()
    assert [m.role for m in msgs] == ["user", "coach"]
    coach = msgs[1]
    assert coach.model_ok is False and coach.model_job == jid
    assert "nothing was invented" in coach.body  # honest fallback, verbatim
    assert coach.citations == []

    got = client.get(f"/sessions/{sid}/coach/messages",
                     headers=users["member"]).json()
    assert got["pending"] == []
