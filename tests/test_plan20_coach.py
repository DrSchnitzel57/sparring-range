"""Plan 20 conversational coach — durable exchange, cutoff, sealed safety.

The full loop with a live provider is pinned in the agent-layer suite;
this layer proves the DURABLE contract with the real API and database:
the member's message survives model absence, pending answers are
visible from the job row after reload, unavailable/failure records are
honest (never invented), the evidence cutoff and citation window are
captured at enqueue, sealed competition red payloads never enter the
coach prompt, and chat never touches verified points or the audit log.
"""
from __future__ import annotations

import uuid as U
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from srplatform.db.models import CoachMessage, Event

pytestmark = pytest.mark.db


def _sid(client, users, mode="practice"):
    return client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                          "mode": mode},
                       headers=users["member"]).json()["session_id"]


def _msgs(client, users, sid, **params):
    r = client.get(f"/sessions/{sid}/coach/messages", params=params,
                   headers=users["member"])
    assert r.status_code == 200, r.text
    return r.json()


def test_chat_without_model_keeps_message_and_records_honest_gap(client,
                                                                 users,
                                                                 monkeypatch):
    """When the coach profile cannot be bound, the member's words are
    kept and the gap is an honest recorded coach turn — never silence,
    never an invented hint."""
    from srplatform import model_admin as ma
    sid = _sid(client, users)

    def _down(db, session_id, role):
        raise ma.ProfileUnavailable("no active profile for role")
    monkeypatch.setattr(ma, "bind_for", _down)

    r = client.post(f"/sessions/{sid}/coach/messages",
                    json={"text": "where do i even start?"},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "coach-unavailable" and body["pending"] is False

    got = _msgs(client, users, sid)
    assert [m["role"] for m in got["messages"]] == ["user", "coach"]
    assert got["messages"][0]["body"] == "where do i even start?"
    coach = got["messages"][1]
    assert coach["model_ok"] is False and coach["citations"] == []
    assert "nothing was invented" in coach["body"]
    assert got["pending"] == []


def test_chat_pending_is_durable_and_failure_falls_back_honestly(
        client, users, monkeypatch):
    """With a profile bound, the answer is a durable job: the reload
    view lists it as PENDING from the job row (never lost), and when
    the model call ultimately fails the honest fallback is persisted —
    the conversation never just stops mid-answer silently. The full
    success loop against a real (fake-server) endpoint is pinned in the
    agent-layer suite; here the failure is forced deterministically so
    the contract is proven without waiting on retry backoff."""
    import time

    from srplatform.db.models import ModelJob
    from srplatform.db.session import db as db_ctx
    from srplatform.model_admin import ProfileUnavailable
    from srplatform.red_agent import conversation as conv
    from tests.test_plan19_model_admin import _make_profile

    def _boom(*a, **k):
        raise ProfileUnavailable("forced coach-model failure (test)")
    monkeypatch.setattr(conv, "run_text", _boom)

    sid = _sid(client, users)
    _make_profile(client, users, "coachchat", "http://x/v1")
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "coach", "profile_name": "coachchat"})
    assert r.status_code == 200, r.text

    r = client.post(f"/sessions/{sid}/coach/messages",
                    json={"text": "what should i check first?"},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "queued" and body["pending"] is True
    jid = U.UUID(body["job_id"])

    got = _msgs(client, users, sid)
    assert [m["role"] for m in got["messages"]] == ["user"]
    assert [p["job_id"] for p in got["pending"]] == [body["job_id"]]
    assert got["pending"][0]["state"] in ("queued", "running")

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with db_ctx() as s:
            state = s.get(ModelJob, jid).state
        if state in ("succeeded", "failed", "cancelled",
                     "cessation_unknown", "cessation_resolved"):
            break
        time.sleep(0.05)
    else:
        pytest.fail("coach-chat job never reached a terminal state")
    assert state == "failed"

    got = _msgs(client, users, sid)
    assert got["pending"] == []
    assert [m["role"] for m in got["messages"]] == ["user", "coach"]
    coach = got["messages"][-1]
    assert coach["model_ok"] is False
    assert coach["model_job"] == body["job_id"]
    assert "nothing was invented" in coach["body"]  # honest fallback text


def test_chat_prompt_cutoff_and_window(client, users, monkeypatch):
    """The evidence base is captured AT ENQUEUE: the cutoff is the last
    visible event id, the citation ids are exactly the window's events,
    and later events cannot ride an already-queued answer."""
    from tests.test_plan19_model_admin import _make_profile
    sid = _sid(client, users)
    _make_profile(client, users, "coachwin", "http://x/v1")
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "coach", "profile_name": "coachwin"})

    from srplatform.db.models import Event
    from srplatform.db.session import db as db_ctx
    now = datetime.now(timezone.utc)
    with db_ctx() as s:
        s.add(Event(session_id=U.UUID(sid), ts=now, actor="blue",
                    action_type="note", payload={"text": "baseline"}))
        s.commit()

    captured = {}
    from srplatform import model_jobs

    real_enqueue = model_jobs.enqueue

    def _spy(db, **kw):
        captured["payload"] = kw.get("payload")
        return real_enqueue(db, **kw)
    monkeypatch.setattr(model_jobs, "enqueue", _spy)

    r = client.post(f"/sessions/{sid}/coach/messages",
                    json={"text": "anything new?"}, headers=users["member"])
    assert r.status_code == 201, r.text
    payload = captured["payload"]
    meta = payload["chat_meta"]

    with db_ctx() as s:
        all_ids = [e.event_id for e in s.execute(
            select(Event).where(Event.session_id == U.UUID(sid))
            .order_by(Event.event_id)).scalars().all()]
    assert meta["cutoff"] == max(all_ids)
    assert set(meta["allowed_ids"]) <= set(all_ids)

    # the frozen citation window is the invariant: a NEW event after
    # enqueue cannot ride an already-queued answer (and the prompt was
    # generated from the pre-enqueue snapshot — the timeline renderer
    # deliberately does not echo raw payloads)
    with db_ctx() as s:
        s.add(Event(session_id=U.UUID(sid), ts=datetime.now(timezone.utc),
                    actor="blue", action_type="note",
                    payload={"text": "after cutoff"}))
        s.commit()
        late_ids = [e.event_id for e in s.execute(
            select(Event).where(Event.session_id == U.UUID(sid))
            .order_by(Event.event_id)).scalars().all()]
    assert set(meta["allowed_ids"]) == set(all_ids)
    assert set(late_ids) - set(all_ids)          # proof there IS a later id
    assert (set(late_ids) - set(all_ids)).isdisjoint(meta["allowed_ids"])


def test_sealed_red_evidence_never_reaches_the_coach_prompt(client, users,
                                                            monkeypatch):
    """Competition visibility is enforced at the coach boundary BEFORE
    the model: the prompt the member's own coach receives contains no
    sealed red payload text — chat cannot launder sealed attack
    internals back through citations, memory or answers."""
    from tests.test_plan19_model_admin import _make_profile
    sid = _sid(client, users, mode="competition")
    _make_profile(client, users, "coachsealed", "http://x/v1")
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "coach", "profile_name": "coachsealed"})
    from srplatform.db.models import AgentState, Event
    from srplatform.db.session import db as db_ctx
    now = datetime.now(timezone.utc)
    with db_ctx() as s:
        s.add_all([
            Event(session_id=U.UUID(sid), ts=now, actor="red",
                  host="web01", action_type="tool_call",
                  payload={"tool": "ssh-exec", "cmd": "cat /root/SEALCMD"}),
            Event(session_id=U.UUID(sid), ts=now, actor="system",
                  action_type="detection",
                  payload={"objective": "foothold", "passed": True}),
        ])
        s.add(AgentState(session_id=U.UUID(sid),
                         summary="SEALEDPLAN privesc", current_phase="p"))
        s.commit()

    captured = {}
    from srplatform import model_jobs
    real_enqueue = model_jobs.enqueue

    def _spy(db, **kw):
        captured["payload"] = kw.get("payload")
        return real_enqueue(db, **kw)
    monkeypatch.setattr(model_jobs, "enqueue", _spy)

    r = client.post(f"/sessions/{sid}/coach/messages",
                    json={"text": "how are we doing?"},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    prompt = captured["payload"]["user"] + captured["payload"]["system"]
    assert "SEALEDPLAN" not in prompt and "SEALCMD" not in prompt

    # the member can still converse; their own conversation is their own
    got = _msgs(client, users, sid)
    assert got["sealed"] is True and got["pending"]


def test_chat_never_awards_or_touches_evidence(client, users):
    sid = _sid(client, users)
    for text in ("hint please", "explain the service state"):
        client.post(f"/sessions/{sid}/coach/messages", json={"text": text},
                    headers=users["member"])
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        kinds = [e.action_type for e in s.execute(
            select(Event).where(Event.session_id == U.UUID(sid))
        ).scalars().all()]
    assert "score_snapshot" not in kinds and "verifier" not in kinds
    assert "coach_chat" not in kinds  # chat is chat, not audit


def test_chat_pagination_and_append_only_corrections(client, users):
    from srplatform.db.models import CoachMessage
    from srplatform.db.session import db as db_ctx
    sid = _sid(client, users)
    with db_ctx() as s:
        for i in range(5):
            s.add(CoachMessage(session_id=U.UUID(sid), role="user",
                               body=f"m{i}"))
        s.commit()

    got = _msgs(client, users, sid, limit=2)
    assert [m["body"] for m in got["messages"]] == ["m3", "m4"]
    got = _msgs(client, users, sid, after_id=got["messages"][0]["message_id"])
    assert [m["body"] for m in got["messages"]] == ["m4"]
    first = _msgs(client, users, sid)["messages"][0]["message_id"]
    got = _msgs(client, users, sid, before_id=first)
    assert got["messages"] == []

    # corrections append: an identical resend is kept (append-only),
    # never deduplicated or rewritten in place
    with db_ctx() as s:
        s.add(CoachMessage(session_id=U.UUID(sid), role="user", body="m4"))
        s.commit()
    got = _msgs(client, users, sid)
    assert [m["body"] for m in got["messages"]].count("m4") == 2


def test_chat_requires_session_access(client, users):
    sid = _sid(client, users)
    # operator may read; member (owner) may read; the token without a
    # session is rejected by auth first
    r = client.get(f"/sessions/{sid}/coach/messages", headers=users["op"])
    assert r.status_code == 200
    r = client.get(f"/sessions/{U.uuid4()}/coach/messages",
                   headers=users["member"])
    assert r.status_code == 404
    r = client.post(f"/sessions/{U.uuid4()}/coach/messages",
                    json={"text": "x"}, headers=users["member"])
    assert r.status_code == 404


def test_validated_citations_only_allow_given_evidence():
    from srplatform.coach import chat
    assert chat.validated_citations("see #7 then #9", [7, 8]) == [7]
    assert chat.validated_citations("no refs", [7]) == []
    assert chat.validated_citations("#7", None) == []
    assert chat.validated_citations("#7 #7 #8", [7, 8]) == [7, 8]
