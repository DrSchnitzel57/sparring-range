"""Plan 19 REVIEW ROUND — the behaviors the independent review proved
absent, each reproduced here over the REAL wire / REAL database (never a
disconnected helper): durable multi-turn replay, obligations that hold
the admission slot across timeouts and restarts, credential
non-observability on every surface, whole-session pin freeze, async
submit/status, match deadlines reaching queued work, and run
finalization reaching model jobs.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from srplatform.db.models import (ConversationRevision, Event, MatchModel,
                                  ModelJob, ModelProfile, Run,
                                  SessionModelPin)
from srplatform.db.session import db as db_ctx
from tests.fake_model import (FakeModelServer, text_response, tool_call,
                              tool_response)
from tests.test_plan19_model_admin import (_make_profile,
                                           _mint_runner_token, _wait_job)

pytestmark = pytest.mark.agent


@pytest.fixture()
def srv():
    s = FakeModelServer().start()
    try:
        yield s
    finally:
        s.stop()


def _worker_h(token) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _session(client, users):
    sid = uuid.UUID(client.post("/sessions", headers=users["member"],
                                json={"scenario_id": "web-foothold-01"}
                                ).json()["session_id"])
    return sid, _mint_runner_token(sid)


# --------------------------------------------------------------------------- #
# finding 1: the wire AND the ledger keep the full conversation                #
# --------------------------------------------------------------------------- #

def test_three_turn_thread_replays_system_and_tool_returns_on_wire(
        client, users, srv):
    """≥3 turns over real HTTP: the permanent system framing appears
    EXACTLY ONCE and only as system; every tool call is answered by its
    tool return; nothing the wire saw is missing from the ledger and
    vice versa."""
    _make_profile(client, users, "thread", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "thread"})
    sid, token = _session(client, users)
    H = _worker_h(token)

    srv.script([tool_response([tool_call("a1", "range_command",
                                         {"command": "id"})]),
                tool_response([tool_call("a2", "range_command",
                                         {"command": "ls"})]),
                text_response("done — two actions observed")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "RULES", "user": "start"})
    assert r.status_code == 200, r.text
    for call_id, out in (("a1", "uid=1"), ("a2", "filelist")):
        r = client.post("/internal/model/turn", headers=H, json={
            "system": "RULES", "user": "next",
            "tool_result": {"call_id": call_id, "exit_code": 0,
                            "output": out, "timed_out": False,
                            "error": None}})
        assert r.status_code == 200, r.text
    assert r.json()["text"].startswith("done")

    bodies = srv.request_bodies()
    assert len(bodies) == 3
    # turn 2 and 3: system persisted + replayed; tool returns ride as
    # structured tool messages keyed to the CALL IDS THAT WERE ASKED
    for n, body in enumerate(bodies[1:], start=2):
        msgs = body["messages"]
        systems = [m for m in msgs if m["role"] == "system"]
        assert len(systems) == 1 and systems[0]["content"] == "RULES", \
            f"turn {n}: permanent framing must be exactly one system msg"
    tools3 = [m for m in bodies[2]["messages"] if m["role"] == "tool"]
    assert {m["tool_call_id"] for m in tools3} == {"a1", "a2"}
    # ledger/wire agreement: 3 turns × (input + response) rows
    with db_ctx() as s:
        revs = s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid,
            ConversationRevision.kind == "messages")).scalars().all()
        assert len(revs) == 6


# --------------------------------------------------------------------------- #
# finding 2: uncertain cessation is an OBLIGATION (timeout + restart)          #
# --------------------------------------------------------------------------- #

def test_timeout_holds_the_slot_and_never_admits_a_second_request(
        client, users, srv):
    """The review's core reproduction: the CLIENT timeout used to release
    the slot while the provider was still generating. Now the timeout is
    an UNCERTAIN cessation that HOLDS the queue until resolved, and the
    provider never saw two live requests."""
    from srplatform import model_jobs
    prof = _make_profile(client, users, "slowmo", srv.base_url, )
    with db_ctx() as s:  # short profile timeout: the wait itself times out
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        p.timeout_s = 1
    # per-item delay: only the FIRST response hangs (client timeout at 1s);
    # the post-resolution job must answer fast
    srv.script([dict(text_response("eventually"), _delay=1.4),
                text_response("second")])
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        first = model_jobs.enqueue(s, kind="text", priority=5,
                                   payload={"mode": "text", "system": "s",
                                            "user": "hangs"}, profile=p)
        fjid = first.job_id
    model_jobs.start_model_jobs()
    job = _wait_job(fjid, timeout_s=15.0)
    assert job.state == "cessation_unknown", job.state
    assert "timed out" in (job.error or "")
    # the obligation HOLDS THE SLOT: a new job queues but is never admitted
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        second = model_jobs.enqueue(s, kind="text", priority=5,
                                    payload={"mode": "text", "system": "s",
                                             "user": "must-wait"}, profile=p)
        sjid = second.job_id
    # let the provider-side generation finish (the handler thread is still
    # "generating" our closed request — exactly the dangerous window)
    time.sleep(1.8)
    with db_ctx() as s:
        assert s.get(ModelJob, sjid).state == "queued", \
            "a second provider request was admitted behind an unresolved "\
            "cessation obligation"
    assert srv.max_concurrent == 1
    # operator resolution releases the queue
    with db_ctx() as s:
        model_jobs.resolve_cessation(
            s, fjid, actor="operator",
            resolution="checked the endpoint: the closed request had "
                       "completed; output discarded")
    after = _wait_job(sjid, timeout_s=30.0)
    assert after.state == "succeeded", after.error
    assert srv.max_concurrent == 1, "provider saw concurrent requests"


def test_restart_reconcile_blocks_claims_until_resolved(client, users, srv,
                                                          monkeypatch):
    from srplatform import model_jobs
    prof = _make_profile(client, users, "restart", srv.base_url)
    with db_ctx() as s:
        j = model_jobs.enqueue(s, kind="text", priority=5, payload={})
        j.state = "running"
        jid = j.job_id
    with db_ctx() as s:
        assert model_jobs.reconcile_startup(s) == 1
    # the obligation is NOT just visible — it blocks admission
    srv.script([text_response("released")])
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        blocked = model_jobs.enqueue(s, kind="text", priority=5,
                                     payload={"mode": "text", "system": "s",
                                              "user": "post-restart"},
                                     profile=p)
        bid = blocked.job_id
    model_jobs.start_model_jobs()
    time.sleep(1.0)
    with db_ctx() as s:
        assert s.get(ModelJob, bid).state == "queued"
        assert s.get(ModelJob, jid).state == "cessation_unknown"
        model_jobs.resolve_cessation(s, jid, actor="operator",
                                     resolution="endpoint audited: no live "
                                                "request remained")
    done = _wait_job(bid, timeout_s=30.0)
    assert done.state == "succeeded", done.error


# --------------------------------------------------------------------------- #
# finding 3: the saved key never surfaces, even from a leaky 401               #
# --------------------------------------------------------------------------- #

def test_leaky_provider_401_never_shows_the_key_on_any_surface(
        client, users, srv):
    secret = "sk-synthetic-SECRET42-review"
    prof = _make_profile(client, users, "leaky", srv.base_url, key=secret)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "leaky"})
    sid, token = _session(client, users)
    H = _worker_h(token)
    # the fake 401 ECHOES the presented Authorization header (real-world
    # leaky-provider behavior): the redaction layer must survive that
    srv.script([{"_status": 401}], auth="Bearer WRONG")
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "go"})
    assert r.status_code == 502, r.text
    surfaces = {"worker 502 body": r.text}
    with db_ctx() as s:
        job = s.execute(select(ModelJob).where(
            ModelJob.session_id == sid,
            ModelJob.kind == "turn")).scalars().one()
        surfaces["job.error"] = job.error or ""
        assert job.state == "failed", \
            "401 is a DEFINITE failure: no obligation, no retry storm"
    r = client.get("/admin/model/jobs", headers=users["op"])
    surfaces["admin jobs"] = r.text
    r = client.get("/admin/model/profiles?all_versions=true",
                   headers=users["op"])
    surfaces["admin profiles"] = r.text
    r = client.get(f"/sessions/{sid}/model-jobs", headers=users["member"])
    surfaces["member jobs"] = r.text
    for where, text in surfaces.items():
        assert secret not in text, f"the saved key surfaced via {where}"
    # where a diagnostic IS shown, the redaction marker (or the neutral
    # credential wording) proves it went through the redactor
    for where in ("worker 502 body", "job.error", "admin jobs"):
        t = surfaces[where]
        assert "[REDACTED]" in t or "credential" in t, where
    # and exactly ONE provider request (401 must not be retried)
    assert len(srv.requests) == 1


# --------------------------------------------------------------------------- #
# finding 9: whole-session freeze at first use                                 #
# --------------------------------------------------------------------------- #

def test_first_use_pins_the_whole_role_set_and_later_overrides_are_ignored(
        client, users, srv):
    _make_profile(client, users, "froze", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "froze"})
    sid, token = _session(client, users)
    H = _worker_h(token)
    srv.script([text_response("one")])
    assert client.post("/internal/model/turn", headers=H,
                       json={"system": "s", "user": "go"}).status_code == 200
    with db_ctx() as s:
        pins = s.execute(select(SessionModelPin).where(
            SessionModelPin.session_id == sid)).scalars().all()
        assert {p.role for p in pins} == {"attacker", "coach", "summarizer"}, \
            "the first use of ANY role freezes ALL roles"
    # an operator override AFTER the session started must not move it
    _make_profile(client, users, "late", srv.base_url)
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "attacker", "profile_name": "late"})
    assert r.status_code == 200
    srv.script([text_response("two")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "again"})
    assert r.status_code == 200, r.text
    assert r.json()["profile"]["name"] == "froze", \
        "a post-start override changed a live session's model"


# --------------------------------------------------------------------------- #
# finding 11: async submit/status, match deadlines, finalization               #
# --------------------------------------------------------------------------- #

def test_async_turn_submit_and_status_follow_the_durable_job(
        client, users, srv):
    _make_profile(client, users, "async", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "async"})
    sid, token = _session(client, users)
    H = _worker_h(token)
    srv.script([dict(text_response("late answer"), _delay=0.4)])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "go", "wait": False})
    assert r.status_code == 202, r.text
    jid = r.json()["job_id"]
    # status is queryable by the owning worker while queued/running
    r = client.get(f"/internal/model/jobs/{jid}", headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] in ("queued", "running")
    # another session's worker cannot see it
    _sid2, token2 = _session(client, users)
    r = client.get(f"/internal/model/jobs/{jid}", headers=_worker_h(token2))
    assert r.status_code == 404
    # …and it lands with the answer
    done = _wait_job(uuid.UUID(jid), timeout_s=30.0)
    assert done.state == "succeeded", done.error
    r = client.get(f"/internal/model/jobs/{jid}", headers=H)
    assert r.json()["done"] is True
    assert r.json()["text"] == "late answer"


def test_match_deadline_caps_admission_and_kills_stale_queue_items(
        client, users, srv):
    """A match ending in 5 s must not accept a 900 s call — the SERVER's
    match row caps the job's deadline (a worker-supplied later deadline
    is ignored), and a queued job past its deadline is cancelled BEFORE
    dispatch, never after."""
    _make_profile(client, users, "deadline", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "deadline"})
    sid, token = _session(client, users)
    H = _worker_h(token)
    with db_ctx() as s:
        m = s.get(MatchModel, sid)   # created AT SESSION CREATION
        assert m is not None
        m.state = "running"
        m.started_at = datetime.now(timezone.utc)
        m.deadline_at = datetime.now(timezone.utc) + timedelta(seconds=5)
    srv.script([text_response("nowhere")])
    r = client.post("/internal/model/turn", headers=H, json={
        "system": "s", "user": "go", "wait": False,
        "deadline_at": (datetime.now(timezone.utc)
                        + timedelta(minutes=30)).isoformat()})
    assert r.status_code == 202, r.text
    jid = uuid.UUID(r.json()["job_id"])
    with db_ctx() as s:
        job = s.get(ModelJob, jid)
        left = (job.deadline_at - datetime.now(timezone.utc)).total_seconds()
        assert 0 < left < 6, \
            "the job deadline must be the SERVER's match end, not the " \
            "worker-supplied +30m"
    # now a job whose deadline has ALREADY passed: cancelled pre-dispatch
    from srplatform import model_jobs
    with db_ctx() as s:
        p = s.execute(select(ModelProfile).where(
            ModelProfile.name == "deadline",
            ModelProfile.status == "active")).scalar_one()
        stale = model_jobs.enqueue(
            s, kind="turn", priority=5,
            payload={"mode": "turn", "messages": []},
            session_id=sid, profile=p,
            deadline_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        stid = stale.job_id
    model_jobs.start_model_jobs()
    done = _wait_job(stid, timeout_s=10.0)
    assert done.state == "cancelled"
    # terminal BEFORE admission now (round-2 finding 8: expiry at
    # enqueue is caught at the ONE admission gate, not only at dispatch)
    assert "nothing was sent to the provider" in (done.error or "")
    assert not any("nowhere" in str(b) for b in srv.request_bodies())


def test_run_finalization_cancels_the_sessions_queued_model_work(
        client, users):
    """Match end/stop must REACH model work: nothing used to call cancel
    from run finalization, so a queued turn could start — or a live call
    could keep burning its timeout — after the match was gone."""
    from srplatform import model_jobs
    from srplatform.api import runs
    prof = _make_profile(client, users, "final", "http://127.0.0.1:9/v1")
    sid, token = _session(client, users)
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        q = model_jobs.enqueue(
            s, kind="text", priority=5,
            payload={"mode": "text", "system": "s", "user": "post-match"},
            session_id=sid, profile=p,
            run_at=datetime.now(timezone.utc) + timedelta(seconds=120))
        qid = q.job_id
    run_id = None
    with db_ctx() as s:
        run_id = s.execute(select(Run.run_id).where(
            Run.session_id == sid)).scalars().one()
    with db_ctx() as s:
        rc = runs.guarded_terminal_update(s, run_id, {"status": "cancelled"})
        assert rc == 1
    with db_ctx() as s:
        job = s.get(ModelJob, qid)
        assert job.state == "cancelled", job.state
        assert "run cancelled" in (job.error or "")


# --------------------------------------------------------------------------- #
# finding 11 (member surface) + async hint persistence                         #
# --------------------------------------------------------------------------- #

def test_async_hint_completes_after_the_request_and_persists_once(
        client, users, srv):
    """A member hint no longer has to survive the request: ``wait=false``
    queues it; the RESULT lands through the job's terminal transaction
    (reload-recoverable) — and the member job list shows state only,
    never sealed payloads."""
    _make_profile(client, users, "coachi", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "coach", "profile_name": "coachi"})
    sid = uuid.UUID(client.post("/sessions", headers=users["member"],
                                json={"scenario_id": "web-foothold-01"}
                                ).json()["session_id"])
    srv.script([dict(text_response("look at the DNS logs"), _delay=0.4)])
    r = client.post(f"/sessions/{sid}/hint", headers=users["member"],
                    json={"question": "where next?", "wait": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pending"] is True and body["hint"] is None
    jid = uuid.UUID(body["job_id"])
    r = client.get(f"/sessions/{sid}/model-jobs", headers=users["member"])
    mine = [j for j in r.json()["jobs"] if j["job_id"] == str(jid)]
    assert mine and mine[0]["state"] in ("queued", "running")
    # round-2 finding 4: the member async surface carries NO raw error
    # (provider diagnostics can echo sealed conversation content even
    # after secret redaction) — only the neutral classification.
    assert "result" not in mine[0] and "error" not in mine[0]
    assert mine[0]["error_kind"] is None
    done = _wait_job(jid, timeout_s=30.0)
    assert done.state == "succeeded", done.error
    with db_ctx() as s:
        hints = s.execute(select(Event).where(
            Event.session_id == sid,
            Event.action_type == "hint")).scalars().all()
        assert len(hints) == 1, "the hint must persist EXACTLY once"
        assert hints[0].payload["hint"] == "look at the DNS logs"
        assert hints[0].payload["model_ok"] is True
        assert hints[0].payload["model_job"] == str(jid)


# --------------------------------------------------------------------------- #
# finding 10: long answers survive the durable path end to end                 #
# --------------------------------------------------------------------------- #

def test_long_final_answer_survives_the_durable_turn(client, users, srv):
    _make_profile(client, users, "longans", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "longans"})
    sid, token = _session(client, users)
    H = _worker_h(token)
    answer = "report " + ("conclusion; " * 900)   # > 7000 chars
    srv.script([text_response(answer)])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "summarize"})
    assert r.status_code == 200, r.text
    assert r.json()["text"] == answer, "the answer was silently truncated"
    with db_ctx() as s:
        rev = s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid)
            .order_by(ConversationRevision.revision_id.desc())).scalars().first()
        assert "conclusion" in str(rev.payload)
