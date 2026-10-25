"""Plan 19 (db layer): versioned profiles, pins, the ONE durable admission
slot, cancellation obligations, visible retries, and the operator-only
model-admin surface.

The scripted OpenAI-compatible server (tests/fake_model.py) is the same
fixture as the fast conversation tests: provider-side facts — that calls
arrived SERIALLY, that a call's auth header carried the pinned key, that
a cancelled queued job never reached the wire — are proven against the
server itself, not against in-process counters.
"""
from __future__ import annotations

import hashlib
import time
import uuid

import pytest
from sqlalchemy import select

from srplatform.db.models import (ConversationRevision, ModelJob,
                                  ModelProfile, Run, SessionModelPin)
from srplatform.db.session import db as db_ctx
from tests.fake_model import (FakeModelServer, text_response, tool_call,
                              tool_response)

@pytest.fixture()
def srv():
    s = FakeModelServer().start()
    try:
        yield s
    finally:
        s.stop()


def _wait_job(job_id, timeout_s=30.0, state_terminal=True):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with db_ctx() as s:
            job = s.get(ModelJob, job_id)
            if job.state in ("succeeded", "failed", "cancelled",
                             "cessation_unknown"):
                return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} never reached a terminal state")


def _mint_runner_token(session_id) -> str:
    token = f"wk-{uuid.uuid4().hex}"
    with db_ctx() as s:
        s.add(Run(session_id=session_id, scenario_id="web-foothold-01",
                  status="running",
                  worker_token=hashlib.sha256(token.encode()).hexdigest()))
    return token


def _make_profile(client, users, name, base_url, *, key="sk-canary-9"):
    r = client.post("/admin/model/profiles", headers=users["op"], json={
        "name": name, "base_url": base_url, "model_name": "gpt-4o",
        "api_key": key, "max_completion_tokens": 512})
    assert r.status_code == 201, r.text
    return r.json()


# --------------------------------------------------------------------------- #
# admin surface: bootstrap, masking, lifecycle, authorization                  #
# --------------------------------------------------------------------------- #

def test_bootstrap_profiles_exist_and_no_read_path_leaks_a_key(client, users, srv):
    body = client.get("/admin/model/profiles", headers=users["op"])
    assert body.status_code == 200, body.text
    assert client.get("/readyz").json()["migration_version"] == "0020"
    data = body.json()
    names = {p["name"] for p in data["profiles"]}
    assert {"environment-red", "environment-coach"} <= names
    assert data["roles"] == {"attacker": "environment-red",
                             "coach": "environment-coach",
                             "summarizer": "environment-red"}
    prof = _make_profile(client, users, "canary", srv.base_url)
    assert prof["api_key_set"] is True
    assert "sk-canary-9" not in prof_base_str(prof)
    for path in ("/admin/model/profiles?all_versions=true",
                 "/admin/model/jobs"):
        r = client.get(path, headers=users["op"])
        assert r.status_code == 200
        assert "sk-canary-9" not in r.text, f"key leaked via {path}"
    # the credential IS stored (only) in the profile row
    with db_ctx() as s:
        row = s.execute(select(ModelProfile).where(
            ModelProfile.name == "canary")).scalar_one()
        assert row.api_key == "sk-canary-9"


def prof_base_str(d) -> str:
    import json
    return json.dumps(d)


def test_rotation_creates_version_demotes_old_and_revocation_is_final(
        client, users):
    _make_profile(client, users, "rot", "http://127.0.0.1:9/v1", key="k1")
    r = client.post("/admin/model/profiles/rot/revise", headers=users["op"],
                    json={"name": "rot", "model_name": "gpt-4o-turbo",
                          "api_key": "k2"})
    assert r.status_code == 200, r.text
    v2 = r.json()
    assert v2["version"] == 2
    active = [p for p in client.get("/admin/model/profiles",
                                    headers=users["op"]).json()["profiles"]
              if p["name"] == "rot"]
    assert [p["version"] for p in active] == [2], "exactly one ACTIVE version"
    allv = client.get("/admin/model/profiles?all_versions=true",
                      headers=users["op"]).json()["profiles"]
    v1 = next(p for p in allv if p["name"] == "rot" and p["version"] == 1)
    assert v1["status"] == "retired"
    # revoking a RETIRED version is terminal
    r = client.post(f"/admin/model/profiles/{v1['profile_id']}/revoke",
                    headers=users["op"], json={"reason": "compromised"})
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"
    # the ACTIVE version is untouched by that revocation: rotation continues
    r = client.post("/admin/model/profiles/rot/revise", headers=users["op"],
                    json={"name": "rot", "model_name": "x"})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 3


def test_admin_is_operator_only(client, users):
    assert client.get("/admin/model/profiles",
                      headers=users["member"]).status_code == 403
    assert client.post("/admin/model/profiles", headers=users["member"],
                       json={"name": "x", "base_url": "http://x/v1",
                             "model_name": "m"}).status_code == 403
    r = client.put("/admin/model/roles", headers=users["member"],
                   json={"role": "attacker", "profile_name": "x"})
    assert r.status_code == 403


def test_role_override_requires_an_active_profile(client, users):
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "attacker", "profile_name": "ghost"})
    assert r.status_code == 422
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "bogus", "profile_name": "environment-red"})
    assert r.status_code == 422


def test_generation_kwargs_allowlist_rejects_envelope_control(client, users):
    for bad in ({"messages": []}, {"tools": []}, {"api_key": "x"},
                {"model": "swap"}, {"temperature": 99}, {"stream": True}):
        r = client.post("/admin/model/profiles", headers=users["op"],
                        json={"name": "kw", "base_url": "http://127.0.0.1:9/v1",
                              "model_name": "m", "generation_kwargs": bad})
        assert r.status_code == 422, f"{bad} accepted"


# --------------------------------------------------------------------------- #
# the durable slot + jobs                                                      #
# --------------------------------------------------------------------------- #

def test_single_running_is_enforced_by_the_database(client, users, monkeypatch):
    from sqlalchemy.exc import IntegrityError
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "start_model_jobs", lambda: None)
    with db_ctx() as s:
        j1 = model_jobs.enqueue(s, kind="text", priority=5, payload={})
        j2 = model_jobs.enqueue(s, kind="text", priority=5, payload={})
        j1.state = "running"
        s.flush()
        with pytest.raises(IntegrityError):
            j2.state = "running"
            s.flush()
        s.rollback()   # the violating rows never existed: the TEST is clean
    # and the scheduler must refuse to claim while one is genuinely running
    with db_ctx() as s:
        j1 = model_jobs.enqueue(s, kind="text", priority=5, payload={})
        j1.state = "running"
        jid = j1.job_id
    try:
        sched = model_jobs.ModelJobScheduler()
        assert sched._claim() is None
    finally:
        with db_ctx() as s:
            job = s.get(ModelJob, jid)
            job.state = "cancelled"
            job.error = "test teardown"


def test_claim_order_is_priority_then_fifo(client, users, monkeypatch):
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "start_model_jobs", lambda: None)
    sched = model_jobs.ModelJobScheduler()
    ids = {}
    with db_ctx() as s:
        ids["aar"] = model_jobs.enqueue(s, kind="text",
                                        priority=model_jobs.PRIORITY_AAR,
                                        payload={}).job_id
        ids["red1"] = model_jobs.enqueue(s, kind="text",
                                         priority=model_jobs.PRIORITY_RED,
                                         payload={}).job_id
        ids["red2"] = model_jobs.enqueue(s, kind="text",
                                         priority=model_jobs.PRIORITY_RED,
                                         payload={}).job_id
        ids["hint"] = model_jobs.enqueue(s, kind="text",
                                         priority=model_jobs.PRIORITY_HINT,
                                         payload={}).job_id
    order = []
    by_id = {str(v): k for k, v in ids.items()}
    for _ in range(4):
        with db_ctx() as s:
            running = s.execute(select(ModelJob).where(
                ModelJob.state == "running")).scalars().all()
            for j in running:      # release the slot between claims
                j.state = "succeeded"
                j.finished_at = j.requested_at
        claimed = sched._claim()
        if claimed is None:
            break
        order.append(by_id[str(claimed)])
    assert order == ["hint", "red1", "red2", "aar"]


def test_scheduler_serializes_live_calls_at_the_provider(client, users, srv):
    from srplatform import model_jobs
    prof = _make_profile(client, users, "serial", srv.base_url)
    srv.script([text_response(f"t{i}") for i in range(4)], hang_s=0.3)
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        for i in range(4):
            model_jobs.enqueue(s, kind="text", priority=5,
                               payload={"mode": "text", "system": "s",
                                        "user": f"u{i}"},
                               profile=p)
    model_jobs.start_model_jobs()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with db_ctx() as s:
            n = s.execute(select(ModelJob).where(
                ModelJob.state == "succeeded")).scalars().all()
            if len(n) == 4:
                break
        time.sleep(0.1)
    else:
        pytest.fail("jobs did not complete")
    assert srv.max_concurrent == 1, (
        f"provider saw {srv.max_concurrent} concurrent requests — the ONE "
        "slot must serialize at the server, not just in our counters")
    assert len(srv.requests) == 4


def test_key_reaches_only_the_auth_header(client, users, srv):
    from srplatform import model_admin as ma
    from srplatform import model_jobs
    prof = _make_profile(client, users, "auth", srv.base_url, key="sk-abc123")
    srv.script([text_response("pong")])
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        job = model_jobs.enqueue(s, kind="text", priority=5,
                                 payload={"mode": "text", "system": "s",
                                          "user": "u"}, profile=p)
        jid = job.job_id
    model_jobs.start_model_jobs()
    job = _wait_job(jid)
    assert job.state == "succeeded", job.error
    assert srv.requests[0]["auth"] == "Bearer sk-abc123"
    assert "sk-abc123" not in str(srv.requests[0]["body"])
    assert "sk-abc123" not in str(job.result)


def test_cancellation_of_queued_never_dispatches_and_running_awaits_return(
        client, users, srv):
    from srplatform import model_jobs
    prof = _make_profile(client, users, "cancel", srv.base_url)
    srv.script([text_response("slow1"), text_response("slow2")], hang_s=0.6)
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        running = model_jobs.enqueue(s, kind="text", priority=5,
                                     payload={"mode": "text", "system": "s",
                                              "user": "slow"}, profile=p)
        queued = model_jobs.enqueue(s, kind="text", priority=5,
                                    payload={"mode": "text", "system": "s",
                                             "user": "never"}, profile=p)
        rid, qid = running.job_id, queued.job_id
    model_jobs.start_model_jobs()
    # wait until the first is genuinely running
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        with db_ctx() as s:
            if s.get(ModelJob, rid).state == "running":
                break
        time.sleep(0.02)
    with db_ctx() as s:
        model_jobs.cancel(s, qid, actor="test")          # queued → cancelled
    # cancel the LIVE one: cessation is only confirmed when it returns
    t0 = time.monotonic()
    with db_ctx() as s:
        j = model_jobs.cancel(s, rid, actor="test")
        assert j.state == "running" and j.cancel_requested is True
    done = _wait_job(rid)
    assert done.state == "cancelled"
    assert "discarded" in (done.error or "") or "returned" in (done.error or "")
    assert time.monotonic() - t0 >= 0.2, (
        "the slot released before the live call returned — cancellation "
        "pretended to preempt")
    # the queued job's payload never reached the provider
    users_seen = [b["messages"][-1]["content"] for b in srv.request_bodies()]
    assert not any("never" in str(u) for u in users_seen)
    with db_ctx() as s:
        assert s.get(ModelJob, qid).state == "cancelled"


def test_restart_leaves_cessation_unknown_never_replayed(client, users,
                                                          monkeypatch):
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "start_model_jobs", lambda: None)
    with db_ctx() as s:
        j = model_jobs.enqueue(s, kind="text", priority=5, payload={})
        j.state = "running"
        jid = j.job_id
    with db_ctx() as s:
        assert model_jobs.reconcile_startup(s) == 1
    with db_ctx() as s:
        job = s.get(ModelJob, jid)
        assert job.state == "cessation_unknown"
        assert "never replayed" in (job.error or "")


def test_retry_is_bounded_new_visible_rows(client, users, srv, monkeypatch):
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "RETRY_DELAYS", (0.05, 0.05))
    prof = _make_profile(client, users, "retry", srv.base_url)
    srv.script([{"index": 0, "message": {"role": "assistant", "content": None},
                 "finish_reason": "stop", "_status": 500},
                text_response("eventually")])
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        job = model_jobs.enqueue(s, kind="text", priority=5,
                                 payload={"mode": "text", "system": "s",
                                          "user": "u"}, profile=p)
        jid = job.job_id
    model_jobs.start_model_jobs()
    first = _wait_job(jid)
    assert first.state == "failed"
    assert "retry attempt 2" in (first.error or "")
    with db_ctx() as s:
        child = s.execute(select(ModelJob).where(
            ModelJob.parent_job == jid)).scalars().one()
        cid = child.job_id
        assert child.attempt == 2
    second = _wait_job(cid)
    assert second.state == "succeeded", second.error
    assert second.result["text"] == "eventually"


def test_rejected_completion_is_not_retried(client, users, srv):
    from srplatform import model_jobs
    prof = _make_profile(client, users, "noretry", srv.base_url)
    srv.script([text_response("", finish="stop")])   # empty → rejected
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        job = model_jobs.enqueue(s, kind="text", priority=5,
                                 payload={"mode": "text", "system": "s",
                                          "user": "u"}, profile=p)
        jid = job.job_id
    model_jobs.start_model_jobs()
    job = _wait_job(jid)
    assert job.state == "failed"
    assert "retry" not in (job.error or "")
    with db_ctx() as s:
        assert s.execute(select(ModelJob).where(
            ModelJob.parent_job == jid)).scalars().all() == []
    assert len(srv.requests) == 1, "non-retryable rejection must not re-hit"


# --------------------------------------------------------------------------- #
# turn route: durable conversation + pins + rotation behavior                  #
# --------------------------------------------------------------------------- #

def _session_and_token(client, users):
    sid = uuid.UUID(client.post("/sessions", headers=users["member"],
                                json={"scenario_id": "web-foothold-01"}
                                ).json()["session_id"])
    token = _mint_runner_token(sid)
    return sid, token


def test_turn_runs_on_pinned_profile_and_persists_structured_history(
        client, users, srv):
    prof = _make_profile(client, users, "turner", srv.base_url)
    r = client.put("/admin/model/roles", headers=users["op"],
                   json={"role": "attacker", "profile_name": "turner"})
    assert r.status_code == 200, r.text
    sid, token = _session_and_token(client, users)
    H = {"Authorization": f"Bearer {token}"}

    srv.script([tool_response([tool_call("c1", "range_command",
                                         {"command": "id", "thought": "who"})],
                              usage={"prompt_tokens": 12,
                                     "completion_tokens": 3,
                                     "total_tokens": 15})])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "SYS", "user": "go"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "tool_call"
    assert body["tool_call"]["command"] == "id"
    assert body["profile"] == {"name": "turner", "version": 1}
    assert body["usage"]["total_tokens"] == 15
    # the attacker role is now PINNED to this exact version
    with db_ctx() as s:
        pin = s.execute(select(SessionModelPin).where(
            SessionModelPin.session_id == sid,
            SessionModelPin.role == "attacker")).scalar_one()
        assert str(pin.profile_id) == prof["profile_id"]
        assert pin.config["version"] == 1
        assert "api_key" not in str(pin.config)
        revs = s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid)
            .order_by(ConversationRevision.revision_id)).scalars().all()
        assert any(r_.kind == "messages" for r_ in revs)
        assert revs[-1].usage["total_tokens"] == 15
    # native tool crossed the wire; tool_result returns as a structured part
    assert srv.request_bodies()[0]["tools"][0]["function"]["name"] == \
        "range_command"
    srv.script([text_response("acted")])
    r = client.post("/internal/model/turn", headers=H, json={
        "system": "SYS", "user": "next action",
        "tool_result": {"call_id": "c1", "exit_code": 0, "output": "uid=0",
                        "timed_out": False, "error": None}})
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "text"
    msgs = srv.request_bodies()[1]["messages"]
    assert any(m["role"] == "tool" for m in msgs), \
        "tool return must ride as a structured tool message"
    # system framing rides only on the FIRST turn of the thread
    assert not any(m["role"] == "system" for m in msgs)


def test_rotation_invalidates_pinned_session_visibly_until_rebind(
        client, users, srv):
    prof = _make_profile(client, users, "rotturn", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "rotturn"})
    sid, token = _session_and_token(client, users)
    H = {"Authorization": f"Bearer {token}"}
    srv.script([text_response("first")])
    assert client.post("/internal/model/turn", headers=H,
                       json={"system": "s", "user": "go"}).status_code == 200
    # rotate the profile under the pinned session
    r = client.post("/admin/model/profiles/rotturn/revise", headers=users["op"],
                    json={"name": "rotturn", "model_name": "gpt-4o"})
    assert r.status_code == 200, r.text
    # the pinned session FAILS VISIBLY — never a silent substitute
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "again"})
    assert r.status_code == 503
    assert "rebind" in r.text
    # and no provider call was made for the refused turn
    assert len(srv.requests) == 1
    # explicit operator rebind restores service on the NEW version
    r = client.post(f"/admin/model/sessions/{sid}/rebind", headers=users["op"],
                    json={"role": "attacker"})
    assert r.status_code == 200, r.text
    assert r.json()["config"]["version"] == 2
    srv.script([text_response("after rebind")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "again"})
    assert r.status_code == 200, r.text
    assert r.json()["profile"]["version"] == 2
    # old conversation history survived rotation untouched (append-only)
    with db_ctx() as s:
        assert s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid)).scalars().all()


def test_hint_falls_back_truthfully_and_leaves_a_visible_failed_job(
        client, users):
    # no coach double injected: the production path queues a real job
    # against the bootstrap coach profile (the dev-default endpoint is
    # dead) — the hint must still answer honestly AND the failure must be
    # visible in the job list
    sid = uuid.UUID(client.post("/sessions", headers=users["member"],
                                json={"scenario_id": "web-foothold-01"}
                                ).json()["session_id"])
    r = client.post(f"/sessions/{sid}/hint", headers=users["member"],
                    json={"question": "where next?"}, timeout=120)
    assert r.status_code == 200, r.text
    jobs = client.get("/admin/model/jobs", headers=users["op"]).json()["jobs"]
    coach_jobs = [j for j in jobs if j["kind"] == "coach-text"]
    assert coach_jobs, "the hint must queue a durable coach job"
    # every attempt is visible (bounded retries are separate rows); NONE
    # succeeded — and none may pretend to still be working
    terminal = [j for j in coach_jobs if j["state"] in
                ("failed", "cancelled", "succeeded")]
    assert terminal and not any(j["state"] == "succeeded" for j in terminal)
    assert terminal[0]["error"]


def test_probe_is_a_queue_member_not_an_out_of_queue_ping(client, users, srv):
    prof = _make_profile(client, users, "probeable", srv.base_url)
    srv.script([text_response("pong")])
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "coach", "profile_name": "probeable"})
    r = client.post("/admin/model/probe", headers=users["op"],
                    json={"role": "coach", "profile_name": "probeable"})
    assert r.status_code == 200, r.text
    jid = uuid.UUID(r.json()["job_id"])
    from srplatform import model_jobs
    model_jobs.start_model_jobs()
    job = _wait_job(jid)
    assert job.state == "succeeded", job.error
    assert job.kind == "probe"
