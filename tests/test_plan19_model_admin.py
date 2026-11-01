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

from srplatform.db.models import (ConversationRevision, Event, ModelJob,
                                  ModelProfile, Run, SessionModelPin)
from srplatform.db.session import db as db_ctx
from tests.fake_model import (FakeModelServer, text_response, tool_call,
                              tool_response)

pytestmark = pytest.mark.agent

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
                             "cessation_unknown", "cessation_resolved"):
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
    # head is DERIVED from the migrations tree (the linear-chain pin lives in
    # test_app_role_grants), so a forward migration never silently breaks the
    # admin surface; what matters is that /readyz reports the actual head.
    from tests.test_app_role_grants import _revisions
    _revs = _revisions()
    _children = {down for down, _ in _revs.values() if down}
    (_head,) = [r for r in _revs if r not in _children]
    assert client.get("/readyz").json()["migration_version"] == _head
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
    # the credential lives ONLY in the secret store; the profile row has
    # no key column at all (finding 8)
    from srplatform import secret_store
    with db_ctx() as s:
        row = s.execute(select(ModelProfile).where(
            ModelProfile.name == "canary")).scalar_one()
        assert not hasattr(row, "api_key")
        assert secret_store.get_key(row.profile_id) == "sk-canary-9"
    # AND the application DB role genuinely cannot read the secret table
    # (a real role probe, not a comment): the app URL is the identity the
    # ingestion plane shares.
    import sqlalchemy as sa
    from srplatform.settings import get_settings
    app_engine = sa.create_engine(get_settings().postgres_url)
    with app_engine.connect() as conn:
        try:
            conn.execute(sa.text(
                "SELECT api_key FROM model_profile_secrets LIMIT 1"))
            raise AssertionError("app role CAN read the secret table")
        except AssertionError:
            raise
        except sa.exc.DBAPIError as exc:
            assert "permission denied" in str(exc).lower(), str(exc)[:200]
        conn.rollback()
    app_engine.dispose()
    # …and the SECRET role reads keys ONLY — not events, not sessions:
    # stealing it must buy nothing else
    from srplatform.settings import get_settings as _gs
    sec_engine = sa.create_engine(_gs().postgres_url_secret)
    with sec_engine.connect() as conn:
        for tbl in ("events", "sessions", "model_jobs"):
            try:
                conn.execute(sa.text(f"SELECT 1 FROM {tbl} LIMIT 1"))
                raise AssertionError(f"secret role can read {tbl}")
            except AssertionError:
                raise
            except sa.exc.DBAPIError as exc:
                assert "permission denied" in str(exc).lower(), str(exc)[:200]
            conn.rollback()
        # its own table IS readable (that is the whole grant)
        assert conn.execute(sa.text(
            "SELECT count(*) FROM model_profile_secrets")).scalar_one() >= 1
    sec_engine.dispose()


def prof_base_str(d) -> str:
    import json
    return json.dumps(d)


def test_rotation_creates_version_demotes_old_and_revocation_is_final(
        client, users):
    """The SECRET axis decides the demotion mode (review finding 9):
    a key-supplied revise REVOKES the old version (its credential dies
    immediately); a non-secret revise SUPERSEDES it (pinned sessions
    keep working)."""
    from srplatform import secret_store
    from srplatform.db.models import ModelProfile as MP
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
    assert v1["status"] == "revoked", "key replaced → old version revoked"
    # the revoked version's credential is GONE from the store immediately
    with db_ctx() as s:
        old = s.execute(select(MP).where(MP.name == "rot",
                                         MP.version == 1)).scalar_one()
        assert secret_store.get_key(old.profile_id) is None
        new = s.execute(select(MP).where(MP.name == "rot",
                                         MP.version == 2)).scalar_one()
        assert secret_store.get_key(new.profile_id) == "k2"
    # revoking an ALREADY-REVOKED version is refused (nothing left to do)
    r = client.post(f"/admin/model/profiles/{v1['profile_id']}/revoke",
                    headers=users["op"], json={"reason": "compromised"})
    assert r.status_code == 422
    # a NON-secret revise of the active version: v2 becomes SUPERSEDED,
    # not revoked — its credential survives (pinned work continues)
    r = client.post("/admin/model/profiles/rot/revise", headers=users["op"],
                    json={"name": "rot", "model_name": "x"})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 3
    with db_ctx() as s:
        v2row = s.execute(select(MP).where(MP.name == "rot",
                                           MP.version == 2)).scalar_one()
        assert v2row.status == "superseded"
        assert secret_store.get_key(v2row.profile_id) == "k2"


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


def test_cancellation_reaches_the_live_call_and_obligation_blocks_then_releases(
        client, users, srv):
    """Review finding 2 at ROOT: cancelling a RUNNING job must CLOSE the
    live request (not wait out its timeout), the close is an UNCERTAIN
    cessation that HOLDS the admission slot, other queued work waits
    behind the obligation, and only a bounded operator resolution frees
    the queue — after which normal admission resumes."""
    from srplatform import model_jobs
    prof = _make_profile(client, users, "cancel", srv.base_url)
    # first scripted response sleeps 3 s BEFORE answering (the live call);
    # the second answers immediately once the obligation is resolved
    srv.script([dict(text_response("slow1"), _delay=3.0),
                text_response("after-resolve")])
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        running = model_jobs.enqueue(s, kind="text", priority=5,
                                     payload={"mode": "text", "system": "s",
                                              "user": "slow"}, profile=p)
        blocked = model_jobs.enqueue(s, kind="text", priority=5,
                                     payload={"mode": "text", "system": "s",
                                              "user": "blocked"}, profile=p)
        doomed = model_jobs.enqueue(s, kind="text", priority=5,
                                    payload={"mode": "text", "system": "s",
                                             "user": "never"}, profile=p)
        rid, bid, qid = running.job_id, blocked.job_id, doomed.job_id
    model_jobs.start_model_jobs()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        with db_ctx() as s:
            if s.get(ModelJob, rid).state == "running":
                break
        time.sleep(0.02)
    with db_ctx() as s:
        model_jobs.cancel(s, qid, actor="test")          # queued → cancelled
    t0 = time.monotonic()
    with db_ctx() as s:
        j = model_jobs.cancel(s, rid, actor="test")
        assert j.state == "running" and j.cancel_requested is True
    done = _wait_job(rid, timeout_s=5.0)
    closed_in = time.monotonic() - t0
    assert done.state == "cessation_unknown", (
        f"a watcher-closed call is an UNCERTAIN cessation, not "
        f"'{done.state}'")
    assert closed_in < 2.0, (
        f"cancel took {closed_in:.1f}s — the watcher did not close the "
        "live request, it waited out the scripted 3 s hang")
    assert "cannot be confirmed" in (done.error or "")
    # THE OBLIGATION HOLDS THE SLOT: the blocked job stays queued while
    # the uncertain cessation is unresolved (no silent admission past it)
    time.sleep(1.2)
    with db_ctx() as s:
        assert s.get(ModelJob, bid).state == "queued", (
            "a second request was admitted while an uncertain cessation "
            "still held the slot")
    # the QUEUED cancellation still works: terminal, payload never sent
    with db_ctx() as s:
        assert s.get(ModelJob, qid).state == "cancelled"
    users_seen = [str(b["messages"][-1]["content"])
                  for b in srv.request_bodies()]
    assert not any("never" in u for u in users_seen)
    # bounded operator resolution (admin surface) frees the queue
    r = client.post(f"/admin/model/jobs/{rid}/resolve-cessation",
                    headers=users["op"],
                    json={"resolution": "confirmed with provider: the "
                                        "closed request completed server-side "
                                        "and its output was discarded"})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "cessation_resolved"
    with db_ctx() as s:
        ev = s.execute(select(Event).where(
            Event.action_type == "model_admin.job.resolve")).scalars().all()
        assert ev, "the resolution must be audited"
    resolved = _wait_job(rid)
    assert resolved.state == "cessation_resolved"
    assert resolved.resolved_by and resolved.resolved_at
    # …and normal admission proceeds: the blocked job runs NOW
    after = _wait_job(bid, timeout_s=30.0)
    assert after.state == "succeeded", after.error


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
    # REVIEW FINDING 1: the permanent system framing PERSISTS on every
    # later wire request (it is durably replayed, not rebuilt from a
    # client string that may change) — and this turn's tool return rides
    # as a structured tool message whose call id was actually asked for
    assert msgs[0]["role"] == "system" and msgs[0]["content"] == "SYS", \
        "system framing must be replayed on later turns, not dropped"
    assert [m for m in msgs if m["role"] == "tool"][0]["tool_call_id"] == "c1"


def test_profile_lifecycle_respects_the_pinned_whole_session_freeze(
        client, users, srv):
    """Review finding 9 end-to-end over real turns and jobs:

    * a NON-secret edit supersedes the old version — the pinned session
      KEEPS working on the version it started with (no mid-match swap);
    * credential revocation of the PINNED version fails that session's
      model work VISIBLY (never a substitute), while a NEW session gets
      the new active version;
    * rebind is refused while the session has queued work (no flip
      under a live/queued request), then explicitly restores service."""
    from srplatform import model_jobs
    from datetime import datetime, timedelta, timezone
    prof = _make_profile(client, users, "rotturn", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "rotturn"})
    sid, token = _session_and_token(client, users)
    H = {"Authorization": f"Bearer {token}"}
    srv.script([text_response("first")])
    assert client.post("/internal/model/turn", headers=H,
                       json={"system": "s", "user": "go"}).status_code == 200
    # ---- NON-secret edit: supersede, pinned session unaffected --------
    r = client.post("/admin/model/profiles/rotturn/revise", headers=users["op"],
                    json={"name": "rotturn", "thinking_level": "low"})
    assert r.status_code == 200, r.text
    srv.script([text_response("still-pinned")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "again"})
    assert r.status_code == 200, r.text
    assert r.json()["profile"] == {"name": "rotturn", "version": 1}, \
        "superseded (non-secret edit) must NOT change what a pinned uses"
    # ---- revoke the PINNED version: work fails visibly, not silently ---
    r = client.post(f"/admin/model/profiles/{prof['profile_id']}/revoke",
                    headers=users["op"], json={"reason": "key compromised"})
    assert r.status_code == 200, r.text
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "after revoke"})
    assert r.status_code == 503, r.text
    assert "rebind" in r.text
    assert len(srv.requests) == 2, "the refused turn must not hit the provider"
    # ---- rebind is FENCED while queued work exists (finding 9) ---------
    # (run_at far in the future: the claimer must not touch it, so the
    # queue state under test is deterministic)
    with db_ctx() as s:
        p = s.get(ModelProfile, uuid.UUID(prof["profile_id"]))
        gate = model_jobs.enqueue(
            s, kind="text", priority=9,
            payload={"mode": "text", "system": "s",
                     "user": "queued behind revoke"},
            session_id=sid, profile=p,
            run_at=datetime.now(timezone.utc) + timedelta(seconds=300))
        gid = gate.job_id
    r = client.post(f"/admin/model/sessions/{sid}/rebind", headers=users["op"],
                    json={"role": "attacker"})
    assert r.status_code == 422, r.text
    with db_ctx() as s:
        model_jobs.cancel(s, gid, actor="test")
    r = client.post(f"/admin/model/sessions/{sid}/rebind", headers=users["op"],
                    json={"role": "attacker"})
    assert r.status_code == 200, r.text
    assert r.json()["config"]["version"] == 2
    srv.script([text_response("after rebind")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "resumed"})
    assert r.status_code == 200, r.text
    assert r.json()["profile"]["version"] == 2
    # old conversation history survived the whole lifecycle (append-only)
    with db_ctx() as s:
        assert s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid)).scalars().all()
    # a NEW session gets the CURRENT active version, not the revoked one
    sid2, token2 = _session_and_token(client, users)
    srv.script([text_response("fresh session")])
    r = client.post("/internal/model/turn",
                    headers={"Authorization": f"Bearer {token2}"},
                    json={"system": "s", "user": "hi"})
    assert r.status_code == 200, r.text
    assert r.json()["profile"]["version"] == 2


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
    assert "deterministic guidance" in r.json()["hint"], \
        "the fallback must say honestly it is not an AI hint"
    jobs = client.get("/admin/model/jobs", headers=users["op"]).json()["jobs"]
    coach_jobs = [j for j in jobs if j["kind"] == "coach-text"]
    assert coach_jobs, "the hint must queue a durable coach job"
    # a dead endpoint is a DEFINITE failure (connection never opened):
    # bounded visible retry rows, none succeeded, none left working
    assert len(coach_jobs) == 3, (
        f"expected the full bounded attempt chain, got "
        f"{[(j['state'], j['attempt']) for j in coach_jobs]}")
    assert {j["attempt"] for j in coach_jobs} == {1, 2, 3}
    assert all(j["state"] == "failed" for j in coach_jobs), coach_jobs
    assert any("unreachable" in (j["error"] or "") for j in coach_jobs)


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


# --------------------------------------------------------------------------- #
# compaction and accounting at the turn route (agent layer)                    #
# --------------------------------------------------------------------------- #

def test_compaction_covers_a_range_and_history_survives_it(client, users, srv):
    """Review finding 4 at ROOT: pressure is evaluated BEFORE the request;
    crossing the compaction point enqueues a visible summarizer job whose
    coverage was CAPTURED AT ENQUEUE, the turn is GATED behind it, and the
    gated request goes out on the COMPACTED context. The next crossing
    repeats; the append-only rows still replay everything the model saw."""
    prof = _make_profile(client, users, "compact", srv.base_url)
    # tiny window: budget = 9216 - 1024 = 8192 tokens; compaction point
    # 80% → 6553 estimated tokens
    r = client.post("/admin/model/profiles/compact/revise", headers=users["op"],
                    json={"name": "compact", "context_window": 9216,
                          "max_completion_tokens": 1024})
    assert r.status_code == 200, r.text
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "compact"})
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "summarizer", "profile_name": "compact"})
    sid, token = _session_and_token(client, users)
    H = {"Authorization": f"Bearer {token}"}

    srv.script([text_response("turn one")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "one"})
    assert r.status_code == 200, r.text
    assert r.json()["needs_compaction"] is False

    # a turn whose INPUT crosses the point: compaction must happen BEFORE
    # this request goes out — an over-budget prompt is never sent "first"
    filler = "recon " + ("x" * 40_000)
    srv.script([
        text_response("COMPACTED: recon over web01; pivot pending."),
        text_response("turn two " + "y" * 6000,
                      usage={"prompt_tokens": 8400,
                             "completion_tokens": 600,
                             "total_tokens": 9000}),
        text_response("COMPACTED2: web01 owned; pivot to db01 pending."),
        text_response("after compaction")])
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": filler})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["needs_compaction"] is True   # provider said 9000/8192

    # the turn was GATED: it carries depends_on and a summarize sibling
    jobs = client.get("/admin/model/jobs", headers=users["op"]).json()["jobs"]
    turn_jobs = [j for j in jobs if j["kind"] == "turn"
                 and j["session_id"] == str(sid)]
    assert len(turn_jobs) == 2
    gated = [j for j in turn_jobs if j["depends_on"]]
    assert len(gated) == 1, \
        [(j["state"], j["depends_on"]) for j in turn_jobs]
    sums = [j for j in jobs if j["kind"] == "summarize"]
    assert len(sums) == 1 and sums[0]["state"] == "succeeded"
    assert gated[0]["depends_on"] == sums[0]["job_id"]
    # the summarizer's own request SAW the range it covers
    assert any("recon" in str(b.get("messages")) for b in srv.request_bodies())

    # crossing AGAIN now: the next turn gates behind a second summarize,
    # and the request that finally goes out is the COMPACTED context
    r = client.post("/internal/model/turn", headers=H,
                    json={"system": "s", "user": "continue"})
    assert r.status_code == 200, r.text
    assert r.json()["needs_compaction"] is False  # stable after compaction
    wire = srv.request_bodies()[-1]
    roles = [m["role"] for m in wire["messages"]]
    assert roles.count("system") == 1, \
        "only the permanent framing is system; a summary never is"
    blob = str(wire)
    assert "COMPACTED2: web01 owned" in blob
    assert "COMPACTED CONVERSATION SUMMARY" in blob, \
        "the checkpoint must ride as a LABELED digest, not silent truth"
    assert "x" * 500 not in blob, "pre-checkpoint bulk must not be resent"

    with db_ctx() as s:
        revs = s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid)
            .order_by(ConversationRevision.revision_id)).scalars().all()
        cps = [v for v in revs if v.kind == "checkpoint"]
        msgs = [v for v in revs if v.kind == "messages"]
        assert len(cps) == 2, [v.kind for v in revs]
        # append-only: the covered bulk is STILL THERE
        assert len(msgs) >= 6
        # coverage is exact: the second checkpoint covers through the
        # LAST row that existed when the gated turn was enqueued — it
        # cannot silently cover rows written later
        assert cps[0].payload["covers_through"] < cps[1].payload["covers_through"]
        assert cps[1].payload["summary"].startswith("COMPACTED2")
        # the summarizer's answers are NOT attacker conversation messages
        assert all("COMPACTED" not in str(v.payload)[:60]
                   for v in msgs if v.kind == "messages")


def test_tool_output_is_bounded_on_the_wire(client, users, srv):
    """A teletype flood cannot inflate the conversation without limit: the
    tool return carries a bounded, honestly-labeled window (the full bytes
    remain in the evidence events, which the model is pointed at)."""
    prof = _make_profile(client, users, "flood", srv.base_url)
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "flood"})
    sid, token = _session_and_token(client, users)
    H = {"Authorization": f"Bearer {token}"}
    srv.script([tool_response([tool_call("c1", "range_command",
                                         {"command": "cat /flood"})])])
    assert client.post("/internal/model/turn", headers=H,
                       json={"system": "s", "user": "go"}).status_code == 200
    huge = "z" * 200_000
    srv.script([text_response("noted")])
    r = client.post("/internal/model/turn", headers=H, json={
        "system": "s", "user": "next",
        "tool_result": {"call_id": "c1", "exit_code": 0, "output": huge,
                        "timed_out": False, "error": None}})
    assert r.status_code == 200, r.text
    wire = srv.request_bodies()[-1]
    tool_msgs = [m for m in wire["messages"] if m["role"] == "tool"]
    assert tool_msgs
    content = str(tool_msgs[0]["content"])
    assert "z" * 500 in content
    assert "z" * 60_001 not in content, "output must be bounded on the wire"
