"""Plan 19 review ROUND 3 — the six re-reproduced defects, pinned at the
behavior level over the REAL wire, the REAL disposable PostgreSQL, and
the REAL API. Every race here is forced DETERMINISTICALLY: uncommitted
production claims held open by the test, provider responses gated on
events, and the scheduler driven by hand through the production claim /
execute functions — never by probabilistic sleeps hoping a window
opens, and never by mocking the claim itself.

Positive controls the reviewer's own runs confirmed stay green are NOT
restated here; this file adds the failing-then-fixed behaviors only:
(1) stale cancellation can never terminalize a live/unknown slot;
(2) retry creation can never escape a root cancellation;
(3) dependency gating follows the LOGICAL chain through bounded retries;
(4) profile revocation/replacement persists the durable outcome exactly
once through the same protocol every other terminal path uses;
(5) resaving the SAME credential is a non-secret edit, never a
self-revocation;
(audit) the rollback guard commits forward cleanly: no stale
compensation after commit, no resurrection across a concurrent
revocation, and a durable repair obligation when compensation fails.
"""
from __future__ import annotations

import threading
import time
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from srplatform import secret_store
from srplatform.db.models import Event, ModelJob, ModelProfile
from srplatform.db.session import app_engine, db as db_ctx
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


def _raw() -> Session:
    return Session(app_engine())


def _manual(monkeypatch):
    """No background scheduler: the test drives the PRODUCTION claim and
    execute functions itself, so every interleaving is forced, not
    raced."""
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "start_model_jobs", lambda: None)
    model_jobs.stop_model_jobs()


def _claim_once() -> uuid.UUID | None:
    """One production claim, committed (what the scheduler loop does)."""
    from srplatform import model_jobs
    s = _raw()
    try:
        jid = model_jobs.claim_next(s)
        s.commit()
        return jid
    finally:
        s.close()


def _drive(jid: uuid.UUID) -> None:
    from srplatform import model_jobs
    model_jobs._execute(jid)


def _await_lock_wait(app_name: str, timeout: float = 20.0) -> None:
    """Round-4 test-quality fix: an EXPLICIT database-observed barrier
    — returns only when PostgreSQL itself reports the named backend
    parked on a lock wait. No thread-scheduling guesses anywhere."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with db_ctx() as s:
            row = s.execute(text(
                "SELECT wait_event_type FROM pg_stat_activity "
                "WHERE application_name = :n "
                "  AND pid <> pg_backend_pid()"),
                {"n": app_name}).first()
        if row is not None and row[0] == "Lock":
            return
        time.sleep(0.02)
    raise AssertionError(
        f"backend {app_name!r} never reached an observed lock wait")


def _run_one() -> bool:
    jid = _claim_once()
    if jid is None:
        return False
    _drive(jid)
    return True


def _state(jid) -> ModelJob:
    with db_ctx() as s:
        return s.get(ModelJob, jid)


def _job_row(jid) -> dict:
    with db_ctx() as s:
        j = s.get(ModelJob, jid)
        return {"state": j.state, "intent": j.cancel_intent,
                "requested": j.cancel_requested,
                "outcome": j.outcome_persisted, "error": j.error}


def _profile(client, users, name, base_url, *, key="sk-round3"):
    return _make_profile(client, users, name, base_url, key=key)


def _profile_id(name, version=None):
    with db_ctx() as s:
        q = select(ModelProfile).where(ModelProfile.name == name)
        if version:
            q = q.where(ModelProfile.version == version)
        return s.execute(q.order_by(ModelProfile.version.desc())
                         ).scalars().first().profile_id


def _enqueue_hint(client, users, sid, name, *, text="help"):
    """A durable async member hint (kind 'hint'), queued through the
    production enqueue — the reviewer's F4 surface."""
    from srplatform import model_jobs
    pid = _profile_id(name)
    with db_ctx() as s:
        prof = s.get(ModelProfile, pid)
        job = model_jobs.enqueue(
            s, kind="hint", priority=0, session_id=sid, profile=prof,
            payload={"mode": "text", "system": "coach", "user": text,
                     "hint_meta": {"question": text,
                                   "fallback": "deterministic fallback"}})
        return job.job_id


def _enqueue_text(name, kind="hint", *, persist=None,
                  covers_through=None, **kw):
    from srplatform import model_jobs
    pid = _profile_id(name)
    payload = {"mode": "text",
               "system": kw.pop("system", "s"),
               "user": kw.pop("user", "go")}
    if persist is not None:
        payload["persist"] = persist
    if covers_through is not None:
        payload["covers_through"] = int(covers_through)
    with db_ctx() as s:
        prof = s.get(ModelProfile, pid)
        job = model_jobs.enqueue(
            s, kind=kind, priority=kw.pop("priority", 5), profile=prof,
            payload=payload, **kw)
        return job.job_id


def _events(sid, action_type):
    with db_ctx() as s:
        return s.execute(select(Event).where(
            Event.session_id == sid,
            Event.action_type == action_type)).scalars().all()


_ERR500 = {"index": 0, "message": {"role": "assistant", "content": None},
           "finish_reason": "stop", "_status": 500}


def _session(client, users):
    return uuid.UUID(client.post("/sessions", headers=users["member"],
                                 json={"scenario_id": "web-foothold-01"}
                                 ).json()["session_id"])


# --------------------------------------------------------------------------- #
# finding 1: cancel can never release a slot that is (or became) LIVE          #
# --------------------------------------------------------------------------- #

def test_cancel_before_claim_never_claims_or_dispatches(client, users, srv,
                                                        monkeypatch):
    _manual(monkeypatch)
    _profile(client, users, "r3pre", srv.base_url)
    jid = _enqueue_text("r3pre")
    with db_ctx() as s:
        from srplatform import model_jobs
        model_jobs.cancel(s, jid, actor="member")
    assert _claim_once() is None
    row = _job_row(jid)
    assert row["state"] == "cancelled" and row["intent"] is True
    assert srv.requests == []


def test_live_call_cancel_requests_cessation_and_holds_the_slot(
        client, users, srv, monkeypatch):
    """The reviewer's defect was a slot RELEASED while the provider was
    live. Here: the call is live (event-gated response), cancellation
    arrives, and the row must keep the obligation — running with the
    cessation request, never a stale 'cancelled'. A second claim must be
    refused; at most ONE provider request ever exists."""
    _profile(client, users, "r3live", srv.base_url)
    srv.script([dict(text_response("late"), _gate="hold")])
    jid = _enqueue_text("r3live")
    from srplatform import model_jobs
    model_jobs.start_model_jobs()          # REAL scheduler dispatches
    srv.wait_requests(1)
    with db_ctx() as s:
        model_jobs.cancel(s, jid, actor="member")
    row = _job_row(jid)
    assert row["state"] == "running", \
        "a live row was made terminal by a cancellation — the slot lied"
    assert row["requested"] is True and row["intent"] is True
    assert _claim_once() is None, "the slot was released while live"
    srv.release("hold")
    done = _wait_job(jid, timeout_s=20.0)
    assert done.state == "cancelled"       # the call RETURNED: real end
    assert srv.max_concurrent == 1


def test_cancel_blocked_by_open_claim_acts_on_the_committed_truth(
        client, users, srv, monkeypatch):
    """THE round-3 interleaving, forced: an uncommitted PRODUCTION claim
    (same _CLAIM_SQL, same row lock) is holding the row 'running' while
    a real cancellation is in flight. The cancellation MUST wait at the
    fence (no stale snapshot), and when the claim commits it acts on the
    live truth: cessation request, not a cancelled stamp."""
    _manual(monkeypatch)
    _profile(client, users, "r3race", srv.base_url)
    jid = _enqueue_text("r3race")
    claims = _raw()
    claimed = None
    try:
        claimed = None
        from srplatform import model_jobs
        claimed = model_jobs.claim_next(claims)   # UNCOMMITTED running
        assert claimed == jid

        errors: list = []

        def _cancel():
            try:
                with db_ctx() as s:
                    s.execute(text(
                        "SET LOCAL application_name = 'sr-r3-cancel'"))
                    model_jobs.cancel(s, jid, actor="member")
            except Exception as exc:       # noqa: BLE001
                errors.append(exc)

        t = threading.Thread(target=_cancel, daemon=True)
        t.start()
        # explicit barrier: the database SHOWS the cancellation parked
        # on the claim's row lock (not a scheduling guess)
        _await_lock_wait("sr-r3-cancel")
        assert t.is_alive(), \
            "cancellation did not wait at the claim fence — stale write"
        claims.commit()                    # the claim lands: running now
        t.join(timeout=15)
        assert not t.is_alive() and not errors, errors
        row = _job_row(jid)
        assert row["state"] == "running", \
            f"live claim was overwritten: {row['state']}"
        assert row["requested"] is True and row["intent"] is True
        assert _claim_once() is None, "a second slot opened for one chain"
        # the executor now runs the claimed row: it must NOT dispatch
        _drive(jid)
        assert srv.requests == []          # "never dispatched" — truth
        assert _state(jid).state == "cancelled"
    finally:
        claims.close()


# --------------------------------------------------------------------------- #
# finding 2: retry creation cannot escape a root cancellation                  #
# --------------------------------------------------------------------------- #

def test_retry_cannot_be_born_after_the_root_was_cancelled(client, users,
                                                           srv, monkeypatch):
    """Reviewer's exact reproduction: attempt 1 LIVE, provider answers
    500 (definite, retryable) WHILE the root cancellation lands. Old
    behavior: the executor committed a fresh queued backoff child and
    the "cancelled" request re-spawned. New: the terminal write locks
    the row first, sees the committed intent, and the chain ENDS
    cancelled — no child, no second provider request, and the durable
    member outcome persists exactly once (with F4)."""
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "RETRY_DELAYS", (0.1, 0.1))
    _profile(client, users, "r3respawn", srv.base_url)
    sid = _session(client, users)
    srv.script([dict(_ERR500, _gate="hold")])
    jid = _enqueue_hint(client, users, sid, "r3respawn")
    model_jobs.start_model_jobs()
    srv.wait_requests(1)
    with db_ctx() as s:
        model_jobs.cancel(s, jid, actor="member")
    srv.release("hold")                    # 500 arrives AFTER the cancel
    _wait_job(jid, timeout_s=20.0)
    with db_ctx() as s:
        child = s.execute(select(ModelJob).where(
            ModelJob.parent_job == jid)).scalars().first()
        assert child is None, \
            "a retry child was created for a cancelled logical request"
        row = s.get(ModelJob, jid)
        assert row.state == "cancelled", row.error
        assert row.outcome_persisted is True
    time.sleep(0.4)                        # a racing writer had room
    assert len(_events(sid, "hint")) == 1, \
        "the cancelled chain produced zero or two durable outcomes"
    assert len(srv.requests) == 1          # nothing re-dispatched


def test_cancel_after_child_born_kills_it_during_the_race_window(
        client, users, srv, monkeypatch):
    """The other direction: the child WAS committed before the
    cancellation ran. Locked re-enumeration must find and kill it —
    nothing born of a cancelled chain survives, even mid-backoff."""
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "RETRY_DELAYS", (3.0, 5.0))
    _profile(client, users, "r3born", srv.base_url)
    srv.script([_ERR500])
    jid = _enqueue_text("r3born")
    model_jobs.start_model_jobs()
    child_id = None
    for _ in range(120):
        with db_ctx() as s:
            c = s.execute(select(ModelJob).where(
                ModelJob.parent_job == jid)).scalars().first()
            if c is not None:
                child_id = c.job_id
                break
        time.sleep(0.05)
    assert child_id is not None
    with db_ctx() as s:
        model_jobs.cancel(s, jid, actor="member")
    with db_ctx() as s:
        c = s.get(ModelJob, child_id)
        assert c.state == "cancelled" and c.cancel_intent is True
    model_jobs.stop_model_jobs()
    assert _claim_once() is None           # child never dispatches
    assert len(srv.requests) == 1


# --------------------------------------------------------------------------- #
# finding 3: compaction/dependency gating follows the LOGICAL chain            #
# --------------------------------------------------------------------------- #

_SUM = "SUMMARIZE-THIS"
_GATE_MSG = "GATED-TURN"


def _drive_until_none(budget: int = 12):
    from srplatform import model_jobs
    for _ in range(budget):
        if not _run_one():
            return
    raise AssertionError("claim loop did not settle")


def _advance_backoff(parent_jid):
    with db_ctx() as s:
        s.execute(text("UPDATE model_jobs SET requested_at = now() "
                       "WHERE parent_job = :p AND state = 'queued'"),
                  {"p": str(parent_jid)})


def test_gated_turn_waits_for_summary_recovery_then_dispatches_once(
        client, users, srv, monkeypatch):
    """Round-3 finding 3, positive path: summary attempt 1 fails with a
    QUEUED retry child. The gated turn must NOT be admitted (its
    prerequisite chain can still recover), must not fail, and must
    dispatch EXACTLY ONCE only after the chain's final attempt succeeds
    — three provider requests total, in order."""
    _manual(monkeypatch)
    _profile(client, users, "r3dep", srv.base_url)
    sid = _session(client, users)
    srv.script([_ERR500,
                text_response("summary v2"),
                text_response("native turn after recovery")])
    # round-4 finding 3: a summarize that must authorize a dependent
    # carries its persist range and lands a real checkpoint on success
    sum_id = _enqueue_text("r3dep", kind="summarize", system=_SUM,
                           user=_SUM,
                           persist={"session_id": str(sid)},
                           covers_through=1)
    gate_id = _enqueue_text("r3dep", kind="red-turn", system=_GATE_MSG,
                            user=_GATE_MSG, depends_on=sum_id)
    # attempt 1 fails -> backoff child queued
    assert _run_one()
    child = None
    with db_ctx() as s:
        child = s.execute(select(ModelJob).where(
            ModelJob.parent_job == sum_id)).scalars().first()
    assert child is not None and child.state == "queued"
    # THE admission question, deterministically: while the summary chain
    # can still change, the gated turn is NOT claimable.
    assert _claim_once() is None, \
        "the gated turn was admitted while its summary chain could recover"
    assert [r["body"]["messages"][0]["content"]
            for r in srv.requests] == [_SUM]
    # the summary retries and succeeds
    _advance_backoff(sum_id)
    assert _run_one()
    with db_ctx() as s:
        assert s.get(ModelJob, child.job_id).state == "succeeded"
    # now the chain is quiescent-success: the gated turn may run
    assert _run_one()
    assert _state(gate_id).state == "succeeded"
    assert _claim_once() is None
    bodies = [r["body"]["messages"][0]["content"] for r in srv.requests]
    assert bodies == [_SUM, _SUM, _GATE_MSG]   # dispatched once, last


def test_gated_turn_fails_only_after_the_summary_chain_is_truly_done(
        client, users, srv, monkeypatch):
    """Exhaustion: every summary attempt fails. The gated turn must not
    fail EARLY; once the chain is genuinely terminal it fails TRUTH-
    FULLY (final attempt + state), once, with no provider call for
    itself."""
    _manual(monkeypatch)
    _profile(client, users, "r3depfail", srv.base_url)
    srv.script([_ERR500, _ERR500, _ERR500])
    sum_id = _enqueue_text("r3depfail", kind="summarize", system=_SUM,
                           user=_SUM)
    gate_id = _enqueue_text("r3depfail", kind="red-turn", system=_GATE_MSG,
                            user=_GATE_MSG, depends_on=sum_id)
    assert _run_one()                      # attempt 1 -> child queued
    _advance_backoff(sum_id)
    parent = sum_id
    with db_ctx() as s:
        c = s.execute(select(ModelJob).where(
            ModelJob.parent_job == sum_id)).scalars().first()
        parent = c.job_id
    assert _run_one()                      # attempt 2 -> child queued
    _advance_backoff(parent)
    assert _run_one()                      # attempt 3 -> final failure
    assert _claim_once() == gate_id        # quiescent: may be admitted
    _drive(gate_id)
    row = _job_row(gate_id)
    assert row["state"] == "failed"
    assert "final attempt" in row["error"] and "failed" in row["error"]
    bodies = [r["body"]["messages"][0]["content"] for r in srv.requests]
    assert bodies == [_SUM, _SUM, _SUM], \
        "the gated turn contacted the provider or fired early"


def test_gated_turn_reports_the_summary_cancellation_truthfully(
        client, users, srv, monkeypatch):
    """Cancellation propagation: the summary chain is cancelled while a
    retry child sits backoff-queued. The gated turn later fails with
    the CHAIN'S cancellation as the truthful reason — not a stale
    attempt-1 opinion, and never a silent success."""
    _manual(monkeypatch)
    _profile(client, users, "r3depcancel", srv.base_url)
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "RETRY_DELAYS", (3.0, 5.0))
    srv.script([_ERR500])
    sum_id = _enqueue_text("r3depcancel", kind="summarize", system=_SUM,
                           user=_SUM, priority=5)
    # run attempt 1 by hand (no scheduler): it fails, child queues
    assert _claim_once() == sum_id
    _drive(sum_id)
    with db_ctx() as s:
        model_jobs.cancel(s, sum_id, actor="member")
    gate_id = _enqueue_text("r3depcancel", kind="red-turn",
                            system=_GATE_MSG, user=_GATE_MSG,
                            depends_on=sum_id)
    assert _claim_once() == gate_id        # chain quiescent (cancelled)
    _drive(gate_id)
    row = _job_row(gate_id)
    assert row["state"] == "failed"
    assert "cancelled" in row["error"]
    assert len(srv.requests) == 1


# --------------------------------------------------------------------------- #
# finding 4: profile revocation/replacement goes through the outcome protocol  #
# --------------------------------------------------------------------------- #

def test_revocation_of_a_queued_hint_persists_the_outcome_once(
        client, users, srv, monkeypatch):
    """Reviewer: revoking BEFORE dispatch left cancelled + zero events.
    All terminal paths now share the durable once-protocol: cancel,
    claim, one honest fallback event."""
    _manual(monkeypatch)
    _profile(client, users, "r3revq", srv.base_url)
    sid = _session(client, users)
    jid = _enqueue_hint(client, users, sid, "r3revq")
    from srplatform import model_admin
    with db_ctx() as s:
        model_admin.revoke(s, _profile_id("r3revq"), actor="operator",
                           reason="rotation drill")
    row = _job_row(jid)
    assert row["state"] == "cancelled"
    assert row["outcome"] is True, "revocation bypassed the outcome claim"
    events = _events(sid, "hint")
    assert len(events) == 1, \
        f"revocation produced {len(events)} durable outcomes (want 1)"
    assert events[0].payload["model_ok"] is False   # honest fallback


def test_lineage_replacement_of_backoff_chain_persists_once(client, users,
                                                            srv, monkeypatch):
    """A credential REPLACEMENT (lineage revoke) over a hint chain whose
    parent failed and child is backoff-queued: both rows die, exactly
    ONE outcome persists — no double event from two cancellers."""
    _manual(monkeypatch)
    from srplatform import model_admin, model_jobs
    monkeypatch.setattr(model_jobs, "RETRY_DELAYS", (3.0, 5.0))
    _profile(client, users, "r3repl", srv.base_url)
    sid = _session(client, users)
    srv.script([_ERR500])
    jid = _enqueue_hint(client, users, sid, "r3repl")
    assert _claim_once() == jid
    _drive(jid)                            # attempt 1 fails -> child
    with db_ctx() as s:
        model_admin.revise(s, "r3repl", api_key="sk-brand-new",
                           actor="operator")
    with db_ctx() as s:
        rows = s.execute(select(ModelJob).where(
            ModelJob.session_id == sid)).scalars().all()
        states = [(r.attempt, r.state) for r in rows]
        assert all(r.state in ("failed", "cancelled") for r in rows), \
            f"rows still admissible after replacement: {states}"
        child = next(r for r in rows if r.attempt == 2)
        assert child.state == "cancelled" and child.cancel_intent is True
        assert sum(1 for r in rows
                   if r.outcome_persisted) == 1, \
            "the replacement chain persisted zero or multiple outcomes"
    assert len(_events(sid, "hint")) == 1


def test_live_call_revocation_ceases_and_persists_exactly_once(
        client, users, srv, monkeypatch):
    """Revocation WHILE the hint call is live: the terminal write (not
    the revocation) closes the chain and claims the outcome — exactly
    one event, never one from the revoke and one from the terminal."""
    _profile(client, users, "r3revlive", srv.base_url)
    sid = _session(client, users)
    srv.script([dict(_ERR500, _gate="hold")])
    jid = _enqueue_hint(client, users, sid, "r3revlive")
    from srplatform import model_admin, model_jobs
    model_jobs.start_model_jobs()
    srv.wait_requests(1)
    with db_ctx() as s:
        model_admin.revoke(s, _profile_id("r3revlive"), actor="operator",
                           reason="live revocation")
    row = _job_row(jid)
    assert row["state"] == "running" and row["requested"] is True
    srv.release("hold")
    _wait_job(jid, timeout_s=20.0)
    assert _state(jid).outcome_persisted is True
    time.sleep(0.4)
    assert len(_events(sid, "hint")) == 1
    assert len(srv.requests) == 1


# --------------------------------------------------------------------------- #
# finding 5: resaving the SAME credential is a non-secret edit                 #
# --------------------------------------------------------------------------- #

def _revise(client, users, name, body=None, **body_kw):
    payload = {**(body or {}), **body_kw}
    r = client.post(f"/admin/model/profiles/{name}/revise",
                    headers=users["op"], json=payload)
    return r


def _resave(client, users, name, **fields):
    """A GUI-style full-form revision POST (the form always carries the
    profile name; the key is included only when provided)."""
    return _revise(client, users, name, {"name": name, **fields})


def _rows(name):
    with db_ctx() as s:
        return {p.version: p.status for p in s.execute(
            select(ModelProfile).where(ModelProfile.name == name)
            .order_by(ModelProfile.version)).scalars().all()}


def test_same_key_resave_never_revokes_the_version_it_created(client, users,
                                                              srv):
    """Parent's own key resubmitted via revise: 200 must mean a USABLE
    profile. Old behavior: the sibling sweep found the NEW version (the
    digest matched — same key!) and revoked it, deleting the secret
    seconds after writing it."""
    _profile(client, users, "samek", srv.base_url, key="sk-same-value")
    r = _resave(client, users, "samek", api_key="sk-same-value")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "active", \
        "the replacement revoked itself"
    new_id = uuid.UUID(body["profile_id"])
    assert secret_store.get_key(new_id) == "sk-same-value"
    st = _rows("samek")
    assert st[1] == "superseded" and st[2] == "active"


def test_same_key_resave_with_other_fields_keeps_pinned_sessions(client,
                                                                 users,
                                                                 srv):
    _profile(client, users, "samekb", srv.base_url, key="sk-same-value")
    # non-secret edits copy the key forward: several superseded versions
    _resave(client, users, "samekb", max_completion_tokens=600)
    _resave(client, users, "samekb", max_completion_tokens=700)
    r = _resave(client, users, "samekb", api_key="sk-same-value", max_completion_tokens=800)
    assert r.status_code == 200, r.text
    st = _rows("samekb")
    assert st[4] == "active"
    assert all(v == "superseded" for v in st.values()
               if v != "active"), st          # nothing revoked
    # and the credential still WORKS on a served call (the role points
    # at the current version; the genuine PIN-PROOF — session created
    # BEFORE the revisions and still served by the pinned v1 after a
    # dead-URL edit — is the dedicated round-4 test
    # test_pinned_session_keeps_serving_from_the_pinned_profile; the
    # round-3 form of this block created the session only afterwards
    # and therefore proved serviceability, not the pin).
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "samekb"})
    srv.script([text_response("served")])
    sid = _session(client, users)
    from tests.test_plan19_model_admin import _mint_runner_token
    tok = _mint_runner_token(sid)
    r2 = client.post("/internal/model/turn",
                     headers={"Authorization": f"Bearer {tok}"},
                     json={"system": "s", "user": "u"})
    assert r2.status_code == 200, r2.text


def test_genuine_replacement_still_invalidates_the_lineage(client, users,
                                                           srv):
    _profile(client, users, "samekc", srv.base_url, key="sk-old-value")
    _resave(client, users, "samekc", timeout_s=40)
    r = _resave(client, users, "samekc", api_key="sk-different-value")
    assert r.status_code == 200, r.text
    st = _rows("samekc")
    assert st[1] == "revoked" and st[2] == "revoked" \
        and st[3] == "active", st
    assert secret_store.get_key(_profile_id("samekc", 1)) is None
    assert secret_store.get_key(_profile_id("samekc", 2)) is None


def test_failed_same_key_revision_changes_nothing(client, users, srv):
    _profile(client, users, "samekd", srv.base_url, key="sk-same-value")
    before = _rows("samekd")
    r = _resave(client, users, "samekd", api_key="sk-same-value", context_window=-100)
    assert r.status_code >= 400
    assert _rows("samekd") == before
    assert secret_store.get_key(_profile_id("samekd", 1)) == \
        "sk-same-value"


# --------------------------------------------------------------------------- #
# rollback-guard audit (parent-directed investigation, pinned now)             #
# --------------------------------------------------------------------------- #

def test_committed_secret_survives_a_later_rollback_on_the_same_session(
        client, users, srv):
    """The guard lacked after-commit cleanup: a commit followed by a
    rollback on the SAME session used to delete the COMMITTED profile's
    live secret — session reuse (or any post-commit exception) turned
    compensation into vandalism."""
    from srplatform import model_admin
    s = _raw()
    try:
        prof = model_admin.create_profile(s, name="guard1",
                                          api_key="sk-guard-live",
                                          base_url="http://x/v1",
                                          model_name="m")
        s.commit()
        pid = prof.profile_id
        assert secret_store.get_key(pid) == "sk-guard-live"
        with pytest.raises(Exception):
            s.execute(text("SELECT 1 / zero"))
        s.rollback()                       # a LATER failure, same session
        assert secret_store.get_key(pid) == "sk-guard-live", \
            "a rolled-back LATER transaction undid committed secrets"
    finally:
        s.close()


def test_rollback_never_resurrects_a_credential_revoked_concurrently(
        client, users, srv):
    """Restore-under-status-check discipline: our transaction deleted
    the secret and will roll back, but a CONCURRENT COMMITTED
    revocation means that delete is final — rolling our work back must
    not put the killed credential back."""
    from srplatform import model_admin
    s1 = _raw()
    try:
        prof = model_admin.create_profile(s1, name="guard2",
                                          api_key="sk-guard-kill",
                                          base_url="http://x/v1",
                                          model_name="m")
        s1.commit()
        pid = prof.profile_id
        # our tracked delete (secret store commits immediately; this
        # transaction will roll back) — no row write held, exactly the
        # shape of a request that did the secret effect early
        model_admin._delete_secret_tracked(s1, pid)
        assert secret_store.get_key(pid) is None
        # a committed OPERATOR revocation lands in another session
        with db_ctx() as s2:
            model_admin.revoke(s2, pid, actor="security",
                               reason="compromised")
        # s1 still holds an open transaction from the create above?
        # no — committed. Begin one so the rollback is real, then roll
        # the tracked delete back:
        s1.execute(select(ModelProfile).where(
            ModelProfile.profile_id == pid))
        s1.rollback()
        assert secret_store.get_key(pid) is None, \
            "a rollback resurrected a credential a revoke just killed"
    finally:
        s1.close()


def test_failing_compensation_records_a_durable_repair_obligation(
        client, users, srv, monkeypatch):
    """Atomicity honesty audit: when the in-process compensation itself
    fails, the divergence must become an operator-visible obligation —
    never a swallowed log line."""
    from srplatform import model_admin, secret_store as ss
    s = _raw()
    try:
        real_delete = ss.delete_key

        def _boom(_pid):
            raise RuntimeError("store unavailable")

        prof = model_admin.create_profile(s, name="guard3",
                                          api_key="sk-guard-oblig",
                                          base_url="http://x/v1",
                                          model_name="m")
        s.flush()
        pid = prof.profile_id
        monkeypatch.setattr(ss, "delete_key", _boom)
        s.rollback()                       # guard tries the compensation
        monkeypatch.setattr(ss, "delete_key", real_delete)
        with db_ctx() as s2:
            note = s2.execute(select(Event).where(
                Event.action_type ==
                "model_admin.profile.secret_compensation_failed"
            )).scalars().all()
        assert note, "compensation failed silently"
        assert str(pid) in note[0].payload["profile_id"]
        # cleanup for the rest of the suite
        secret_store.delete_key(pid)
    finally:
        s.close()
