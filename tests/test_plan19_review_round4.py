"""Plan 19 review ROUND 4 — the three source findings, pinned against the
REAL database and the REAL wire with explicit, database-observed
concurrency barriers. No test here trusts a thread's ``is_alive()`` or a
sleep as proof of an interleaving: where a race must be forced, the test
waits until ``pg_stat_activity`` SHOWS the victim backend parked on a
lock — an observed fact about the production code's actual lock — and
only then pulls the trigger.

* F1: rollback compensation restoring a deleted credential can no
  longer resurrect one a revocation deleted concurrently — the restore
  holds the profile row's FOR UPDATE across check + secret write, the
  same row a revocation locks to change status.
* F2: an escaped child of the pre-0023 defect (clean flags, cancelled
  root) never dispatches: the claim fence consults the WHOLE chain, the
  executor reconciles before touching the provider, and migration 0024
  repairs populated pre-0023 databases on upgrade (pinned in
  ``test_plan19_review_round4_migrations.py``).
* F3: dependency success means a genuinely SUCCEEDED summary whose
  coverage-bounded checkpoint exists. An operator's cessation
  resolution is a slot-release attestation, not a result, and never
  authorizes the dependent native call.
"""
from __future__ import annotations

import threading
import time
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from srplatform import secret_store
from srplatform.db.models import ConversationRevision, ModelJob, ModelProfile
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
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "start_model_jobs", lambda: None)
    model_jobs.stop_model_jobs()


def _claim_once() -> uuid.UUID | None:
    from srplatform import model_jobs
    s = _raw()
    try:
        jid = model_jobs.claim_next(s)
        s.commit()
        return jid
    finally:
        s.close()


def _drive(jid) -> None:
    from srplatform import model_jobs
    model_jobs._execute(jid)


def _state(jid) -> ModelJob:
    with db_ctx() as s:
        return s.get(ModelJob, jid)


def _rows(name):
    with db_ctx() as s:
        return {p.version: p.status for p in s.execute(
            select(ModelProfile).where(ModelProfile.name == name)
            .order_by(ModelProfile.version)).scalars().all()}


def _session(client, users):
    return uuid.UUID(client.post("/sessions", headers=users["member"],
                                 json={"scenario_id": "web-foothold-01"}
                                 ).json()["session_id"])


def _await_lock_wait(app_name: str, timeout: float = 20.0) -> None:
    """Deterministic concurrency barrier: returns only when
    PostgreSQL ITSELF reports the named backend parked on a lock wait.
    This replaces every 'sleep then is_alive' guess — the interleaving
    is proven from the database's own view, not from scheduling."""
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


_ERR500 = {"index": 0, "message": {"role": "assistant", "content": None},
           "finish_reason": "stop", "_status": 500}


# --------------------------------------------------------------------------- #
# F1: restore compensation vs a CONCURRENT revocation (check→write race)       #
# --------------------------------------------------------------------------- #

def _create_committed(name, key, session: Session | None = None):
    """Create a committed profile. Pass the SAME session the test will
    later roll back: the rollback guard is installed per-session, and
    the compensation must be armed on the session whose rollback the
    test drives (exactly how the request paths use it)."""
    from srplatform import model_admin
    s = session if session is not None else _raw()
    try:
        prof = model_admin.create_profile(s, name=name, api_key=key,
                                          base_url="http://x/v1",
                                          model_name="m")
        s.commit()
        return prof.profile_id
    finally:
        if session is None:
            s.close()


def test_restore_cannot_undo_a_revocation_committing_mid_write(
        client, users, srv, monkeypatch):
    """THE check→write window, forced: the restore has PASSED its status
    check and is inside the secret write (event-held), and the
    revocation is then dispatched. With the row lock held across the
    write the revocation cannot commit through the window — it parks on
    the lock (proven via pg_stat_activity), then lands AFTER the
    restore, and its delete is final. Net effect: the compromised
    credential stays deleted, the profile stays revoked, and no
    ordering resurrects it."""
    from srplatform import model_admin
    s1 = _raw()
    try:
        pid = _create_committed("r4toctou", "sk-r4-compromised",
                                session=s1)

        model_admin._delete_secret_tracked(s1, pid)
        assert secret_store.get_key(pid) is None  # store commits now
        # open a REAL transaction so the rollback is real (an empty
        # session's rollback is a no-op and dispatches nothing — the
        # guard only owes compensation for a transaction that existed)
        s1.execute(select(ModelProfile).where(
            ModelProfile.profile_id == pid))

        real_set = secret_store.set_key
        arrived = threading.Event()
        proceed = threading.Event()

        def _hold(key_id, value):
            if key_id == pid:
                arrived.set()               # we are INSIDE the restore,
                assert proceed.wait(30)     # holding the row lock
            return real_set(key_id, value)
        monkeypatch.setattr(secret_store, "set_key", _hold)

        rerr: list = []

        def _rollback():
            try:
                s1.rollback()
            except Exception as exc:       # noqa: BLE001
                rerr.append(exc)

        tr = threading.Thread(target=_rollback, daemon=True)
        tr.start()
        assert arrived.wait(20), "restore never reached the write"

        verr: list = []

        def _revoke():
            try:
                with db_ctx() as s2:
                    s2.execute(text(
                        "SET LOCAL application_name = 'sr-r4-revoke'"))
                    model_admin.revoke(s2, pid, actor="security",
                                       reason="compromised mid-restore")
            except Exception as exc:       # noqa: BLE001
                verr.append(exc)

        tv = threading.Thread(target=_revoke, daemon=True)
        tv.start()
        _await_lock_wait("sr-r4-revoke")   # OBSERVED: revoke is blocked
        # by our restore's row lock — the revocation CANNOT commit
        # through the check→write window any more.
        proceed.set()
        tr.join(30)
        tv.join(30)
        assert not tr.is_alive() and not rerr, rerr
        assert not tv.is_alive() and not verr, verr

        assert secret_store.get_key(pid) is None, \
            "the compensation resurrected the credential the revocation killed"
        with db_ctx() as s3:
            assert s3.get(ModelProfile, pid).status == "revoked"
    finally:
        try:
            secret_store.delete_key(pid)
        except Exception:
            pass
        s1.close()


def test_restore_still_recovers_a_legitimate_undone_delete(client, users,
                                                           srv):
    """Positive control for the same code path: with no competing
    revocation, the rollback restore DOES put the credential back —
    the serialization fence must never become a silent refusal."""
    from srplatform import model_admin
    s1 = _raw()
    try:
        pid = _create_committed("r4legit", "sk-r4-restore-me",
                                session=s1)
        model_admin._delete_secret_tracked(s1, pid)
        assert secret_store.get_key(pid) is None
        s1.execute(select(ModelProfile).where(
            ModelProfile.profile_id == pid))   # open a real transaction
        s1.rollback()
        assert secret_store.get_key(pid) == "sk-r4-restore-me"
    finally:
        try:
            secret_store.delete_key(pid)
        except Exception:
            pass
        s1.close()


# --------------------------------------------------------------------------- #
# F2: escaped legacy children never dispatch (runtime fence)                   #
# --------------------------------------------------------------------------- #

def _legacy_escaped_chain(name):
    """Cancelled root + queued child + queued grandchild, all with the
    CLEAN flags the pre-0023 defect left behind (no intent, no cancel
    request) — a raw writer that grew the chain around the fence."""
    root, child, gchild = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    with db_ctx() as s:
        for jid, parent, state, attempt in (
                (root, None, "cancelled", 1),
                (child, root, "queued", 2),
                (gchild, child, "queued", 3)):
            s.add(ModelJob(job_id=jid, kind=name, priority=5,
                           payload={"mode": "text", "system": "s",
                                    "user": "escaped"},
                           state=state, attempt=attempt, parent_job=parent,
                           chain_root=root,
                           error=("cancelled by member before execution"
                                  if state == "cancelled" else None)))
        s.commit()
    return root, child, gchild


def test_claim_refuses_a_legacy_escaped_child_and_execution_reconciles(
        client, users, srv, monkeypatch):
    _manual(monkeypatch)
    _make_profile(client, users, "r4fence", srv.base_url)
    root, child, gchild = _legacy_escaped_chain("text")
    assert _claim_once() is None, \
        "a queued child of a cancelled logical chain was admitted — " \
        "the pre-0023 escaped state is dispatchable again"
    # force the dispatch anyway (a stale/legacy claim that bypassed
    # the gate): the executor's own pre-dispatch reconciliation must
    # still refuse, cancel truthfully, and NEVER touch the provider.
    with db_ctx() as s:
        s.execute(text("UPDATE model_jobs SET state='running', "
                       "started_at=now() WHERE job_id = :j"),
                  {"j": str(child)})
    _drive(child)
    row = _state(child)
    assert row.state == "cancelled" and row.cancel_intent is True
    assert "fence" in (row.error or "")
    assert srv.requests == [], "the escaped attempt contacted the provider"
    # and the whole chain settles consistently — the grandchild too
    g = _state(gchild)
    assert g.state == "cancelled" and g.cancel_intent is True


def test_ordinary_failed_parent_retry_chain_survives_the_fence(
        client, users, srv, monkeypatch):
    """The complement the fence must NEVER touch: a FAILED parent with
    a queued retry child is an ordinary logical request — no cancelled
    row anywhere — and its retry dispatches normally."""
    _manual(monkeypatch)
    _make_profile(client, users, "r4keep", srv.base_url)
    srv.script([text_response("retry served")])
    root = uuid.uuid4()
    child = uuid.uuid4()
    with db_ctx() as s:
        prof = s.execute(select(ModelProfile)
                         .where(ModelProfile.name == "r4keep")
                         .order_by(ModelProfile.version.desc())
                         ).scalars().first()
        s.add(ModelJob(job_id=root, kind="text", priority=5,
                       profile_id=prof.profile_id, profile_name=prof.name,
                       payload={"mode": "text", "system": "s", "user": "p"},
                       state="failed", attempt=1,
                       error="upstream 500 — retry attempt 2/3 queued"))
        s.add(ModelJob(job_id=child, kind="text", priority=5,
                       profile_id=prof.profile_id, profile_name=prof.name,
                       payload={"mode": "text", "system": "s",
                                "user": "retry"},
                       state="queued", attempt=2, parent_job=root,
                       chain_root=root))
        s.commit()
    claimed = _claim_once()
    assert claimed == child          # legitimate retry: admitted
    _drive(child)
    assert _state(child).state == "succeeded"
    assert len(srv.requests) == 1


# --------------------------------------------------------------------------- #
# F3: dependency success = succeeded summary WITH its checkpoint               #
# --------------------------------------------------------------------------- #

def _enqueue_summary(client, users, sid, name, *, key="sk-r4sum",
                     covers_through=1):
    from srplatform import model_jobs
    payload = {"mode": "text", "system": "SUM", "user": "SUM",
               "persist": {"session_id": str(sid)}}
    if covers_through is not None:
        payload["covers_through"] = int(covers_through)
    with db_ctx() as s:
        prof = s.execute(select(ModelProfile)
                         .where(ModelProfile.name == name)
                         .order_by(ModelProfile.version.desc())
                         ).scalars().first()
        job = model_jobs.enqueue(s, kind="summarize", priority=5,
                                 profile=prof, payload=payload)
        return job.job_id


def _enqueue_gated(sid, dep_id, text="GATED-TURN"):
    from srplatform import model_jobs
    with db_ctx() as s:
        prof = s.execute(select(ModelProfile)
                         .where(ModelProfile.name == "r4dep")
                         .order_by(ModelProfile.version.desc())
                         ).scalars().first()
        job = model_jobs.enqueue(
            s, kind="red-turn", priority=5, profile=prof,
            session_id=sid, depends_on=dep_id,
            payload={"mode": "text", "system": text, "user": text})
        return job.job_id


def _checkpoints(sid):
    with db_ctx() as s:
        return s.execute(select(ConversationRevision).where(
            ConversationRevision.session_id == sid,
            ConversationRevision.kind == "checkpoint")).scalars().all()


def _timeout_profile(client, users, name, base_url, timeout_s=5):
    r = client.post("/admin/model/profiles", headers=users["op"], json={
        "name": name, "base_url": base_url, "model_name": "fake",
        "api_key": "sk-r4slow", "timeout_s": timeout_s})
    assert r.status_code in (200, 201), r.text


def test_resolved_cessation_of_a_summary_never_authorizes_the_gated_turn(
        client, users, srv, monkeypatch):
    """Reviewer's exact sequence: the summary call ends UNCERTAIN
    (client timeout), an operator audits and releases the slot
    (``resolve_cessation``), and the gated turn must STILL refuse. A
    resolution created no summary and no checkpoint — dispatching the
    native turn now would send the uncompacted, over-budget context.
    Nothing may reach the provider for the dependent, ever."""
    from srplatform import model_jobs
    _timeout_profile(client, users, "r4dep", srv.base_url)
    sid = _session(client, users)
    srv.script([dict(text_response("too late to matter"), _gate="hold")])
    sum_id = _enqueue_summary(client, users, sid, "r4dep")
    gate_id = _enqueue_gated(sid, sum_id)
    model_jobs.start_model_jobs()          # REAL scheduler
    srv.wait_requests(1)
    done = _wait_job(sum_id, timeout_s=40.0, state_terminal=True)
    srv.release("hold")
    assert done.state == "cessation_unknown", \
        f"expected the timeout to hold the obligation, got {done.state}"
    with db_ctx() as s:
        model_jobs.resolve_cessation(s, sum_id, actor="operator",
                                     resolution="provider confirmed stopped")
    # the dependent may now be admitted (chain quiescent) — and must
    # refuse with the truthful reason, without contacting the provider
    claimed = _claim_once()
    assert claimed == gate_id
    _drive(gate_id)
    row = _state(gate_id)
    assert row.state == "failed"
    assert "cessation_resolved" in row.error and "did not succeed" in row.error
    assert _checkpoints(sid) == []
    bodies = [r["body"]["messages"][0]["content"] for r in srv.requests]
    assert bodies == ["SUM"], \
        f"the gated turn was dispatched: {bodies}"


def test_summary_success_without_checkpoint_blocks_the_gated_turn(
        client, users, srv, monkeypatch):
    """A summary attempt can end ``succeeded`` while its checkpoint
    never materialized (no durable coverage artifact). The state label
    alone must not authorize the dependent: no checkpoint row, no
    dispatch, and the refusal names the missing checkpoint."""
    _manual(monkeypatch)
    _make_profile(client, users, "r4dep", srv.base_url)
    sid = _session(client, users)
    srv.script([text_response("summary without coverage")])
    sum_id = _enqueue_summary(client, users, sid, "r4dep",
                              covers_through=None)
    gate_id = _enqueue_gated(sid, sum_id)
    assert _claim_once() == sum_id
    _drive(sum_id)
    assert _state(sum_id).state == "succeeded"
    assert _checkpoints(sid) == []
    assert _claim_once() == gate_id          # quiescent: admitted…
    _drive(gate_id)                          # …then refused, truthfully
    row = _state(gate_id)
    assert row.state == "failed"
    assert "checkpoint" in row.error and "uncompacted" in row.error
    bodies = [r["body"]["messages"][0]["content"] for r in srv.requests]
    assert bodies == ["SUM"]                 # provider never saw the turn


def test_summary_retry_with_checkpoint_dispatches_the_gated_turn(
        client, users, srv, monkeypatch):
    """Positive control through the reworked logic: 500 → bounded retry
    → the retry's summary persists its coverage-bounded checkpoint →
    the gated turn dispatches EXACTLY ONCE with the real call."""
    _manual(monkeypatch)
    from srplatform import model_jobs
    monkeypatch.setattr(model_jobs, "RETRY_DELAYS", (0.1, 0.1))
    _make_profile(client, users, "r4dep", srv.base_url)
    sid = _session(client, users)
    srv.script([_ERR500, text_response("summary v2"),
                text_response("native ok")])
    sum_id = _enqueue_summary(client, users, sid, "r4dep")
    gate_id = _enqueue_gated(sid, sum_id)
    assert _claim_once() == sum_id
    _drive(sum_id)                            # attempt 1 fails → child
    with db_ctx() as s:
        s.execute(text("UPDATE model_jobs SET requested_at = now() "
                       "WHERE parent_job = :p AND state = 'queued'"),
                  {"p": str(sum_id)})
        child = s.execute(select(ModelJob).where(
            ModelJob.parent_job == sum_id)).scalars().first().job_id
    # The claim takes the legitimate retry child, NOT the gated turn —
    # and the gated turn was queued EARLIER than the child, so a
    # broken dependency gate would have picked IT first by FIFO.
    assert _claim_once() == child
    _drive(child)
    assert _state(child).state == "succeeded"
    cps = _checkpoints(sid)
    assert len(cps) == 1 and cps[0].payload["covers_through"] == 1
    assert _claim_once() == gate_id
    _drive(gate_id)
    assert _state(gate_id).state == "succeeded"
    bodies = [r["body"]["messages"][0]["content"] for r in srv.requests]
    assert bodies == ["SUM", "SUM", "GATED-TURN"]


# --------------------------------------------------------------------------- #
# pinned-v1 proof (test-quality finding): pin FIRST, edit AFTER                #
# --------------------------------------------------------------------------- #

def test_pinned_session_keeps_serving_from_the_pinned_profile(client,
                                                              users, srv):
    """The pin proof the round-3 test missed: the session's FIRST
    served turn freezes the pin while v1 is active (bind_for freezes
    all roles on first use); THEN a non-secret edit points v2 at a
    DEAD provider URL and a same-key resave makes v3. The next
    provider call through the SAME session must still be served by
    v1 — if the session followed the active version it would hit the
    dead URL and 502 (that is exactly how the pre-fix form of this
    test failed)."""
    from tests.test_plan19_model_admin import _mint_runner_token
    dead = "http://127.0.0.1:1/v1"
    _make_profile(client, users, "r4pin", srv.base_url, key="sk-r4-pin")
    client.put("/admin/model/roles", headers=users["op"],
               json={"role": "attacker", "profile_name": "r4pin"})
    sid = _session(client, users)
    tok = _mint_runner_token(sid)
    srv.script([text_response("served by v1 — freeze"),
                text_response("served by v1 — after")],
               auth="Bearer sk-r4-pin")
    r1 = client.post("/internal/model/turn",
                     headers={"Authorization": f"Bearer {tok}"},
                     json={"system": "s", "user": "pin the version"})
    assert r1.status_code == 200, r1.text   # first use FREEZES the pin (v1)
    # v2: non-secret edit pointing at an unreachable provider
    r = client.post("/admin/model/profiles/r4pin/revise",
                    headers=users["op"],
                    json={"name": "r4pin", "base_url": dead})
    assert r.status_code == 200, r.text
    # v3: GUI resave of the SAME key — still a non-secret edit
    r = client.post("/admin/model/profiles/r4pin/revise",
                    headers=users["op"],
                    json={"name": "r4pin", "api_key": "sk-r4-pin"})
    assert r.status_code == 200, r.text
    st = _rows("r4pin")
    assert st[3] == "active" and all(v != "revoked" for v in st.values())

    r2 = client.post("/internal/model/turn",
                     headers={"Authorization": f"Bearer {tok}"},
                     json={"system": "s", "user": "still v1?"})
    assert r2.status_code == 200, \
        f"pinned session lost its profile: {r2.status_code} {r2.text[:300]}"
    assert len(srv.requests) == 2
