"""Fast regressions for honest live-practice operational diagnostics."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

import pytest
from pydantic import ValidationError


def test_role_budgets_are_configurable_and_positive(monkeypatch):
    from srplatform.settings import Settings
    monkeypatch.setenv("SR_LLM_MAX_TOKENS_RED", "4096")
    monkeypatch.setenv("SR_LLM_MAX_TOKENS_COACH", "6144")
    settings = Settings(_env_file=None)
    assert settings.llm_max_tokens_red == 4096
    assert settings.llm_max_tokens_coach == 6144
    for value in (0, -1, 32769):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, llm_max_tokens_red=value)


def test_rejected_completion_is_not_retried(monkeypatch):
    from srplatform.model_gateway import ModelGateway
    from srplatform.red_agent.llm import CompletionRejected
    calls = []
    def rejected():
        calls.append(True)
        raise CompletionRejected("token budget exhausted")
    # Exercise the retry implementation without starting a background worker.
    gateway = object.__new__(ModelGateway)
    gateway.metrics = {"last_error": None}
    with pytest.raises(CompletionRejected):
        gateway._execute("red", rejected, (), {})
    assert len(calls) == 1


class _StubSession:
    """The complete route reads the server-authoritative match deadline
    (round-2 finding 8); this stub answers 'no match row' — no cap."""

    def execute(self, *a, **k):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(
            first=lambda: None))


def test_internal_model_rejection_is_explicit_bad_gateway(monkeypatch):
    """A failed DURABLE JOB (here: a rejected completion) is an explicit
    502 with the truthful error — never a fake success and never a silent
    substitution of another profile."""
    from contextlib import contextmanager

    from fastapi import HTTPException
    import srplatform.api.app as app_module
    from srplatform.api.app import ModelCompleteIn, internal_model_complete
    import srplatform.model_admin as ma
    import srplatform.model_jobs as mj

    class _FailedJob:
        job_id = None
        state = "failed"
        result = None
        error = "model request failed: token budget exhausted"

    _FailedJob.job_id = uuid.uuid4()

    @contextmanager
    def _fake_db():
        yield _StubSession()

    monkeypatch.setattr(app_module, "db", _fake_db)
    monkeypatch.setattr(ma, "bind_for", lambda db, sid, role: (None, None))
    monkeypatch.setattr(
        mj, "enqueue",
        lambda *a, **k: SimpleNamespace(job_id=_FailedJob.job_id, state="queued"))
    monkeypatch.setattr(mj, "wait",
                        lambda db, jid, bound: _FailedJob())
    with pytest.raises(HTTPException) as exc:
        internal_model_complete(ModelCompleteIn(system="fixture", user="fixture"),
                                SimpleNamespace(session_id=uuid.uuid4()))
    assert exc.value.status_code == 502
    assert "token budget exhausted" in exc.value.detail


def test_internal_model_timeout_requests_cessation_never_silent_replay(monkeypatch):
    """Exceeding the wait bound must cancel the row (queued: dead; live:
    cessation requested) and answer 504 — the late answer may never be
    consumed as if the request were still open."""
    from contextlib import contextmanager

    from fastapi import HTTPException
    import srplatform.api.app as app_module
    from srplatform.api.app import ModelCompleteIn, internal_model_complete
    import srplatform.model_admin as ma
    import srplatform.model_jobs as mj

    jid = uuid.uuid4()
    cancelled = []

    @contextmanager
    def _fake_db():
        yield _StubSession()

    def _bound_exceeded(db, id_, bound):
        raise TimeoutError("bound")

    monkeypatch.setattr(app_module, "db", _fake_db)
    monkeypatch.setattr(ma, "bind_for", lambda db, sid, role: (None, None))
    monkeypatch.setattr(mj, "enqueue",
                        lambda *a, **k: SimpleNamespace(job_id=jid, state="queued"))
    monkeypatch.setattr(mj, "wait", _bound_exceeded)
    monkeypatch.setattr(mj, "cancel",
                        lambda db, id_, *, actor="": cancelled.append(id_))
    with pytest.raises(HTTPException) as exc:
        internal_model_complete(ModelCompleteIn(system="fixture", user="fixture"),
                                SimpleNamespace(session_id=uuid.uuid4()))
    assert exc.value.status_code == 504
    assert cancelled == [jid]


@pytest.mark.parametrize("sealed", [False, True])
def test_failed_attacker_is_visible_without_exposing_credentials(sealed):
    from srplatform.api.web_routes import _attacker_projection
    now = datetime.now(timezone.utc)
    run = SimpleNamespace(
        run_id=uuid.uuid4(), status="failed", outcome="model_unavailable",
        error="private command details", worker_token="secret", result={"secret": True},
        started_at=now - timedelta(minutes=8), worker_heartbeat_at=now - timedelta(seconds=5))
    event = SimpleNamespace(ingested_at=now - timedelta(minutes=6), action_type="action_result")
    result = _attacker_projection(run, event, sealed=sealed, now=now)
    assert result["status"] == "failed"
    assert result["event_age_s"] == 360
    assert result["heartbeat_age_s"] == 5
    assert "worker_token" not in result and "result" not in result
    assert result["error"] == ("Attacker failed; operator diagnostics required" if sealed else run.error)
    assert result["last_event_kind"] == (None if sealed else "action_result")
    assert result["outcome"] == (None if sealed else run.outcome)


def test_no_event_is_not_fabricated_progress():
    from srplatform.api.web_routes import _attacker_projection
    now = datetime.now(timezone.utc)
    run = SimpleNamespace(run_id=uuid.uuid4(), status="running", outcome=None,
                          error=None, started_at=now - timedelta(seconds=301),
                          worker_heartbeat_at=None)
    result = _attacker_projection(run, None, sealed=False, now=now)
    assert result["last_event_at"] is None
    assert result["event_age_s"] == 301
    assert result["heartbeat_age_s"] is None
    assert _attacker_projection(None, None, sealed=False, now=now) is None


@pytest.mark.parametrize("mode", ["practice", "competition"])
def test_live_api_separates_failed_attacker_from_match(client, users, mode):
    from srplatform.db.models import Event, Run, Session as SessionModel
    from srplatform.db.session import db as db_ctx
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01", "mode": mode},
                      headers=users["member"]).json()["session_id"]
    now = datetime.now(timezone.utc)
    with db_ctx() as db:
        db.get(SessionModel, uuid.UUID(sid)).status = "running"
        db.add(Run(session_id=uuid.UUID(sid), scenario_id="web-foothold-01",
                   status="failed", outcome="model_unavailable", error="private diagnostic",
                   started_at=now - timedelta(minutes=6), ended_at=now))
        db.add(Event(session_id=uuid.UUID(sid), ts=now, actor="red",
                     action_type="agent_note", payload={"model_error": "private diagnostic"}))
    result = client.get(f"/sessions/{sid}/live", headers=users["member"])
    assert result.status_code == 200, result.text
    live = result.json()
    assert live["status"] == "running"
    assert live["attacker"]["status"] == "failed"
    assert live["attacker"]["error"] == ("private diagnostic" if mode == "practice"
                                              else "Attacker failed; operator diagnostics required")
    assert live["attacker"]["last_event_kind"] == ("agent_note" if mode == "practice" else None)
    operator_live = client.get(f"/sessions/{sid}/live", headers=users["op"]).json()
    assert operator_live["attacker"]["error"] == "private diagnostic"


def test_aar_keeps_deterministic_report_when_narrative_rejected(client, users, monkeypatch):
    from srplatform.api import coach_routes
    from srplatform.red_agent.llm import CompletionRejected
    class TruncatedCoach:
        def complete(self, *args, **kwargs):
            raise CompletionRejected("token budget exhausted")
    monkeypatch.setattr(coach_routes, "_coach_llm", TruncatedCoach())
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    result = client.post(f"/sessions/{sid}/aar", json={"regenerate": True},
                         headers=users["member"])
    assert result.status_code == 200, result.text
    report = result.json()
    assert report["persisted"] is True
    assert "UNSCORED" in report["markdown"]
    assert report["grade"] is None


def test_model_outage_completion_is_failed_not_success(client, users):
    import hashlib
    from srplatform.api import runs
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    token = "synthetic-worker-token"
    run_id = uuid.uuid4()
    with db_ctx() as db:
        db.add(Run(run_id=run_id, session_id=uuid.UUID(sid), scenario_id="quick-win-01",
                   status="running", worker_token=hashlib.sha256(token.encode()).hexdigest(),
                   started_at=datetime.now(timezone.utc)))
    with db_ctx() as db:
        runs.complete_run(db, run_id, token, {"outcome": "model_unavailable"})
    with db_ctx() as db:
        run = db.get(Run, run_id)
        assert run.status == "failed"
        assert run.outcome == "model_unavailable"
        assert "model unavailable" in run.error
