"""Shared fixtures — reproducible, disposable, explicit (audit F22 / Phase A).

Database tests run against a REAL Postgres because append-only enforcement is a
database-level guarantee and must not be mocked. But the old fixture was neither
disposable nor explicit (fixed `sparring_range_test` name, hardcoded `su
postgres`, dev roles). This version:

  * Admin access is EXPLICIT, one of:
      SR_PG_ADMIN_URL   superuser SQLAlchemy URL (what CI uses), e.g.
                        postgresql+psycopg2://postgres:ci@localhost:5432/postgres
      SR_PG_ADMIN_CMD   command prefix that executes its argument string as the
                        admin OS user, e.g. `su postgres -c` (single-host dev).
    Without either, DB-marked tests SKIP with instructions — they never touch a
    developer's cluster implicitly and never fail destructively.
  * Every test session creates a UNIQUE database (`srtest_<hex>`) plus unique
    owner/app roles, migrates it with the real Alembic path, and drops
    everything afterwards. Defensive guards refuse to touch non-`srtest_` names.
  * `sys.executable` is used everywhere (no `.venv` assumption).
  * Environment, settings/engine caches, and module singletons are restored
    after the session so test order doesn't leak.

Proxmox/GPU/range-host boundaries use test doubles (Drew owns that reality).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable  # never assume .venv/bin/python (audit F22)

DB_NAME_PREFIX = "srtest_"
FORBIDDEN_DB_NAMES = {"postgres", "template0", "template1", "sparring_range", "sparring_range_test"}

# --------------------------------------------------------------------------- #
# Layer classification (milestone 01): a test can never leak a prerequisite.   #
# --------------------------------------------------------------------------- #
# Integration-layer markers are DERIVED from the fixture closure: any test
# whose fixture graph touches the disposable DB (`migrated_db` is the single
# DB chokepoint) is `db`; any test using the real-supervisor containment
# fixture is `containment`. Explicit markers remain valid and additive. This
# closes the baseline's unmarked-DB-dependency leak (r04) structurally.
_DB_FIXTURE = "migrated_db"
_CONTAINMENT_FIXTURES = {"local_supervisor"}

# Required-mode environment flags: with the flag set to 1, a test of that
# layer that SKIPS is converted to a FAILURE — a skipped required test is
# never acceptance (audit F8). Prerequisite absence itself fails inside the
# layer helpers with the exact missing prerequisite.
REQUIRED_LAYER_ENV = {
    "db": "SR_REQUIRE_DB",
    "containment": "SR_REQUIRE_CONTAINMENT",
    "packet": "SR_REQUIRE_PACKET",
    "authority": "SR_REQUIRE_AUTHORITY",
    "adapter": "SR_REQUIRE_ADAPTER",
    "browser": "SR_REQUIRE_BROWSER",
    "live": "SR_REQUIRE_LIVE",
    "images": "SR_REQUIRE_IMAGES",
    "capture": "SR_REQUIRE_CAPTURE",
    "hypervisor": "SR_REQUIRE_HYPERVISOR",
    "access": "SR_REQUIRE_ACCESS",
    "journey": "SR_REQUIRE_JOURNEY",
    "agent": "SR_REQUIRE_AGENT",
}


def pytest_collection_modifyitems(config, items):
    for item in items:
        names = set(getattr(item, "fixturenames", ()))
        if _DB_FIXTURE in names:
            item.add_marker(pytest.mark.db)
        if _CONTAINMENT_FIXTURES & names:
            item.add_marker(pytest.mark.containment)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if not report.skipped:
        return
    for layer, env in REQUIRED_LAYER_ENV.items():
        if os.environ.get(env) == "1" and item.get_closest_marker(layer):
            reason = getattr(report, "longrepr", "")
            if isinstance(reason, tuple) and len(reason) == 3:
                reason = reason[2]
            report.outcome = "failed"
            report.longrepr = (
                f"required layer {layer!r} ({env}=1) test was SKIPPED — a skip "
                f"is never acceptance: {reason}")
            break


def _safe_db_name(name: str) -> str:
    assert re.fullmatch(rf"{DB_NAME_PREFIX}[a-z0-9_]+", name), f"refusing to touch {name!r}"
    assert name not in FORBIDDEN_DB_NAMES
    return name


def _admin_available() -> bool:
    return bool(os.environ.get("SR_PG_ADMIN_URL") or os.environ.get("SR_PG_ADMIN_CMD"))


def _admin_endpoint() -> tuple[str, int]:
    """Host/port the per-test databases live on — DERIVED from the explicit
    admin endpoint (milestone 01: no hardcoded localhost:5432; the Docker
    fixture may use any loopback port). SR_PG_ADMIN_CMD means the local
    cluster unless SR_PG_ADMIN_HOST/PORT say otherwise."""
    url = os.environ.get("SR_PG_ADMIN_URL")
    if url:
        from sqlalchemy.engine import make_url
        u = make_url(url)
        return u.host or "localhost", int(u.port or 5432)
    return (os.environ.get("SR_PG_ADMIN_HOST", "localhost"),
            int(os.environ.get("SR_PG_ADMIN_PORT", "5432")))


def _admin_sql(sql: str) -> None:
    """Run admin SQL through the explicitly configured mechanism only."""
    url = os.environ.get("SR_PG_ADMIN_URL")
    if url:
        from sqlalchemy import create_engine, text

        # AUTOCOMMIT: CREATE/DROP DATABASE and role ops cannot run inside a
        # transaction block (psycopg2 ActiveSqlTransaction otherwise).
        eng = create_engine(url).execution_options(isolation_level="AUTOCOMMIT")
        try:
            with eng.connect() as conn:
                conn.execute(text(sql))
        finally:
            eng.dispose()
        return
    cmd = os.environ.get("SR_PG_ADMIN_CMD")
    if cmd:
        # Write to a world-readable temp file: avoids all nested-quoting hazards
        # (`su postgres -c` cannot receive argument vectors anyway).
        fd, path = tempfile.mkstemp(suffix=".sql", prefix="srtest_admin_")
        os.chmod(path, 0o644)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(sql + "\n")
            r = subprocess.run(f'{cmd} "psql -X -q -v ON_ERROR_STOP=1 -f {path}"',
                               shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f"admin psql failed: {r.stderr or r.stdout}")
        finally:
            os.unlink(path)
        return
    raise RuntimeError("no explicit Postgres admin configured (SR_PG_ADMIN_URL / SR_PG_ADMIN_CMD)")


@pytest.fixture(scope="session")
def pg_names() -> dict:
    """Unique names for this test session's disposable database."""
    hex8 = uuid.uuid4().hex[:8]
    return {"db": _safe_db_name(f"{DB_NAME_PREFIX}{hex8}"),
            "owner": f"sro_{hex8}", "app": f"sra_{hex8}",
            "secret": f"srs_{hex8}",
            "owner_pw": f"o_{uuid.uuid4().hex}", "app_pw": f"a_{uuid.uuid4().hex}",
            "secret_pw": f"s_{uuid.uuid4().hex}"}


@pytest.fixture(scope="session")
def test_db_url_secret(pg_names) -> str:
    """The dedicated SECRET-role identity (plan 19 review finding 8):
    grants on exactly one table — model_profile_secrets."""
    host, port = _admin_endpoint()
    return (f"postgresql+psycopg2://{pg_names['secret']}:{pg_names['secret_pw']}"
            f"@{host}:{port}/{pg_names['db']}")


@pytest.fixture(scope="session")
def test_db_url_app(pg_names) -> str:
    host, port = _admin_endpoint()
    return (f"postgresql+psycopg2://{pg_names['app']}:{pg_names['app_pw']}"
            f"@{host}:{port}/{pg_names['db']}")


@pytest.fixture(scope="session")
def test_db_url_owner(pg_names) -> str:
    host, port = _admin_endpoint()
    return (f"postgresql+psycopg2://{pg_names['owner']}:{pg_names['owner_pw']}"
            f"@{host}:{port}/{pg_names['db']}")


@pytest.fixture(scope="session")
def migrated_db(pg_names, test_db_url_owner, test_db_url_app,
                test_db_url_secret):
    """Fresh schema in a UNIQUE disposable DB via the real migration path."""
    if not _admin_available():
        pytest.skip("no explicit Postgres admin (set SR_PG_ADMIN_URL or SR_PG_ADMIN_CMD) "
                    "— DB tests are opt-in; see tests/conftest.py docstring")
    n = pg_names
    _admin_sql(f"CREATE ROLE {n['owner']} LOGIN PASSWORD '{n['owner_pw']}'")
    _admin_sql(f"CREATE ROLE {n['app']} LOGIN PASSWORD '{n['app_pw']}'")
    _admin_sql(f"CREATE ROLE {n['secret']} LOGIN PASSWORD '{n['secret_pw']}'")
    # explicit UTF8: cluster defaults may be SQL_ASCII, which breaks JSONB unicode
    _admin_sql(f"CREATE DATABASE {n['db']} OWNER {n['owner']} ENCODING 'UTF8' "
               f"TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'")

    saved = {k: os.environ.get(k) for k in
             ("POSTGRES_URL", "POSTGRES_URL_OWNER", "POSTGRES_URL_SECRET",
              "DB_APP_ROLE", "DB_SECRET_ROLE")}
    os.environ.update(POSTGRES_URL=test_db_url_app,
                      POSTGRES_URL_OWNER=test_db_url_owner,
                      POSTGRES_URL_SECRET=test_db_url_secret,
                      DB_APP_ROLE=n["app"],
                      DB_SECRET_ROLE=n["secret"])

    def _clear_app_caches():
        try:
            from srplatform import settings as s
            s.get_settings.cache_clear()
            from srplatform.db import session as dbs
            dbs.owner_engine.cache_clear()
            dbs.app_engine.cache_clear()
            from srplatform import secret_store
            secret_store.dispose()
        except Exception:
            pass

    _clear_app_caches()
    try:
        env = {**os.environ, "POSTGRES_URL_OWNER": test_db_url_owner,
               "DB_APP_ROLE": n["app"], "DB_SECRET_ROLE": n["secret"]}
        r = subprocess.run([PY, "-m", "alembic", "upgrade", "head"],
                           cwd=REPO_ROOT, env=env, capture_output=True, text=True)
        assert r.returncode == 0, f"alembic failed:\n{r.stdout}\n{r.stderr}"
        yield test_db_url_owner
    finally:
        # tear the whole thing down — nothing survives the session
        try:
            from srplatform import secret_store
            secret_store.dispose()
        except Exception:
            pass
        try:
            _admin_sql(
                f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{n['db']}'")
            _admin_sql(f"DROP DATABASE IF EXISTS {n['db']}")
            _admin_sql(f"DROP ROLE IF EXISTS {n['owner']}")
            _admin_sql(f"DROP ROLE IF EXISTS {n['app']}")
            _admin_sql(f"DROP ROLE IF EXISTS {n['secret']}")
        except Exception as e:  # noqa: BLE001 — teardown failure must not mask test results
            print(f"[conftest] teardown warning: could not drop {n['db']}: {e}", file=sys.stderr)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        _clear_app_caches()
        _reset_singletons()


def _reset_singletons() -> None:
    """Module-level singletons must not survive a settings/DB swap (F22)."""
    try:
        from srplatform.safety import set_supervisor
        set_supervisor(None)
    except Exception:
        pass
    try:
        from srplatform.api import deps
        deps.set_broker(None)
    except Exception:
        pass
    try:
        from srplatform.api import coach_routes
        coach_routes.set_coach_llm(None)
    except Exception:
        pass
    try:
        # plan 19: the job scheduler thread must not outlive a settings/DB
        # swap (it polls through the engine that is about to be reset)
        from srplatform import model_jobs
        model_jobs.stop_model_jobs()
    except Exception:
        pass
    try:
        # the secret store has its OWN engine; it must not outlive the DB
        from srplatform import secret_store
        secret_store.dispose()
    except Exception:
        pass


@pytest.fixture
def clean_singletons():
    """Function-scoped guard for tests that swap global doubles."""
    yield
    _reset_singletons()


# -------------------------------------------------------------------------- #
# Authenticated API client harness (used by every lifecycle test)            #
# -------------------------------------------------------------------------- #

@pytest.fixture()
def env_dirs(migrated_db, tmp_path, monkeypatch, test_db_url_secret):
    """Point ALL filesystem/URL knobs at disposable locations. Env vars beat
    .env for pydantic-settings, so no dotenv games are needed."""
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("POSTGRES_URL_SECRET", test_db_url_secret)
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety_state.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "recordings"))
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")   # fixture-only transport
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")  # isolated fixtures only
    monkeypatch.setenv("API_BASE_URL", "http://127.0.0.1:1")  # nothing listens: accidental
    #                                              # outbound calls fail fast & loudly
    monkeypatch.setenv("MODEL_API_KEY", "")
    # uptime prober OFF by default: background probe threads would race the
    # deterministic db tests; the uptime tests enable it explicitly
    monkeypatch.setenv("UPTIME_SCORING_ENABLED", "0")
    from srplatform import settings as s
    s.get_settings.cache_clear()
    yield tmp_path
    s.get_settings.cache_clear()


@pytest.fixture()
def fake_pve(env_dirs):
    """ProxmoxClient over FakePVEHttp: the REAL client code (verbs, UPID
    polling) against a fake HTTP boundary, with the scenario templates present.
    This is the PVE-boundary double BELOW the broker; tests inspect it via
    fake_pve.api (FakePVEHttp)."""
    from infra.proxmox_client import FakePVEHttp, ProxmoxClient

    http = FakePVEHttp()
    for vmid, name in ((9001, "tpl-web"), (9002, "tpl-dc"), (9003, "tpl-win10"),
                       (9004, "tpl-db")):
        http.vms[vmid] = {"name": name, "template": vmid, "status": "stopped"}
    return ProxmoxClient(api=http)


@pytest.fixture()
def fake_broker(env_dirs, fake_pve, tmp_path):
    """Real BrokerService (policy + SQLite ledger + typed ops) over the
    fake_pve boundary — the milestone-02 deployment authority the API uses."""
    from types import SimpleNamespace

    from infra.broker.testing import make_broker_over, policy_from_settings
    from srplatform.settings import get_settings

    client, service = make_broker_over(
        fake_pve.api, policy=policy_from_settings(get_settings()),
        ledger_path=tmp_path / "broker-ledger.sqlite3")
    return SimpleNamespace(client=client, service=service, http=fake_pve.api)


def wipe_data(db_url_owner: str) -> None:
    """Per-test isolation for the shared disposable schema (fast TRUNCATE via
    the owner role; the append-only trigger blocks DELETE/TRUNCATE on events?
    no — triggers guard UPDATE/DELETE rows; TRUNCATE is DDL owner-only)."""
    from sqlalchemy import create_engine, text
    eng = create_engine(db_url_owner)
    tables = ("events", "sessions", "agent_state", "login_tokens", "service_tokens",
              "deployments", "runs", "safety_records", "safety_state", "recordings",
              "range_lease", "users", "model_jobs", "conversation_revisions",
              "session_model_pins", "model_role_overrides", "model_profiles",
              "model_profile_secrets")
    with eng.begin() as c:
        c.execute(text("TRUNCATE " + ", ".join(tables) + " CASCADE"))
    eng.dispose()


@pytest.fixture()
def client(env_dirs, clean_singletons, fake_broker, test_db_url_owner):
    """TestClient with supervisor(noop datapath)/broker doubles injected.
    Dev mode: evidence gate relaxed (documented), latch+runner gates LIVE."""
    from fastapi.testclient import TestClient

    from srplatform.api import deps
    from srplatform.safety import Supervisor, set_supervisor
    from srplatform.safety.datapath import NoopDatapath

    wipe_data(test_db_url_owner)
    deps.set_broker(fake_broker.client)
    sup = Supervisor(datapath=NoopDatapath(),
                     state_file=str(env_dirs / "safety_state.json"))
    # audit N07: missing state is LOST state, not a healthy fresh store —
    # tests explicitly initialize the documented first-install state
    sup.initialize_state(reason="test fixture initialization")
    set_supervisor(sup)
    from srplatform.api.app import app
    import os as _os
    with TestClient(app, raise_server_exceptions=_os.environ.get("SR_TEST_RAISE") == "1") as c:
        yield c
    from srplatform import verification_service
    verification_service.set_verifier_exec(None)


OP_PW = "operator-testpw-9"
MEM_PW = "member-testpw-9"


@pytest.fixture()
def users(client):
    """Bootstrap operator + one member, with ready auth headers."""
    r = client.post("/auth/bootstrap",
                    json={"username": "drew", "password": OP_PW})
    assert r.status_code == 201, r.text
    tok = client.post("/auth/login", json={"username": "drew", "password": OP_PW}).json()["token"]
    op = {"Authorization": f"Bearer {tok}"}
    r = client.post("/users", headers=op,
                    json={"username": "blue", "password": MEM_PW, "role": "member"})
    assert r.status_code == 201, r.text
    tok2 = client.post("/auth/login", json={"username": "blue", "password": MEM_PW}).json()["token"]
    return {"op": op, "op_token": tok, "member": {"Authorization": f"Bearer {tok2}"},
            "member_token": tok2}


# --- async lifecycle helpers (plan 13 phase 5, 202 refinement) ----------------
# /launch and /reset return 202 immediately after durable acceptance; the
# supervised executor completes the attempt in the background. Tests that
# need the completed deployment poll the operation to a terminal state.
def wait_operation(client, headers, session_id, timeout_s: float = 120.0):
    """Poll GET /sessions/{id}/operation until terminal. Returns the body.
    Terminal failure returns the body too (caller asserts the outcome)."""
    import time as _t
    deadline = _t.monotonic() + timeout_s
    last = None
    while True:
        r = client.get(f"/sessions/{session_id}/operation", headers=headers)
        assert r.status_code == 200, r.text
        last = r.json()
        if last["state"] in ("succeeded", "failed", "interrupted"):
            return last
        assert _t.monotonic() < deadline, \
            f"operation {last['operation_id']} stuck in {last['state']}/{last['phase']}"
        _t.sleep(0.2)


def launch_and_wait(client, headers, session_id, timeout_s: float = 120.0):
    """POST /launch (expect 202 accepted) then wait for completion. Returns
    the operation body including the redacted `result` on success."""
    r = client.post(f"/sessions/{session_id}/launch", headers=headers)
    assert r.status_code == 202, r.text
    body = wait_operation(client, headers, session_id, timeout_s)
    assert body["state"] == "succeeded", body
    return body


def reset_and_wait(client, headers, session_id, timeout_s: float = 120.0):
    r = client.post(f"/sessions/{session_id}/reset", headers=headers)
    assert r.status_code == 202, r.text
    body = wait_operation(client, headers, session_id, timeout_s)
    assert body["state"] == "succeeded", body
    return body
