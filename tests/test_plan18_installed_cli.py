"""Plan 18 — installed-package rangectl outside the checkout (criterion 6).

The appliance's `rangectl db migrate`/`status` must work the way an
operator actually runs it: non-editable package layout, arbitrary working
directory, no source checkout in sight. The historical defect: the
checked-in alembic.ini spells script_location relative to the project
root, Alembic resolves it against the process CWD, and outside the
checkout migrate/status failed with a path error that looked like a
broken installation.

* Fast layer: a site-packages-style copy of the packages, driven from
  OUTSIDE this checkout, proves the root lookup follows the installed
  package and that the resolved config reaches the migrations with
  absolute paths — tree case (alembic.ini present) and pure case
  (synthesised fallback config).
* DB layer (gated on the explicit disposable Postgres admin): the same
  installed copy runs the REAL `db migrate` then `db status` against a
  freshly created database and must reach head.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import uuid

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
PACKAGES = ("srplatform", "rangectl", "verifiers", "infra", "telemetry")


def _install_copy(dest: pathlib.Path, *, with_ini: bool) -> pathlib.Path:
    """A non-editable, site-packages-style layout: packages copied, no
    checkout relationship, editable finder shadowed via PYTHONPATH."""
    dest.mkdir(parents=True)
    for pkg in PACKAGES:
        src = REPO / pkg
        if src.is_dir():
            shutil.copytree(src, dest / pkg,
                            ignore=shutil.ignore_patterns("__pycache__",
                                                          "*.pyc"))
    if with_ini:
        shutil.copy2(REPO / "alembic.ini", dest / "alembic.ini")
    return dest


def _run(args: list[str], cwd: pathlib.Path, installed: pathlib.Path,
         env_extra: dict | None = None):
    env = {**os.environ, "PYTHONPATH": str(installed)}
    env.pop("SR_ALEMBIC_ROOT", None)
    env.update(env_extra or {})
    assert str(REPO) not in str(cwd)
    return subprocess.run(args, cwd=str(cwd), env=env,
                          capture_output=True, text=True, timeout=600)


_RESOLVE = (
    "import pathlib, srplatform, rangectl;"
    "assert srplatform.__file__ != %r, 'imported the checkout, not the copy';"
    "from rangectl.commands.db import _alembic_root, _alembic_config_path;"
    "root=_alembic_root();"
    "assert str(root) == %r, f'root lookup resolved to {root}';"
    "ctx = _alembic_config_path(root); p = ctx.__enter__();"
    "body = pathlib.Path(p).read_text(); ctx.__exit__(None, None, None);"
    "assert not pathlib.Path(p).exists(), 'private config leaked past its context';"
    "print(body, end='')"
)


@pytest.mark.parametrize("with_ini", (True, False),
                         ids=("tree-copy", "pure-installed"))
def test_installed_config_reaches_migrations_outside_checkout(tmp_path,
                                                              with_ini):
    installed = _install_copy(tmp_path / "site", with_ini=with_ini)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    r = _run([sys.executable, "-c",
              _RESOLVE % (str(REPO / "srplatform" / "__init__.py"),
                          str(installed))],
             elsewhere, installed)
    assert r.returncode == 0, r.stderr
    # the resolve printed the CONFIG BODY and cleaned its own private temp
    # file; the test re-materialises it in ITS OWN directory (never a
    # shared-temp path it did not create)
    assert r.stdout.startswith("[alembic]") or "script_location" in r.stdout, \
        r.stdout
    cfg_file = elsewhere / "resolved-alembic.ini"
    cfg_file.write_text(r.stdout)
    cfg = str(cfg_file)
    text = cfg_file.read_text()
    assert "script_location = " in text
    line = [l for l in text.splitlines()
            if l.startswith("script_location")][0]
    location = line.split("=", 1)[1].strip()
    assert location.startswith("/") and str(installed) in location
    migrations = pathlib.Path(location)
    assert (migrations / "env.py").is_file()
    assert list((migrations / "versions").glob("*.py"))

    # the proof: alembic reads the full history from outside the checkout
    h = _run([sys.executable, "-m", "alembic", "-c", cfg, "history"],
             elsewhere, installed)
    assert h.returncode == 0, h.stderr
    assert h.stdout.strip(), "history empty — migrations not found"


# --------------------------------------------------------------------------- #
# DB layer: the REAL migrate + status from outside the checkout                #
# --------------------------------------------------------------------------- #

pytest_db = pytest.mark.db


@pytest_db
def test_installed_migrate_and_status_reach_head(tmp_path):
    from tests.conftest import _admin_available, _admin_sql
    if not _admin_available():
        pytest.skip("no explicit Postgres admin (SR_PG_ADMIN_URL/CMD) — "
                    "installed-CLI DB acceptance is opt-in")
    hex8 = uuid.uuid4().hex[:8]
    db, owner, app_role = f"srtest_inst{hex8}", f"sro_i{hex8}", f"sra_i{hex8}"
    owner_pw, app_pw = f"o_{hex8}", f"a_{hex8}"
    host = os.environ.get("SR_PG_ADMIN_HOST", "localhost")
    port = os.environ.get("SR_PG_ADMIN_PORT", "5432")
    if url := os.environ.get("SR_PG_ADMIN_URL"):
        from sqlalchemy.engine import make_url
        u = make_url(url)
        host, port = u.host or "localhost", int(u.port or 5432)
    installed = _install_copy(tmp_path / "site", with_ini=False)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env = {"POSTGRES_URL_OWNER":
           f"postgresql+psycopg2://{owner}:{owner_pw}@{host}:{port}/{db}",
           "DB_APP_ROLE": app_role}
    try:
        _admin_sql(f"CREATE ROLE {owner} LOGIN PASSWORD '{owner_pw}'")
        _admin_sql(f"CREATE ROLE {app_role} LOGIN PASSWORD '{app_pw}'")
        _admin_sql(f"CREATE DATABASE {db} OWNER {owner} ENCODING 'UTF8' "
                   "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'")

        m = _run([sys.executable, "-c",
                  "from rangectl.cli import app; app()",
                  "db", "migrate"], elsewhere, installed, env)
        assert m.returncode == 0, (m.stdout, m.stderr)
        assert "Running" in (m.stdout + m.stderr), \
            "migrate reported no upgrade steps for a fresh database"

        s = _run([sys.executable, "-c",
                  "from rangectl.cli import app; app()",
                  "db", "status"], elsewhere, installed, env)
        assert s.returncode == 0, (s.stdout, s.stderr)
        assert "(head)" in s.stdout, f"status did not reach head: {s.stdout}"

        # rerun must be a clean no-op (idempotent installed migrate)
        m2 = _run([sys.executable, "-c",
                   "from rangectl.cli import app; app()",
                   "db", "migrate"], elsewhere, installed, env)
        assert m2.returncode == 0, (m2.stdout, m2.stderr)
    finally:
        for stmt in (f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                     f"WHERE datname='{db}'",
                     f"DROP DATABASE IF EXISTS {db}",
                     f"DROP ROLE IF EXISTS {owner}",
                     f"DROP ROLE IF EXISTS {app_role}"):
            try:
                _admin_sql(stmt)
            except Exception:
                pass
