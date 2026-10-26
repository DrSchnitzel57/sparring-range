"""Plan 19 review round 2 (finding 10, fast half): the credential-store
deployment contract WITHOUT a database — the documented env alias, the
installer's secret-role provisioning, and which units may load the
secret URL."""
from __future__ import annotations

import os
import pathlib

from deploy import appliance_services as svc

ROOT = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# settings: the DOCUMENTED name resolves; old names keep working               #
# --------------------------------------------------------------------------- #

def _settings_secret_url(monkeypatch, env):
    from srplatform.settings import Settings
    for k in ("SR_PG_SECRET_URL", "SR_POSTGRES_URL_SECRET",
              "POSTGRES_URL_SECRET"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return Settings(_env_file=None).postgres_url_secret


def test_documented_alias_and_legacy_names_all_resolve(monkeypatch):
    # the reviewer's probe, reproduced: ONLY SR_PG_SECRET_URL set —
    # the secret connection must NOT come out empty
    assert _settings_secret_url(
        monkeypatch,
        {"SR_PG_SECRET_URL": "postgresql+psycopg2://sr_secret:pw@h/d"}
    ) == "postgresql+psycopg2://sr_secret:pw@h/d"
    assert _settings_secret_url(
        monkeypatch, {"SR_POSTGRES_URL_SECRET": "url-b"}) == "url-b"
    assert _settings_secret_url(
        monkeypatch, {"POSTGRES_URL_SECRET": "url-c"}) == "url-c"
    assert _settings_secret_url(monkeypatch, {}) == ""


# --------------------------------------------------------------------------- #
# installer: the 0021-granted role is PROVISIONED, not an operator ritual      #
# --------------------------------------------------------------------------- #

class _RunRecorder:
    def __init__(self, dry_run: bool = False):
        self.calls: list = []
        self.envs: list = []
        self.dry_run = dry_run

    def __call__(self, *args, **kwargs):
        self.calls.append([str(a) for a in args])
        if "env" in kwargs:
            self.envs.append(dict(kwargs["env"]))

    def flat(self) -> str:
        return " | ".join(" ".join(c) for c in self.calls)


def _install_fixture(tmp_path: pathlib.Path):
    prefix = tmp_path / "opt"
    (prefix / ".venv" / "bin").mkdir(parents=True)
    (prefix / ".venv" / "bin" / "alembic").write_text("#!/bin/sh\n")
    etc = tmp_path / "etc"
    (etc / "secrets").mkdir(parents=True)
    (etc / "secrets" / "db-owner.env").write_text(
        "SR_POSTGRES_URL_OWNER=postgresql+psycopg2://sr_owner:ownpw@"
        "127.0.0.1:5432/sparring_range\n")
    (etc / "control-plane.env").write_text(
        "SR_POSTGRES_URL=postgresql+psycopg2://sr_app:app pw@127.0.0.1:5432/"
        "sparring_range\n".replace("app pw", "app_pw"))
    return prefix, etc


def test_fresh_install_provisions_the_secret_role_and_api_only_file(tmp_path,
                                                                    monkeypatch):
    monkeypatch.delenv("SR_PG_SECRET_URL", raising=False)
    monkeypatch.delenv("SR_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SR_POSTGRES_URL_OWNER", raising=False)
    prefix, etc = _install_fixture(tmp_path)
    rec = _RunRecorder()
    out = svc.ensure_database(rec, prefix=prefix,
                              env_file=etc / "control-plane.env",
                              sandboxed=True)
    secret_file = etc / "secrets" / "db-secret.env"
    assert secret_file.is_file(), \
        "migration 0021 GRANTs to sr_secret — the installer must create it"
    content = secret_file.read_text()
    assert content.startswith("#")
    assert "SR_PG_SECRET_URL=postgresql+psycopg2://sr_secret:" in content
    # the generated password appears ONLY in the 0640 file — never in a
    # command line and never in the returned receipt
    generated = content.split("SR_PG_SECRET_URL=", 1)[1].split("@", 1)[0] \
        .split(":", 1)[1]
    assert len(generated) >= 16
    assert generated not in rec.flat()
    for value in out.values():
        assert generated not in str(value)
        assert "postgresql+psycopg2://" not in str(value)
    # the role-creation SQL went through the postgres-file path (the
    # password never rides a command line)
    flat = rec.flat()
    assert "CREATE ROLE sr_secret" not in flat
    assert "su postgres" in flat and "sr-sql-" in flat
    # alembic got the role NAME (its grant needs it), never the URL
    assert len(rec.envs) == 1, "only the alembic invocation takes an env"
    alembic_env = rec.envs[0]
    assert alembic_env["DB_SECRET_ROLE"] == "sr_secret"
    assert "SR_PG_SECRET_URL" not in alembic_env
    assert out["secret_role"] == "sr_secret"
    assert out["secret_role_generated"] is True
    assert out["secret_url_in_returned_data"] is False
    # round-3 finding 6: the file is created ATOMICALLY at 0600 — there
    # is no "write then hope the chmod lands" command sequence any more;
    # the mode is verified on the file itself
    mode = secret_file.stat().st_mode & 0o777
    assert mode == 0o600, f"secret file mode {oct(mode)}, expected 0600"
    assert not any("chmod" in call and call[-1].endswith("db-secret.env")
                   for call in rec.calls), \
        "secret securing must not depend on a check=False chmod afterthought"


def test_rerun_preserves_the_existing_secret_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SR_PG_SECRET_URL", raising=False)
    monkeypatch.delenv("SR_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SR_POSTGRES_URL_OWNER", raising=False)
    prefix, etc = _install_fixture(tmp_path)
    svc.ensure_database(_RunRecorder(), prefix=prefix,
                        env_file=etc / "control-plane.env", sandboxed=True)
    secret_file = etc / "secrets" / "db-secret.env"
    before = secret_file.read_text()
    rec = _RunRecorder()
    out = svc.ensure_database(rec, prefix=prefix,
                              env_file=etc / "control-plane.env",
                              sandboxed=True)
    assert secret_file.read_text() == before, \
        "a rerun re-keyed the credential-store role (would desync the DB)"
    assert out["secret_role_generated"] is False
    # an operator PROVISIONED URL with no file yet is BOOTSTRAPPED into
    # the file — sr-api.service reads it from there at boot, and the
    # installer environment dies with the installer
    monkeypatch.setenv("SR_PG_SECRET_URL",
                       "postgresql+psycopg2://sr_secret:operator-pw@h/d")
    secret_file.unlink()
    out = svc.ensure_database(_RunRecorder(), prefix=prefix,
                              env_file=etc / "control-plane.env",
                              sandboxed=True)
    assert secret_file.read_text().splitlines()[-1] == \
        "SR_PG_SECRET_URL=postgresql+psycopg2://sr_secret:operator-pw@h/d"
    assert out["secret_role_generated"] is False


def test_dry_run_writes_no_secret_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SR_PG_SECRET_URL", raising=False)
    monkeypatch.delenv("SR_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SR_POSTGRES_URL_OWNER", raising=False)
    prefix, etc = _install_fixture(tmp_path)
    svc.ensure_database(_RunRecorder(dry_run=True), prefix=prefix,
                        env_file=etc / "control-plane.env", sandboxed=True)
    assert not (etc / "secrets" / "db-secret.env").exists()


# --------------------------------------------------------------------------- #
# units: ONLY the API loads the secret URL                                     #
# --------------------------------------------------------------------------- #

def test_only_the_api_unit_loads_the_secret_url():
    api = (ROOT / "deploy" / "systemd" / "sr-api.service").read_text()
    assert "EnvironmentFile=-/etc/sparring-range/secrets/db-secret.env" \
        in api
    for other in ("sr-api-ingest.service", "sr-bastion.service",
                  "sr-worker-supervisor.service", "sr-brokerd.service"):
        text = (ROOT / "deploy" / "systemd" / other).read_text()
        assert "db-secret.env" not in text, \
            f"{other} must never receive the credential-store URL"


def test_credential_digest_is_one_way_and_legacy_never_matches():
    from srplatform.model_admin import _credential_digest
    d = _credential_digest("uvxyz")            # SHORT keys still identify
    assert d and d.startswith("sha256:") and "uvxyz" not in d
    assert d == _credential_digest("uvxyz")
    assert d != _credential_digest("uvxyzz")
    assert _credential_digest(None) is None
    assert _credential_digest("") is None
