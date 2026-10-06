"""Stage 5 item 3 — reproducible fresh-stack bootstrap path.

Drives the REAL `rangectl bootstrap` core (run_bootstrap) against the real
API app on the disposable DB, runs the REAL compose seed script against
volume-shaped directories, and asserts the bastion's own key resolver
(load_authorized_keys) accepts the seeded member key. A second bootstrap run
must be idempotent: closed bootstrap tolerated, nothing re-minted, same
tokens, no new DB rows.

docker compose config / fresh-volume boot remain BLOCKED (no docker here);
this covers everything the harness can honestly execute.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable

OP_PW = "operator-bootstrap-pw-9"
SEED = REPO / "infra" / "dev" / "seed_bastion_keys.sh"


def _call_with(client):
    """Adapt the CLI's call contract onto the TestClient (same httpx layer)."""
    def call(method, path, *, json_body=None, headers=None):
        return client.request(method, path, json=json_body, headers=headers or {})
    return call


def _run_seed(src, dest, rec):
    env = {**os.environ, "SR_SEED_SRC_DIR": str(src), "SR_SEED_DEST_DIR": str(dest),
           "SR_SEED_REC_DIR": str(rec)}
    return subprocess.run(["sh", str(SEED)], env=env, capture_output=True, text=True)


@pytest.mark.db
def test_stage5_bootstrap_then_idempotent_rerun(client, tmp_path, test_db_url_owner):
    import asyncssh

    from rangectl.cli import run_bootstrap
    from srplatform.bastion.proxy import load_authorized_keys

    # --- operator-supplied files (what the compose seed step consumes) ------
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    pub = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    (deploy / "authorized_keys").write_text(f"blue {pub}\n")
    (deploy / "target_known_hosts").write_text("target01 ssh-ed25519 AAAAk3yh0stK3y\n")

    state, rec_dir = tmp_path / "state" / "bootstrap.json", tmp_path / "rec"
    rep = run_bootstrap(_call_with(client), username="drew", password=OP_PW,
                        telemetry_hosts=["web01", "db01"], state_path=state,
                        recordings_dir=str(rec_dir), keys_dir=str(deploy))
    assert rep["problems"] == [], rep

    # operator account exists (POST /auth/bootstrap worked) and can log in
    assert client.post("/auth/login",
                       json={"username": "drew", "password": OP_PW}).status_code == 200
    assert rec_dir.is_dir()

    # mint ledger: 0600, bastion + both telemetry hosts
    assert (state.stat().st_mode & 0o077) == 0, "state file with live tokens must be 0600"
    minted = json.loads(state.read_text())["minted"]
    assert set(minted) == {"bastion", "telemetry:web01", "telemetry:db01"}
    assert all(minted[k]["token"].startswith(("svc-bastion-", "svc-telemetry-")) for k in minted)

    # the minted bastion capability AUTHENTICATES against a bastion-scoped
    # route: 404 = authenticated-but-not-found, vs 401/403 without it
    h = {"Authorization": f"Bearer {minted['bastion']['token']}"}
    assert client.get("/tokens/nonexistent", headers=h).status_code == 404
    assert client.get("/tokens/nonexistent").status_code in (401, 403)

    # --- compose seed step: real script, volume-shaped dirs ------------------
    dest = tmp_path / "etc" / "sparring-range"
    r = _run_seed(deploy, dest, tmp_path / "vol-rec")
    assert r.returncode == 0, r.stderr
    # bastion key RESOLUTION works on the seeded file
    assert load_authorized_keys(str(dest / "authorized_keys")) == {"blue": [pub]}
    assert (dest / "target_known_hosts").read_text().startswith("target01 ")
    assert (tmp_path / "vol-rec").is_dir()

    # seed is idempotent, and fails loudly when operator files vanish
    r = _run_seed(deploy, dest, tmp_path / "vol-rec")
    assert r.returncode == 0 and "unchanged" in r.stdout, r.stdout
    (deploy / "authorized_keys").unlink()
    r = _run_seed(deploy, dest, tmp_path / "vol-rec")
    assert r.returncode == 1 and "authorized_keys" in r.stderr, r.stderr
    (deploy / "authorized_keys").write_text(f"blue {pub}\n")

    # --- second bootstrap run: idempotent ------------------------------------
    rep2 = run_bootstrap(_call_with(client), username="drew", password=OP_PW,
                         telemetry_hosts=["web01", "db01"], state_path=state,
                         recordings_dir=str(rec_dir), keys_dir=str(deploy))
    assert rep2["problems"] == [], rep2
    assert rep2["tokens"] == {k: v["token"] for k, v in minted.items()}
    assert any("already" in m for m in rep2["steps"])

    from sqlalchemy import create_engine, text
    eng = create_engine(test_db_url_owner)
    with eng.connect() as conn:
        n = conn.execute(text("SELECT count(*) FROM service_tokens")).scalar()
        d = conn.execute(text("SELECT count(DISTINCT token) FROM service_tokens")).scalar()
    eng.dispose()
    assert (n, d) == (3, 3), "second run must not re-mint capabilities"


@pytest.mark.db
def test_stage5_bootstrap_reports_useful_failures(client, tmp_path):
    from rangectl.cli import run_bootstrap

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    state = tmp_path / "state.json"
    # wrong username (not the configured bootstrap operator) -> loud, no crash
    rep = run_bootstrap(_call_with(client), username="mallory", password="attacker-pw-1234",
                        state_path=state, keys_dir=str(deploy))
    assert rep["problems"] and any("BOOTSTRAP_OPERATOR_USERNAME" in p for p in rep["problems"])
    # missing key material is named explicitly with the runbook pointer
    assert any("authorized_keys" in p and "OPERATOR_RUNBOOK" in p for p in rep["problems"])
    assert any("target_known_hosts" in p for p in rep["problems"])
