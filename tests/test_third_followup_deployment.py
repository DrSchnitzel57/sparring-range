"""Third-follow-up regressions — Stage 3: snapshot deployment (T04), durable
telemetry ENROLLMENT (T05), enforced production readiness + reset parity
(T06).

Every test drives the real routes (/sessions, /launch, /reset) and asserts
route status + database state — not helper return values.
"""
from __future__ import annotations

import shlex
import uuid

import pytest
from sqlalchemy import select

pytestmark = pytest.mark.db


def _session(client, users, scenario="web-foothold-01"):
    return client.post("/sessions", json={"scenario_id": scenario},
                       headers=users["member"]).json()["session_id"]


# --------------------------------------------------------------------------- #
# T04 — deployment resolves the IMMUTABLE session snapshot                      #
# --------------------------------------------------------------------------- #

def _mutated_scenarios(real_dir, tmp_path):
    import shutil
    dst = tmp_path / "scenarios"
    shutil.copytree(real_dir, dst)
    return dst


def test_t04_launch_and_reset_use_the_session_snapshot_not_live_yaml(
        client, users, fake_pve, tmp_path, monkeypatch):
    """Create a session, THEN edit the source YAML's template/IP/topology.
    The real launch AND reset routes must still provision the ORIGINAL
    snapshot (the spec that is executed and graded)."""
    from srplatform.scenario_engine import loader

    real = loader.scenarios_dir()
    dst = _mutated_scenarios(real, tmp_path)
    monkeypatch.setattr(loader, "scenarios_dir", lambda: dst)

    sid = _session(client, users)  # snapshot: web01 / template 9001 / .10

    # mutate the CURRENT YAML: different template, different IP, extra host
    p = dst / "web-foothold-01.yaml"
    text = p.read_text()
    text = text.replace("template_vmid: 9001", "template_vmid: 9002")
    text = text.replace("ip: 10.66.0.10", "ip: 10.66.0.77")
    text = text.replace("red:\n",
                        "    - name: db01\n      template_vmid: 9002\n"
                        "      ip: 10.66.0.88\n      services: [http]\n"
                        "      os: linux\nred:\n", 1)
    p.write_text(text)
    cur = loader.load_scenario("web-foothold-01")
    assert len(cur["topology"]["hosts"]) == 2  # the live file really changed

    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    non_tpl = [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)]
    assert len(non_tpl) == 1, "the snapshot has ONE host — the edited second host must NOT be cloned"
    v = fake_pve.api.vms[non_tpl[0]]
    assert v["template"] == 9001, "cloned from the EDITED template, not the snapshot"
    assert "10.66.0.10" in v["config"]["ipconfig0"], "cloned with the EDITED IP"

    # reset must ALSO resolve the snapshot, not the mutated YAML
    r = client.post(f"/sessions/{sid}/reset", headers=users["member"])
    assert r.status_code == 200, r.text
    non_tpl = [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)]
    assert len(non_tpl) == 1
    v = fake_pve.api.vms[non_tpl[0]]
    assert v["template"] == 9001 and "10.66.0.10" in v["config"]["ipconfig0"]
    assert len(r.json()["hosts"]) == 1


# --------------------------------------------------------------------------- #
# T05 — enrollment PROVISIONS and CONFIRMS through the management channel       #
# --------------------------------------------------------------------------- #

class ScriptedChannel:
    """Records every provisioning command; scripts exit codes per pattern."""

    def __init__(self, fail=(), ok_code=0):
        self.commands = []
        self.fail = fail          # substrings whose command returns 1
        self.ok_code = ok_code

    def __call__(self, addr, command):
        self.commands.append((addr, command))
        for pat in self.fail:
            if pat in command:
                return 1, f"scripted failure for {pat!r}"
        if "is-active" in command:
            return self.ok_code, "active\n"
        if "list-unit-files" in command:
            return 0, "nginx.service enabled enabled\nssh.service enabled enabled\n"
        return 0, ""

    def provision_env(self):
        for _, cmd in self.commands:
            if "shipper.env" in cmd:
                part = next(s for s in cmd.split("&&") if "printf" in s)
                return shlex.split(part)[2]
        return None


@pytest.fixture()
def enrollment_channel(monkeypatch):
    from srplatform.scenario_engine import orchestrator
    orchestrator.set_enrollment_exec(None)
    yield orchestrator
    orchestrator.set_enrollment_exec(None)


def _enroll_state(client, sid, host):
    from srplatform.db.session import db
    from srplatform.db.models import Deployment
    with db() as s:
        dep = s.execute(select(Deployment).where(Deployment.session_id == sid)
                        .order_by(Deployment.created_at.desc())).scalars().first()
        for r in (dep.resources or []):
            if r.get("host") == host:
                return dict(r.get("telemetry_enroll") or {})
    return {}


def test_t05_enrollment_provisions_env_and_confirms_service(
        client, users, fake_pve, enrollment_channel):
    from srplatform import verification_service
    chan = ScriptedChannel()
    enrollment_channel.set_enrollment_exec(chan)
    verification_service.set_verifier_exec(chan)

    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    out = r.json()
    token = out["deployment"]["telemetry_enrollments"]["web01"]

    # the REAL provisioning contract: env file written with the session-bound
    # capability, no placeholders, service enabled+restarted, then confirmed
    env = chan.provision_env()
    assert env is not None and "shipper.env" in " ".join(c for _, c in chan.commands)
    assert f"SR_TELEMETRY_TOKEN={token}" in env
    assert "SR_HOST=web01" in env and "SR_API_URL=" in env
    assert "PROVISION-PER-DEPLOYMENT" not in env and "SET-PER-CLONE" not in env
    assert any("systemctl enable --now sparring-shipper" in c for _, c in chan.commands)
    assert any("is-active" in c for _, c in chan.commands)

    # DURABLE phase in the deployment inventory (not just the response)
    st = _enroll_state(client, sid, "web01")
    assert st.get("phase") == "confirmed", st

    # readiness was ENFORCED and passed with the enrollment confirmed
    assert out["readiness"]["enforced"] and out["readiness"]["ok"]

    # the issued capability works against the REAL ingest endpoint with a
    # harmless command (this is what enrollment is FOR)
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "echo enrollment-check", "source_id": "1",
         "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201, r.text
    evs = client.get(f"/events?session_id={sid}", headers=users["member"]).json()
    tel = [e for e in evs if e["actor"] == "telemetry"]
    assert tel and tel[0]["host"] == "web01"


def test_t05_interrupted_provisioning_resumes_with_the_same_token(
        client, users, fake_pve, enrollment_channel):
    """Lost response / failing channel: the phase is persisted, the session
    does NOT reach ready, and a retry completes enrollment with the SAME
    capability (no second token issued)."""
    from srplatform.db.session import db
    from srplatform.db.models import ServiceToken, Session as SessionModel

    from srplatform import verification_service
    bad = ScriptedChannel(fail=("shipper.env",))
    enrollment_channel.set_enrollment_exec(bad)
    verification_service.set_verifier_exec(bad)
    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 409 and r.json()["detail"]["error"] == "readiness_failed"
    assert _enroll_state(client, sid, "web01").get("phase") == "provision_failed"
    with db() as s:
        tokens = s.execute(select(ServiceToken).where(
            ServiceToken.session_id == sid,
            ServiceToken.scope == "telemetry")).scalars().all()
        assert len(tokens) == 1
        assert s.get(SessionModel, uuid.UUID(sid)).status != "ready"

    # channel repaired — the retry (idempotent deploy path) must RESUME:
    # recover the issued token, provision, confirm.
    good = ScriptedChannel()
    enrollment_channel.set_enrollment_exec(good)
    verification_service.set_verifier_exec(good)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    assert _enroll_state(client, sid, "web01").get("phase") == "confirmed"
    with db() as s:
        tokens = s.execute(select(ServiceToken).where(
            ServiceToken.session_id == sid,
            ServiceToken.scope == "telemetry")).scalars().all()
        assert len(tokens) == 1, "retry must NOT issue a second capability"
        assert f"SR_TELEMETRY_TOKEN={tokens[0].token}" in good.provision_env()


def test_t05_unconfirmed_service_blocks_ready(client, users, fake_pve,
                                              enrollment_channel):
    """Provisioning succeeds but the service is NOT running: enrollment is
    unconfirmed -> launch refuses `ready` (route status + DB state)."""
    from srplatform import verification_service
    chan = ScriptedChannel(ok_code=3)   # is-active -> inactive
    enrollment_channel.set_enrollment_exec(chan)
    verification_service.set_verifier_exec(chan)
    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 409 and r.json()["detail"]["error"] == "readiness_failed"
    en = r.json()["detail"]["enrollments"]
    assert en and en[0]["phase"] == "confirm_failed" and en[0]["ok"] is False
    assert _enroll_state(client, sid, "web01").get("phase") == "confirm_failed"


def test_t05_dev_relaxation_is_visible(client, users, fake_pve, enrollment_channel):
    """Without a provisioning channel the phase is `unconfigured` and
    readiness reports enforced=False — never a silent 'enrolled'."""
    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    assert r.json()["readiness"]["enforced"] is False
    assert "dev-mode relaxation" in r.json()["readiness"]["reason"]
    assert _enroll_state(client, sid, "web01").get("phase") == "unconfigured"


# --------------------------------------------------------------------------- #
# T06 — production cannot skip readiness; reset shares the launch workflow      #
# --------------------------------------------------------------------------- #

def _prod_env(monkeypatch):
    """A production config that PASSES validate_production (the review's
    reproduction) while the management channel stays unavailable: pins are
    merely NON-EMPTY (validation does not require existence — the T06 gap)
    and the verifier key is missing."""
    monkeypatch.setenv("SR_ENV", "production")
    monkeypatch.setenv("PROXMOX_TOKEN_ID", "sparring@pve!token")
    monkeypatch.setenv("PROXMOX_TOKEN_SECRET", "s3cret")
    monkeypatch.setenv("PROXMOX_TLS_CA_FILE", "/etc/ssl/certs/ca-certificates.crt")
    monkeypatch.setenv("RUNNER_TRANSPORT", "ssh")
    monkeypatch.setenv("RUNNER_SSH_TARGET", "runner.internal")
    monkeypatch.setenv("RUNNER_SSH_KNOWN_HOSTS", "/etc/sr/runner-known-hosts")
    monkeypatch.setenv("BASTION_TARGETS_KNOWN_HOSTS", "/etc/sr/bastion-known-hosts")
    monkeypatch.setenv("VERIFIER_SSH_KNOWN_HOSTS", "/etc/sr/verifier-known-hosts-MISSING")
    monkeypatch.setenv("VERIFIER_SSH_KEY_PATH", "")
    from srplatform.settings import get_settings
    get_settings.cache_clear()


def _clear_prod(monkeypatch):
    for k in ("SR_ENV", "PROXMOX_TOKEN_ID", "PROXMOX_TOKEN_SECRET",
              "PROXMOX_TLS_CA_FILE", "RUNNER_TRANSPORT", "RUNNER_SSH_TARGET",
              "RUNNER_SSH_KNOWN_HOSTS", "BASTION_TARGETS_KNOWN_HOSTS",
              "VERIFIER_SSH_KNOWN_HOSTS", "VERIFIER_SSH_KEY_PATH"):
        monkeypatch.delenv(k, raising=False)
    from srplatform.settings import get_settings
    get_settings.cache_clear()


def test_t06_production_without_channel_refuses_ready(client, users, fake_pve,
                                                      monkeypatch):
    """The dev relaxation EXPLICITLY requires dev mode: with production
    settings and no management key/pins, /launch must 409 and the session
    must not be `ready` in the database."""
    from srplatform.db.session import db
    from srplatform.db.models import Session as SessionModel

    sid = _session(client, users)
    _prod_env(monkeypatch)
    try:
        r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "readiness_failed"
        assert "production" in r.json()["detail"]["reason"]
        with db() as s:
            sess = s.get(SessionModel, uuid.UUID(sid))
            assert sess.status != "ready"
    finally:
        _clear_prod(monkeypatch)


def test_t06_dev_relaxation_requires_dev_mode_and_is_visible(client, users, fake_pve):
    """Same missing channel in dev: allowed, but the response SAYS it is an
    unverified relaxation (enforced=False)."""
    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    assert r.json()["readiness"]["enforced"] is False


def test_t06_reset_runs_the_launch_readiness_and_credential_workflow(
        client, users, fake_pve, monkeypatch):
    """Reset must (a) succeed to a clear NEW ready state with NEW connection
    capabilities, and (b) when readiness fails (production, no channel),
    refuse with 409 and leave the session explicitly `preparing`."""
    import uuid as U
    from srplatform.settings import get_settings
    from srplatform.db.session import db
    from srplatform.db.models import LoginToken, Session as SessionModel

    sid = _session(client, users)
    r1 = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r1.status_code == 200, r1.text
    old_tokens = {c["login_token"] for c in r1.json()["connections"]}

    # (a) happy path: reset -> ready + NEW credentials, old ones revoked
    r = client.post(f"/sessions/{sid}/reset", headers=users["member"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "ready" and out["connections"]
    new_tokens = {c["login_token"] for c in out["connections"]}
    assert new_tokens and not (new_tokens & old_tokens)
    with db() as s:
        old = s.execute(select(LoginToken).where(
            LoginToken.session_id == sid,
            LoginToken.token.in_(old_tokens))).scalars().all()
        assert all(t.revoked_at is not None for t in old)
        assert s.get(SessionModel, U.UUID(sid)).status == "ready"

    # (b) readiness failure path: production without a channel -> reset
    # destroys+redeploys but CANNOT claim ready
    _prod_env(monkeypatch)
    try:
        r = client.post(f"/sessions/{sid}/reset", headers=users["member"])
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "readiness_failed", r.text
        with db() as s:
            assert s.get(SessionModel, U.UUID(sid)).status == "preparing"
    finally:
        _clear_prod(monkeypatch)
