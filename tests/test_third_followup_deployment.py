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
from tests.conftest import launch_and_wait, reset_and_wait, wait_operation

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
    assert r.status_code == 202, r.text
    wait_operation(client, users["member"], sid)
    non_tpl = [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)]
    assert len(non_tpl) == 1, "the snapshot has ONE host — the edited second host must NOT be cloned"
    v = fake_pve.api.vms[non_tpl[0]]
    assert v["template"] == 9001, "cloned from the EDITED template, not the snapshot"
    assert "10.66.0.10" in v["config"]["ipconfig0"], "cloned with the EDITED IP"

    # reset must ALSO resolve the snapshot, not the mutated YAML
    out = reset_and_wait(client, users["member"], sid)["result"]
    non_tpl = [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)]
    assert len(non_tpl) == 1
    v = fake_pve.api.vms[non_tpl[0]]
    assert v["template"] == 9001 and "10.66.0.10" in v["config"]["ipconfig0"]
    assert len(out["hosts"]) == 1


# --------------------------------------------------------------------------- #
# T05 — enrollment PROVISIONS and CONFIRMS through the management channel       #
# --------------------------------------------------------------------------- #

class ScriptedChannel:
    """Records every provisioning command; scripts exit codes per pattern.

    With a `host_client` (the in-process API client) it also SIMULATES THE
    PROVISIONED HOST's side of the enrollment contract (audit T-05): after
    provisioning, the installed service sends its AUTHENTICATED NONCE
    CALLBACK (/enroll/confirm), and the capture probe's harmless command
    arrives as an AUDIT EVENT (/ingest/auditd) carrying the marker. Those —
    not `systemctl is-active` — are the evidence enrollment advances on.
    `confirm`/`deliver_capture` toggle the two evidence paths to model a
    service that runs while its delivery or capture path is broken."""

    def __init__(self, fail=(), ok_code=0, host_client=None,
                 confirm=True, deliver_capture=True):
        self.commands = []
        self.fail = fail          # substrings whose command returns 1
        self.ok_code = ok_code
        self.host_client = host_client
        self.confirm = confirm
        self.deliver_capture = deliver_capture
        self.provisioned_env = None

    def __call__(self, addr, command):
        self.commands.append((addr, command))
        for pat in self.fail:
            if pat in command:
                return 1, f"scripted failure for {pat!r}"
        if "shipper.env" in command:
            self.provisioned_env = self._env_of(command)
            if self.host_client is not None and self.confirm:
                self._host_confirm(self.provisioned_env)
        if "is-active" in command:
            return self.ok_code, "active\n"
        if "SR-CAPTURE-" in command:
            if self.host_client is not None and self.deliver_capture:
                self._host_capture(command)
            return 0, ""
        if "list-unit-files" in command:
            return 0, "nginx.service enabled enabled\nssh.service enabled enabled\n"
        return 0, ""

    @staticmethod
    def _env_of(command):
        part = next(s for s in command.split("&&") if "printf" in s)
        return shlex.split(part)[2]

    @staticmethod
    def _env_value(env, key):
        for line in env.splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1]
        return None

    def _host_confirm(self, env):
        import uuid as _u
        tok = self._env_value(env, "SR_TELEMETRY_TOKEN")
        nonce = self._env_value(env, "SR_ENROLL_NONCE")
        r = self.host_client.post("/enroll/confirm",
                                  json={"nonce": nonce, "machine_id": "test-clone",
                                        "boot_id": _u.uuid4().hex},
                                  headers={"Authorization": f"Bearer {tok}"})
        self.last_confirm_status = r.status_code

    def _host_capture(self, command):
        import uuid as _u
        marker = next(w for w in command.split() if w.startswith("SR-CAPTURE-"))
        env = self.provisioned_env or ""
        tok = self._env_value(env, "SR_TELEMETRY_TOKEN")
        r = self.host_client.post(
            "/ingest/auditd",
            json={"events": [{"kind": "command", "argv": f"/bin/true {marker}",
                              "source_id": _u.uuid4().hex, "boot_id": "b1"}]},
            headers={"Authorization": f"Bearer {tok}"})
        self.last_capture_status = r.status_code

    def provision_env(self):
        for _, cmd in self.commands:
            if "shipper.env" in cmd:
                return self._env_of(cmd)
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
    chan = ScriptedChannel(host_client=client)
    enrollment_channel.set_enrollment_exec(chan)
    verification_service.set_verifier_exec(chan)

    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    out = wait_operation(client, users["member"], sid)
    assert out["state"] == "succeeded", out
    out = out["result"]
    # the plaintext enrollment is NEVER in the async result (redacted by
    # construction) — recover it through the durable ServiceToken record,
    # exactly as a client that lost its response would.
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine.orchestrator import _recover_telemetry_token
    with db_ctx() as s2:
        rec = _recover_telemetry_token(s2, uuid.UUID(sid), "web01")
        assert rec is not None
        token = rec[0]
    assert out["readiness"]["enforced"] and out["readiness"]["ok"]

    # the REAL provisioning contract: env file written with the session-bound
    # capability AND a fresh enrollment nonce, no placeholders, service
    # enabled+restarted
    env = chan.provision_env()
    assert env is not None and "shipper.env" in " ".join(c for _, c in chan.commands)
    assert f"SR_TELEMETRY_TOKEN={token}" in env
    assert "SR_HOST=web01" in env and "SR_API_URL=" in env
    assert "SR_ENROLL_NONCE=" in env and "PROVISION-PER-DEPLOYMENT" not in env \
        and "SET-PER-CLONE" not in env
    assert any("systemctl enable --now sparring-shipper" in c for _, c in chan.commands)
    assert any("is-active" in c for _, c in chan.commands)

    # DURABLE phase in the deployment inventory (not just the response):
    # confirmed ONLY because the host's authenticated callback (delivery) and
    # the capture probe's audit event (capture) were both observed (T-05).
    st = _enroll_state(client, sid, "web01")
    assert st.get("phase") == "confirmed", st
    assert "stage" not in st, st   # no failure stage on the happy path
    assert st.get("delivery_confirmed_at") and st.get("capture_verified_at")

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
    assert r.status_code == 202, r.text
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed
    assert "readiness_failed" in (failed["error"] or ""), failed
    assert _enroll_state(client, sid, "web01").get("phase") == "provision_failed"
    with db() as s:
        tokens = s.execute(select(ServiceToken).where(
            ServiceToken.session_id == sid,
            ServiceToken.scope == "telemetry")).scalars().all()
        assert len(tokens) == 1
        assert s.get(SessionModel, uuid.UUID(sid)).status != "ready"

    # channel repaired — the retry (idempotent deploy path) must RESUME:
    # recover the issued token AND nonce, provision, and advance on the
    # host's delivery + capture evidence.
    good = ScriptedChannel(host_client=client)
    enrollment_channel.set_enrollment_exec(good)
    verification_service.set_verifier_exec(good)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    out = wait_operation(client, users["member"], sid)
    assert out["state"] == "succeeded", out
    out = out["result"]
    assert _enroll_state(client, sid, "web01").get("phase") == "confirmed"
    with db() as s:
        tokens = s.execute(select(ServiceToken).where(
            ServiceToken.session_id == sid,
            ServiceToken.scope == "telemetry")).scalars().all()
        assert len(tokens) == 1, "retry must NOT issue a second capability"
        assert f"SR_TELEMETRY_TOKEN={tokens[0].token}" in good.provision_env()
        assert tokens[0].enroll_nonce in good.provision_env(), \
            "retry must resume with the SAME enrollment nonce"


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
    assert r.status_code == 202, r.text
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed
    assert "readiness_failed" in (failed["error"] or ""), failed
    assert _enroll_state(client, sid, "web01").get("phase") == "confirm_failed"


def test_t05_dev_relaxation_is_visible(client, users, fake_pve, enrollment_channel):
    """Without a provisioning channel the phase is `unconfigured` and
    readiness reports enforced=False — never a silent 'enrolled'."""
    sid = _session(client, users)
    out = launch_and_wait(client, users["member"], sid)["result"]
    assert out["readiness"]["enforced"] is False
    assert "dev-mode relaxation" in out["readiness"]["reason"]
    assert _enroll_state(client, sid, "web01").get("phase") == "unconfigured"


# --------------------------------------------------------------------------- #
# T06 — production cannot skip readiness; reset shares the launch workflow      #
# --------------------------------------------------------------------------- #

def _prod_env(monkeypatch, tmp_path=None):
    """A production config that PASSES validate_production (the review's
    reproduction) while the management channel stays unavailable: pins are
    merely NON-EMPTY (validation does not require existence — the T06 gap)
    and the verifier key is missing. Pin PUBLICATION uses isolated tmp
    known-hosts files when tmp_path is given, so the test exercises the
    intended channel-missing refusal instead of tripping on unpublished
    pins first. Milestone 02 contract: the controller presents broker
    mutual-TLS material and NO hypervisor credentials."""
    monkeypatch.setenv("SR_ENV", "production")
    # plan 13 phase 4: production trust is mandatory — guests ship
    # authenticated telemetry to the controller's range address over
    # verified TLS (the file need not exist for validation; only that the
    # anchor is configured).
    monkeypatch.setenv("SR_API_BASE_URL", "https://10.66.0.1:8443")
    monkeypatch.setenv("SR_TELEMETRY_CA_FILE", "/etc/sr/api-ca.crt")
    monkeypatch.setenv("BROKER_URL", "https://broker.lab:8443")
    monkeypatch.setenv("BROKER_CLIENT_CERT", "/etc/sr/broker-client.pem")
    monkeypatch.setenv("BROKER_CLIENT_KEY", "/etc/sr/broker-client.key")
    monkeypatch.setenv("BROKER_TLS_CA_FILE", "/etc/sr/broker-ca.pem")
    monkeypatch.setenv("RUNNER_TRANSPORT", "ssh")
    monkeypatch.setenv("RUNNER_SSH_TARGET", "runner.internal")
    monkeypatch.setenv("RUNNER_SSH_KNOWN_HOSTS", "/etc/sr/runner-known-hosts")
    monkeypatch.setenv("BASTION_TARGETS_KNOWN_HOSTS", "/etc/sr/bastion-known-hosts")
    monkeypatch.setenv("VERIFIER_SSH_KNOWN_HOSTS", "/etc/sr/verifier-known-hosts-MISSING")
    monkeypatch.setenv("VERIFIER_SSH_KEY_PATH", "")
    if tmp_path is not None:
        for var in ("RUNNER_SSH_KNOWN_HOSTS", "BASTION_TARGETS_KNOWN_HOSTS",
                    "VERIFIER_SSH_KNOWN_HOSTS"):
            f = tmp_path / (var.lower() + ".test")
            f.write_text("")
            monkeypatch.setenv(var, str(f))
    from srplatform.settings import get_settings
    get_settings.cache_clear()


def _clear_prod(monkeypatch):
    for k in ("SR_ENV", "SR_API_BASE_URL", "SR_TELEMETRY_CA_FILE",
              "BROKER_URL", "BROKER_CLIENT_CERT", "BROKER_CLIENT_KEY",
              "BROKER_TLS_CA_FILE",
              "RUNNER_TRANSPORT", "RUNNER_SSH_TARGET", "RUNNER_SSH_KNOWN_HOSTS",
              "BASTION_TARGETS_KNOWN_HOSTS", "VERIFIER_SSH_KNOWN_HOSTS",
              "VERIFIER_SSH_KEY_PATH"):
        monkeypatch.delenv(k, raising=False)
    from srplatform.settings import get_settings
    get_settings.cache_clear()


def test_t06_production_without_channel_refuses_ready(
        client, users, fake_pve, monkeypatch, tmp_path):
    """The dev relaxation EXPLICITLY requires dev mode: with production
    settings and no management key/pins, /launch must 409 and the session
    must not be `ready` in the database."""
    from srplatform.db.session import db
    from srplatform.db.models import Session as SessionModel

    sid = _session(client, users)
    _prod_env(monkeypatch, tmp_path)
    try:
        r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
        assert r.status_code == 202, r.text
        failed = wait_operation(client, users["member"], sid)
        assert failed["state"] == "failed", failed
        assert "readiness_failed" in (failed["error"] or ""), failed
        assert "production" in (failed["error"] or ""), failed
        with db() as s:
            sess = s.get(SessionModel, uuid.UUID(sid))
            assert sess.status != "ready"
    finally:
        _clear_prod(monkeypatch)


def test_t06_dev_relaxation_requires_dev_mode_and_is_visible(client, users, fake_pve):
    """Same missing channel in dev: allowed, but the response SAYS it is an
    unverified relaxation (enforced=False)."""
    sid = _session(client, users)
    from tests.conftest import launch_and_wait
    out = launch_and_wait(client, users["member"], sid)["result"]
    assert out["readiness"]["enforced"] is False


def test_t06_reset_runs_the_launch_readiness_and_credential_workflow(
        client, users, fake_pve, monkeypatch, tmp_path):
    """Reset must (a) succeed to a clear NEW ready state with NEW connection
    capabilities, and (b) when readiness fails (production, no channel),
    refuse with 409 and leave the session explicitly `preparing`."""
    import uuid as U
    from srplatform.settings import get_settings
    from srplatform.db.session import db
    from srplatform.db.models import LoginToken, Session as SessionModel

    sid = _session(client, users)
    out = launch_and_wait(client, users["member"], sid)["result"]
    old_tokens = {c["login_token"] for c in out["connections"]}

    # (a) happy path: reset -> ready + NEW credentials, old ones revoked
    out = reset_and_wait(client, users["member"], sid)["result"]
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
    _prod_env(monkeypatch, tmp_path)
    try:
        r = client.post(f"/sessions/{sid}/reset", headers=users["member"])
        assert r.status_code == 202, r.text
        failed = wait_operation(client, users["member"], sid)
        assert failed["state"] == "failed", failed
        assert "readiness_failed" in (failed["error"] or ""), failed
        with db() as s:
            assert s.get(SessionModel, U.UUID(sid)).status == "preparing"
    finally:
        _clear_prod(monkeypatch)


def test_assumed_breach_proof_executes_as_web_user(client, users, fake_pve,
                                                   monkeypatch):
    """The foothold is ESTABLISHED over the attacker-identical path: an
    unauthenticated HTTP request to the documented flaw, whose response
    names the web-user identity. No privilege is used to trigger it; the
    test fakes only the transport, never the verdict logic."""
    from srplatform import lifecycle as lifecycle_mod
    seen = {}

    class FlawResp:
        status_code = 200
        # exact production verdict line: limited identity + success
        text = "[uid=1001 user=web-user] exit=0\nid: output follows\n"

    def fake_flaw_get(url, timeout=10.0):
        seen["url"] = url
        assert url.startswith("http://10.66.0.10/diagnostic?cmd="), url
        assert "PRIV" not in url and "sudo" not in url and "runuser" not in url
        return FlawResp()

    monkeypatch.setattr(lifecycle_mod, "_flaw_get", fake_flaw_get)
    from tests.conftest import launch_and_wait
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                         "start_condition": "assumed-breach"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    assert client.post(f"/sessions/{sid}/begin",
                       headers=users["member"]).status_code == 202
    evs = client.get("/events", params={"session_id": sid, "tail": 40},
                     headers=users["member"]).json()
    begin = next(e for e in evs if e["action_type"] == "match_begin")
    proof = begin["payload"].get("disclosed_foothold")
    assert proof and proof.get("established") is True, proof
    assert proof.get("http_status") == 200
    # the trigger used zero privilege over plain HTTP (no sudo,
    # no runuser, no credentials anywhere in the request)
    assert seen.get("url", "").startswith("http://10.66.0.10/diagnostic?cmd="), seen
    for banned in ("sudo", "runuser", "PRIV", "token", "password"):
        assert banned not in seen["url"], seen
    # the worker is SUPPLIED the foothold: agent_state seeds its
    # start phase and prompt summary (the runner token reads this;
    # members cannot — competition sealed)
    from srplatform.db.models import AgentState
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        st = s.get(AgentState, uuid.UUID(sid))
        assert st is not None and st.current_phase == "initial-access"
        assert "ASSUMED BREACH" in (st.summary or "") \
            and "web-user" in st.summary


def test_assumed_breach_refused_begin_spawns_no_worker(
        client, users, fake_broker, monkeypatch, tmp_path):
    """A refused Begin (unproven foothold) must not leave an attacker
    running: the proof runs BEFORE the worker spawns, so the 409 means no
    worker exists and the clock never started."""
    from srplatform.api import runs as runs_svc
    from srplatform import lifecycle as lifecycle_mod

    def dead_flaw(url, timeout=10.0):
        raise OSError("flaw unreachable in this test")

    monkeypatch.setattr(lifecycle_mod, "_flaw_get", dead_flaw)
    # deploy first in dev (production without a channel cannot go
    # ready), then switch to production with isolated pins for Begin:
    # valid publication, but the flaw itself unreachable.
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                         "start_condition": "assumed-breach"},
                      headers=users["member"]).json()["session_id"]
    from tests.conftest import launch_and_wait
    launch_and_wait(client, users["member"], sid)
    _prod_env(monkeypatch, tmp_path)
    try:
        r = client.post(f"/sessions/{sid}/begin", headers=users["member"])
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "assumed_breach_unproven"
        from srplatform.db.session import db as db_ctx
        with db_ctx() as s:
            assert runs_svc.active_run_for_session(s, sid) is None
            from srplatform import lifecycle
            assert lifecycle.get_match(s, sid).state != "running"
    finally:
        _clear_prod(monkeypatch)


def test_assumed_breach_rejects_wrong_identity_and_error_text(
        client, users, fake_broker, monkeypatch):
    """The strict verdict: root execution output and error text that merely
    mentions the account must NOT establish the foothold (the reviewer's
    reproduction: `[uid=0 user=root] exit=1` + `no such user` previously
    passed substring matching)."""
    from srplatform import lifecycle as lifecycle_mod
    from srplatform.db.session import db as db_ctx
    from tests.conftest import launch_and_wait
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                         "start_condition": "assumed-breach"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    hostile = {
        # root-equivalent execution masquerading with the name attached
        "root": (200, "[uid=0 user=web-user] exit=0\n"),
        "error": (200, "id: web-user: no such user\n"),
        "failed": (200, "[uid=1001 user=web-user] exit=1\n"),
        "created": (404, "not found\n"),
    }

    def hostile_flaw(url, timeout=10.0):
        mode = hostile_flaw.mode
        code, text = hostile[mode]
        return type("R", (), {"status_code": code, "text": text})()

    hostile_flaw.mode = "root"
    monkeypatch.setattr(lifecycle_mod, "_flaw_get", hostile_flaw)
    with db_ctx() as s:
        for mode in ("root", "error", "failed", "created"):
            hostile_flaw.mode = mode
            proof = lifecycle_mod.prove_assumed_breach(
                s, __import__("uuid").UUID(sid))
            assert proof is not None and proof.get("established") is False, \
                (mode, proof)
