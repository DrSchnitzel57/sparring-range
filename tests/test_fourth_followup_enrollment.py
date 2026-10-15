"""Fourth-follow-up regressions — acceptance blocker T-05: telemetry
enrollment must be proven by HOST-ORIGINATED evidence, not by a controller-
side `systemctl is-active`.

The contract under test: provisioning writes the capability AND a fresh
enrollment nonce; the phase machine advances only on distinct evidence —
service active → the host's AUTHENTICATED NONCE CALLBACK (delivery) → a
capture probe OBSERVED AS AN AUDIT EVENT through the installed service
(capture). Startup status and delivery confirmation stay distinct; a service
that runs while its API address, token, or capture input is broken remains
visibly stuck and blocks readiness.

Tests drive the real routes and the real DB; the end-to-end test runs the
REAL shipper as a subprocess against a REAL uvicorn-served API. The final
systemd+auditd capture on the golden image remains a documented hardware
gate (see the completion report).
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import threading
import time
import uuid

import pytest
from sqlalchemy import select
from tests.conftest import wait_operation

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIPPER = REPO / "telemetry" / "shipper.py"


def _session(client, users):
    return client.post("/sessions", json={"scenario_id": "quick-win-01"},
                       headers=users["member"]).json()["session_id"]


def _issue(sid, host="web01"):
    """Issue a capability + fresh nonce through the PRODUCTION issuance
    path (the same function deploy uses)."""
    from srplatform.db.session import db
    from srplatform.scenario_engine import orchestrator
    with db() as s:
        tok, nonce = orchestrator._enroll_telemetry(s, sid, host, None)
        s.commit()
    return tok, nonce


def _token_row(token):
    from srplatform.db.models import ServiceToken
    from srplatform.db.session import db
    with db() as s:
        row = s.get(ServiceToken, token)
        return (row.enroll_confirmed_at if row else None,
                row.enroll_capture_at if row else None)


def _events(sid, action_type):
    from srplatform.db.models import Event
    from srplatform.db.session import db
    with db() as s:
        return s.execute(select(Event).where(
            Event.session_id == sid,
            Event.action_type == action_type)).scalars().all()


def _wait_for(fn, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(0.2)
    return False


# --------------------------------------------------------------------------- #
# The authenticated enrollment callback (delivery evidence)                     #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_t05_confirm_route_bound_to_capability_and_fresh_nonce(client, users):
    """The callback is AUTHENTICATED (capability), BOUND to the session+host
    the capability carries (never the body), and to the FRESH NONCE issued
    with it. Wrong nonce, no capability, or a foreign capability confirm
    NOTHING; the right pair confirms exactly once (idempotent)."""
    sid = _session(client, users)
    tok, nonce = _issue(sid)

    r = client.post("/enroll/confirm", json={"nonce": "deadbeef" * 4},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403, r.text          # nonce mismatch
    assert _token_row(tok)[0] is None

    r = client.post("/enroll/confirm", json={"nonce": nonce})
    assert r.status_code in (401, 403), r.text   # unauthenticated
    assert _token_row(tok)[0] is None

    # a DIFFERENT capability (other session) must not confirm this one
    sid2 = _session(client, users)
    tok2, nonce2 = _issue(sid2)
    r = client.post("/enroll/confirm", json={"nonce": nonce},   # wrong nonce for tok2
                    headers={"Authorization": f"Bearer {tok2}"})
    assert r.status_code == 403
    assert _token_row(tok2)[0] is None and _token_row(tok)[0] is None

    r = client.post("/enroll/confirm", json={"nonce": nonce, "machine_id": "clone-a",
                                             "boot_id": uuid.uuid4().hex},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201, r.text
    first = _token_row(tok)[0]
    assert first is not None
    evs = _events(sid, "telemetry_enroll_confirmed")
    assert len(evs) == 1 and evs[0].payload["machine_id"] == "clone-a"

    # idempotent: repeats never move the evidence timestamp
    r = client.post("/enroll/confirm", json={"nonce": nonce},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201
    assert _token_row(tok)[0] == first
    assert len(_events(sid, "telemetry_enroll_confirmed")) == 1


@pytest.mark.db
def test_t05_capture_probe_observed_through_ingest(client, users):
    """Capture evidence exists ONLY when the harmless probe command arrives
    AS AN AUDIT EVENT through the installed service under its capability —
    ordinary events without the marker never fake it."""
    from srplatform.scenario_engine.orchestrator import capture_marker
    sid = _session(client, users)
    tok, nonce = _issue(sid)
    hdr = {"Authorization": f"Bearer {tok}"}

    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "whoami", "source_id": uuid.uuid4().hex,
         "boot_id": "b1"}]}, headers=hdr)
    assert r.status_code == 201
    assert _token_row(tok)[1] is None, "ordinary event must not fake capture"

    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": f"/bin/true {capture_marker(nonce)}",
         "source_id": uuid.uuid4().hex, "boot_id": "b1"}]}, headers=hdr)
    assert r.status_code == 201
    assert _token_row(tok)[1] is not None
    assert len(_events(sid, "telemetry_capture_verified")) == 1


# --------------------------------------------------------------------------- #
# Phase machine: an ACTIVE SERVICE with a broken path never confirms           #
# --------------------------------------------------------------------------- #

class HostChannel:
    """Management-channel double that also plays the PROVISIONED HOST when
    given a client: the authenticated callback after provisioning, and the
    capture event delivery when the probe runs. Toggles model a service that
    is ACTIVE while its delivery or capture path is broken."""

    def __init__(self, host_client=None, confirm=True, deliver_capture=True,
                 ok_code=0, fail=()):
        self.commands = []
        self.host_client = host_client
        self.confirm = confirm
        self.deliver_capture = deliver_capture
        self.ok_code = ok_code
        self.fail = fail
        self.env = None

    def __call__(self, addr, command):
        self.commands.append((addr, command))
        for pat in self.fail:
            if pat in command:
                return 1, f"scripted failure for {pat!r}"
        if "shipper.env" in command:
            self.env = self._env_of(command)
            if self.host_client is not None and self.confirm:
                self._host_confirm()
        if "is-active" in command:
            return self.ok_code, "active\n"
        if "list-unit-files" in command:
            # the PROVISIONED host answers the readiness probe (service_present
            # verifier): the exact unit exists. `fail` patterns above still
            # model a broken channel.
            import shlex as _shlex
            parts = _shlex.split(command)
            unit = ""
            if "list-unit-files" in parts:
                i = parts.index("list-unit-files")
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    unit = parts[i + 1]
            return self.ok_code, (f"{unit} enabled\n" if unit else "")
        if "SR-CAPTURE-" in command:
            if self.host_client is not None and self.deliver_capture:
                self._host_capture(command)
            return 0, ""
        return 0, ""

    @staticmethod
    def _env_of(command):
        import shlex
        part = next(s for s in command.split("&&") if "printf" in s)
        return shlex.split(part)[2]

    def _env_value(self, key):
        for line in (self.env or "").splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1]
        return None

    def _host_confirm(self):
        self.host_client.post(
            "/enroll/confirm",
            json={"nonce": self._env_value("SR_ENROLL_NONCE"),
                  "machine_id": "test-clone", "boot_id": uuid.uuid4().hex},
            headers={"Authorization": f"Bearer {self._env_value('SR_TELEMETRY_TOKEN')}"})

    def _host_capture(self, command):
        marker = next(w for w in command.split() if w.startswith("SR-CAPTURE-"))
        self.host_client.post(
            "/ingest/auditd",
            json={"events": [{"kind": "command", "argv": f"/bin/true {marker}",
                              "source_id": uuid.uuid4().hex, "boot_id": "b1"}]},
            headers={"Authorization": f"Bearer {self._env_value('SR_TELEMETRY_TOKEN')}"})


@pytest.fixture()
def enrollment_channel(monkeypatch):
    from srplatform.scenario_engine import orchestrator
    orchestrator.set_enrollment_exec(None)
    yield orchestrator
    orchestrator.set_enrollment_exec(None)


def _enroll_state(client, sid, host="web01"):
    from srplatform.db.models import Deployment
    from srplatform.db.session import db
    with db() as s:
        dep = s.execute(select(Deployment).where(Deployment.session_id == sid)
                        .order_by(Deployment.created_at.desc())).scalars().first()
        for r in (dep.resources or []):
            if r.get("host") == host:
                return dict(r.get("telemetry_enroll") or {})
    return {}


@pytest.mark.db
def test_t05_active_service_without_callback_stuck_at_delivery(
        client, users, fake_pve, enrollment_channel, monkeypatch):
    """THE review case: provisioning succeeded and `systemctl is-active`
    passes, but the host NEVER calls back (wrong API address / rejected
    token / blocked path). Enrollment must stop at delivery and readiness
    must block — 'service is active' is startup status, not confirmation."""
    from srplatform import verification_service
    from srplatform.settings import get_settings
    monkeypatch.setenv("ENROLL_CONFIRM_TIMEOUT_S", "1")
    get_settings.cache_clear()
    chan = HostChannel(host_client=None)     # service runs; host never calls
    enrollment_channel.set_enrollment_exec(chan)
    verification_service.set_verifier_exec(chan)

    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    from tests.conftest import wait_operation
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed
    assert "readiness_failed" in (failed["error"] or ""), failed
    st = _enroll_state(client, sid)
    assert st.get("phase") == "confirm_failed" and st.get("stage") == "delivery_confirmed", st
    assert "callback" in st.get("error", "").lower() or "delivery" in st.get("error", "").lower()
    # it DID get as far as service_running — the phases are DISTINCT
    assert st.get("service_running_at") and "delivery_confirmed_at" not in st


@pytest.mark.db
def test_t05_delivery_ok_but_capture_broken_blocks_confirmation(
        client, users, fake_pve, enrollment_channel, monkeypatch):
    """Delivery working while CAPTURE is broken (unreadable audit input,
    wrong unit identity) is not a healthy evidence stream: the phase stops
    at capture_verified, visibly, and readiness blocks."""
    from srplatform import verification_service
    from srplatform.settings import get_settings
    monkeypatch.setenv("ENROLL_CONFIRM_TIMEOUT_S", "1")
    monkeypatch.setenv("ENROLL_CAPTURE_TIMEOUT_S", "1")
    get_settings.cache_clear()
    chan = HostChannel(host_client=client, deliver_capture=False)  # capture dead
    enrollment_channel.set_enrollment_exec(chan)
    verification_service.set_verifier_exec(chan)

    sid = _session(client, users)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    from tests.conftest import wait_operation
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed
    assert "readiness_failed" in (failed["error"] or ""), failed
    st = _enroll_state(client, sid)
    assert st.get("phase") == "confirm_failed" and st.get("stage") == "capture_verified", st
    assert st.get("delivery_confirmed_at"), "delivery evidence must be retained"
    assert "capture" in st.get("error", "").lower()
    # the probe really ran on the host — the evidence just never arrived
    assert any("SR-CAPTURE-" in c for _, c in chan.commands)


# --------------------------------------------------------------------------- #
# The INSTALLED shipper proves its own delivery + capture (real subprocess)    #
# --------------------------------------------------------------------------- #

def _free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.db
def test_t05_installed_shipper_proves_delivery_and_capture(client, users, tmp_path):
    """DISPOSABLE-LINUX-FIXTURE acceptance: the REAL shipper artifact runs
    as a subprocess (its actual service identity's env contract: SR_API_URL,
    SR_TELEMETRY_TOKEN, SR_HOST, SR_ENROLL_NONCE) against the API served by
    REAL uvicorn on a socket. The shipper's own callback produces DELIVERY
    evidence; a harmless command fed through its stdin — exactly what auditd
    would write — produces the CAPTURE evidence. Nothing controller-side
    asserts either one."""
    import uvicorn

    from srplatform.api.app import app
    sid = _session(client, users)
    tok, nonce = _issue(sid)

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    base = f"http://127.0.0.1:{port}"

    env = {**os.environ, "SR_API_URL": base, "SR_TELEMETRY_TOKEN": tok,
           "SR_HOST": "web01", "SR_ENROLL_NONCE": nonce,
           "SR_SPOOL_DIR": str(tmp_path / "spool")}
    proc = subprocess.Popen([sys.executable, str(SHIPPER), "--close-after-s", "0.2"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env=env)
    try:
        # DELIVERY: the shipper's authenticated nonce callback arrives on its
        # own — the controller has done nothing since issuing the capability.
        assert _wait_for(lambda: _token_row(tok)[0] is not None, timeout=20), \
            "installed shipper never produced the enrollment callback"

        # CAPTURE: the harmless probe command, observed as an audit record
        # and delivered THROUGH THE INSTALLED SERVICE.
        from srplatform.scenario_engine.orchestrator import capture_marker
        marker = capture_marker(nonce)
        audit = (
            f'type=EXECVE msg=audit(1700000000.5000:777): argc=2 '
            f'a0="/bin/true" a1="{marker}"\n'
            'type=SYSCALL msg=audit(1700000000.5000:777): arch=c000003e '
            'syscall=59 success=yes exit=0 ppid=1 pid=4242 key="sparring_cmd"\n'
            'type=EOE msg=audit(1700000000.5000:777): \n')
        proc.stdin.write(audit)
        proc.stdin.flush()
        time.sleep(1.0)          # let the bounded completion timeout close it
        shipper_out = proc.communicate(timeout=30)[0]  # closes stdin -> final flush

        assert _wait_for(lambda: _token_row(tok)[1] is not None, timeout=15), \
            "capture probe never arrived as an audit event through the service; " \
            f"shipper said: {shipper_out[-800:]!r}"
        assert len(_events(sid, "telemetry_enroll_confirmed")) == 1
        assert len(_events(sid, "telemetry_capture_verified")) == 1
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.db
def test_t05_shipper_with_unreachable_api_or_bad_token_never_confirms(
        client, users, tmp_path):
    """Negatives: an ACTIVE shipper whose API is unreachable, or whose token
    is not a valid capability, produces NO delivery evidence — the enrollment
    stays visibly unconfirmed (this is what blocks readiness in the field)."""
    import uvicorn

    from srplatform.api.app import app
    sid = _session(client, users)
    tok, nonce = _issue(sid)

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started

    # unreachable API (nothing listening on this port)
    dead_port = _free_port()
    env = {**os.environ, "SR_API_URL": f"http://127.0.0.1:{dead_port}",
           "SR_TELEMETRY_TOKEN": tok, "SR_HOST": "web01", "SR_ENROLL_NONCE": nonce,
           "SR_SPOOL_DIR": str(tmp_path / "spool1")}
    proc = subprocess.Popen([sys.executable, str(SHIPPER), "--close-after-s", "0.2"],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, text=True, env=env)
    proc.stdin.close()
    proc.wait(timeout=30)

    # live API, but the capability was never issued (rejected callback)
    env2 = {**env, "SR_API_URL": f"http://127.0.0.1:{port}",
            "SR_TELEMETRY_TOKEN": "svc-telemetry-never-issued",
            "SR_SPOOL_DIR": str(tmp_path / "spool2")}
    proc = subprocess.Popen([sys.executable, str(SHIPPER), "--close-after-s", "0.2"],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, text=True, env=env2)
    proc.stdin.close()
    proc.wait(timeout=30)

    time.sleep(0.5)
    assert _token_row(tok)[0] is None, "delivery evidence appeared without a callback"
    assert _token_row(tok)[1] is None


# --------------------------------------------------------------------------- #
# Shipper confirmer: retries visibly, gives up visibly — never silently        #
# --------------------------------------------------------------------------- #

def test_t05_confirmer_retries_until_reachable_then_stops_trying(monkeypatch,
                                                                 capsys):
    from telemetry import shipper
    calls = {"n": 0}

    def flaky(api, token, nonce, host, machine_id, boot_id):
        calls["n"] += 1
        return calls["n"] >= 3

    monkeypatch.setattr(shipper, "confirm_enrollment", flaky)
    c = shipper.EnrollmentConfirmer("http://api", "tok", "n" * 32, "web01",
                                    "m", "b", sleeper=lambda s: None)
    c._run()
    assert c.confirmed.is_set() and not c.gave_up.is_set()
    assert calls["n"] == 3
    assert "delivery NOT yet proven" in capsys.readouterr().err

    monkeypatch.setattr(shipper, "confirm_enrollment",
                        lambda *a, **k: False)
    c = shipper.EnrollmentConfirmer("http://api", "tok", "n" * 32, "web01",
                                    "m", "b", max_attempts=2,
                                    sleeper=lambda s: None)
    c._run()
    assert c.gave_up.is_set() and not c.confirmed.is_set()
    assert "ABANDONED" in capsys.readouterr().err
