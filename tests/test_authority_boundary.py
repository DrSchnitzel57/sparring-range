"""Milestone 02 — private deployment broker: boundary, durability, cessation.

These are the AUTHORITY-layer acceptance tests: real policy enforcement,
real mutual-TLS handshakes, real SQLite durability across process-object
restarts, real task/read-back cessation, and real writer races. Nothing is
mocked above the proxmoxer boundary (FakePVEHttp) — the broker service,
ledger, transports and HTTP server are the production code.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import subprocess
import threading
import time

import pytest

from infra.broker.client import BrokerClient, HttpTransport, LocalTransport
from infra.broker.errors import (BrokerConflict, BrokerLatched, BrokerRefused,
                                 BrokerUnavailable, PolicyViolation)
from infra.broker.ledger import Ledger
from infra.broker.policy import BrokerPolicy
from infra.broker.testing import DEFAULT_TEST_POLICY, make_fake_broker, make_test_policy

pytestmark = pytest.mark.authority

NODE = "r740"
# Plan 13 phase 2: fixtures must satisfy the CURRENT name policy (prefix
# "sr-", see infra/broker/policy.py check_name) — the pre-policy
# "web01-deadbeef" was correctly refused. The policy stays; the fixtures
# were stale. Foreign-resource fixtures below deliberately keep NON-sr
# names because they model someone else's machine.
NAME = "sr-web01-deadbeef"
TAG = "srsess-" + "a" * 32
IPC = "ip=10.66.0.10/24"  # on-link only: a gw= is refused by policy
NET0 = "virtio,bridge=vmbr1,tag=66"


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def now(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def _mk(tmp_path, *, clock: Clock | None = None, policy=None, **kw):
    return make_fake_broker(policy=policy or make_test_policy(),
                            ledger_path=tmp_path / "ledger.sqlite3",
                            now=clock.now if clock else None, **kw)


def _clone(client, vmid=210, name=NAME, session_id="sess-1", generation="g1"):
    client.clone_and_wait(NODE, 9001, vmid, name, full=False,
                          session_id=session_id, generation=generation)


def _place(client, vmid=210, session_id="sess-1"):
    client.set_config(NODE, vmid, session_id=session_id,
                      ipconfig0=IPC, net0=NET0, tags=TAG)


# --------------------------------------------------------------------------- #
# 1. policy: the allowlist boundary                                           #
# --------------------------------------------------------------------------- #

def test_policy_rejects_every_out_of_boundary_operation(tmp_path):
    client, service, http = _mk(tmp_path)
    # node
    with pytest.raises(PolicyViolation, match="policy node"):
        client.lookup_vm("other-node", 210)
    # template
    with pytest.raises(PolicyViolation, match="not in the approved set"):
        client.clone_and_wait(NODE, 9999, 210, NAME, session_id="s")
    # VMID outside bounded range
    with pytest.raises(PolicyViolation, match="bounded range"):
        client.clone_and_wait(NODE, 9001, 1000, NAME, session_id="s")
    # clone mode
    with pytest.raises(PolicyViolation, match="clone mode"):
        client.clone_and_wait(NODE, 9001, 210, NAME, full=True, session_id="s")
    # name shape
    with pytest.raises(PolicyViolation, match="name"):
        client.clone_and_wait(NODE, 9001, 210, "Bad Name/../x", session_id="s")
    # now place a legitimate VM and attack its config
    _clone(client)
    for cfg, why in (
        ({"mount0": "local:100,mp0=/etc"}, "keys not provisionable"),
        ({"net0": "virtio,bridge=vmbr0,tag=66"}, "exact policy NIC"),
        ({"net0": "virtio,bridge=vmbr1,tag=999"}, "exact policy NIC"),
        ({"ipconfig0": "ip=10.99.0.10/24"}, "outside range network"),
        ({"ipconfig0": "ip=10.66.0.10/24,gw=10.66.0.1"},
         "default route is refused by policy"),
        ({"ipconfig0": "ip=10.66.0.10/16"}, "prefix"),
        ({"tags": "anything-goes"}, "must all match"),
        ({"tags": "srsess-" + "z" * 32}, "must all match"),
    ):
        with pytest.raises(PolicyViolation, match=why):
            client.set_config(NODE, 210, session_id="sess-1", **cfg)
    # aggregate capacity
    policy = make_test_policy(limits={**DEFAULT_TEST_POLICY["limits"],
                                      "max_vms": 1})
    c2, s2, h2 = make_fake_broker(policy=policy,
                                  ledger_path=tmp_path / "l2.sqlite3")
    _clone(c2, 210)
    with pytest.raises(PolicyViolation, match="max_vms"):
        _clone(c2, 211)


def test_policy_file_fails_closed_on_load(tmp_path):
    good = dict(DEFAULT_TEST_POLICY)
    # missing file
    with pytest.raises(PolicyViolation, match="missing"):
        BrokerPolicy.load(tmp_path / "nope.json")
    for label, mutate in (
        ("unknown key", lambda d: d.update({"arbitrary_pve_paths": True})),
        ("inverted range", lambda d: d.update({"vmid_range": [300, 200]})),
        ("unbounded range", lambda d: d.update({"vmid_range": [1, 99999999]})),
        ("two NICs", lambda d: d.update({"nic": {"bridge": "vmbr1", "vlan": 66,
                                                 "bridge2": "x"}})),
        ("bad cidr", lambda d: d.update({"provision": {"cidr": "10.66.0.0/33",
                                                       "gateway": "10.66.0.1"}})),
        ("no limits", lambda d: d.pop("limits")),
        ("lease ttl below heartbeat",
         lambda d: d.update({"lease_ttl_s": 2, "heartbeat_interval_s": 5})),
    ):
        raw = json.loads(json.dumps(good))
        mutate(raw)
        with pytest.raises(PolicyViolation, match="policy"):
            BrokerPolicy.from_dict(raw, source=label)
        assert label


# --------------------------------------------------------------------------- #
# 2. mutual TLS + typed wire surface                                          #
# --------------------------------------------------------------------------- #

def _tls_material(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def _name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def _issue(subject_cn, issuer_name=None, issuer_key=None, ca=False,
               host_san=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(_name(subject_cn))
             .issuer_name(issuer_name or _name(subject_cn))
             .public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=2)))
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                critical=True)
        if host_san:
            b = b.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("broker.lab"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert = b.sign(issuer_key or key, hashes.SHA256())
        return key, cert

    ca_key, ca_cert = _issue("sr-test-ca", ca=True)
    srv_key, srv_cert = _issue("broker.lab", x509.Name(ca_cert.subject), ca_key,
                               host_san=True)
    cli_key, cli_cert = _issue("api-client", x509.Name(ca_cert.subject), ca_key)
    evil_key, evil_cert = _issue("evil", ca=True)
    evil_key2, evil_cert2 = _issue("evil-client", x509.Name(evil_cert.subject),
                                   evil_key)

    def _write(tag, key, cert):
        kp = tmp_path / f"{tag}.key"
        cp = tmp_path / f"{tag}.pem"
        kp.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(cp), str(kp)

    ca_p = tmp_path / "ca.pem"
    ca_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    evil_ca_p = tmp_path / "evil-ca.pem"
    evil_ca_p.write_bytes(evil_cert.public_bytes(serialization.Encoding.PEM))
    return {"ca": str(ca_p), "evil_ca": str(evil_ca_p),
            "server": _write("server", srv_key, srv_cert),
            "client": _write("client", cli_key, cli_cert),
            "evil_client": _write("evil_client", evil_key2, evil_cert2)}


@pytest.fixture()
def tls_broker(tmp_path):
    """Real mutual-TLS broker server on an ephemeral loopback port."""
    from infra.broker.server import make_server

    mat = _tls_material(tmp_path)
    client, service, http = _mk(tmp_path)
    srv = make_server(service, "127.0.0.1", 0, certfile=mat["server"][0],
                      keyfile=mat["server"][1], ca_file=mat["ca"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    yield mat, port, service, http
    srv.shutdown()
    srv.server_close()


def _transport(mat, port):
    return HttpTransport(f"https://127.0.0.1:{port}", mat["ca"],
                         mat["client"][0], mat["client"][1])


def _raw_tls(mat, port, *, client_cert=None, client_key=None, ca=None):
    """One TLS handshake + request attempt; returns the first bytes read
    (a TLS 1.3 refusal can surface as an alert on the first read)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca or mat["ca"])
    if client_cert:
        ctx.load_cert_chain(client_cert, client_key)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
            tls.sendall(b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            return tls.recv(128)


def _no_http_response(fn, *a, **kw) -> bool:
    """True when the attempt produced NO valid HTTP response (handshake
    alert, closed connection, or non-HTTP bytes)."""
    try:
        data = fn(*a, **kw)
    except (ssl.SSLError, OSError):
        return True
    return not data.startswith(b"HTTP/1.")


def test_mutual_tls_negatives_and_positive(tls_broker):
    mat, port, _service, _http = tls_broker
    # (a) no client certificate: the boundary refuses — no HTTP at all
    assert _no_http_response(_raw_tls, mat, port), \
        "server answered WITHOUT a client certificate"
    # (b) client cert from a FOREIGN CA: refused
    assert _no_http_response(_raw_tls, mat, port,
                             client_cert=mat["evil_client"][0],
                             client_key=mat["evil_client"][1]), \
        "server accepted a foreign-CA client certificate"
    # (c) plaintext HTTP to the TLS port: no valid response
    def _plaintext():
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            return sock.recv(64)
    assert _no_http_response(_plaintext), "plaintext HTTP was accepted"
    # (d) the right client works end to end
    client = BrokerClient(_transport(mat, port))
    assert client.latch_status()["latched"] is False
    _clone(client)
    assert 210 in _http_vms(_service)


def _http_vms(service):
    return {v for v in service.pve.api.vms}


def _clones(http):
    """CLONE requests only — not the task-status polls whose URLs embed the
    clone path."""
    return [r for r in http.requests if r[0] == "POST" and r[1].endswith("/clone")]


def test_wire_surface_is_typed_only(tls_broker):
    mat, port, service, http = tls_broker
    client = BrokerClient(_transport(mat, port))
    # unknown operation -> 404 (BrokerRefused), never executed
    with pytest.raises(BrokerRefused, match="unknown operation"):
        client._t.call("delete", {"path": "/nodes/r740/qemu/101"})
    # operator-local operations are NOT reachable over the wire at all
    for op in ("release_latch", "enroll", "startup_reconcile"):
        with pytest.raises(BrokerRefused, match="unknown operation"):
            client._t.call(op, {})
    # malformed body -> 400
    with pytest.raises(BrokerRefused, match="HTTP 400"):
        client._t.call("clone_and_wait", {"node": NODE, "template_vmid": "not-a-vmid",
                                          "new_vmid": 210, "name": NAME})
    # policy violation over the wire -> 403
    with pytest.raises(PolicyViolation):
        client.clone_and_wait("evil-node", 9001, 210, NAME)
    # a successful typed call still works
    _clone(client)
    assert client.vm_status(NODE, 210) == "stopped"


def test_latched_refuses_mutation_allows_cessation(tmp_path):
    client, service, http = _mk(tmp_path)
    _clone(client)
    service.hard_stop_all("test-cessation")
    with pytest.raises(BrokerLatched):
        _place(client)
    with pytest.raises(BrokerLatched):
        client.clone_and_wait(NODE, 9001, 211, NAME + "-2", session_id="s")
    with pytest.raises(BrokerLatched):
        client.destroy_and_wait(NODE, 210)
    with pytest.raises(BrokerLatched):
        client.renew_lease("api")  # renewal can never resume a stopped range
    # cessation + reads still proceed
    assert client.vm_status(NODE, 210) == "stopped"
    assert client.inventory()["latch"]["latched"] is True
    assert client.stop_and_confirm(NODE, 210) == "stopped"


# --------------------------------------------------------------------------- #
# 3. ledger durability: intent before effect, reconcile not replay            #
# --------------------------------------------------------------------------- #

def test_intent_recorded_before_effect_and_reconciled_not_replayed(tmp_path):
    client, service, http = _mk(tmp_path)
    # the clone task FAILS after the request reached PVE: uncertain outcome
    http.fail_task_fragments = ("/clone",)
    with pytest.raises(BrokerUnavailable):
        _clone(client)
    assert service.ledger.open_obligations(), "uncertain clone must retain an obligation"
    assert service.ledger.get_claim(210)["state"] in ("creating", "reserved")
    # operator clears the fault; retry must RECONCILE, not blind-replay:
    # nothing exists at 210, so a real (second) clone is legitimate
    http.fail_task_fragments = ()
    _clone(client)
    assert len(_clones(http)) == 2, "one failed + one reconciled clone"
    assert service.ledger.get_claim(210)["state"] == "created"


def test_idempotent_replay_never_clones_twice(tmp_path):
    client, service, http = _mk(tmp_path)
    _clone(client)
    _clone(client)  # same generation, same args -> ledger replay
    _clone(client)
    assert len(_clones(http)) == 1
    # a NEW generation at the same VMID is a NEW intent (reset semantics)
    service.ledger.upsert_claim(210, node=NODE, state="destroyed", name=NAME)
    http.vms.pop(210)
    client.clone_and_wait(NODE, 9001, 210, NAME, full=False,
                          session_id="sess-1", generation="g2")
    assert len(_clones(http)) == 2


def test_crash_between_side_effect_and_confirmation_reconciles(tmp_path):
    """Simulate the crash: clone completed in PVE but the broker died before
    confirming. The pending intent must be SURFACED (never auto-replayed) and
    the next same-intent call must CONFIRM from reality, never re-clone."""
    ledger_path = tmp_path / "ledger.sqlite3"
    client, service, http = make_fake_broker(ledger_path=ledger_path)
    _clone(client)
    # forge the crash state: claim rolled back to 'creating', intent pending
    con = service.ledger._con
    con.execute("UPDATE claims SET state='creating' WHERE vmid=210")
    con.execute("UPDATE intents SET state='pending'")
    con.commit()
    assert service.ledger.pending_intents(), "pending intent must be surfaced"
    # reconcile by re-issuing the same intent: it must CONFIRM, not clone
    _clone(client)
    assert len(_clones(http)) == 1, "reconcile must not blind-replay the clone"
    assert service.ledger.get_claim(210)["state"] == "created"


def test_restart_with_active_claims_and_unverified_lease_latches_and_stops(tmp_path):
    from infra.broker.testing import reopen_broker
    ledger_path = tmp_path / "ledger.sqlite3"
    client, service, http = make_fake_broker(ledger_path=ledger_path)
    _clone(client)
    _place(client)
    client.start_and_wait(NODE, 210)
    assert client.vm_status(NODE, 210) == "running"
    # broker restarts (new service object, same ledger AND same PVE), lease
    # never armed
    service.stop_watchdog()
    client2, service2 = reopen_broker(http, policy=service.policy,
                                      ledger_path=ledger_path)
    report = service2.startup_reconcile()
    assert report["stopped"] is not None
    assert service2.ledger.get_latch()["latched"] is True
    assert http.vms[210]["status"] == "stopped", "restart must stop owned VMs"
    with pytest.raises(BrokerLatched):
        client2.start_and_wait(NODE, 210)


def test_restart_with_fresh_lease_does_not_stop(tmp_path):
    from infra.broker.testing import reopen_broker
    ledger_path = tmp_path / "ledger.sqlite3"
    clock = Clock()
    client, service, http = make_fake_broker(ledger_path=ledger_path, now=clock.now)
    _clone(client)
    client.start_and_wait(NODE, 210)
    client.renew_lease("api")
    clock.advance(2)
    client2, service2 = reopen_broker(http, policy=service.policy,
                                      ledger_path=ledger_path, now=clock.now)
    report = service2.startup_reconcile()
    assert report["stopped"] is None
    assert service2.ledger.get_latch()["latched"] is False
    assert http.vms[210]["status"] == "running"


# --------------------------------------------------------------------------- #
# 4. control lease: expiry stops, renewals prevent                            #
# --------------------------------------------------------------------------- #

def test_lease_expiry_stops_range_and_cannot_resume(tmp_path):
    clock = Clock()
    client, service, http = _mk(tmp_path, clock=clock)
    _clone(client)
    client.start_and_wait(NODE, 210)
    client.renew_lease("api")
    clock.advance(20)
    assert service.check_lease() is None, "must not fire inside the TTL"
    assert client.vm_status(NODE, 210) == "running"
    clock.advance(15)  # 35s since renewal > 30s TTL
    report = service.check_lease()
    assert report is not None and report["latched"]
    assert http.vms[210]["status"] == "stopped"
    with pytest.raises(BrokerLatched):
        client.renew_lease("api")  # expiry stops; renewal never resumes
    # a second tick is a no-op (already latched)
    assert service.check_lease() is None


def test_healthy_renewals_prevent_stop(tmp_path):
    clock = Clock()
    client, service, http = _mk(tmp_path, clock=clock)
    _clone(client)
    client.start_and_wait(NODE, 210)
    for _ in range(10):
        clock.advance(4)
        client.renew_lease("api")
        assert service.check_lease() is None
    assert http.vms[210]["status"] == "running"


# --------------------------------------------------------------------------- #
# 5. cessation: read-back, partial failure, recycled VMIDs                    #
# --------------------------------------------------------------------------- #

def test_hard_stop_all_stops_with_readback_and_retains_obligations(tmp_path):
    client, service, http = _mk(tmp_path)
    for vmid in (210, 211, 212):
        client.clone_and_wait(NODE, 9001, vmid, f"{NAME}-h{vmid}",
                              session_id="s", generation="g")
        client.set_config(NODE, vmid, session_id="s",
                          ipconfig0=f"ip=10.66.0.{vmid-200}/24",
                          net0=NET0, tags=TAG)
        client.start_and_wait(NODE, vmid)
    # 212 refuses to stop: task fails
    http.fail_requests["qemu/212/status/stop"] = 500
    report = client.hard_stop_all("acceptance")
    assert report["latched"] and sorted(report["stopped"]) == [210, 211]
    assert report["failed"] and report["failed"][0]["vmid"] == 212
    assert http.vms[210]["status"] == "stopped"
    assert http.vms[211]["status"] == "stopped"
    assert http.vms[212]["status"] == "running", "unconfirmed stays truthful"
    ob = service.ledger.open_obligations()
    assert any(o["vmid"] == 212 for o in ob), "unconfirmed stop must retain obligation"
    assert service.ledger.get_claim(212)["state"] == "unknown"
    # release is refused while obligations are open
    with pytest.raises(BrokerConflict, match="obligation"):
        service.release_latch("operator")
    # operator fixes reality (VM gone), obligation resolves via stop_and_confirm
    http.fail_requests.pop("qemu/212/status/stop")
    http.vms.pop(212)
    assert client.stop_and_confirm(NODE, 212) == "absent"
    for o in ob:
        service.ledger.resolve_obligation(o["id"])
    assert service.release_latch("operator")["released"]


def test_hard_stop_spares_recycled_vmid(tmp_path):
    client, service, http = _mk(tmp_path)
    _clone(client)
    client.start_and_wait(NODE, 210)
    # VMID recycled out from under us: our VM is gone, a FOREIGN one lives here
    http.vms.pop(210)
    http.vms[210] = {"name": "someone-elses-prod", "status": "running"}
    report = client.hard_stop_all("acceptance")
    assert report["stopped"] == [] and report["failed"] == []
    assert report["foreign-retained"] and report["foreign-retained"][0]["vmid"] == 210
    assert http.vms[210]["status"] == "running", "foreign VM must NOT be stopped"
    assert any(o["vmid"] == 210 for o in service.ledger.open_obligations())


def test_cross_session_and_unowned_mutation_refused(tmp_path):
    client, service, http = _mk(tmp_path)
    _clone(client)
    # another session may not touch our VMID
    with pytest.raises(BrokerConflict, match="different session"):
        client.set_config(NODE, 210, session_id="sess-2", tags=TAG)
    # a VM the ledger never claimed may not be mutated at all
    http.vms[215] = {"name": "legacy", "status": "stopped"}
    with pytest.raises(BrokerConflict, match="never claimed"):
        client.set_config(NODE, 215, tags=TAG)
    with pytest.raises(BrokerConflict, match="never claimed"):
        client.destroy_and_wait(NODE, 215)
    with pytest.raises(BrokerConflict, match="never claimed"):
        client.stop_and_confirm(NODE, 215)


# --------------------------------------------------------------------------- #
# 6. writer races                                                             #
# --------------------------------------------------------------------------- #

def test_reserved_claim_is_not_double_counted(tmp_path):
    """Plan 13 phase 2 reservation accounting: next_vmid's 'reserved' claim
    IS the future VM — clone_and_wait must not charge it AGAIN against
    max_vms (the old code counted it twice and refused the third guest of a
    three-VM range)."""
    policy = make_test_policy(limits={**DEFAULT_TEST_POLICY["limits"],
                                      "max_vms": 3})
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l3.sqlite3")
    vmids = []
    for i in range(3):
        vmid = client.next_vmid(NODE, 210 + i, session_id="s")
        vmids.append(vmid)
        assert service.ledger.get_claim(vmid)["state"] == "reserved"
        client.clone_and_wait(NODE, 9001, vmid, f"{NAME}-{i}",
                              session_id="s", generation=f"g{i}")
        assert service.ledger.get_claim(vmid)["state"] == "created"
    assert len(set(vmids)) == 3
    # the FOURTH reservation is the first genuine capacity violation
    with pytest.raises(PolicyViolation, match="max_vms"):
        client.next_vmid(NODE, 220, session_id="s")


def test_concurrent_same_clone_executes_exactly_once(tmp_path):
    client, service, http = _mk(tmp_path)
    http.task_polls_needed = 2  # widen the window
    errors: list = []
    start = threading.Barrier(2)

    def worker():
        try:
            start.wait()
            _clone(client)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    assert not errors, errors
    assert len(_clones(http)) == 1
    assert service.ledger.get_claim(210)["state"] == "created"


def test_concurrent_hard_stop_fences_clone(tmp_path):
    client, service, http = _mk(tmp_path)
    http.task_polls_needed = 5
    outcome: dict = {}
    start = threading.Barrier(2)

    def clone_worker():
        start.wait()
        try:
            _clone(client)
            outcome["clone"] = "done"
        except BrokerLatched:
            outcome["clone"] = "fenced"
        except Exception as e:  # noqa: BLE001
            outcome["clone"] = f"error: {e}"

    def stop_worker():
        start.wait()
        time.sleep(0.01)
        outcome["stop"] = client.hard_stop_all("race")

    ts = [threading.Thread(target=clone_worker), threading.Thread(target=stop_worker)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    assert service.ledger.get_latch()["latched"], "cessation must win the latch"
    assert outcome.get("clone") in ("done", "fenced"), outcome
    if outcome.get("clone") == "done":
        # a clone that completed BEFORE the fence must be stopped by it
        assert http.vms[210]["status"] == "stopped"
    else:
        assert 210 not in http.vms or http.vms[210]["status"] == "stopped"


def test_emergency_cancel_races_spawn_attach_window():
    """The runner supervisory table: cancel_active() racing the
    register->spawn->attach window must leave NO live command group."""
    import srplatform.red_agent.runner as runner

    spawned: list[subprocess.Popen] = []
    stop = threading.Event()

    def canceller():
        while not stop.is_set():
            runner.cancel_active(timeout_s=2)
            time.sleep(0.001)

    canceller_thread = threading.Thread(target=canceller, daemon=True)
    canceller_thread.start()
    try:
        for _ in range(25):
            op_id = runner._new_op_id()
            runner._register(op_id, {"kind": "local", "state": "pending"})
            proc = subprocess.Popen(["sleep", "120"], start_new_session=True)
            spawned.append(proc)
            runner._attach_proc(op_id, proc)
            time.sleep(0.002)
    finally:
        stop.set()
        canceller_thread.join(10)
        runner.cancel_active(timeout_s=5)
    deadline = time.time() + 15
    for proc in spawned:
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.05)
        assert proc.poll() is not None, (
            f"pid {proc.pid} survived the cancel/register race")
    for proc in spawned:
        if proc.poll() is None:
            proc.kill()
    assert runner.active_ops() == []


def test_registry_terminate_races_registration():
    """The API-side run registry: emergency termination racing worker
    registration must never lose a process group."""
    from srplatform.safety.runregistry import (RunHandle, RunRegistry,
                                               pgid_start_time)

    reg = RunRegistry()
    spawned: list[subprocess.Popen] = []
    stop = threading.Event()

    def terminator():
        while not stop.is_set():
            for h in reg.active():
                reg.terminate_group(h.pgid, grace_s=0.2,
                                    expected_pstart=h.pgid_pstart)
            time.sleep(0.005)

    term = threading.Thread(target=terminator, daemon=True)
    term.start()
    try:
        for i in range(15):
            proc = subprocess.Popen(["sleep", "120"], start_new_session=True)
            spawned.append(proc)
            reg.add(RunHandle(run_id=f"race-{i}", pid=proc.pid, pgid=proc.pid,
                              pgid_pstart=pgid_start_time(proc.pid)))
            time.sleep(0.002)
    finally:
        stop.set()
        term.join(10)
    deadline = time.time() + 30
    for proc in spawned:
        while proc.poll() is None and time.time() < deadline:
            reg.terminate_group(proc.pid, grace_s=0.2)
            time.sleep(0.05)
        assert proc.poll() is not None, (
            f"pgid {proc.pid} escaped the terminate/register race")
    for proc in spawned:
        if proc.poll() is None:
            proc.kill()


# --------------------------------------------------------------------------- #
# 7. transport honesty + structural boundary                                  #
# --------------------------------------------------------------------------- #

def test_transport_down_is_uncertain_not_absent(tmp_path):
    # bind and close a port so the connection is refused deterministically
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    mat = _tls_material(tmp_path)
    t = HttpTransport(f"https://broker.lab:{port}", mat["ca"],
                      mat["client"][0], mat["client"][1])
    with pytest.raises(BrokerUnavailable):
        t.call("vm_status", {"node": NODE, "vmid": 210})
    # http:// is refused outright — no plaintext fallback exists
    with pytest.raises(BrokerRefused):
        HttpTransport(f"http://broker.lab:{port}", mat["ca"],
                      mat["client"][0], mat["client"][1])


def test_api_holds_no_proxmox_path():
    """Structural: nothing under srplatform/ may import the broker-private
    PVE adapter; only infra/broker (and its own adapter) may."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for py in (root / "srplatform").rglob("*.py"):
        text = py.read_text()
        for m in re.finditer(r"^\s*(?:from|import)\s+infra\.proxmox_client",
                             text, re.M):
            offenders.append(f"{py.relative_to(root)}:{m.group(0).strip()}")
    assert not offenders, (
        "the API layer must reach PVE only through the broker: " + str(offenders))
    # and the broker client exposes no raw-path escape hatch
    import infra.broker.client as bc
    for name in ("get", "post", "delete", "raw", "api"):
        assert not hasattr(BrokerClient, name), f"BrokerClient.{name} is an escape hatch"
    assert not hasattr(bc, "ProxmoxClient")


def test_local_transport_is_not_a_wire_bypass(tmp_path):
    """LocalTransport exposes exactly the CONTROL_OPS surface — operator-
    local operations cannot be invoked through it either."""
    client, service, http = _mk(tmp_path)
    with pytest.raises(BrokerRefused, match="not exposed"):
        LocalTransport(service).call("release_latch", {})
    with pytest.raises(BrokerRefused, match="not exposed"):
        LocalTransport(service).call("enroll", {"vmid": 210, "name": NAME,
                                                "tag": TAG, "operator": "x"})
    with pytest.raises(BrokerRefused, match="not exposed"):
        LocalTransport(service).call("delete", {"path": "/nodes/r740/qemu/101"})
