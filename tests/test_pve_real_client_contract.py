"""Plan 13 phase 2 — `pve-contract`: the REAL pinned proxmoxer client over
local HTTPS speaking the PVE API dialect.

This gate exists because every earlier adapter test substituted a `_Recorder`
or an in-process fake BELOW the proxmoxer boundary — so the actual HTTP
contract (the `/api2/json` prefix proxmoxer joins paths onto, the
`PVEAPIToken` auth header, form-encoded POST bodies, `{"data": ...}` replies,
ResourceException status mapping) was never executed. The live-deploy prefix
bug (every call losing `/api2/json`, answered by PVE's router with 500
"no such file") survived all of those. Here the production
`ProxmoxClient`/`ProxmoxAPI` stack performs real HTTPS requests against a
synthetic PVE dialect server; source-checked PVE 9.2 error dialects are
replayed over the wire, and absence/uncertainty classification is asserted
on the REAL exception shapes proxmoxer raises.

Infrastructure-free: loopback HTTPS with an ephemeral CA, no PVE, no
credentials, no external network.
"""
from __future__ import annotations

import datetime
import http.server
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.parse

import pytest

from infra.broker.client import HttpTransport
from infra.broker.errors import BrokerUnavailable
from infra.proxmox_client import (
    PveUnavailable,
    ProxmoxClient,
    ProxmoxError,
    ProxmoxTaskError,
    classify_pve_error,
)

pytestmark = pytest.mark.adapter

TOKEN_ID = "sr-broker@pve!contracttest"
TOKEN_SECRET = "synthetic-secret-value"
NODE = "pve"

# Exact live/source PVE 9.2 dialects replayed over the wire.
ROUTER_NO_SUCH_FILE_TEXT = "no such file '/nodes/pve/qemu/999/status/current'"


# --------------------------------------------------------------------------- #
# TLS material (ephemeral CA; SAN 127.0.0.1)                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    tmp = tmp_path_factory.mktemp("pve-contract-tls")

    def _name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def _issue(cn, issuer=None, issuer_key=None, ca=False, san=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(_name(cn))
             .issuer_name(issuer or _name(cn))
             .public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=2))
             # OpenSSL 3.x verification requires key identifiers on issued
             # certificates
             .add_extension(
                 x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                 critical=False)
             .add_extension(
                 x509.AuthorityKeyIdentifier.from_issuer_public_key(
                     issuer_key.public_key() if issuer_key
                     else key.public_key()),
                 critical=False))
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                critical=True)
            b = b.add_extension(
                x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True,
                              crl_sign=True, encipher_only=False,
                              decipher_only=False), critical=True)
        if san:
            b = b.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
        cert = b.sign(issuer_key or key, hashes.SHA256())
        return key, cert

    ca_key, ca_cert = _issue("pve-contract-ca", ca=True)
    srv_key, srv_cert = _issue("pve-contract", _name("pve-contract-ca"), ca_key,
                               san=True)
    cli_key, cli_cert = _issue("api-client", _name("pve-contract-ca"), ca_key)
    evil_key, evil_cert = _issue("evil-ca", ca=True)

    def _pem(tag, key, cert):
        kp = tmp / f"{tag}.key"
        cp = tmp / f"{tag}.pem"
        kp.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(cp), str(kp)

    ca_p = tmp / "ca.pem"
    ca_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    evil_p = tmp / "evil-ca.pem"
    evil_p.write_bytes(evil_cert.public_bytes(serialization.Encoding.PEM))
    return {"ca": str(ca_p), "evil_ca": str(evil_p),
            "server": _pem("server", srv_key, srv_cert),
            "client": _pem("client", cli_key, cli_cert)}


# --------------------------------------------------------------------------- #
# Synthetic PVE dialect server (real HTTPS)                                    #
# --------------------------------------------------------------------------- #

class _DialectHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _one(self):
        server = self.server
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        rec = {"method": self.command, "path": parsed.path,
               "query": urllib.parse.parse_qs(parsed.query),
               "headers": {k.lower(): v for k, v in self.headers.items()},
               "form": dict(urllib.parse.parse_qsl(body.decode("utf-8",
                                                              "replace")))}
        server.requests.append(rec)
        if server.sleep_s:
            time.sleep(server.sleep_s)

        # every API route must carry the /api2/json prefix — a client that
        # loses it (the historical bug) gets 501 HERE, loudly, not silence
        if not parsed.path.startswith("/api2/json/"):
            return self._send(501, text=f"unrouted {parsed.path}")

        auth = rec["headers"].get("authorization", "")
        if not auth.startswith("PVEAPIToken=") or TOKEN_SECRET not in auth:
            return self._send(401, text="authentication failure")

        if server.inject:
            status, text = server.inject
            return self._send(status, text=text)

        for rule in server.rules:
            m = rule["path"].fullmatch(parsed.path[len("/api2/json"):])
            if rule["method"] == self.command and m:
                status, kind, payload = rule["handler"](server, rec, *m.groups())
                if kind == "json":
                    return self._send(status, data=payload)
                return self._send(status, text=payload)
        # un-routed API path: replay the PVE router's routing-bug dialect
        return self._send(500, text=ROUTER_NO_SUCH_FILE_TEXT)

    do_GET = do_POST = do_DELETE = _one

    def _send(self, status, data=None, text=None):
        if data is not None:
            body = json.dumps({"data": data}).encode()
            ctype = "application/json"
        else:
            body = (text or "").encode()
            ctype = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DialectServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):  # client-abort noise
        pass

    def __init__(self, certfile, keyfile):
        super().__init__(("127.0.0.1", 0), _DialectHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)
        self.server_address = self.socket.getsockname()
        self.rules: list[dict] = []
        self.requests: list[dict] = []
        self.sleep_s = 0.0
        self.inject: tuple[int, str] | None = None
        self.task_polls_needed = 1
        self._upid = 0
        self.tasks: dict[str, dict] = {}
        self.vms: dict[int, dict] = {
            9005: {"name": "tpl-attacker", "status": "stopped", "template": 1},
        }

    def route(self, method: str, path: str, handler):
        """Later routes take precedence (inserted at the front)."""
        self.rules.insert(0, {"method": method, "path": re.compile(path),
                              "handler": handler})

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.server_address[1]}"


def _ok(payload):
    return (200, "json", payload)


def _text(status, text):
    return (status, "text", text)


def _default_routes(srv: DialectServer):
    """A minimal but honest PVE dialect: state, async UPID tasks, both
    absence dialects and the router's routing-bug 500 for unrouted paths."""
    absent_as_500 = {"on": False}  # PVE 9.2 answers per-guest reads with 500

    def absent(vmid):
        if absent_as_500["on"]:
            return _text(500, f"Configuration file 'nodes/{NODE}/qemu-server/"
                              f"{vmid}.conf' does not exist")
        return _text(404, f"no VM {vmid}")

    srv.absent_as_500 = absent_as_500

    def new_upid(kind, done):
        srv._upid += 1
        upid = f"UPID:pve:0000{srv._upid:04d}:0:0:{srv._upid}:qemu:{kind}::"
        srv.tasks[upid] = {"polls": 0, "done": done}
        return upid

    srv.new_upid = new_upid

    srv.route("GET", r"/version", lambda s, r: _ok(
        {"version": "8.4.0", "release": "9.2", "repoid": "synthetic"}))

    def nextid(s, r):
        want = int(r["query"].get("vmid", ["0"])[0])
        if want in s.vms:
            return _text(400, f"VM {want} already exists")
        return _ok(str(want))
    srv.route("GET", r"/cluster/nextid", nextid)

    srv.route("GET", r"/cluster/resources", lambda s, r: _ok(
        [{"vmid": v, "name": d["name"], "node": NODE, "type": "qemu",
          "status": d["status"]} for v, d in s.vms.items()]))

    def clone(s, r, _node, tpl):
        if "newid" not in r["form"]:
            return _text(400, "missing required parameter 'newid'")
        if "newvmid" in r["form"]:
            return _text(400, "unrecognized parameter: newvmid")
        new = int(r["form"]["newid"])
        if new in s.vms:
            return _text(500, f"unable to create VM {new}: config file "
                              "already exists")
        name = r["form"].get("name", "")

        def done():
            s.vms[new] = {"name": name, "status": "stopped", "template": 0}
        return _ok(s.new_upid("clone", done))
    srv.route("POST", r"/nodes/(\w+)/qemu/(\d+)/clone", clone)

    def config(s, r, _node, vmid):
        v = s.vms.get(int(vmid))
        if not v:
            return absent(int(vmid))
        return _ok({"name": v["name"], "net0": "virtio,bridge=vmbr1"})
    srv.route("GET", r"/nodes/(\w+)/qemu/(\d+)/config", config)

    def set_config(s, r, _node, vmid):
        v = s.vms.get(int(vmid))
        if not v:
            return absent(int(vmid))
        v.update(r["form"])
        return _ok(None)
    srv.route("POST", r"/nodes/(\w+)/qemu/(\d+)/config", set_config)

    def status_current(s, r, _node, vmid):
        v = s.vms.get(int(vmid))
        if not v:
            return absent(int(vmid))
        return _ok({"status": v["status"], "vmid": int(vmid)})
    srv.route("GET", r"/nodes/(\w+)/qemu/(\d+)/status/current", status_current)

    def power(action):
        def handler(s, r, _node, vmid):
            v = s.vms.get(int(vmid))
            if not v:
                return absent(int(vmid))

            def done():
                v["status"] = {"start": "running"}.get(action, "stopped")
            return _ok(s.new_upid(action, done))
        return handler
    for action in ("start", "stop", "shutdown"):
        srv.route("POST", rf"/nodes/(\w+)/qemu/(\d+)/status/{action}",
                  power(action))

    def destroy(s, r, _node, vmid):
        v = s.vms.pop(int(vmid), None)
        if not v:
            return absent(int(vmid))
        return _ok(s.new_upid("destroy", lambda: None))
    srv.route("DELETE", r"/nodes/(\w+)/qemu/(\d+)$", destroy)

    def task_status(s, r, _node, upid):
        t = s.tasks.get(upid)
        if not t:
            return _text(500, f"no such task '{upid}'")
        t["polls"] += 1
        if t["polls"] <= s.task_polls_needed:
            return _ok({"status": "running", "upids": upid})
        t["done"]()
        exitstatus = t.get("exitstatus", "OK")
        return _ok({"status": "stopped", "exitstatus": exitstatus,
                    "upids": upid})
    srv.route("GET", r"/nodes/(\w+)/tasks/([^/]+)/status", task_status)

    def file_read(s, r, _node, vmid):
        v = s.vms.get(int(vmid))
        if not v:
            return absent(int(vmid))
        want = r["query"].get("file", [""])[0]
        if want != "/etc/ssh/ssh_host_ed25519_key.pub":
            return _text(400, f"invalid file parameter {want!r}")
        import base64
        import hashlib
        raw = hashlib.sha256(f"contract:{vmid}".encode()).digest()
        key = "ssh-ed25519 " + base64.b64encode(raw + raw).decode()[:68]
        return _ok({"content": f"{key} root@synthetic\n"})  # cloud-init comment
    srv.route("GET", r"/nodes/(\w+)/qemu/(\d+)/agent/file-read", file_read)


@pytest.fixture()
def pve(tls):
    srv = DialectServer(*tls["server"])
    _default_routes(srv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _client(pve_server, monkeypatch, tls, *, ca="default", http_timeout=30,
            task_timeout=300):
    from srplatform import settings as settings_mod
    if ca == "default":
        ca_file = tls["ca"]
    elif ca is None:
        ca_file = None
    else:
        ca_file = ca
    s = settings_mod.Settings(_env_file=None,
                              proxmox_tls_ca_file=ca_file,
                              proxmox_http_timeout_s=http_timeout,
                              proxmox_task_timeout_s=task_timeout)
    monkeypatch.setattr(settings_mod, "get_settings", lambda: s)
    return ProxmoxClient(host=pve_server.host, token_id=TOKEN_ID,
                         token_secret=TOKEN_SECRET)


# --------------------------------------------------------------------------- #
# 1. the real proxmoxer HTTP contract                                          #
# --------------------------------------------------------------------------- #

def test_real_client_uses_api2_json_prefix_and_token_header(pve, monkeypatch,
                                                            tls):
    client = _client(pve, monkeypatch, tls)
    info = client.version()
    assert info["release"] == "9.2"
    rec = pve.requests[-1]
    # the historical bug: proxmoxer's posixpath.join let a leading slash
    # replace the /api2/json base — real HTTP proves the prefix survives
    assert rec["path"] == "/api2/json/version"
    auth = rec["headers"]["authorization"]
    assert auth.startswith("PVEAPIToken=sr-broker@pve!contracttest=")
    assert TOKEN_SECRET in auth


def test_query_and_form_encoding_match_pve(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    assert client.next_vmid(210) == 210
    rec = pve.requests[-1]
    assert rec["path"] == "/api2/json/cluster/nextid"
    assert rec["query"].get("vmid") == ["210"]

    upid = client.clone_template(NODE, 9005, 210, "sr-x-1", full=True,
                                 storage="local-zfs")
    rec = pve.requests[-1]
    assert rec["method"] == "POST"
    # documented parameter is newid; the form body must carry it
    assert rec["form"]["newid"] == "210"
    assert rec["form"]["full"] == "1"
    assert rec["form"]["storage"] == "local-zfs"
    assert upid.startswith("UPID:")

    client.set_config(NODE, 9005, name="tpl-attacker", tags="srsess-" + "a" * 32)
    rec = pve.requests[-1]
    assert rec["form"]["name"] == "tpl-attacker"


def test_nextid_collision_asserts_then_scans(pve, monkeypatch, tls):
    """`?vmid=N` is an ASSERTION (400 when taken); the resources() scan
    fallback must then find the next free id — over real HTTP."""
    client = _client(pve, monkeypatch, tls)
    pve.vms[210] = {"name": "someone-else", "status": "stopped", "template": 0}
    assert client.next_vmid(210) == 211
    collision = [r for r in pve.requests
                 if r["path"] == "/api2/json/cluster/nextid"]
    assert collision and collision[-1]["query"]["vmid"] == ["210"]
    assert any(r["path"] == "/api2/json/cluster/resources" for r in pve.requests)


def test_clone_start_stop_delete_task_lifecycle(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    pve.task_polls_needed = 2  # observe running -> stopped over real polls
    client.clone_and_wait(NODE, 9005, 210, "sr-life-1", full=False)
    assert pve.vms[210]["status"] == "stopped"
    client.start_and_wait(NODE, 210, timeout=30)
    assert pve.vms[210]["status"] == "running"
    assert client.vm_status(NODE, 210) == "running"
    outcome = client.destroy_and_wait(NODE, 210, force_stop_timeout=30)
    assert outcome == "destroyed"
    assert 210 not in pve.vms
    polls = [r for r in pve.requests
             if "/tasks/" in r["path"] and r["path"].endswith("/status")]
    assert len(polls) >= 4, "task waiting must really poll"


def test_task_exitstatus_error_is_task_error(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    upid = pve.new_upid("clone", lambda: None)
    pve.tasks[upid]["exitstatus"] = "ERROR: disk full"
    with pytest.raises(ProxmoxTaskError, match="ERROR"):
        client.wait_for_task(NODE, upid, timeout=5)


def test_task_that_never_stops_times_out_uncertain(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    upid = pve.new_upid("clone", lambda: None)
    pve.task_polls_needed = 10_000  # stays "running"
    with pytest.raises(ProxmoxTaskError, match="timed out"):
        client.wait_for_task(NODE, upid, timeout=1, poll_s=0.1)


def test_malformed_replies_are_uncertain_not_absent(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    pve.vms[210] = {"name": "sr-x", "status": "stopped", "template": 0}
    pve.route("GET", r"/nodes/(\w+)/qemu/(\d+)/config",
              lambda s, r, n, v: _ok("a string, not a config"))
    with pytest.raises(PveUnavailable, match="malformed config"):
        client.lookup_config(NODE, 210)


def test_status_without_field_is_uncertain(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    pve.vms[210] = {"name": "sr-x", "status": "stopped", "template": 0}
    pve.route("GET", r"/nodes/(\w+)/qemu/(\d+)/status/current",
              lambda s, r, n, v: _ok({"vmid": int(v)}))  # no status field
    with pytest.raises(PveUnavailable, match="no status field"):
        client.lookup_vm(NODE, 210)


# --------------------------------------------------------------------------- #
# 2. absence vs uncertainty dialects over REAL HTTP                            #
# --------------------------------------------------------------------------- #

def test_404_is_confirmed_absence(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    assert client.lookup_vm(NODE, 999) is None
    assert client.vm_status(NODE, 999) == "absent"
    assert client.destroy_and_wait(NODE, 999) == "already-absent"


def test_pve92_config_absent_500_dialect_is_confirmed_absence(pve, monkeypatch,
                                                              tls):
    client = _client(pve, monkeypatch, tls)
    pve.absent_as_500["on"] = True
    assert client.lookup_config(NODE, 999) is None
    assert client.lookup_vm(NODE, 999) is None


def test_router_no_such_file_500_is_NEVER_absence(pve, monkeypatch, tls):
    """Audit A1 over real HTTP: the router's routing-bug 500 ("no such file
    '<path>'") must stay UNCERTAIN — treating it as absence turns any URL
    prefix bug into free-looking VMIDs and false 'already-absent' teardowns."""
    client = _client(pve, monkeypatch, tls)
    # the raw exception proxmoxer really raised classifies as uncertain
    try:
        client.get("/nodes/pve/qemu/998/no-such-endpoint")
    except Exception as exc:  # noqa: BLE001
        assert "no such file" in str(exc)
        assert isinstance(classify_pve_error(exc), PveUnavailable)
    else:
        pytest.fail("unrouted path must raise, not answer")
    # and when the ROUTER dialect answers a real per-guest endpoint (e.g.
    # after a prefix bug), the lookup must raise, never report absence
    pve.inject = (500, ROUTER_NO_SUCH_FILE_TEXT)
    with pytest.raises(PveUnavailable):
        client.lookup_vm(NODE, 210)
    with pytest.raises(PveUnavailable):
        client.destroy_and_wait(NODE, 210)  # never a false 'already-absent'


def test_auth_and_server_errors_are_uncertain(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls)
    pve.route("GET", r"/nodes/(\w+)/qemu/(\d+)/config",
              lambda s, r, n, v: _text(403, "permission denied"))
    with pytest.raises(PveUnavailable):
        client.lookup_config(NODE, 210)
    pve.route("GET", r"/nodes/(\w+)/qemu/(\d+)/status/current",
              lambda s, r, n, v: _text(401, "auth required"))
    with pytest.raises(PveUnavailable):
        client.lookup_vm(NODE, 210)


def test_connection_refused_is_uncertain(monkeypatch, tls):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    from srplatform import settings as settings_mod
    st = settings_mod.Settings(_env_file=None, proxmox_tls_ca_file=tls["ca"])
    monkeypatch.setattr(settings_mod, "get_settings", lambda: st)
    client = ProxmoxClient(host=f"127.0.0.1:{port}", token_id=TOKEN_ID,
                           token_secret=TOKEN_SECRET)
    with pytest.raises(PveUnavailable):
        client.lookup_vm(NODE, 210)


def test_http_timeout_is_uncertain(pve, monkeypatch, tls):
    client = _client(pve, monkeypatch, tls, http_timeout=1)
    pve.sleep_s = 2.0
    try:
        with pytest.raises(PveUnavailable):
            client.lookup_vm(NODE, 210)
    finally:
        pve.sleep_s = 0.0


def test_tls_trust_is_enforced(tls, pve, monkeypatch):
    """No CA / foreign CA must FAIL CLOSED — TLS checks are never silently
    disabled for readiness (plan phase 4 boundary, proven at phase 2)."""
    from srplatform import settings as settings_mod
    st = settings_mod.Settings(_env_file=None, proxmox_tls_ca_file=None)
    monkeypatch.setattr(settings_mod, "get_settings", lambda: st)
    client = ProxmoxClient(host=pve.host, token_id=TOKEN_ID,
                           token_secret=TOKEN_SECRET)
    with pytest.raises(PveUnavailable):
        client.lookup_vm(NODE, 210)
    st2 = settings_mod.Settings(_env_file=None,
                                proxmox_tls_ca_file=tls["evil_ca"])
    monkeypatch.setattr(settings_mod, "get_settings", lambda: st2)
    client2 = ProxmoxClient(host=pve.host, token_id=TOKEN_ID,
                            token_secret=TOKEN_SECRET)
    with pytest.raises(PveUnavailable):
        client2.lookup_vm(NODE, 210)


def test_malformed_token_id_fails_before_any_request(monkeypatch, tls):
    from srplatform import settings as settings_mod
    st = settings_mod.Settings(_env_file=None)
    monkeypatch.setattr(settings_mod, "get_settings", lambda: st)
    with pytest.raises(ProxmoxError, match="malformed"):
        ProxmoxClient(host="127.0.0.1:1", token_id="sr-broker-pve!range",
                      token_secret="x")
    with pytest.raises(ProxmoxError, match="malformed"):
        ProxmoxClient(host="127.0.0.1:1", token_id="no-realm!range",
                      token_secret="x")


# --------------------------------------------------------------------------- #
# 3. guest-agent read over real HTTP                                           #
# --------------------------------------------------------------------------- #

def test_guest_agent_read_encodes_query_and_strips_comment(pve, monkeypatch,
                                                           tls):
    client = _client(pve, monkeypatch, tls)
    pve.vms[210] = {"name": "sr-x", "status": "running", "template": 0}
    key = client.read_guest_file(NODE, 210, client.GUEST_HOST_KEY_PATH)
    rec = pve.requests[-1]
    assert rec["path"] == "/api2/json/nodes/pve/qemu/210/agent/file-read"
    assert rec["query"]["file"] == ["/etc/ssh/ssh_host_ed25519_key.pub"]
    # cloud-init's root@host comment stripped; exactly two fields remain
    parts = key.split()
    assert len(parts) == 2 and parts[0] == "ssh-ed25519"


def test_guest_agent_read_refuses_other_paths_before_http(pve, monkeypatch,
                                                          tls):
    client = _client(pve, monkeypatch, tls)
    before = len(pve.requests)
    with pytest.raises(ProxmoxError, match="allowlisted"):
        client.read_guest_file(NODE, 210, "/etc/shadow")
    assert len(pve.requests) == before, "no HTTP may leave for a non-allowlisted path"


# --------------------------------------------------------------------------- #
# 4. broker transport deadlines: client/server/task checked together           #
# --------------------------------------------------------------------------- #

class _BrokerStubHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        op = self.path.rsplit("/", 1)[-1]
        server.calls.append((op, body))
        delay = server.delays_first.pop(op, server.delays.get(op, 0.0))
        if delay:
            time.sleep(delay)
        payload = json.dumps({"result": server.results.get(op, {"ok": True})}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _BrokerStub(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):  # lost-response noise
        pass

    def __init__(self, certfile, keyfile):
        super().__init__(("127.0.0.1", 0), _BrokerStubHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)
        self.server_address = self.socket.getsockname()
        self.calls: list[tuple[str, dict]] = []
        self.delays: dict[str, float] = {}
        self.delays_first: dict[str, float] = {}
        self.results: dict[str, dict] = {}

    @property
    def url(self):
        return f"https://127.0.0.1:{self.server_address[1]}"


@pytest.fixture()
def broker_stub(tls):
    srv = _BrokerStub(*tls["server"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_op_timeouts_exceed_server_bounds():
    """Static deadline contract (plan phase 2): every client bound exceeds
    the documented server-side bound of the same op, so a legitimate task
    is never cut off client-side at the old flat 30 s."""
    from infra.broker.client import HttpTransport as T
    assert T.OP_TIMEOUTS["clone_and_wait"] > 300        # task timeout bound
    assert T.OP_TIMEOUTS["read_host_key"] > 300         # (120 s boot-marker
    #   + 30 s in-flight request) + (120 s SHARED re-read window + 30 s
    #   in-flight request) = 300 s worst case (review find 2026-10-16 r2)
    assert T.OP_TIMEOUTS["start_and_wait"] > 90
    assert T.OP_TIMEOUTS["stop_and_confirm"] > 60
    assert T.OP_TIMEOUTS["destroy_and_wait"] > 120      # stop + delete waits
    assert T.OP_TIMEOUTS["hard_stop_all"] > 300


def test_task_outlasting_the_old_30s_rpc_limit(broker_stub, tls):
    """A server-side task longer than the OLD flat 30 s client limit must
    complete, not die client-side: the per-op bound is what applies."""
    transport = HttpTransport(broker_stub.url, tls["ca"], *tls["client"],
                              timeout=0.5)  # default would time out
    broker_stub.delays["clone_and_wait"] = 1.2
    # clone_and_wait's OP_TIMEOUT (330 s) governs, not the 0.5 s default
    assert transport.call("clone_and_wait", {}) == {"ok": True}


def test_lost_mutation_response_is_uncertain_and_never_replayed(broker_stub,
                                                                tls):
    """A mutation whose response is lost stays UNCERTAIN; the transport must
    not blind-replay it (the broker ledger reconciles afterwards)."""
    transport = HttpTransport(broker_stub.url, tls["ca"], *tls["client"],
                              timeout=0.4)
    # set_config: a mutation with no per-op bound -> the 0.4 s default applies
    broker_stub.delays["set_config"] = 1.5
    with pytest.raises(BrokerUnavailable):
        transport.call("set_config", {"vmid": 210})
    assert [op for op, _ in broker_stub.calls if op == "set_config"] == \
        ["set_config"], "mutation must not be retried by the transport"


def test_lost_read_response_gets_one_safe_retry(broker_stub, tls):
    transport = HttpTransport(broker_stub.url, tls["ca"], *tls["client"],
                              timeout=0.4)
    # first read slow (response lost), second immediate: reads may retry
    broker_stub.delays_first["vm_status"] = 1.5
    assert transport.call("vm_status", {"node": NODE, "vmid": 210}) == \
        {"ok": True}
    statuses = [op for op, _ in broker_stub.calls if op == "vm_status"]
    assert len(statuses) == 2, "exactly one retry for a lost read"
