"""API-side broker client — typed calls over mutual TLS, no fallback.

The API never holds a PVE token and never constructs PVE paths: it calls
these typed methods. Transport failures raise BrokerUnavailable (uncertain
— retain obligations); refusals raise typed BrokerRefused subclasses. There
is deliberately NO path from this module to a direct Proxmox connection.
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse

from .errors import (BrokerConflict, BrokerLatched, BrokerRefused,
                     BrokerUnavailable, PolicyViolation)
from .service import BrokerService

_STATUS_ERRORS = {
    400: BrokerRefused, 403: PolicyViolation, 404: BrokerRefused,
    409: BrokerConflict, 423: BrokerLatched, 503: BrokerUnavailable,
}


class LocalTransport:
    """In-process transport for isolated synthetic fixtures and unit tests.
    NOT a production bypass: production configuration must provide
    broker_url and the mutual-TLS material (settings validation enforces)."""

    def __init__(self, service: BrokerService):
        self.service = service

    def call(self, op: str, args: dict):
        from .server import CONTROL_OPS
        if op not in CONTROL_OPS:
            raise BrokerRefused(f"operation {op!r} is not exposed over the broker "
                                "boundary")
        fn = getattr(self.service, op)
        try:
            return fn(**args)
        except (BrokerRefused, BrokerUnavailable):
            raise
        except (TypeError, ValueError) as e:
            raise BrokerRefused(f"invalid arguments: {e}") from e
        except Exception as e:  # noqa: BLE001 — internal fault: outcome uncertain
            raise BrokerUnavailable(f"broker internal error: {e}") from e


class HttpTransport:
    """Mutual-TLS HTTPS transport. A missing/foreign client certificate
    fails at the TLS handshake — before any request is sent."""

    # Plan 13 phase 2: client/server/task deadlines are checked TOGETHER.
    # Every bound below exceeds the documented SERVER-side bound of the op
    # (task timeout 300 s; the pin read is a 120 s boot-marker wait plus a
    # bounded stability read of up to 120 s; start wait 90 s; stop/destroy
    # waits 60 s each) so a legitimate long task is never cut off
    # client-side at the old flat 30 s. When the client bound IS
    # exceeded (or the response is otherwise lost) the call raises
    # BrokerUnavailable — UNCERTAIN, never failure: the broker persisted its
    # intent/claim before the effect, keeps stopping on the latch path, and
    # reconciliation (never blind replay) resolves the outcome afterwards.
    # Mutations are NEVER retried by this transport; only idempotent reads
    # get one bounded retry, and only for a pure transport failure.
    OP_TIMEOUTS = {
        "read_host_key": 300.0,     # server bound: 120 s boot-marker wait
                                    # + 120 s stability read + margin
        "clone_and_wait": 330.0,    # server bound: 300 s task timeout
        "start_and_wait": 125.0,    # server bound: 90 s task wait + read-back
        "stop_and_confirm": 95.0,   # server bound: 60 s task wait + read-back
        "destroy_and_wait": 160.0,  # server bound: 60 s stop + 60 s delete
        "hard_stop_all": 330.0,     # latch is durable FIRST; a lost response
        # keeps stopping server-side and stays an explicit obligation
    }
    READ_OPS = frozenset({
        "lookup_vm", "lookup_config", "try_lookup_config", "read_config",
        "vm_status", "inventory", "latch_status",
    })

    def __init__(self, url: str, ca_file: str, cert_file: str, key_file: str,
                 timeout: float = 30.0):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            raise BrokerRefused(f"broker_url must be https (mutual TLS), got {url!r}")
        self.host, self.port = parts.hostname, parts.port or 8443
        self.timeout = timeout
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca_file)
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self._ctx = ctx

    def _call_once(self, op: str, body: bytes):
        conn = http.client.HTTPSConnection(
            self.host, self.port,
            timeout=self.OP_TIMEOUTS.get(op, self.timeout), context=self._ctx)
        try:
            conn.request("POST", f"/v1/{op}", body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            payload = resp.read()
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            raise BrokerUnavailable(f"broker transport failure: {e}") from e
        finally:
            conn.close()
        return resp, payload

    def call(self, op: str, args: dict):
        body = json.dumps(args, default=str).encode()
        try:
            resp, payload = self._call_once(op, body)
        except BrokerUnavailable:
            # Reads are side-effect-free: one retry is safe. Mutations are
            # NOT replayed — their outcome is uncertain and must be
            # reconciled (intent-before-effect ledger), never assumed away.
            if op not in self.READ_OPS:
                raise
            resp, payload = self._call_once(op, body)
        if resp.status == 200:
            try:
                return json.loads(payload or "null")["result"]
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                raise BrokerUnavailable(f"malformed broker reply: {e}") from e
        try:
            detail = json.loads(payload).get("detail", payload.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = repr(payload[:200])
        cls = _STATUS_ERRORS.get(resp.status, BrokerUnavailable)
        raise cls(f"broker refused {op} (HTTP {resp.status}): {detail}")


class BrokerClient:
    def __init__(self, transport):
        self._t = transport

    def _call(self, op: str, **args):
        return self._t.call(op, args)

    # reads ------------------------------------------------------------------
    def lookup_vm(self, node, vmid):
        return self._call("lookup_vm", node=node, vmid=int(vmid))

    def lookup_config(self, node, vmid):
        return self._call("lookup_config", node=node, vmid=int(vmid))

    def try_lookup_config(self, node, vmid):
        return self._call("try_lookup_config", node=node, vmid=int(vmid))

    def read_config(self, node, vmid):
        return self._call("read_config", node=node, vmid=int(vmid))

    def read_host_key(self, node, vmid, session_id=None, generation=1):
        return self._call("read_host_key", node=node, vmid=int(vmid),
                          session_id=session_id, generation=str(generation))

    def vm_status(self, node, vmid):
        return self._call("vm_status", node=node, vmid=int(vmid))

    def inventory(self):
        return self._call("inventory")

    def latch_status(self):
        return self._call("latch_status")

    # mutations ---------------------------------------------------------------
    def next_vmid(self, node, start, session_id=None):
        return self._call("next_vmid", node=node, start=int(start),
                          session_id=session_id)

    def clone_and_wait(self, node, template_vmid, new_vmid, name, full=False,
                       session_id=None, generation=1):
        return self._call("clone_and_wait", node=node, template_vmid=int(template_vmid),
                          new_vmid=int(new_vmid), name=name, full=bool(full),
                          session_id=session_id, generation=str(generation))

    def set_config(self, node, vmid, session_id=None, **cfg):
        return self._call("set_config", node=node, vmid=int(vmid),
                          session_id=session_id, **cfg)

    def start_and_wait(self, node, vmid, timeout=90, session_id=None):
        return self._call("start_and_wait", node=node, vmid=int(vmid),
                          timeout=int(timeout), session_id=session_id)

    def stop(self, node, vmid, force=False, session_id=None):
        return self._call("stop", node=node, vmid=int(vmid), force=bool(force),
                          session_id=session_id)

    def stop_and_confirm(self, node, vmid, timeout=60, session_id=None):
        return self._call("stop_and_confirm", node=node, vmid=int(vmid),
                          timeout=int(timeout), session_id=session_id)

    def destroy_and_wait(self, node, vmid, force_stop_timeout=60, session_id=None):
        return self._call("destroy_and_wait", node=node, vmid=int(vmid),
                          force_stop_timeout=int(force_stop_timeout),
                          session_id=session_id)

    # authority ----------------------------------------------------------------
    def hard_stop_all(self, reason: str) -> dict:
        return self._call("hard_stop_all", reason=str(reason))

    def disown(self, node, vmid, session_id=None, reason=""):
        return self._call("disown", node=node, vmid=int(vmid),
                          session_id=session_id, reason=str(reason))

    def renew_lease(self, holder: str) -> dict:
        return self._call("renew_lease", holder=str(holder))

    def disarm_lease(self) -> None:
        self._call("disarm_lease")
