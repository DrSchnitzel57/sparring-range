"""Mutual-TLS HTTPS front door for the broker service.

Authentication is the TLS handshake itself: the server REQUIRES a client
certificate signed by the broker CA, so an unauthorized caller never speaks
HTTP at all. Only the typed CONTROL_OPS are exposed over the wire — latch
release and offline enrollment are broker-LOCAL operator tools (tools.py)
and can never be reached, let alone invoked, by the API.
"""
from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .errors import BrokerLatched, BrokerUnavailable, PolicyViolation
from .service import BrokerService

# Operations the control plane may invoke. hard_stop_all is here on purpose
# (the killswitch must reach cessation); release_latch and enroll are NOT.
CONTROL_OPS = frozenset({
    "lookup_vm", "lookup_config", "try_lookup_config", "read_config",
    "read_host_key",
    "vm_status", "inventory", "latch_status", "next_vmid", "clone_and_wait",
    "artifact_for_template", "template_catalog",
    "set_config", "start_and_wait", "stop", "stop_and_confirm",
    "destroy_and_wait", "disown", "hard_stop_all", "renew_lease",
    # Idle-range lifecycle: disarming is safe while latched (it can never
    # resume a stopped range — only release_latch does that), and without it
    # an armed-forever lease re-latches the broker after every session.
    "disarm_lease",
})


class BrokerHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------- plumbing ---
    def _send(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep the broker log deterministic
        pass

    # ---------------------------------------------------------------- routes ---
    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/v1/health":
            st = self.server.service.latch_status()
            self._send(200, {"result": {"ok": True, "latched": st["latched"],
                                        "reason": st["reason"]}})
        else:
            self._send(404, {"detail": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlsplit(self.path).path
        op = path[len("/v1/"):] if path.startswith("/v1/") else ""
        service: BrokerService = self.server.service
        if op not in CONTROL_OPS:
            self._send(404, {"detail": f"unknown operation {op!r}"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 65536:
                raise ValueError("request body too large")
            args = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(args, dict):
                raise ValueError("body must be a JSON object")
        except (ValueError, json.JSONDecodeError) as e:
            self._send(400, {"detail": f"invalid request: {e}"})
            return
        try:
            result = getattr(service, op)(**args)
        except BrokerLatched as e:
            self._send(423, {"detail": str(e)})
            return
        except PolicyViolation as e:
            self._send(403, {"detail": str(e)})
            return
        except BrokerUnavailable as e:
            self._send(503, {"detail": str(e)})
            return
        except (TypeError, ValueError) as e:
            self._send(400, {"detail": f"invalid arguments: {e}"})
            return
        except Exception as e:  # noqa: BLE001 — typed taxonomy for the caller
            from .errors import BrokerConflict, BrokerRefused
            if isinstance(e, BrokerConflict):
                self._send(409, {"detail": str(e)})
                return
            if isinstance(e, BrokerRefused):
                self._send(400, {"detail": str(e)})
                return
            self._send(500, {"detail": f"broker internal error: {e}"})
            return
        if op in ("next_vmid", "clone_and_wait", "set_config", "start_and_wait",
                  "stop", "stop_and_confirm", "destroy_and_wait", "disown",
                  "hard_stop_all"):
            service.ledger.audit("request", {"op": op, "peer": self.client_address[0]})
        self._send(200, {"result": result})


def make_server(service: BrokerService, host: str, port: int, *, certfile: str,
                keyfile: str, ca_file: str) -> ThreadingHTTPServer:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.verify_mode = ssl.CERT_REQUIRED          # mutual TLS: no cert, no HTTP
    ctx.load_verify_locations(cafile=ca_file)
    srv = ThreadingHTTPServer((host, port), BrokerHTTPHandler)
    srv.service = service
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.daemon_threads = True
    return srv
