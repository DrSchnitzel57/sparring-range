"""Unix-socket broker front door for the appliance.

There is no TCP listener and no bearer token. The server reads SO_PEERCRED
from the connected socket and refuses the request unless the peer UID is the
single operator-selected service UID (normally ``sr-api``). The socket lives in
a root/broker-owned directory; the broker never exposes latch release or
offline enrollment over this transport because ``CONTROL_OPS`` does not include
them.

The HTTP shape is deliberately identical to the legacy mutual-TLS broker, so
the API uses the same typed :class:`BrokerClient` and error taxonomy.
"""
from __future__ import annotations

import os
import pwd
import socket
import socketserver
import struct
import time
from http.server import HTTPServer

from infra.broker.server import BrokerHTTPHandler, CONTROL_OPS

_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
_CRED = struct.Struct("3i")


class ApplianceBrokerHandler(BrokerHTTPHandler):
    def handle(self) -> None:
        try:
            raw = self.connection.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED,
                                             _CRED.size)
            pid, uid, gid = _CRED.unpack(raw)
        except OSError:
            self.close_connection = True
            return
        self.peer_uid = uid
        if uid not in self.server.allowed_uids:
            # Do not read a request from an unauthorized peer. The response
            # is best-effort; closing is the security-relevant action.
            self.close_connection = True
            body = b'{"detail":"peer uid not allowed"}'
            try:
                self.wfile.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body)
            except OSError:
                pass
            return
        self.client_address = (f"uid:{uid}", 0)
        super().handle()


class UnixHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def server_bind(self) -> None:  # noqa: D401 - socketserver hook
        path = str(self.server_address)
        if os.path.exists(path):
            # A live peer means another broker already owns the path: refuse
            # to steal it. A stale socket (connection refused) is removed.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.5)
                probe.connect(path)
            except (ConnectionRefusedError, FileNotFoundError):
                os.unlink(path)
            except OSError as exc:
                raise RuntimeError(f"broker socket {path} is not usable: {exc}") from exc
            else:
                raise RuntimeError(f"broker socket {path} is already served")
            finally:
                probe.close()
        self.socket.bind(path)
        os.chmod(path, 0o660)
        self.server_name = "appliance-broker"
        self.server_port = 0

    def get_request(self):
        return self.socket.accept()

    def server_close(self) -> None:
        path = str(self.server_address)
        super().server_close()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _resolve_uids(values) -> frozenset[int]:
    out: set[int] = set()
    for value in values:
        if isinstance(value, int):
            out.add(value)
            continue
        text = str(value).strip()
        if not text:
            continue
        if text.isdigit():
            out.add(int(text))
            continue
        try:
            out.add(pwd.getpwnam(text).pw_uid)
        except KeyError as exc:
            raise RuntimeError(f"unknown service account {text!r}") from exc
    if not out:
        raise RuntimeError("appliance broker requires at least one allowed peer UID")
    if 0 in out:
        raise RuntimeError("refusing to authorize root as a broker client")
    return frozenset(out)


def make_unix_server(service, socket_path: str, allowed_uids) -> UnixHTTPServer:
    parent = os.path.dirname(socket_path) or "."
    os.makedirs(parent, mode=0o750, exist_ok=True)
    st = os.stat(parent)
    if st.st_mode & 0o002:
        raise RuntimeError(f"broker socket directory {parent} is world-writable")
    uids = _resolve_uids(allowed_uids)
    srv = UnixHTTPServer(socket_path, ApplianceBrokerHandler)
    srv.service = service
    srv.allowed_uids = uids
    return srv
