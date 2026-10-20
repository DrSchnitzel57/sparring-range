"""Appliance broker transport tests: local Unix socket + peer UID.

Infrastructure-free: a real BrokerService over the synthetic PVE boundary,
served on a real Unix socket. No PVE, libvirt or database is touched.
"""
from __future__ import annotations

import os
import threading

import pytest

from infra.appliance.server import _resolve_uids, make_unix_server
from infra.broker.client import BrokerClient, HttpTransport
from infra.broker.errors import BrokerRefused
from infra.broker.testing import make_fake_broker


def test_unix_socket_typed_calls_and_no_tcp_listener(tmp_path):
    _client, service, _http = make_fake_broker()
    sock = str(tmp_path / "run" / "broker.sock")
    srv = make_unix_server(service, sock, [os.getuid()])
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        assert os.path.exists(sock)
        transport = HttpTransport(f"unix://{sock}")
        client = BrokerClient(transport)
        assert client.latch_status()["latched"] is False
        vmid = client.next_vmid("r740", 200)
        assert 200 <= vmid <= 999
        inv = client.inventory()
        assert "claims" in inv and "lease" in inv
        with pytest.raises(Exception):
            # the legacy TLS requirement is not silently downgraded
            HttpTransport(f"http://localhost:{srv.server_port or 1}")
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
    assert not os.path.exists(sock)


def test_unix_auth_refuses_root_and_relative_or_non_socket(tmp_path):
    with pytest.raises(RuntimeError, match="root"):
        _resolve_uids([0])
    with pytest.raises(RuntimeError, match="unknown service"):
        _resolve_uids(["definitely-not-a-user"])
    with pytest.raises(BrokerRefused, match="absolute"):
        HttpTransport("unix://relative.sock")
    with pytest.raises(BrokerRefused):
        HttpTransport("unix:///tmp/not-a-sock")
    with pytest.raises(BrokerRefused, match="https"):
        HttpTransport("http://127.0.0.1:8443")
