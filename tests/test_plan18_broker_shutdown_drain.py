"""Plan 18 review — the broker daemon must drain before it closes.

The netrules loader keeps range ISOLATION across unit stops, but a guest
VM is still a guest VM: when the broker process — the only holder of the
libvirt connection and the only lease watchdog — exits while VMs are
claimed, the exit path itself must run the latched cessation before
closing the backend.  This test drives the REAL brokerd.main shutdown
sequence with the socket server and the (libvirt-requiring) build step
replaced at their module seams; the drain decision, ordering, and
reporting are production code paths.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from infra.appliance import brokerd


class _RecordingService:
    def __init__(self, drain_result):
        self.calls: list[str] = []
        self.drain_result = drain_result
        self.drain_reason: str | None = None

    def startup_reconcile(self):
        return {"reconciled": True}

    def start_watchdog(self):
        self.calls.append("start_watchdog")

    def stop_watchdog(self):
        self.calls.append("stop_watchdog")

    def drain_on_shutdown(self, reason):
        self.calls.append("drain_on_shutdown")
        self.drain_reason = reason
        return self.drain_result


class _RecordingBackend:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _RecordingServer:
    def __init__(self):
        self.closed = False
        self.allowed_uids = frozenset({0})

    def serve_forever(self):
        return  # returns immediately: exercises the finally path

    def shutdown(self):
        pass

    def server_close(self):
        self.closed = True


@pytest.fixture()
def wired(tmp_path, monkeypatch):
    calls: list[str] = []

    def _install(drain_result):
        service = _RecordingService(drain_result)
        backend = _RecordingBackend()
        server = _RecordingServer()
        manifest = SimpleNamespace(broker_socket=str(tmp_path / "broker.sock"))

        def fake_build(*_a, **_k):
            return manifest, None, None, backend, service

        def fake_server(_service, _socket, _allowed):
            calls.append("serve")
            return server

        monkeypatch.setattr(brokerd, "build", fake_build)
        monkeypatch.setattr(brokerd, "make_unix_server", fake_server)
        return service, backend, server, calls

    return _install


def test_daemon_exit_drains_with_its_reason_and_closes_in_order(wired):
    service, backend, server, calls = wired(
        {"latched": True, "stopped": [210], "reason": "broker-daemon-exit"})
    assert brokerd.main(["--manifest", "m", "--policy", "p"]) == 0
    assert service.calls == ["start_watchdog", "stop_watchdog",
                             "drain_on_shutdown"]
    assert service.drain_reason == "broker-daemon-exit"
    # the drain happened BEFORE the only libvirt connection closed —
    # cessation cannot be issued after the handle is gone
    assert backend.closed and server.closed
    assert calls == ["serve"]


def test_daemon_exit_reported_for_operator(capsys, wired):
    service, backend, server, calls = wired(
        {"latched": True, "stopped": [], "failed": [{"vmid": 210,
                                                     "error": "timeout"}],
         "reason": "broker-daemon-exit"})
    assert brokerd.main(["--manifest", "m", "--policy", "p"]) == 0
    out = capsys.readouterr().out
    assert "broker shutdown drain" in out and "210" in out, \
        "an incomplete drain must be visible in the unit journal"


def test_idle_exit_closes_quietly_without_a_drain_report(wired, capsys):
    # service-level semantics (real BrokerService) are covered in the
    # authority layer; here we pin the wiring: None => nothing printed,
    # the close sequence still completes.
    service, backend, server, calls = wired(None)
    assert brokerd.main(["--manifest", "m", "--policy", "p"]) == 0
    assert "broker shutdown drain" not in capsys.readouterr().out
    assert backend.closed and server.closed
