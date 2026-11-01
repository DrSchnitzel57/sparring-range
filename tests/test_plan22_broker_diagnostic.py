"""Plan 22 LIVE-03: a broker peer-identity refusal is a diagnostic, not an
outage.

Reproduced defect (installed appliance 2026-10-29): after a successful
upgrade the root-run `appliance.py doctor` reported "broker reachable:
false — broker refused inventory (HTTP 403)", sending the operator after a
broker failure while /readyz proved the broker healthy. Root is
DELIBERATELY outside the peer-UID allowlist; the fix classifies the refusal
and says so, without granting root any broker access.
"""
from __future__ import annotations

import types

import pytest

import deploy.appliance as ap
from infra.broker.errors import BrokerUnavailable, PolicyViolation

_M = types.SimpleNamespace(broker_socket="/run/sparring-range/broker.sock")


class _FakeClient:
    def __init__(self, exc=None, inventory=None):
        self._exc = exc
        self._inventory = inventory or {"vms": []}

    def inventory(self):
        if self._exc:
            raise self._exc
        return self._inventory


@pytest.fixture
def _patch_client(monkeypatch):
    import infra.broker.client as bc

    def _patch(exc=None, inventory=None):
        monkeypatch.setattr(bc, "BrokerClient",
                            lambda *a, **k: _FakeClient(exc, inventory))
        monkeypatch.setattr(bc, "HttpTransport", lambda *a, **k: object())
    return _patch


def test_refusal_is_classified_as_peer_identity_refused(_patch_client):
    _patch_client(exc=PolicyViolation("broker refused inventory (HTTP 403)"))
    out = ap._broker_status(_M)
    assert out["ok"] is False
    assert out["reason"] == "peer-identity-refused"
    assert "403" in out["error"]
    advice = out["advice"]
    assert "REFUSED" in advice and "srrange" in advice
    assert "unreachable" not in advice.lower()
    # the refusal must not be softened into an outage anywhere in the entry
    assert "unreachable" not in str(out).lower()


def test_a_real_outage_stays_an_outage(_patch_client):
    _patch_client(exc=BrokerUnavailable("broker Unix socket is missing"))
    out = ap._broker_status(_M)
    assert out["ok"] is False
    assert "reason" not in out and "advice" not in out
    assert "missing" in out["error"]


def test_answering_broker_reports_inventory(_patch_client):
    _patch_client(inventory={"vms": [{"vmid": 200}]})
    out = ap._broker_status(_M)
    assert out == {"ok": True, "inventory": {"vms": [{"vmid": 200}]}}


def test_doctor_shows_the_refusal_advice(monkeypatch, tmp_path):
    m = _manifest(tmp_path)
    monkeypatch.setattr(ap, "_broker_status", lambda _m: {
        "ok": False, "reason": "peer-identity-refused",
        "error": "broker refused inventory (HTTP 403)",
        "advice": ("the broker answered and REFUSED this process's identity"
                   " — re-run as sudo -u srrange, do NOT widen the allowlist"),
    })
    monkeypatch.setattr(ap, "_unit_state", lambda _u: "active")
    report = ap.doctor(m)
    checks = {c["check"]: c for c in report["checks"]}
    broker = checks["broker reachable"]
    assert broker["ok"] is False
    assert "sudo -u srrange" in broker["detail"]
    assert "REFUSED" in broker["detail"]


def _manifest(tmp_path):
    from infra.appliance.manifest import ApplianceManifest
    from tests.test_appliance_install import _manifest as base
    return ApplianceManifest.from_dict(base(tmp_path), verify_images=True)
