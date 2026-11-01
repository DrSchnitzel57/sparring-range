"""Backend + broker-service NIC-vector behaviour (the applied side of the lane).

The policy refusals are guarded in test_nic_vector_lane.py; here the fake-libvirt
`LibvirtBackend` proves the WRITE-side discipline:

  * a stopped domain gets the FULL effective vector rewritten and every
    interface is then verified from the defined domain XML;
  * a running domain whose XML already matches the wanted vector CONVERGES
    (no redefine, seed untouched — the crash-resume case), while a genuine
    mismatch on a running domain still refuses;
  * multi-leg vectors refuse unplanned legs and legs with no parsable
    ipconfig before anything mutates;
  * the real BrokerService derives bridges from its OWN segment lane (callers
    plan segments, never bridges) and retains a durable obligation when the
    post-effect XML read-back disagrees.
Infrastructure-free: fake libvirt domain objects only, no KVM.
"""
from __future__ import annotations

import pytest

from infra.appliance import backend as B
from infra.appliance.manifest import ApplianceManifest
from infra.appliance.policy import AppliancePolicy
from infra.broker.errors import PolicyViolation
from infra.broker.errors import BrokerUnavailable  # noqa: F401  (contract)
from tests.test_appliance_contract import _manifest
from tests.test_segment_nic_lane import _broker_policy

NODE = None  # replaced with the manifest installation id


class FakeDom:
    def __init__(self, xml: str, active: bool = False):
        self._xml = xml
        self.active = active

    def isActive(self):
        return self.active

    def XMLDesc(self, flags=0):
        return self._xml

    def name(self):
        return "sr-env-vm"

    def UUID(self):
        return "u-1"


class FakeConn:
    def __init__(self, dom: FakeDom):
        self.dom = dom
        self.defined: list[str] = []

    def defineXML(self, xml):
        self.defined.append(xml)
        self.dom._xml = xml  # next XMLDesc reflects what was defined


def _domain_xml(legs):
    ifs = "".join(
        f"<interface type='bridge'><mac address='{mac}'/>"
        f"<source bridge='{br}'/></interface>"
        for br, mac in legs)
    return f"<domain><devices>{ifs}</devices></domain>"


def _backend(tmp_path, monkeypatch, *, active, legs, want_cfg, desc_extra=None):
    raw = _manifest(tmp_path, verify_files=True)
    m = ApplianceManifest.from_dict(raw, verify_images=True,
                                    verify_model_key=False)
    policy = AppliancePolicy.from_manifest(m)
    # allow_tcg here only bypasses the /dev/kvm precondition; these tests
    # never boot QEMU — they exercise the define/XML/seed codecs directly.
    backend = B.LibvirtBackend(m, policy, B.BackendConfig(allow_tcg=True))
    vmid = 210
    dom = FakeDom(_domain_xml(legs), active=active)
    conn = FakeConn(dom)
    desc = {"node": m.installation_id, "vmid": vmid, "name": "sr-env-vm",
            "template_id": 9005, "tags": "srsess-" + "a" * 32,
            "ipconfig0": "ip=172.20.240.10/24",
            "overlay": str(tmp_path / "guests" / str(vmid) / "disk.qcow2"),
            "serial": str(tmp_path / "guests" / str(vmid) / "serial.log"),
            "seed": str(tmp_path / "seed" / "seed.iso"),
            "session_id": "a" * 32}
    desc.update(desc_extra or {})
    monkeypatch.setattr(backend, "_find", lambda *a: (dom, desc))
    monkeypatch.setattr(backend, "connect", lambda: conn)
    seeds = []
    real_seed = backend._write_seed

    def spy_seed(*a, **k):
        seeds.append(True)
        return real_seed(*a, **k)

    monkeypatch.setattr(backend, "_write_seed", spy_seed)
    _ = want_cfg
    return backend, dom, conn, desc, seeds, vmid, m


PLAN_CFG = {  # closed segment lane: inside-lan + transit (broker-derived)
    "net0": "virtio,bridge=sr-inside", "ipconfig0": "ip=172.20.240.10/24",
    "net1": "virtio,bridge=sr-transit", "ipconfig1": "ip=172.16.0.5/24",
}


def _legs(m, *bridges):
    from infra.appliance.backend import _nic_mac
    return [(br, _nic_mac(m.installation_id, 210, i))
            for i, br in enumerate(bridges)]


# --------------------------------------------------------------- stopped apply --
def test_stopped_domain_rewrites_full_vector_and_verifies_xml(tmp_path, monkeypatch):
    m_raw = _manifest(tmp_path, verify_files=True)
    m = ApplianceManifest.from_dict(m_raw, verify_images=True,
                                    verify_model_key=False)
    # Domain XML currently has ONE leg; the wanted vector has two.
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=False,
        legs=[("srlab0", "52:54:00:00:00:99")], want_cfg=PLAN_CFG)
    from infra.appliance.backend import _nic_mac
    backend.set_config(m.installation_id, vmid, **PLAN_CFG,
                       name="sr-env-vm")
    assert len(conn.defined) == 1  # one atomic full redefine
    assert dom._xml.count("<interface") == 2
    assert desc["nics"] == [
        {"index": 0, "bridge": "sr-inside",
         "mac": _nic_mac(m.installation_id, vmid, 0)},
        {"index": 1, "bridge": "sr-transit",
         "mac": _nic_mac(m.installation_id, vmid, 1)}]
    assert seeds  # seed re-rendered to bind addresses by MAC


def test_partial_leg_vector_refused(tmp_path, monkeypatch):
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=False,
        legs=[("srlab0", "52:54:00:00:00:99")], want_cfg=None)
    with pytest.raises(B.BackendUnavailable, match="FULL effective NIC"):
        backend.set_config(m.installation_id, vmid,
                           net1="virtio,bridge=sr-transit",
                           ipconfig1="ip=172.16.0.5/24",
                           ipconfig0="ip=172.20.240.10/24")
    assert conn.defined == [] and seeds == []


def test_multi_leg_requires_parsable_ipconfig_per_leg(tmp_path, monkeypatch):
    """Chunk-A guard: an unplanned empty address would render a broken
    netplan entry; refuse BEFORE any mutation."""
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=False,
        legs=[("srlab0", "52:54:00:00:00:99")], want_cfg=None)
    desc.pop("ipconfig0")  # neither cfg nor recorded state carries it
    with pytest.raises(B.BackendUnavailable, match="parsable"):
        backend.set_config(m.installation_id, vmid,
                           net0="virtio,bridge=sr-inside",
                           net1="virtio,bridge=sr-transit")
    assert conn.defined == [] and seeds == []


def test_duplicate_bridge_refused(tmp_path, monkeypatch):
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=False,
        legs=[("srlab0", "52:54:00:00:00:99")], want_cfg=None)
    with pytest.raises(B.BackendUnavailable, match="duplicate bridge"):
        backend.set_config(m.installation_id, vmid,
                           net0="virtio,bridge=sr-inside",
                           ipconfig0="ip=172.20.240.10/24",
                           net1="virtio,bridge=sr-inside",
                           ipconfig1="ip=172.20.240.11/24")
    assert conn.defined == []


# ----------------------------------------------------------- running domains ---
def test_running_domain_with_matching_xml_converges(tmp_path, monkeypatch):
    """Crash-resume case: a previous pass applied the vector (or parked the
    resource pending) before the intent committed. A running domain whose
    XML already equals the wanted vector must reconcile, not raise forever —
    and must NOT re-render the seed the booted guest already consumed."""
    from infra.appliance.backend import _nic_mac
    m_raw = _manifest(tmp_path, verify_files=True)
    m = ApplianceManifest.from_dict(m_raw, verify_images=True,
                                    verify_model_key=False)
    xml = _domain_xml([("sr-inside", _nic_mac(m.installation_id, 210, 0)),
                       ("sr-transit", _nic_mac(m.installation_id, 210, 1))])
    # The applied vector is in desc too: a real crash-resume reads the
    # ALREADY-configured domain, so this call changes nothing at all.
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=True, legs=[], want_cfg=None,
        desc_extra={"net0": "virtio,bridge=sr-inside",
                    "net1": "virtio,bridge=sr-transit",
                    "ipconfig1": "ip=172.16.0.5/24",
                    "nics": [
                        {"index": 0, "bridge": "sr-inside",
                         "mac": _nic_mac(m.installation_id, 210, 0)},
                        {"index": 1, "bridge": "sr-transit",
                         "mac": _nic_mac(m.installation_id, 210, 1)}]})
    dom._xml = xml
    backend.set_config(m.installation_id, vmid, **PLAN_CFG, name="sr-env-vm")
    assert conn.defined == []  # nothing to redefine
    assert seeds == []          # the applied boot keeps its seed bytes


def test_running_domain_with_genuine_mismatch_still_refuses(
        tmp_path, monkeypatch):
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=True,
        legs=[("srlab0", "52:54:00:00:00:99")], want_cfg=None)
    with pytest.raises(B.BackendUnavailable, match="stopped domain"):
        backend.set_config(m.installation_id, vmid, **PLAN_CFG,
                           name="sr-env-vm")
    assert conn.defined == [] and seeds == []


def test_converged_vector_but_changed_ipconfig0_refused(tmp_path, monkeypatch):
    """Reconcile-skip binds to the vector only; a CHANGED primary address on
    a running domain is still a re-bind the running guest never applied."""
    from infra.appliance.backend import _nic_mac
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=True, legs=[], want_cfg=None)
    dom._xml = _domain_xml([
        ("sr-inside", _nic_mac(m.installation_id, 210, 0)),
        ("sr-transit", _nic_mac(m.installation_id, 210, 1))])
    with pytest.raises(B.BackendUnavailable, match="silent seed swap"):
        backend.set_config(m.installation_id, vmid,
                           **{**PLAN_CFG, "ipconfig0": "ip=172.20.240.99/24"},
                           name="sr-env-vm")
    assert conn.defined == [] and seeds == []


def test_define_then_xml_tampering_fails_readback(tmp_path, monkeypatch):
    """If what libvirt reports after the redefine disagrees with the intent
    (here: a foreign bridge on leg 1), the call refuses — never reports
    success."""
    backend, dom, conn, desc, seeds, vmid, m = _backend(
        tmp_path, monkeypatch, active=False,
        legs=[("srlab0", "52:54:00:00:00:99")], want_cfg=None)

    real_define = conn.defineXML

    def define_tamper(xml):
        real_define(xml)
        dom._xml = xml.replace("sr-transit", "br-evil")

    conn.defineXML = define_tamper
    with pytest.raises((B.BackendReadBackFailed, B.BackendUnavailable)):
        backend.set_config(m.installation_id, vmid, **PLAN_CFG,
                           name="sr-env-vm")


# ------------------------------------------------- broker service producer ----
def test_service_derives_bridges_from_its_own_lane(tmp_path):
    """Callers plan SEGMENTS; the broker's lane resolves bridges. An explicit
    net/ipconfig override that deviates is refused, never honoured."""
    from infra.broker.testing import make_fake_broker
    policy = _broker_policy()
    client, service, http = make_fake_broker(policy=policy)
    client.clone_and_wait("r740", 9011, 210, "sr-labvm", full=True,
                          session_id="s1")
    service.set_config("r740", 210, session_id="s1",
                       expected_nics=[{"segment": "inside-lan",
                                       "address": "172.20.240.10"},
                                      {"segment": "transit",
                                       "address": "172.16.0.5"}])
    stored = http.vms[210]["config"]
    assert stored["net1"] == "virtio,bridge=sr-transit"  # derived, not sent
    with pytest.raises(PolicyViolation, match="does not equal the exact"):
        service.set_config("r740", 210, session_id="s1",
                           expected_nics=[{"segment": "inside-lan",
                                           "address": "172.20.240.10"}],
                           net0="virtio,bridge=sr-team")  # smuggle attempt


def test_service_readback_mismatch_retains_obligation(tmp_path, monkeypatch):
    from infra.broker.testing import make_fake_broker
    client, service, http = make_fake_broker(policy=_broker_policy())
    client.clone_and_wait("r740", 9011, 210, "sr-labvm", full=True,
                          session_id="s1")
    real = service.backend.try_lookup_config

    def swapped(node, vmid):
        cfg = real(node, vmid)
        cfg["nics"][0]["bridge"] = "sr-team"  # domain reports another lane
        return cfg

    monkeypatch.setattr(service.backend, "try_lookup_config", swapped)
    with pytest.raises(BrokerUnavailable, match="obligation retained"):
        service.set_config("r740", 210, session_id="s1",
                           expected_nics=[{"segment": "inside-lan",
                                           "address": "172.20.240.10"}])
    obligations = service.ledger.open_obligations()
    kinds = [str(o.get("kind")) for o in obligations]
    assert any("nic-vector-readback-mismatch" in k for k in kinds)
