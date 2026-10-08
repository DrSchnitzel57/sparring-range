"""Third-follow-up regressions — Stage 2: EFFECTIVE network-policy checks
(audit T03).

The review reproduced, with real nft JSON: `baseline_status()` accepted an
inserted `meta nfproto ipv4 accept` before the expected sequence and an
expanded range_hosts set (0.0.0.0/1). These tests pin EXACT effective-policy
equivalence, EXACT set membership, port-scoped established allowances,
namespace-consistent bridge discovery, tri-state inspection, and a live
topology check in the start gate — plus a disposable-namespace PACKET test
showing an already-established range->management:8080 connection no longer
survives the baseline while intended flows still work.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid

import pytest

# --------------------------------------------------------------------------- #
# Real-nft-JSON fixtures (shape captured from `nft -j list table`)            #
# --------------------------------------------------------------------------- #

def meta(k):
    return {"meta": {"key": k}}


def ip(k):
    return {"payload": {"protocol": "ip", "field": k}}


def tcp(k):
    return {"payload": {"protocol": "tcp", "field": k}}


def match(left, right, op="=="):
    return {"match": {"left": left, "right": right, "op": op}}


def rule(*expr):
    return {"expr": list(expr)}


CT = {"ct": {"key": "state"}}
MGMT = {"prefix": {"addr": "10.0.0.0", "len": 24}}
CTRL = "10.0.0.1"
API_PORT = 8000


def baseline_table(with_port_scoped_established=True):
    """The expected policy as REAL nft JSON (the probe's fixture shape)."""
    if with_port_scoped_established:
        est = [rule(match(CT, [2, 4]), match(ip("daddr"), MGMT), match(tcp("sport"), 22),
                    match(meta("iifname"), "vmbr1"), {"accept": None}),
               rule(match(CT, [2, 4]), match(ip("daddr"), CTRL), match(tcp("dport"), API_PORT),
                    match(meta("iifname"), "vmbr1"), {"accept": None})]
    else:  # the OLD destination-wide established accepts (the T03 hole)
        est = [rule(match(CT, [2, 4]), match(ip("daddr"), MGMT),
                    match(meta("iifname"), "vmbr1"), {"accept": None}),
               rule(match(CT, [2, 4]), match(ip("daddr"), CTRL),
                    match(meta("iifname"), "vmbr1"), {"accept": None})]
    rules = [rule(match(meta("iifname"), "vmbr1", "!="), {"return": None})] + est + [
        rule(match(ip("saddr"), "@range_hosts"), match(ip("daddr"), "@range_hosts"), {"accept": None}),
        rule(match(ip("protocol"), 6), match(ip("daddr"), CTRL), match(tcp("dport"), API_PORT),
             match(CT, 8), {"accept": None}),
        rule(match(ip("protocol"), 6), match(ip("saddr"), MGMT), match(ip("daddr"), "@range_hosts"),
             match(tcp("dport"), 22), match(CT, 8), {"accept": None}),
        rule(match(meta("nfproto"), 2), {"drop": None}),
        rule(match(meta("nfproto"), 10), {"drop": None}),
    ]
    return {"family": "inet", "name": "sr_range_baseline",
            "chains": [{"name": "range_forward",
                        "hooks": [{"hook": "forward", "family": "inet", "prio": 0,
                                   "policy": "accept"}], "rule": rules}],
            "sets": [{"name": "range_hosts", "type": "ipv4_addr", "flags": ["interval"],
                      "elem": [{"prefix": {"addr": "10.66.0.0", "len": 24}}]}]}


@pytest.fixture()
def nft_validator(monkeypatch):
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import Settings
    monkeypatch.setattr(firewall, "_ctrl_addr", lambda s: CTRL)
    monkeypatch.setattr(firewall, "_api_port", lambda s: API_PORT)
    monkeypatch.setattr(firewall, "validate_port_coverage", lambda s: (True, "fixture"))
    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    nft.s = Settings(sr_env="dev", range_bridge="vmbr1", range_cidr="10.66.0.0/24",
                     management_cidr="10.0.0.0/24", api_base_url=f"http://{CTRL}:{API_PORT}")

    def serve(table):
        def fake(args):
            if args[:3] == ["-nn", "-j", "list"]:
                if table is None:
                    return 1, "Error: Could not process rule: No such file or directory"
                return 0, json.dumps({"nftables": [
                    {"table": {"family": table["family"], "name": table["name"], "handle": 1}}]
                    + [{"chain": {"family": "inet", "name": c["name"], "table": table["name"],
                                  "hook": c["hooks"][0]["hook"], "prio": c["hooks"][0]["prio"],
                                  "policy": c["hooks"][0]["policy"], "type": "filter"}}
                       for c in table["chains"]]
                    + [{"rule": {"family": "inet", "table": table["name"],
                                 "chain": c["name"], "handle": 10 + i, "expr": r["expr"]}}
                       for c in table["chains"] for i, r in enumerate(c["rule"])]
                    + [{"set": {**s_, "family": "inet", "table": table["name"]}}
                       for s_ in table["sets"]]})
            return 1, "unexpected args"
        nft._run_nft = fake
    return nft, serve


def test_t03_exact_expected_policy_verifies(nft_validator):
    nft, serve = nft_validator
    serve(baseline_table())
    res = nft.baseline_status()
    assert res["ok"] is True, res["detail"]


def test_t03_extra_conditional_accept_is_rejected(nft_validator):
    """The probe's reproduction: `meta nfproto ipv4 accept` inserted BEFORE
    the expected sequence allowed ALL IPv4 before the deny rules."""
    nft, serve = nft_validator
    tbl = baseline_table()
    tbl["chains"][0]["rule"].insert(0, rule(match(meta("nfproto"), 2), {"accept": None}))
    serve(tbl)
    res = nft.baseline_status()
    assert res["ok"] is False and "NOT exactly the expected baseline" in res["detail"]


def test_t03_widened_range_set_is_rejected(nft_validator):
    """Containment of the required CIDR is not membership: adding 0.0.0.0/1
    turns the intra-range accept into an external allowance."""
    nft, serve = nft_validator
    tbl = baseline_table()
    tbl["sets"][0]["elem"].append({"prefix": {"addr": "0.0.0.0", "len": 1}})
    serve(tbl)
    res = nft.baseline_status()
    assert res["ok"] is False and "not exactly" in res["detail"]


def test_t03_reordered_rules_are_rejected(nft_validator):
    nft, serve = nft_validator
    tbl = baseline_table()
    r = tbl["chains"][0]["rule"]
    r[3], r[4] = r[4], r[3]     # swap two allows — same multiset, different policy
    serve(tbl)
    assert nft.baseline_status()["ok"] is False


def test_t03_destination_wide_established_allowance_is_rejected(nft_validator):
    """The OLD destination-wide established accepts (no sport/dport scope)
    must NOT verify: an already-established range->management connection to
    any port survived them."""
    nft, serve = nft_validator
    serve(baseline_table(with_port_scoped_established=False))
    res = nft.baseline_status()
    assert res["ok"] is False, "destination-wide established allowance still verifies"


def test_t03_rendered_policy_and_validator_cannot_drift(monkeypatch):
    """The rendered ruleset and the expected statements are the SAME policy:
    established allowances carry tcp sport 22 / the ingest dport."""
    from srplatform.settings import Settings
    monkeypatch.setenv("API_BASE_URL", f"http://{CTRL}:{API_PORT}")
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        from srplatform.safety.firewall import render_baseline_ruleset
        base = render_baseline_ruleset()
        assert f'tcp sport 22 iifname "vmbr1" accept' in base
        assert f'tcp dport {API_PORT} iifname "vmbr1" accept' in base
        assert 'ct state established,related ip daddr 10.0.0.0/24 iifname "vmbr1" accept' not in base
    finally:
        get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# Tri-state inspection: absent != unknown                                      #
# --------------------------------------------------------------------------- #

def test_t03_unknown_inspection_is_not_absent_nor_verified(monkeypatch):
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import Settings
    monkeypatch.setattr(firewall, "validate_port_coverage", lambda s: (True, "ok"))
    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    nft.s = Settings(sr_env="dev")
    nft._run_nft = lambda args: (1, "Operation not permitted")
    nft._run_nft_stdin = lambda rs: (0, "")

    res = nft.baseline_status()
    assert res["ok"] is False and res.get("unknown") is True, res
    assert "ABSENT" not in res["detail"]

    rel = nft.remove_emergency()
    assert rel["ok"] is False and "RETAINED" in rel["detail"]
    app = nft.apply_emergency()
    assert app["ok"] is False and "inspection UNAVAILABLE" in app["detail"]

    # even with a verified baseline, UNKNOWN emergency-table inspection can
    # never substantiate a removal
    nft.baseline_status = lambda: {"ok": True, "detail": "faked", "mechanism": "nft"}
    rel = nft.remove_emergency()
    assert rel["ok"] is False and "cannot substantiate removal" in rel["detail"]


def test_t03_absent_is_still_absent(monkeypatch):
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import Settings
    monkeypatch.setattr(firewall, "validate_port_coverage", lambda s: (True, "ok"))
    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    nft.s = Settings(sr_env="dev")
    nft._run_nft = lambda args: (1, "Error: Could not process rule: No such file or directory")
    res = nft.baseline_status()
    assert res["ok"] is False and "ABSENT" in res["detail"] and not res.get("unknown")


# --------------------------------------------------------------------------- #
# Discovery happens in the nft namespace, not the local /sys                   #
# --------------------------------------------------------------------------- #

def test_t03_discovery_uses_prefix_namespace_even_when_local_bridge_exists(monkeypatch):
    """A same-named bridge in the LOCAL /sys must never be mistaken for the
    target namespace: with a prefix configured, discovery runs THROUGH the
    prefix and its answer governs.

    The local read is doubled through the module's named seam — replacing
    global pathlib.Path (as this test used to) breaks Python 3.11 pathlib
    internals and crashes the whole suite.
    """
    from srplatform.safety import firewall
    from srplatform.settings import Settings

    calls = []
    local_reads = []

    def local_trap(br):
        # LOCAL same-named bridge with DIFFERENT ports — the trap. It must
        # NEVER be consulted while an execution prefix is configured.
        local_reads.append(br)
        return ["LOCALtap9"]

    monkeypatch.setattr(firewall, "_local_bridge_ports", local_trap)

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="veth7\nveth8\n", stderr="")
    monkeypatch.setattr("subprocess.run", fake_run)

    s = Settings(sr_env="dev", range_bridge="vmbr1",
                 nft_command_prefix="ip netns exec rangehost ")
    ports = firewall.discover_bridge_ports(s)
    assert ports == ["veth7", "veth8"], ports
    assert calls and calls[0][:4] == ["ip", "netns", "exec", "rangehost"], calls
    assert not local_reads  # local /sys never consulted through the trap


@pytest.mark.db  # uses the client fixture (real DB for the safety-record mirror)
def test_t03_start_gate_requires_live_topology_match(client, users, env_dirs, monkeypatch):
    """Config-string equality is not live coverage: a port attached AFTER
    the evidence was recorded must deny new runs. The live re-check runs for
    the NFT controller, so the double must carry that mechanism (the previous
    double's 'test-fake' mechanism silently skipped the very check under
    test — the assertion could never fire)."""
    from srplatform.safety import Supervisor, set_supervisor
    from srplatform.safety import firewall
    from srplatform.settings import get_settings
    from tests.helpers import FakeDatapath as FakeDP

    class NftFakeDP(FakeDP):
        mechanism = "nft"

    monkeypatch.setenv("RANGE_BRIDGE_PORTS", "tap1,tap2")
    get_settings.cache_clear()
    sup = Supervisor(datapath=NftFakeDP(ok=True),
                     state_file=str(env_dirs / "safety_state.json"))
    set_supervisor(sup)
    sup.initialize_state(reason="test")
    for kind in ("baseline_check", "datapath_proof", "killswitch_test"):
        sup.record(kind, True, {})
    monkeypatch.setattr(firewall, "discover_bridge_ports",
                        lambda s: ["tap1", "tap2", "tap3-new"])
    ok, reasons = sup.start_gate()
    assert ok is False and any("live bridge topology" in r for r in reasons), reasons


# --------------------------------------------------------------------------- #
# PACKET TEST: established allowances are port-scoped in the real datapath     #
# --------------------------------------------------------------------------- #

@pytest.mark.packet
def test_t03_netns_established_flows_are_port_scoped(tmp_path, monkeypatch):
    """Disposable namespaces: with the rendered baseline applied,
    (a) an ALREADY-ESTABLISHED range->management:8080 connection (created
    before the baseline) must STOP working — the old destination-wide
    established accept let it survive;
    (b) the intended flows still work: management->range:22 with replies,
    and range->API:8000 ingest."""
    from tests.helpers import require_packet_prereq
    require_packet_prereq()
    import subprocess as sp

    uid = uuid.uuid4().hex[:6]
    ns, RANGE1, MGMT, SRV = (f"tp_{u}{uid}" for u in ("rt", "r1", "mg", "sv"))
    R1_IP, GW_IP = "10.66.0.10", "10.66.0.1"
    MGMT_GW, MGMT_IP = "10.0.0.1", "10.0.0.2"
    SRV_GW, SRV_IP, API_PORT_ = "10.88.0.1", "10.88.0.2", 8000
    br = "srbr0"
    created = []

    def ip(*args, check=True):
        return sp.run(["ip", *args], capture_output=True, text=True, check=check)

    def inns(target, *args, check=True):
        return ip("netns", "exec", target, "ip", *args, check=check)

    def sysctl_ns(target, key, value):
        path = "/proc/sys/" + key.replace(".", "/")
        return ip("netns", "exec", target, "unshare", "-m", "--mount-proc",
                  "sh", "-c", f"echo {value} > {path}")

    try:
        for name in (ns, RANGE1, MGMT, SRV):
            ip("netns", "add", name)
            created.append(name)

        def link_pair(a_ns, a_name, b_ns, b_name, a_ip=None, b_ip=None, via=None):
            ip("link", "add", f"x{a_name}", "type", "veth", "peer", "name", f"x{b_name}")
            ip("link", "set", f"x{a_name}", "netns", a_ns)
            ip("link", "set", f"x{b_name}", "netns", b_ns)
            inns(a_ns, "link", "set", f"x{a_name}", "name", a_name)
            inns(b_ns, "link", "set", f"x{b_name}", "name", b_name)
            for t, d in ((a_ns, a_name), (b_ns, b_name)):
                inns(t, "link", "set", d, "up")
            if a_ip:
                inns(a_ns, "addr", "add", a_ip, "dev", a_name)
            if b_ip:
                inns(b_ns, "addr", "add", b_ip, "dev", b_name)
            if via:
                inns(b_ns, "route", "add", "default", "via", via, check=False)

        inns(ns, "link", "add", br, "type", "bridge")
        inns(ns, "addr", "add", f"{GW_IP}/24", "dev", br)
        inns(ns, "link", "set", br, "up")
        sysctl_ns(ns, "net.ipv4.ip_forward", 1)
        # one range host on the bridge
        ip("link", "add", "xr1", "type", "veth", "peer", "name", "yr1")
        ip("link", "set", "xr1", "netns", ns)
        ip("link", "set", "yr1", "netns", RANGE1)
        inns(ns, "link", "set", "xr1", "name", "xr1")
        inns(ns, "link", "set", "xr1", "master", br)
        inns(ns, "link", "set", "xr1", "up")
        inns(RANGE1, "link", "set", "yr1", "name", "eth0")
        inns(RANGE1, "link", "set", "eth0", "up")
        inns(RANGE1, "addr", "add", f"{R1_IP}/24", "dev", "eth0")
        inns(RANGE1, "route", "add", "default", "via", GW_IP)
        link_pair(ns, "mgmt0", MGMT, "eth0", a_ip=f"{MGMT_GW}/24", b_ip=f"{MGMT_IP}/24",
                  via=MGMT_GW)
        link_pair(ns, "srv0", SRV, "eth0", a_ip=f"{SRV_GW}/24", b_ip=f"{SRV_IP}/24",
                  via=SRV_GW)

        from srplatform.safety import datapath as dp
        from srplatform.safety import firewall
        from srplatform.settings import Settings
        s = Settings(sr_env="dev", range_bridge=br, range_cidr="10.66.0.0/24",
                     management_cidr="10.0.0.0/24", range_bridge_ports="",
                     api_base_url=f"http://{SRV_IP}:{API_PORT_}",
                     datapath_controller="nft",
                     nft_command_prefix=f"ip netns exec {ns} ",
                     safety_state_file=str(tmp_path / "st"))
        nft = dp.NftDatapath(s)
        monkeypatch.setattr(firewall, "validate_port_coverage", lambda s_: (True, "netns"))

        # (a) establish range->MGMT:8080 BEFORE the baseline exists
        holder = sp.Popen(["ip", "netns", "exec", RANGE1, "python3", "-c",
                           "import socket,sys,time\n"
                           "s=None\n"
                           "for _ in range(20):\n"
                           "    try:\n"
                           "        s=socket.create_connection(('" + MGMT_IP + "',8080),2); break\n"
                           "    except Exception:\n"
                           "        time.sleep(0.5)\n"
                           "if s is None: print('DIED no-listener', flush=True); sys.exit(1)\n"
                           "print('ESTABLISHED', flush=True)\n"
                           "for i in range(24):\n"
                           "    try:\n"
                           "        s.sendall(b'ping%d' % i); s.settimeout(1.0); s.recv(32)\n"
                           "    except Exception as e:\n"
                           "        print('DIED', type(e).__name__, flush=True); break\n"
                           "    time.sleep(0.5)\n"],
                          stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        listener = sp.Popen(["ip", "netns", "exec", MGMT, "python3", "-c",
                             "import socket\n"
                             "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                             f"s.bind(('{MGMT_IP}',8080)); s.listen(4)\n"
                             "conns=[]\n"
                             "import time\n"
                             "t=time.time()\n"
                             "while time.time()-t<20:\n"
                             "    s.settimeout(1)\n"
                             "    try:\n"
                             "        c,_=s.accept(); conns.append(c)\n"
                             "    except Exception: pass\n"
                             "for c in conns:\n"
                             "    try:\n"
                             "        while True:\n"
                             "            d=c.recv(32)\n"
                             "            if not d: break\n"
                             "            c.sendall(d)\n"
                             "    except Exception: pass\n"],
                            stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        # wait for the connection to be REAL before the baseline exists
        est_deadline = time.time() + 15
        established = False
        while time.time() < est_deadline:
            line = holder.stdout.readline()
            if not line:
                break
            if "ESTABLISHED" in line:
                established = True
                break
        assert established, "pre-baseline range->management:8080 flow never established"

        # apply the rendered baseline; verification must pass against REAL nft
        code, out = nft._run_nft_stdin(nft.render_baseline())
        assert code == 0, out
        status = nft.baseline_status()
        assert status["ok"] is True, status["detail"]

        # the pre-established range->mgmt:8080 flow must now be DEAD
        deadline = time.time() + 12
        died = False
        while time.time() < deadline:
            line = holder.stdout.readline()
            if not line:
                break
            if "DIED" in line:
                died = True
                break
        assert died, ("pre-established range->management:8080 connection SURVIVED "
                      "the baseline (destination-wide established allowance)")
        holder.kill()
        listener.kill()

        # (b) intended flows still work: mgmt->range:22 with replies
        l22 = sp.Popen(["ip", "netns", "exec", RANGE1, "python3", "-c",
                        "import socket\n"
                        "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                        f"s.bind(('{R1_IP}',22)); s.listen(1)\n"
                        "c,_=s.accept(); c.sendall(b'ssh-banner'); c.close()"],
                       stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(0.5)
        r = ip("netns", "exec", MGMT, "python3", "-c",
               "import socket\n"
               "try:\n"
               f"    s=socket.create_connection(('{R1_IP}',22),3); print('OPEN', s.recv(32).decode())\n"
               "except Exception as e: print('BLOCKED', e)", check=False)
        assert "OPEN" in r.stdout and "ssh-banner" in r.stdout, \
            f"management SSH flow (incl. replies) must work: {r.stdout}"
        l22.terminate()

        l8k = sp.Popen(["ip", "netns", "exec", SRV, "python3", "-c",
                        "import socket\n"
                        "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                        f"s.bind(('{SRV_IP}',{API_PORT_})); s.listen(1)\n"
                        "c,_=s.accept(); c.sendall(b'ingest-ok'); c.close()"],
                       stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(0.5)
        r = ip("netns", "exec", RANGE1, "python3", "-c",
               "import socket\n"
               "try:\n"
               f"    s=socket.create_connection(('{SRV_IP}',{API_PORT_}),3); print('OPEN', s.recv(32).decode())\n"
               "except Exception as e: print('BLOCKED', e)", check=False)
        assert "OPEN" in r.stdout and "ingest-ok" in r.stdout, \
            f"range->API ingest flow must work: {r.stdout}"
        l8k.terminate()
    finally:
        for name in created:
            ip("netns", "del", name, check=False)
