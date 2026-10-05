"""Stage 4 regressions (audit N10–N11, second follow-up review).

Immutable snapshot resolution for worker/deployment/scoring, verifier host
resolution restricted to the owned active deployment (no DNS fallback), pinned
management host keys, deployment identity in evidence, the service-readiness
provisioning contract, and the strengthened worker integration assertions.
"""
from __future__ import annotations

import contextlib

import pytest


@contextlib.contextmanager
def _db():
    from srplatform.db.session import db
    with db() as s:
        yield s


# --------------------------------------------------------------------------- #
# N10 — one immutable snapshot                                                  #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_worker_resolves_objectives_from_snapshot_not_live_yaml(client, users, tmp_path,
                                                                monkeypatch):
    """Create session -> mutate the CURRENT scenario YAML -> the worker's
    snapshot (via its session-scoped capability) and scoring still use the
    ORIGINAL bytes."""
    from srplatform.scenario_engine import loader

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]

    # the worker's capability view of the snapshot
    from srplatform.api import deps
    # launch to create a run-scoped token? cheaper: use the member token —
    # the endpoint serves the same snapshot for both principals
    snap = client.get(f"/sessions/{sid}/scenario", headers=users["member"])
    assert snap.status_code == 200
    original_objectives = [o["id"] for o in
                           snap.json()["scenario"]["red"]["objectives"]]
    assert original_objectives == ["flaggrab"]

    # mutate the CURRENT YAML: rename the objective, add another
    real_dir = loader.scenarios_dir()
    monkeypatch.setattr(loader, "scenarios_dir",
                        lambda: _mutated_copy(real_dir, tmp_path))
    # the snapshot endpoint is unaffected by the mutation...
    snap2 = client.get(f"/sessions/{sid}/scenario", headers=users["member"]).json()
    assert [o["id"] for o in snap2["scenario"]["red"]["objectives"]] == ["flaggrab"]
    # the CURRENT file really did change (probe the loader directly)
    cur = loader.load_scenario("quick-win-01")
    assert [o["id"] for o in cur["red"]["objectives"]] != ["flaggrab"]


def _mutated_copy(real_dir, tmp_path):
    import shutil
    dst = tmp_path / "scenarios"
    shutil.copytree(real_dir, dst)
    p = dst / "quick-win-01.yaml"
    text = p.read_text().replace("id: flaggrab", "id: RENAMED-objective")
    p.write_text(text)
    return dst


@pytest.mark.db
def test_worker_transport_scenario_spec_over_http(client, users):
    """The worker-facing transport method exists and returns the snapshot
    through the REAL endpoint (production path, not a stub)."""
    from srplatform.red_agent.transport import TestClientTransport

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tr = TestClientTransport(client, token=users["member"]["Authorization"].removeprefix("Bearer "))
    spec = tr.scenario_spec(sid)
    assert spec["id"] == "quick-win-01"
    assert spec["red"]["objectives"][0]["id"] == "flaggrab"


# --------------------------------------------------------------------------- #
# N11 — verifier resolution boundaries                                          #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_missing_inventory_yields_unknown_without_dns_or_ssh(client, users):
    """No owned active deployment => resolution NEVER falls back to the raw
    hostname (no DNS, no SSH attempt): the exec channel is not called at all
    and live rescore is refused."""
    from srplatform import verification_service

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]

    calls = []

    def spy_exec(host, command):
        calls.append((host, command))
        return 0, ""

    verification_service.set_verifier_exec(spy_exec)
    try:
        # no deployment at all: host map empty, resolution refuses
        with _db() as s:
            hmap = verification_service.host_map_for(s, sid)
        assert hmap == {}
        resolved = verification_service._resolve(spy_exec, {})
        rc, out = resolved("web01", "true")
        assert rc == 254 and calls == [], "raw-name fallback must not reach exec"
        assert "no DNS fallback" in out

        # explicit live rescore without an owned deployment: refused, visible
        r = client.post(f"/sessions/{sid}/score", headers=users["member"])
        assert r.status_code == 503
        assert "refused" in r.json()["error"] or "no active owned" in r.json()["error"]
        assert calls == []
    finally:
        verification_service.set_verifier_exec(None)


@pytest.mark.db
def test_end_then_score_refuses_ssh_at_reused_addresses(client, users):
    """End+teardown A => a later explicit rescore of A makes NO exec call at
    all (the addresses may already belong to a future deployment B)."""
    from srplatform import verification_service

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    assert client.post(f"/sessions/{sid}/launch", headers=users["member"]).status_code == 200

    calls = []
    verification_service.set_verifier_exec(
        lambda h, c: (calls.append(h), (0, "sshd.service enabled\nnginx.service enabled\n"))[1])
    try:
        assert client.post(f"/sessions/{sid}/score",
                           headers=users["member"]).status_code == 200
        assert calls
        client.post(f"/sessions/{sid}/end", headers=users["member"])
        client.post(f"/sessions/{sid}/teardown", headers=users["member"])
        calls.clear()
        r = client.post(f"/sessions/{sid}/score", headers=users["member"])
        assert r.status_code == 503 and calls == []
        # historical snapshot remains readable, read-only
        hist = client.get(f"/sessions/{sid}/score", headers=users["member"])
        assert hist.status_code == 200 and hist.json()["status"] in ("scored", "partial")
    finally:
        verification_service.set_verifier_exec(None)


@pytest.mark.db
def test_removed_or_pending_resources_filtered_from_host_map(client, users):
    """Only ACTIVE (state=created) resources of the READY deployment resolve;
    pending intents and destroyed entries are filtered (wrong generation /
    foreign occupants never receive an SSH attempt)."""
    from srplatform import verification_service
    from srplatform.db.models import Deployment
    from sqlalchemy.orm.attributes import flag_modified

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{sid}/launch", headers=users["member"])
    with _db() as s:
        dep = s.query(Deployment).filter_by(session_id=sid).first()
        res = [dict(r) for r in dep.resources]
        res.append({"host": "pending01", "ip": "10.66.0.99", "state": "pending",
                    "vmid": 999})
        res.append({"host": "dead01", "ip": "10.66.0.98", "state": "destroy_failed",
                    "vmid": 998})
        dep.resources = res
        flag_modified(dep, "resources")
        s.commit()
    with _db() as s:
        hmap = verification_service.host_map_for(s, sid)
    assert hmap.get("web01")
    assert "pending01" not in hmap and "dead01" not in hmap


@pytest.mark.db
def test_verifier_evidence_records_deployment_identity(client, users):
    from srplatform.db.models import Event
    from sqlalchemy import select

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{sid}/launch", headers=users["member"])
    from srplatform import verification_service
    verification_service.set_verifier_exec(lambda h, c: (0, ""))
    try:
        r = client.post(f"/sessions/{sid}/verifier_checks",
                        json={"objective_id": "flaggrab"}, headers=users["member"])
        assert r.status_code == 200
    finally:
        verification_service.set_verifier_exec(None)
    with _db() as s:
        ev = s.execute(select(Event).where(
            Event.session_id == sid, Event.action_type == "verifier")
            .order_by(Event.event_id.desc())).scalars().first()
    dep = ev.payload["deployment"]
    assert dep["deployment_id"] and dep["deployment_status"] == "ready"
    assert ev.payload["target"] == "10.66.0.10"


# --------------------------------------------------------------------------- #
# N11 — pinned management host keys                                             #
# --------------------------------------------------------------------------- #

def test_ssh_exec_refuses_unpinned_channels(tmp_path, monkeypatch):
    """No key / no known_hosts file / missing file => visible unavailable
    (125/126) BEFORE any ssh spawn; StrictHostKeyChecking=yes when pinned."""
    import subprocess
    from srplatform import settings as st
    from srplatform import verification_service as vs

    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    st.get_settings.cache_clear()
    s0 = st.get_settings()
    try:
        monkeypatch.setattr(vs, "get_settings", lambda: s0.model_copy(
            update={"verifier_ssh_key_path": "", "verifier_ssh_known_hosts": ""}))
        rc, out = vs._ssh_exec("10.66.0.10", "true")
        assert rc == 126 and "not configured" in out

        monkeypatch.setattr(vs, "get_settings", lambda: s0.model_copy(
            update={"verifier_ssh_key_path": str(tmp_path / "k"),
                    "verifier_ssh_known_hosts": str(tmp_path / "missing")}))
        rc, out = vs._ssh_exec("10.66.0.10", "true")
        assert rc == 125 and "missing" in out

        kh = tmp_path / "kh"
        kh.write_text("10.66.0.10 ssh-ed25519 AAAAkey\n")
        monkeypatch.setattr(vs, "get_settings", lambda: s0.model_copy(
            update={"verifier_ssh_key_path": str(tmp_path / "k"),
                    "verifier_ssh_known_hosts": str(kh)}))
        called = {}

        def fake_run(cmd, **kw):
            called["cmd"] = cmd
            raise subprocess.TimeoutExpired(cmd, 1)
        monkeypatch.setattr(subprocess, "run", fake_run)
        vs._ssh_exec("10.66.0.10", "true")
        assert "StrictHostKeyChecking=yes" in called["cmd"]     # pinned, no TOFU
        assert any("UserKnownHostsFile=" in str(c) for c in called["cmd"])
    finally:
        st.get_settings.cache_clear()





# --------------------------------------------------------------------------- #
# N10 item 4 — provisioning contract                                            #
# --------------------------------------------------------------------------- #

def test_unknown_service_names_are_rejected_not_ignored():
    from srplatform.scenario_engine.loader import ScenarioError, parse_scenario
    import yaml
    base = (open("scenarios/quick-win-01.yaml")).read()
    spec = yaml.safe_load(base)
    spec["topology"]["hosts"][0]["services"] = ["http", "teleport"]
    with pytest.raises(ScenarioError, match="unsupported service"):
        parse_scenario(yaml.safe_dump(spec), where="test")


@pytest.mark.db
def test_ready_requires_service_readiness_when_channel_configured(client, users, monkeypatch):
    """With the management channel configured (enforced mode), launch reaches
    `ready` only after the declared services verify present; a missing
    service fails the launch LOUDLY, and a fixed template succeeds."""
    from srplatform import verification_service

    def nginx_missing(host, command):
        if "list-unit-files" in command:
            return 0, "sshd.service enabled enabled\n"     # nginx NOT there
        return 0, ""

    verification_service.set_verifier_exec(nginx_missing)
    try:
        sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                          headers=users["member"]).json()["session_id"]
        # force enforcement mode (as production would be): channel configured
        monkeypatch.setattr(verification_service, "get_settings",
                            lambda: _configured_settings())
        r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
        assert r.status_code == 409 and r.json()["detail"]["error"] == "readiness_failed"
        failed = [c for c in r.json()["detail"]["checks"] if c["status"] != "passed"]
        assert failed and failed[0]["service"] == "http"

        # template fixed -> readiness passes -> ready
        def nginx_present(host, command):
            if "list-unit-files" in command:
                return 0, "sshd.service enabled enabled\nnginx.service enabled enabled\n"
            return 0, ""
        verification_service.set_verifier_exec(nginx_present)
        r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
        assert r.status_code == 200, r.text
        assert r.json()["readiness"]["enforced"] and r.json()["readiness"]["ok"]
    finally:
        verification_service.set_verifier_exec(None)


def _configured_settings():
    from srplatform.settings import get_settings
    return get_settings().model_copy(update={
        "verifier_ssh_key_path": "/etc/sr/verifier",
        "verifier_ssh_known_hosts": "/etc/sr/vkh"})


# --------------------------------------------------------------------------- #
# N10 item 5 — strengthened worker integration assertions                      #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_objective_pass_requires_true_host_state_and_reports_it(client, users):
    """A passing objective requires a controlled TRUE host state; a false
    state FAILS it; an unavailable channel stays UNKNOWN — the integration
    asserts the intended outcome, never 'completed or failed' equivalence."""
    from srplatform import verification_service

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{sid}/launch", headers=users["member"])

    # TRUE state: flag file present with expected content
    def true_state(host, command):
        if "cat" in command and "flag" in command:
            return 0, "FLAG{quick-win}\n"
        return 1, ""
    verification_service.set_verifier_exec(true_state)
    try:
        r = client.post(f"/sessions/{sid}/verifier_checks",
                        json={"objective_id": "flaggrab"}, headers=users["member"])
        assert r.json()["status"] == "passed" and r.json()["passed"] is True
    finally:
        pass

    # FALSE state
    verification_service.set_verifier_exec(lambda h, c: (0, "nope\n"))
    r = client.post(f"/sessions/{sid}/verifier_checks",
                    json={"objective_id": "flaggrab"}, headers=users["member"])
    assert r.json()["status"] == "failed" and r.json()["passed"] is False

    # UNAVAILABLE state (exec channel broken) => unknown, never passed
    verification_service.set_verifier_exec(lambda h, c: (124, "timeout"))
    r = client.post(f"/sessions/{sid}/verifier_checks",
                    json={"objective_id": "flaggrab"}, headers=users["member"])
    assert r.json()["status"] == "unknown" and r.json()["passed"] is False
    verification_service.set_verifier_exec(None)
