"""Plan 18 — installer, credential and provisioning repairs (fast layer).

Every test here reproduces a defect that the live practice run found on
2026-10-23 and proves its repair WITHOUT root, WITHOUT a real appliance and
WITHOUT touching a model endpoint:

* the model credential is a FILE reference resolved by the API process
  alone, and a missing/empty/unreadable file fails LOUDLY naming the file;
* production validation refuses an empty or world-readable credential file;
* members' SSH hints name the REACHABLE bastion address, falling back to
  the range-side planning address only when no LAN address was configured;
* the Node runtime decision is explicit (kept/provisioned/refused), never
  a silent half-installed dependency;
* the installer Runner refuses to hand a non-str environment value to a
  subprocess — it fails naming the key, not inside exec;
* firstboot distinguishes PENDING (the operator's manual window has not
  run yet — exit 3) from broken (exit 1).
"""
from __future__ import annotations

import ipaddress
import os
import pathlib
import subprocess

import pytest

from deploy.appliance import InstallError, Runner
from deploy import appliance_services as svc
from srplatform.settings import (Settings, bastion_login_target,
                                 model_api_key, validate_production)


def _settings(tmp_path, **over):
    base = dict(_env_file=None)
    base.update(over)
    return Settings(**base)


# --------------------------------------------------------------------------- #
# model credential: file is the authority, failure names the file              #
# --------------------------------------------------------------------------- #

def test_model_api_key_prefers_file_strips_and_falls_back(tmp_path):
    key = tmp_path / "model.key"
    key.write_text("  secret-token\n")
    s = _settings(tmp_path, llm_api_key="dummy",
                  llm_api_key_file=str(key))
    assert model_api_key(s) == "secret-token"
    missing = _settings(tmp_path, llm_api_key="literal-fallback",
                        llm_api_key_file=str(tmp_path / "absent"))
    assert model_api_key(missing) == ""          # NOT the silent fallback
    legacy = _settings(tmp_path, llm_api_key="legacy-value",
                       llm_api_key_file="")
    assert model_api_key(legacy) == "legacy-value"


def test_llm_construction_reads_key_file_and_fails_naming_it(tmp_path,
                                                             monkeypatch):
    from srplatform.red_agent import llm as llm_mod

    good = tmp_path / "model.key"
    good.write_text("file-credential\n")
    monkeypatch.setattr(llm_mod, "get_settings", lambda: _settings(
        tmp_path, llm_api_key_file=str(good)))
    assert llm_mod.LLM().client.api_key == "file-credential"

    empty = tmp_path / "empty.key"
    empty.write_text("")
    monkeypatch.setattr(llm_mod, "get_settings", lambda: _settings(
        tmp_path, llm_api_key_file=str(empty)))
    with pytest.raises(ValueError, match="unreadable or empty.*empty\\.key"):
        llm_mod.LLM()

    # an explicit argument still wins (the API gateway and tests)
    assert llm_mod.LLM(api_key="explicit").client.api_key == "explicit"


# --------------------------------------------------------------------------- #
# production validation of the credential file                                 #
# --------------------------------------------------------------------------- #

_REAL_KEY = ""


@pytest.fixture(scope="module", autouse=True)
def real_verifier_key(tmp_path_factory):
    """Owned lifecycle (review finding): production validation needs a
    REAL parseable verifier key, but generating one at MODULE IMPORT into
    an anonymous temp dir left a private key in the system temp folder
    forever — module import is not a lifecycle. The key now lives in the
    fixture's own directory and its removal after the module is VERIFIED,
    not assumed."""
    global _REAL_KEY
    import shutil

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    d = pathlib.Path(str(tmp_path_factory.mktemp("verifier-key")))
    f = d / "verifier"
    f.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()))
    f.chmod(0o600)
    _REAL_KEY = str(f)
    try:
        yield f
    finally:
        shutil.rmtree(d)
        assert not d.exists(), "fixture leaked its key directory"


def _prod(**over):
    base = dict(
        sr_env="production",
        postgres_url="postgresql+psycopg2://sr_app:real@db/sr",
        postgres_url_owner="postgresql+psycopg2://sr_owner:real@db/sr",
        broker_socket="/run/sparring-range/broker.sock",
        runner_transport="ssh", runner_ssh_target="runner@10.66.0.9",
        runner_ssh_key_path="/etc/sr/runner", runner_ssh_known_hosts="/etc/sr/kh",
        verifier_ssh_key_path=_REAL_KEY,
        verifier_ssh_known_hosts="/etc/sr/vkh",
        bastion_targets_known_hosts="/etc/sr/tkh",
        api_base_url="https://api.range.internal",
        telemetry_ca_file="/etc/sr/api-ca.crt",
    )
    base.update(over)
    return _settings(pathlib.Path("/nonexistent"), **base)


def test_production_accepts_a_valid_credential_file(tmp_path):
    key = tmp_path / "model.key"
    key.write_text("real-credential\n")
    key.chmod(0o640)
    validate_production(_prod(llm_api_key_file=str(key)))  # no raise


def test_production_refuses_empty_or_world_readable_credential(tmp_path):
    empty = tmp_path / "empty.key"
    empty.write_text("")
    empty.chmod(0o640)
    with pytest.raises(RuntimeError, match="llm_api_key_file is empty"):
        validate_production(_prod(llm_api_key_file=str(empty)))
    open_ = tmp_path / "open.key"
    open_.write_text("secret\n")
    open_.chmod(0o644)
    with pytest.raises(RuntimeError, match="world-readable"):
        validate_production(_prod(llm_api_key_file=str(open_)))
    with pytest.raises(RuntimeError, match="unreadable"):
        validate_production(
            _prod(llm_api_key_file=str(tmp_path / "absent.key")))


# --------------------------------------------------------------------------- #
# member SSH hints: reachable address first, planning address as fallback      #
# --------------------------------------------------------------------------- #

def test_bastion_login_target_prefers_reachable_address():
    assert bastion_login_target(
        _settings(pathlib.Path("/"), bastion_public_address="10.10.10.50",
                  bastion_address="10.66.0.2")) == "10.10.10.50"
    assert bastion_login_target(
        _settings(pathlib.Path("/"), bastion_public_address="",
                  bastion_address="10.66.0.2")) == "10.66.0.2"


# --------------------------------------------------------------------------- #
# Node runtime: an explicit decision, never a silent partial dependency        #
# --------------------------------------------------------------------------- #

def test_node_action_is_explicit_per_mode():
    assert svc.node_action("auto", (22, 14)) == "kept"
    assert svc.node_action("auto", (18, 19)) == "provision"   # Ubuntu 24.04
    assert svc.node_action("auto", None) == "provision"       # missing node
    assert svc.node_action(None, (18, 19)) == "provision"     # default auto
    assert svc.node_action("provision", (22, 14)) == "provision"
    with pytest.raises(RuntimeError, match="require forbids provisioning"):
        svc.node_action("require", (18, 19))
    with pytest.raises(RuntimeError, match="not one of auto\\|require"):
        svc.node_action("maybe", (22, 0))
    assert svc.node_action("require", (22, 0)) == "kept"


def test_node_pin_matches_the_pinned_lts_filename():
    url = svc.NODE_URL_TEMPLATE.format(version=svc.NODE_PIN_VERSION)
    assert url.endswith(f"node-v{svc.NODE_PIN_VERSION}-linux-x64.tar.xz")
    assert len(svc.NODE_PIN_SHA256_LINUX_X64) == 64


# --------------------------------------------------------------------------- #
# Runner: non-str environment fails HERE naming the key (HTTPS_IP defect)      #
# --------------------------------------------------------------------------- #

def test_runner_refuses_non_str_env_naming_the_key():
    run = Runner(dry_run=False)
    with pytest.raises(InstallError, match="HTTPS_IP.*IPv4Address.*not str"):
        run("true", env={"HTTPS_IP": ipaddress.ip_address("10.10.10.50")})


def test_native_packages_carry_the_broker_and_node_dependencies():
    # plan 18 live finds: python3-libvirt was missing (broker import died),
    # and the Node provisioning needs curl/ca-certificates/xz-utils.
    for pkg in ("python3-libvirt", "curl", "ca-certificates", "xz-utils"):
        assert pkg in svc.NATIVE_PACKAGES, pkg


# --------------------------------------------------------------------------- #
# bounded diagnostic SSH: keepalives + stdin=/dev/null on every platform call  #
# --------------------------------------------------------------------------- #

class _CapturingProc:
    def __init__(self, *args, **kwargs):
        _CapturingProc.last = (args, kwargs)
        self.returncode = 0
        self.pid = os.getpid()  # real pgid so _attach_proc can resolve it

    def wait(self, timeout=None):
        return 0

    def communicate(self, timeout=None):
        return "gone", ""

    def poll(self):
        return 0


def _runner(tmp_path):
    from srplatform.red_agent.runner import SshRunner
    kh = tmp_path / "kh"
    kh.write_text("10.66.0.9 ssh-ed25519 AAAA\n")
    key = tmp_path / "runner_key"
    key.write_text("k\n")
    s = _settings(tmp_path, runner_transport="ssh",
                  runner_ssh_target="runner@10.66.0.9",
                  runner_ssh_key_path=str(key),
                  runner_ssh_known_hosts=str(kh),
                  sr_env="lab")
    return SshRunner(s)


def test_runner_ssh_channel_is_bounded(tmp_path, monkeypatch):
    from srplatform.red_agent import runner as runner_mod
    r = _runner(tmp_path)
    base = r._base_cmd()
    assert "ServerAliveInterval=5" in base and "ServerAliveCountMax=3" in base

    monkeypatch.setattr(runner_mod.subprocess, "Popen", _CapturingProc)
    r._control("status", "op-1", timeout=5)
    _args, kwargs = _CapturingProc.last
    assert kwargs.get("stdin") is subprocess.DEVNULL

    monkeypatch.setattr(runner_mod, "_bounded_reader",
                        lambda *a, **k: (b"out", False))
    res = r.run("id", timeout=5)
    _args, kwargs = _CapturingProc.last
    assert kwargs.get("stdin") is subprocess.DEVNULL
    assert res.exit_code == 0


def test_verifier_exec_channels_are_bounded(tmp_path, monkeypatch):
    import srplatform.verification_service as vs
    from srplatform.red_agent.sandbox import KaliSandbox

    captured: list[dict] = []

    def _fake_run(cmd, **kwargs):
        captured.append({"cmd": cmd, **kwargs})
        return subprocess.CompletedProcess(cmd, 0, stdout="x", stderr="")

    monkeypatch.setattr("srplatform.red_agent.sandbox.subprocess.run", _fake_run)
    KaliSandbox().verifier_exec("10.66.0.10", "true")
    monkeypatch.setattr(vs.subprocess, "run", _fake_run)
    kh = tmp_path / "vkh"
    kh.write_text("10.66.0.10 ssh-ed25519 AAAA\n")
    key = tmp_path / "vk"
    key.write_text("k\n")
    monkeypatch.setattr(vs, "get_settings", lambda: _settings(
        tmp_path, verifier_ssh_key_path=str(key),
        verifier_ssh_known_hosts=str(kh)))
    vs._ssh_exec("10.66.0.10", "true")

    assert len(captured) == 2
    for call in captured:
        assert "ServerAliveInterval=5" in call["cmd"]
        assert "ServerAliveCountMax=3" in call["cmd"]
        assert call.get("stdin") is subprocess.DEVNULL
        assert call.get("timeout"), "outer command timeout must stay"


def _firstboot_exit(monkeypatch, report):
    from deploy import appliance as ap
    monkeypatch.setattr(ap, "firstboot_report", lambda m, lay: report)
    monkeypatch.setattr(ap, "_load", lambda args: (None, None))
    rc = ap.main(["firstboot", "--manifest", "/unused/manifest.json"])
    return rc


def test_firstboot_exit_codes_distinguish_pending_from_broken(monkeypatch):
    """CLI contract, tested separately from the report's JSON semantics:
    pending manual steps are exit 3 (with a remediation line), genuine
    failures are exit 1, and only a fully real pass is exit 0."""
    checks = [{"check": "x", "ok": False, "pending": True, "detail": ""}]
    assert _firstboot_exit(monkeypatch, {"ok": False, "failed": [],
                                         "pending": ["x"],
                                         "checks": checks}) == 3
    assert _firstboot_exit(monkeypatch, {"ok": True, "failed": [],
                                         "pending": [],
                                         "checks": []}) == 0
    assert _firstboot_exit(monkeypatch, {"ok": False, "failed": ["broker"],
                                         "pending": [],
                                         "checks": []}) == 1
    # a genuine failure outranks pending work
    assert _firstboot_exit(monkeypatch, {"ok": False, "failed": ["images"],
                                         "pending": ["x"],
                                         "checks": []}) == 1


def test_firstboot_report_marks_manual_window_checks_pending(tmp_path,
                                                             monkeypatch):
    """Before the operator applies the bridge/nft/starts, every check that
    DEPENDS on those steps is pending — never a FAIL wall — while genuine
    installation failures (a missing image) still fail."""
    from infra.dev import install_sequences as seq
    from deploy import appliance as ap

    manifest = seq.build_manifest(tmp_path / "materials")
    root = tmp_path / "root"
    seq._run(root, manifest, "apply")
    m = ap.ApplianceManifest.load(manifest)
    lay = ap.default_layout(root=root)
    sm = ap.sandbox_manifest(m, root)

    monkeypatch.setattr(ap.shutil, "which",
                        lambda name: "/usr/sbin/nft" if name == "nft" else None)
    monkeypatch.setattr(ap, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(ap, "_broker_status", lambda _m: {"ok": True})

    import socket
    import urllib.request

    def _refuse(*a, **k):
        raise OSError("connection refused (test)")

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    # the TLS directory and the bastion key file are provisioned by the
    # REAL (root) half of apply, not the sandbox half; the test provides
    # them so the report's genuine checks are exercised, and proves a
    # missing IMAGE still fails for real.
    (lay.etc / "tls").mkdir(parents=True, exist_ok=True)
    (lay.etc / "ssh").mkdir(parents=True, exist_ok=True)
    (lay.etc / "ssh" / "authorized_keys").write_text("member ssh-ed25519 AAAA\n")
    # no bridge under /sys/class/net in the test environment: the manual
    # window has not run, so every dependent check is pending.
    report = ap.firstboot_report(sm, lay)
    pending = set(report["pending"])
    assert {"api /healthz", "bastion listener", "isolated bridge"} <= pending
    # Review finding (machine-readable honesty): while the operator's
    # manual window is incomplete the report may NOT claim ok — the CLI
    # already exited 3, the JSON must be just as truthful.
    assert report["ok"] is False, report
    assert report["failed"] == [], report
    for c in report["checks"]:
        if c["check"] in pending:
            assert c["pending"] and c["ok"] is False, c
        else:
            assert c["ok"] is True, c
    # the image/TLS/token checks are REAL checks and passed for real
    names = {c["check"] for c in report["checks"]}
    assert "image attacker" in names and "TLS material" in names
    assert "image attacker" not in pending and not any(
        c["check"] == "image attacker" and not c["ok"]
        for c in report["checks"])
    # a genuine breakage stays visible as `failed` even while other
    # checks are pending: pending and failed never mix into one bucket
    victim = next(pathlib.Path(i.path) for r, i in sm.images.items()
                  if r == "attacker")
    victim.unlink()
    report2 = ap.firstboot_report(sm, lay)
    assert report2["failed"] == ["image attacker"], report2["failed"]
    assert report2["ok"] is False
    assert "isolated bridge" in report2["pending"], "still pending separately"
