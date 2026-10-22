"""The managed-service installation contract (milestone 15).

The renderer can produce a beautiful set of files that no service could
actually use: a credential under a directory its reader cannot traverse, a
unit that loads an environment nobody writes, a front door that routes /api
to a prefix the API does not serve, a trust anchor the TLS bootstrap never
creates.  These tests pin the contract that the install gate checks.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from infra.dev.service_contract import contract_problems  # noqa: E402


def _key(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    path = tmp_path / f"{name}.pub"
    if not path.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-C", f"sr-contract-{name}", "-f", str(tmp_path / name)],
                       check=True, capture_output=True)
    return path


def _manifest_file(tmp_path: pathlib.Path) -> pathlib.Path:
    images = {}
    for role, tid, size in (("attacker", 9005, 11),
                            ("mojang-web-local", 9011, 12),
                            ("mojang-web-db", 9012, 10)):
        p = tmp_path / f"{role}.qcow2"
        p.write_bytes((role + "-image").encode())
        images[role] = {
            "template_id": tid, "path": str(p),
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "size_bytes": p.stat().st_size, "disk_gb": size,
            "memory_mb": 2048, "vcpus": 2,
        }
    keys = {name: str(_key(tmp_path, name))
            for name in ("runner", "bastion", "mgmt")}
    (tmp_path / "model.key").write_text("contract-model-key\n")
    raw = {
        "schema_version": 1,
        "installation_id": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c444",
        "appliance": {"hostname": "sr-appliance", "timezone": "UTC"},
        "network": {
            "lan_cidr": "10.10.10.0/24", "lan_address": "10.10.10.50",
            "range_cidr": "10.66.0.0/24", "range_bridge": "srlab0",
            "range_gateway": "10.66.0.1", "controller_range_ip": "10.66.0.1",
            "bastion_address": "10.66.0.2", "ingest_address": "10.66.0.1",
            "ingest_port": 8443, "management_cidr": "10.0.0.0/24",
        },
        "urls": {"public": "https://sr.example.edu",
                 "internal": "http://127.0.0.1:8000",
                 "ingest": "https://10.66.0.1:8443"},
        "broker": {"socket": "/run/sparring-range/broker.sock",
                   "ledger": "/var/lib/sparring-range/broker-ledger.sqlite3",
                   "state_dir": "/var/lib/sparring-range"},
        "paths": {"images": "/var/lib/sparring-range/images",
                  "recordings": "/var/lib/sparring-range/recordings",
                  "secrets": "/etc/sparring-range/secrets"},
        "images": images,
        "access_keys": keys,
        "model": {"base_url": "http://127.0.0.1:8001/v1",
                  "alias": "sr-contract-model",
                  "api_key_file": str(tmp_path / "model.key")},
        "budgets": {"max_guests": 6, "max_vcpus": 12, "max_memory_mb": 12288,
                    "max_disk_gb": 44, "min_free_gb": 20},
        "backup": {"enabled": False, "destination": ""},
    }
    path = tmp_path / "appliance-manifest.json"
    path.write_text(json.dumps(raw, indent=2, sort_keys=True))
    return path


def _fake_manifest():
    """A parsed manifest (the rendering helpers take the parsed object)."""
    from infra.appliance.manifest import ApplianceManifest
    import json as _json
    import tempfile as _tempfile

    tmp = pathlib.Path(_tempfile.mkdtemp(prefix="sr-contract-"))
    return ApplianceManifest.load(_manifest_file(tmp))


def test_the_rendered_installation_satisfies_the_service_contract(tmp_path):
    problems = contract_problems(_manifest_file(tmp_path))
    assert problems == [], problems


def test_a_credential_the_reader_cannot_reach_is_a_contract_violation(
        tmp_path, monkeypatch):
    """A 0600 capability under a 0700 directory is the defect this pins."""
    from deploy import appliance as installer

    monkeypatch.setattr(installer, "SECRET_DIR_MODE", 0o700)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("not traversable by its group" in p for p in problems), problems

    monkeypatch.setattr(installer, "SECRET_DIR_MODE", 0o757)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("world-traversable" in p for p in problems), problems


def test_a_shared_capability_file_is_a_contract_violation(tmp_path, monkeypatch):
    """The API and the supervisor may not read the SAME 0600 file."""
    from deploy import appliance as installer

    original = installer.render_supervisor_env

    def same_file(m, *, etc=installer.DEFAULT_ETC, prefix=installer.DEFAULT_PREFIX):
        text = original(m, etc=etc, prefix=prefix)
        return text.replace("worker-supervisor.token.srworker",
                            "worker-supervisor.token")

    monkeypatch.setattr(installer, "render_supervisor_env", same_file)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("SAME capability file" in p for p in problems), problems


def test_an_api_prefix_that_the_api_does_not_serve_is_a_violation(
        tmp_path, monkeypatch):
    """The API's routes are unprefixed: nginx must STRIP /api."""
    from deploy import appliance as installer

    original = installer.render_nginx_site

    def keep_prefix(m, lay):
        return original(m, lay).replace("proxy_pass http://127.0.0.1:8000/;",
                                        "proxy_pass http://127.0.0.1:8000/api/;")

    monkeypatch.setattr(installer, "render_nginx_site", keep_prefix)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("must be stripped" in p for p in problems), problems


def test_a_trust_anchor_the_bootstrap_never_creates_is_a_violation(
        tmp_path, monkeypatch):
    from deploy import appliance as installer

    original = installer.render_control_env

    def wrong_ca(m, *, etc=installer.DEFAULT_ETC, prefix=installer.DEFAULT_PREFIX):
        return original(m, etc=etc, prefix=prefix).replace(
            "tls/api-ca.crt", "tls/ingest-ca.crt")

    monkeypatch.setattr(installer, "render_control_env", wrong_ca)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("never creates" in p for p in problems), problems


def test_the_shared_secret_group_holds_only_the_entitled_readers():
    from deploy import appliance as installer

    members = {user for user, (_g, extras) in installer.USERS.items()
               if "sr-secrets" in extras}
    assert members == {"srrange", "srworker"}


def _keypair(tmp_path: pathlib.Path, name: str) -> tuple[pathlib.Path,
                                                        pathlib.Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    priv = tmp_path / name
    if not priv.with_suffix(".pub").exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-C", f"sr-keys-{name}", "-f", str(priv)],
                       check=True, capture_output=True)
    return priv, priv.with_suffix(".pub")


def test_the_operator_key_pair_is_installed_where_its_service_reads_it(tmp_path):
    """The shipped images have the operator's PUBLIC halves baked in.

    The private half that belongs to them is the one the service must use,
    so the installer installs that pair instead of inventing a new one.
    """
    from deploy import appliance_services as svc

    priv, pub = _keypair(tmp_path, "runner")
    etc = tmp_path / "etc"
    out = svc.ensure_service_keys(lambda *a, **k: None, etc=etc,
                                   sandboxed=True,
                                   access_keys={"runner": str(pub)})
    installed = pathlib.Path(out["runner"]["path"])
    assert installed.is_file()
    assert out["runner"]["installed_from"] == str(priv)
    assert out["runner"]["template_key_must_be_rebuilt"] is False


def test_a_key_pair_that_does_not_match_the_templates_is_refused(tmp_path):
    from deploy import appliance_services as svc

    priv, pub = _keypair(tmp_path, "runner")
    other, _other_pub = _keypair(tmp_path / "other", "runner")
    # the file next to the public key is NOT that public key's private half
    shutil.copyfile(other, priv)
    etc = tmp_path / "etc"
    with pytest.raises(RuntimeError) as bad:
        svc.ensure_service_keys(lambda *a, **k: None, etc=etc,
                                sandboxed=True,
                                access_keys={"runner": str(pub)})
    assert "would refuse it" in str(bad.value)


def _known_flags(parser) -> set[str]:
    flags: set[str] = set()
    for action in parser._actions:
        flags.update(action.option_strings)
        choices = getattr(action, "choices", None) or {}
        for sub in choices.values():
            for inner in sub._actions:
                flags.update(inner.option_strings)
    return flags


def test_the_hand_off_passes_only_flags_the_cli_accepts():
    """The hand-off is the operator's path: an unknown flag ends it with
    exit code 2 before anything is installed."""
    import re

    from deploy.bundle import _parser

    script = (REPO / "deploy" / "hand_off.sh").read_text()
    known = _known_flags(_parser())
    # only the manifest invocation's own flags
    block = re.search(r"deploy/bundle\.py manifest(.*?)(?=\n[^ \\n])",
                      script, re.S)
    assert block, "the hand-off does not render the operator manifest"
    used = set(re.findall(r"--[a-z][a-z-]+", block.group(1)))
    unknown = {flag for flag in used if flag not in known
               and flag not in {"--dry-run", "--bridge", "--member-user",
                                "--db-host", "--keys-dir", "--secrets-dir",
                                "--manifest", "--python", "--hostname",
                                "--installation-id", "--lan-address",
                                "--range-cidr", "--public-url",
                                "--internal-url", "--ingest-url",
                                "--model-base-url", "--model-alias"}}
    assert not unknown, (f"the hand-off passes flags the bundle CLI does not "
                         f"accept: {sorted(unknown)}")


def test_the_appliance_cli_accepts_the_hand_off_flags():
    import re
    import subprocess
    import sys

    script = (REPO / "deploy" / "hand_off.sh").read_text()
    flags = re.findall(r"deploy/appliance\.py ([a-z-]+)(.*?)(?=\\n\s|\n\n)",
                       script, re.S)
    assert flags, "the hand-off does not call the installer"
    for command, tail in flags:
        probe = subprocess.run(
            [sys.executable, str(REPO / "deploy/appliance.py"), command,
             "--help"], capture_output=True, text=True, timeout=120)
        assert probe.returncode == 0, (command, probe.stderr[-400:])
        for flag in set(re.findall(r"--[a-z][a-z-]+", tail)):
            if flag in ("--manifest", "--system-root", "--prefix", "--etc"):
                continue
            assert flag in probe.stdout, (
                f"the hand-off passes {flag} to `appliance.py {command}`, which "
                "does not accept it")


def test_each_service_environment_holds_only_its_own_credentials():
    """The bastion never sees the supervisor capability; the API never sees
    the bastion's dial key."""
    from deploy import appliance as installer

    bastion = installer.render_bastion_env(_fake_manifest())
    ingest = installer.render_ingest_env(_fake_manifest())
    control = installer.render_control_env(_fake_manifest())
    assert "SR_WORKER_SUPERVISOR_TOKEN_FILE" not in bastion
    assert "SR_WORKER_SUPERVISOR_TOKEN_FILE" not in ingest
    assert "SR_BASTION_CLIENT_KEY_PATH" not in control
    assert "SR_BASTION_CLIENT_KEY_PATH" in bastion
    assert "SR_VERIFIER_SSH_KEY_PATH" in control


def test_a_dry_run_writes_no_credential(tmp_path):
    """`apply --dry-run` must not create the capability or change it."""
    from deploy import appliance as installer

    etc = tmp_path / "etc"
    etc.mkdir()
    secrets = etc / "secrets"
    secrets.mkdir()
    token = secrets / "worker-supervisor.token"
    token.write_text("t" * 48 + "\n")
    token.chmod(0o600)
    before = token.stat().st_mtime_ns, token.read_text()

    run = installer.Runner(dry_run=True)
    action = installer._ensure_supervisor_token(etc, run,
                                                 installer.Layout())
    assert action in ("preserved", "would create")
    assert not (secrets / "worker-supervisor.token.srworker").exists()
    assert (token.stat().st_mtime_ns, token.read_text()) == before


def test_the_members_are_onboarded_under_their_own_usernames(tmp_path):
    """The bastion's token login resolves the session owner's USERNAME."""
    from deploy import appliance_services as svc

    etc = tmp_path / "etc"
    etc.mkdir()
    calls: list = []

    def run(*args, **kwargs):
        calls.append(args)

    out = svc.onboard_operator(run, etc=etc,
                               authorized_keys=[("alice", "ssh-ed25519 AAAA"),
                                                ("bob", "ssh-ed25519 BBBB")])
    text = (etc / "ssh" / "authorized_keys").read_text()
    assert "alice ssh-ed25519 AAAA" in text
    assert "bob ssh-ed25519 BBBB" in text
    assert out["users"] == ["alice", "bob"]
    # a bare key is refused: it would be registered as "ssh-ed25519"
    with pytest.raises(RuntimeError):
        svc.onboard_operator(run, etc=etc,
                             authorized_keys=["ssh-ed25519 AAAA"])


def test_a_corrupted_private_key_is_refused(tmp_path):
    """A key that cannot produce its public half is an error, never a pass.

    The adjacent .pub file is a hint, not a substitute: believing it would
    install a broken pair and accept it again on the next run.
    """
    from deploy import appliance_services as svc

    priv, pub = _keypair(tmp_path, "runner")
    priv.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\ncorrupted\n")
    etc = tmp_path / "etc"
    with pytest.raises(RuntimeError) as bad:
        svc.ensure_service_keys(lambda *a, **k: None, etc=etc,
                                sandboxed=True,
                                access_keys={"runner": str(pub)})
    assert "cannot be read" in str(bad.value)
    # nothing was installed
    assert not (etc / "secrets" / "worker_runner_key").exists()


def test_the_bastion_owns_its_service_token():
    """The bastion's credential is a secret in the bastion's OWN file.

    The unit no longer loads the controller's environment, so the token must
    come from a source the bastion can read — otherwise every callback to
    the API is refused and no member can authenticate.
    """
    from deploy import appliance as installer

    m = _fake_manifest()
    bastion = installer.render_bastion_env(m)
    assert "SR_BASTION_TOKEN_FILE" in bastion
    assert "SR_BASTION_TOKEN=" not in bastion
    # the proxy reads the file when the environment has no token
    from srplatform.bastion import proxy

    import os as _os
    import tempfile as _tempfile

    tmp = pathlib.Path(_tempfile.mkdtemp(prefix="sr-bastion-token-"))
    token_file = tmp / "bastion.token"
    token_file.write_text("svc-bastion-abc123\n")
    token_file.chmod(0o600)
    old = _os.environ.pop("SR_BASTION_TOKEN", None)
    _os.environ["SR_BASTION_TOKEN_FILE"] = str(token_file)
    try:
        headers = proxy._svc_headers()
    finally:
        _os.environ.pop("SR_BASTION_TOKEN_FILE", None)
        if old is not None:
            _os.environ["SR_BASTION_TOKEN"] = old
    assert headers.get("Authorization") == "Bearer svc-bastion-abc123"


def test_the_bastion_token_file_is_reachable_by_the_bastion(tmp_path):
    """Owning a file is not enough: the service must be able to TRAVERSE
    its directory and READ the file."""
    from deploy import appliance as installer
    from deploy import appliance_services as svc

    calls: list[tuple] = []

    def run(*args, **kwargs):
        calls.append(args)

    etc = tmp_path / "etc"
    out = svc.ensure_bastion_token_file(run, etc=etc, sandboxed=True)
    # it lives in the bastion's OWN directory, not under the shared secrets
    # directory (which srbastion may not traverse)
    assert out["path"] == str(etc / "ssh" / "bastion.token"), out
    assert installer.SSH_DIR_GROUP == "srbastion"
    assert installer.SSH_DIR_MODE & 0o010, "the group cannot traverse it"
    # 0640 root:srbastion: the service's group reads it
    assert out["mode"] == "0640"
    assert out["owner"] == "root:srbastion"
    assert ("chmod", "0640", str(etc / "ssh" / "bastion.token")) in calls
    # the shared secrets directory is NOT the bastion's
    assert installer.SECRET_DIR_GROUP != "srbastion"
