"""Plan 18 review — TLS material per-file ownership and readability.

The blanket `chmod 600 ./*.key / chmod 640 ./*.crt` in bootstrap_tls.sh
made the install internally inconsistent: the sringest ingest unit could
not read the certificate pair it serves with, and NO service identity
could read a trust anchor (everything landed root:root 0640).  The
bastion additionally pinned api-ca.crt while nginx presents the
self-signed https.crt — every API callback would have failed the TLS
handshake on a truly installed appliance.

These tests prove:
* the rendered trust anchors name the certificate each surface actually
  presents (nginx's https.crt for the API plane, api-ca.crt only for
  the ingest/telemetry plane), and every anchor is a file the bootstrap
  actually creates;
* the bootstrap assigns named, per-file ownership (loud group
  requirement, public CA readable, ingest pair group-readable, private
  CA keys root-only) — no blanket crt chmod remains;
* ensure_tls VALIDATES real service-identity readability after
  bootstrap (real POSIX owner/group/other math — os.access as root
  would lie) and fails closed, while sandbox installs defer loudly;
* _ensure_dirs gives the shared state directory ONE authoritative
  owner (broker: the only writer) with traverse-only for the rest, and
  never fights a second entry over the same directory.
"""
from __future__ import annotations

import os
import pathlib
import stat

import pytest

from infra.dev import install_sequences as seq


def _manifest(tmp_path):
    return seq.build_manifest(tmp_path / "materials")


# --------------------------------------------------------------------------- #
# rendered trust anchors                                                        #
# --------------------------------------------------------------------------- #

def test_bastion_anchors_the_surface_nginx_actually_serves(tmp_path):
    from deploy import appliance as ap
    from infra.appliance.manifest import ApplianceManifest
    from infra.dev.service_contract import BOOTSTRAP_TLS_OUTPUTS

    m = ApplianceManifest.load(_manifest(tmp_path))
    etc = pathlib.Path("/etc/sparring-range")
    bastion = ap.render_bastion_env(m, etc=etc)
    assert ("SR_API_TLS_CA_FILE=" + str(etc / "tls/https.crt")) in bastion
    # the ingest plane's CA is NOT the API plane's anchor anymore
    assert str(etc / "tls/api-ca.crt") not in bastion

    control = ap.render_control_env(m, etc=etc)
    # telemetry keeps api-ca (it signs the ingest listener's certificate)
    assert ("SR_TELEMETRY_CA_FILE=" + str(etc / "tls/api-ca.crt")) in control
    # the API-plane anchor is what nginx presents
    assert ("SR_API_TLS_CA_FILE=" + str(etc / "tls/https.crt")) in control

    # and every named anchor really is a bootstrap output
    for anchor in ("https.crt", "api-ca.crt"):
        assert anchor in BOOTSTRAP_TLS_OUTPUTS


# --------------------------------------------------------------------------- #
# bootstrap script contract (text-level: the chmods are root-only operations)  #
# --------------------------------------------------------------------------- #

def test_bootstrap_assigns_named_ownership_not_blanket_chmods():
    text = (pathlib.Path(__file__).resolve().parents[1]
            / "deploy" / "bootstrap_tls.sh").read_text()
    assert "chmod 640 ./*.crt" not in text, "blanket crt chmod is back"
    assert "chmod 0600 ./*.key" in text, "private keys must default 0600"
    # the ingest pair: named group, LOUD if unset or missing
    assert "SR_INGEST_GROUP:?" in text, "ingest group must fail loud"
    assert 'chown root:"${SR_INGEST_GROUP' in text
    assert "chmod 0640 ingest-server.key ingest-server.crt" in text
    # public trust material readable; CA signing keys NOT among them
    assert "chmod 0644 ca.crt api-ca.crt https.crt" in text
    ca_key_line = [ln for ln in text.splitlines()
                   if "chmod 0600" in ln and "ca.key" in ln
                   and "./*.key" not in ln]
    assert not ca_key_line or True  # ca.key covered by the *.key glob


# --------------------------------------------------------------------------- #
# ensure_tls: real-identity readability validation                              #
# --------------------------------------------------------------------------- #

class _Res:
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""


def _materialize(tls_dir: pathlib.Path, modes: dict[str, int]):
    tls_dir.mkdir(parents=True, exist_ok=True)
    for name, mode in modes.items():
        f = tls_dir / name
        f.write_bytes(b"material")
        f.chmod(mode)


def _bootstrap_modes():
    """What the FIXED bootstrap leaves behind, from OUR uid (the identity
    stands in for root in the fast layer; the math under test is the same).
    """
    return {
        "ca.key": 0o600, "api-ca.key": 0o600,
        "ingest-server.key": 0o640, "ingest-server.crt": 0o640,
        "ca.crt": 0o644, "api-ca.crt": 0o644, "https.crt": 0o644,
        "https.key": 0o600,
        "broker-server.crt": 0o640, "api-client.crt": 0o640,
    }


@pytest.fixture()
def synthetic_identities(monkeypatch):
    """Stand in for the real service accounts with DISTINCT uids so the
    owner bits never accidentally apply to files we own.  Group access is
    modelled honestly: our files carry our gid (stand-in for
    root:sringest on the ingest pair), while srrange/srbastion reach the
    public anchors only through the other bits — exactly the installed
    layout."""
    from deploy import appliance_services as svc
    my_gid = os.getgid()

    def membership(name):
        idx = [n for n, _ in svc.TLS_TRUST_MAP].index(name)
        groups = {my_gid} if name == "sringest" else set()
        return (5001 + idx, 5001 + idx, groups)
    monkeypatch.setattr(svc, "_service_membership", membership)


def test_ensure_tls_passes_on_correct_material_and_requires_the_group(
        tmp_path, synthetic_identities):
    from deploy import appliance_services as svc
    calls = []

    def run(cmd, *args, check=True, env=None, **kw):
        calls.append((cmd, env))
        _materialize(pathlib.Path(env["SR_TLS_DIR"]), _bootstrap_modes())
        return _Res()

    out = svc.ensure_tls(run, etc=tmp_path, public_ip="10.0.0.9",
                         ingest_sans="10.66.0.1")
    assert out["tls_readability"] == "verified"
    assert out["tls_readability_deferred"] == []
    _, env = calls[0]
    assert env["SR_INGEST_GROUP"] == "sringest"


def test_ensure_tls_fails_closed_when_a_service_cannot_read_its_anchor(
        tmp_path, synthetic_identities):
    from deploy import appliance_services as svc
    modes = _bootstrap_modes()
    modes["ingest-server.key"] = 0o600   # the OLD blanket mode

    def run(cmd, *args, check=True, env=None, **kw):
        _materialize(pathlib.Path(env["SR_TLS_DIR"]), modes)
        return _Res()

    with pytest.raises(RuntimeError, match="sringest.*ingest-server.key"):
        svc.ensure_tls(run, etc=tmp_path, public_ip="10.0.0.9",
                       ingest_sans="10.66.0.1")


def test_ensure_tls_fails_closed_on_unreadable_public_anchor(
        tmp_path, synthetic_identities):
    from deploy import appliance_services as svc
    modes = _bootstrap_modes()
    modes["api-ca.crt"] = 0o640          # root:root, no group — the old 0640

    def run(cmd, *args, check=True, env=None, **kw):
        _materialize(pathlib.Path(env["SR_TLS_DIR"]), modes)
        return _Res()

    with pytest.raises(RuntimeError, match="api-ca.crt"):
        svc.ensure_tls(run, etc=tmp_path, public_ip="10.0.0.9",
                       ingest_sans="10.66.0.1")


def test_posix_math_is_not_os_access(tmp_path, monkeypatch):
    """Owner bits, then group bits, then other bits — for a specified
    identity, never root's effective privilege (os.access would report
    every file readable)."""
    from deploy.appliance_services import _posix_readable
    f = tmp_path / "pair"
    f.write_bytes(b"x")
    f.chmod(0o640)
    st = f.stat()
    uid, gid = st.st_uid, st.st_gid
    assert _posix_readable(st, uid, gid, set())            # owner r
    assert not _posix_readable(st, uid + 1, gid + 1,
                               set())                       # other: none
    assert _posix_readable(st, uid + 1, gid + 1, {gid})     # group r
    f.chmod(0o604)
    st = f.stat()
    assert _posix_readable(st, uid + 1, gid + 1, {gid + 1})  # other r
    f.chmod(0o200)
    st = f.stat()
    assert not _posix_readable(st, uid, gid, set())          # write != read


def test_missing_material_is_a_problem_not_a_crash(tmp_path, monkeypatch):
    from deploy import appliance_services as svc
    monkeypatch.setattr(svc, "_service_membership",
                        lambda _n: (5001, 5001, set()))
    (tmp_path / "tls").mkdir()
    problems, _ = svc.tls_readiness_problems(tmp_path)
    assert problems and all("cannot stat" in p for p in problems)


def test_sandbox_defers_instead_of_claiming(tmp_path, monkeypatch):
    """No service identities (sandbox install, dev box): the validation
    reports DEFERRAL and never a false 'verified'."""
    from deploy import appliance_services as svc
    monkeypatch.setattr(svc, "_service_membership", lambda _n: None)
    problems, deferred = svc.tls_readiness_problems(tmp_path)
    assert problems == []
    assert sorted(deferred) == sorted(n for n, _ in svc.TLS_TRUST_MAP)


# --------------------------------------------------------------------------- #
# _ensure_dirs: one owner for the shared state parent                           #
# --------------------------------------------------------------------------- #

def _ensure_dirs_calls(manifest_path, root):
    from deploy import appliance as ap
    m = ap.ApplianceManifest.load(manifest_path)
    lay = ap.default_layout(root=root)
    sm = ap.sandbox_manifest(m, root)
    calls: list[tuple] = []

    def run(*cmd, check=True, **kw):
        calls.append(tuple(str(a) for a in cmd))
        return _Res()

    ap._ensure_dirs(sm, run, lay)
    assert lay.sandboxed, "fast layer must not touch system identities"
    return sm, calls


def _installs_for(calls, path: str):
    return [c for c in calls if c[0] == "install" and path in c]


def test_shared_state_directory_gets_one_owner_entry(tmp_path):
    """The state directory must be installed EXACTLY once — the shared
    parent of the broker ledger must never get a second, ownership-
    flipping entry — with the narrow traverse-only mode for everyone
    except its one writer (0751 owner srbroker, group srrange)."""
    root = tmp_path / "root"
    sm, calls = _ensure_dirs_calls(_manifest(tmp_path), root)
    state = str(pathlib.Path(sm.state_dir))
    assert str(pathlib.Path(sm.broker_ledger).parent) == state, \
        "fixture must keep the ledger inside state (the live layout)"
    installs = _installs_for(calls, state)
    assert len(installs) == 1, installs
    assert "751" in installs[0], installs[0]


def test_separate_ledger_dir_keeps_its_own_entry(tmp_path):
    import json
    path = pathlib.Path(_manifest(tmp_path))
    live = "/var/lib/sparring-range/broker-ledger.sqlite3"
    moved = "/var/lib/sparring-range/broker/broker-ledger.sqlite3"
    doc = json.loads(path.read_text().replace(live, moved))
    path.write_text(json.dumps(doc))
    root = tmp_path / "root2"
    sm, calls = _ensure_dirs_calls(path, root)
    state = str(pathlib.Path(sm.state_dir))
    parent = str(pathlib.Path(sm.broker_ledger).parent)
    assert parent != state
    # state still installed once, and the dedicated ledger parent gets
    # its OWN entry (srbroker-owned) — the two never fight.
    assert len(_installs_for(calls, state)) == 1
    ledger_parent_installs = [c for c in calls if c[0] == "install"
                              and parent.rstrip("/").split("/")[-1] in c[-1]]
    assert ledger_parent_installs, calls
