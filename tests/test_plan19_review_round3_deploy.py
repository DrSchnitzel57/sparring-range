"""Plan 19 review ROUND 3, finding 6 (fast half): the credential-store
file is an OS-level API-only secret — distinct service identities, an
atomically restrictive create with fail-closed verification, and exact
POSIX readability math that NO service identity (not even the API's own
user) can open the file. This is the deployment CONTRACT proof; the
installed-OS qualification (real uid switch on a real appliance) stays
an operator gate and is never claimed here.
"""
from __future__ import annotations

import os
import pathlib
import stat

import pytest

from deploy import appliance_services as svc
from infra.dev.service_contract import secret_file_boundary_problems

ROOT = pathlib.Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy" / "systemd"


# --------------------------------------------------------------------------- #
# identities: one OS user per service, the API alone is srrange                #
# --------------------------------------------------------------------------- #

def _unit_users() -> dict[str, dict[str, list[str]]]:
    out: dict[str, dict[str, list[str]]] = {}
    for unit in sorted(UNITS.glob("*.service")):
        fields = {"User": [], "Group": [], "EnvironmentFile": []}
        for line in unit.read_text().splitlines():
            line = line.strip()
            for f in fields:
                if line.startswith(f + "="):
                    fields[f].append(line.split("=", 1)[1].strip())
        out[unit.name] = fields
    return out


def test_no_two_installed_units_share_an_os_identity():
    """Same uid = readable /proc/<pid>/environ, ptrace, and every file
    that identity's group can open. An EnvironmentFile is NOT an access
    control between processes that share an identity — this is the
    boundary that let the ingest listener read the API's credential
    store, and it is now forbidden STRUCTURALLY for every shipped unit."""
    users = {}
    for name, fields in _unit_users().items():
        for user in fields["User"]:
            assert user not in users, \
                f"{name} and {users[user]} share the identity {user}"
            users[user] = name
    assert "sr-api.service" in _unit_users()
    api_user = _unit_users()["sr-api.service"]["User"][0]
    ing = _unit_users()["sr-api-ingest.service"]["User"][0]
    assert ing != api_user, "ingest shares the API identity — finding 6"
    assert ing == "sringest"


def test_only_the_api_unit_references_the_credential_store_file():
    for name, fields in _unit_users().items():
        loads = any("db-secret.env" in f for f in fields["EnvironmentFile"])
        if name == "sr-api.service":
            assert loads
        else:
            assert not loads, f"{name} loads the credential-store file"


def test_installer_creates_the_ingest_identity_and_gives_it_its_own_key():
    inst = (ROOT / "deploy" / "install.sh").read_text()
    assert "sringest" in inst.split("SR_ALL_USERS=")[1].splitlines()[0], \
        "the installer never creates the sringest identity"
    tls_map = inst.split("declare -A TLS_KEY_GROUPS=(")[1]
    ingest_line = [ln for ln in tls_map.splitlines()
                   if "ingest-server.key" in ln][0]
    assert "=sringest" in ingest_line, ingest_line
    assert "chown root:sringest \"$ETC/ingest-listener.env\"" in inst


# --------------------------------------------------------------------------- #
# provisioning: atomic, restrictive, fail closed                               #
# --------------------------------------------------------------------------- #

def test_secret_file_is_created_restrictive_from_the_first_byte(tmp_path):
    f = tmp_path / "db-secret.env"
    svc._write_secret_file_securely(f, "SR_PG_SECRET_URL=x\n")
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    # no temporary plaintext is left behind
    assert list(tmp_path.glob("*.tmp.*")) == []
    with pytest.raises(RuntimeError):
        svc._write_secret_file_securely(f, "second\n")  # O_EXCL never
                                                        # silently replaces
    assert f.read_text() == "SR_PG_SECRET_URL=x\n"


def test_verification_fails_closed_when_the_file_cannot_be_secured(
        tmp_path, monkeypatch):
    f = tmp_path / "db-secret.env"
    f.write_text("x")
    f.chmod(0o644)                      # the legacy group-readable shape
    monkeypatch.setattr(os, "chmod",
                        lambda *a, **k: (_ for _ in ()).throw(
                            OSError("read-only")))
    with pytest.raises((RuntimeError, OSError)):
        svc._verify_secret_file(f, sandboxed=True)


def test_boundary_math_no_identity_can_read_and_a_loose_file_is_caught(
        tmp_path):
    good = tmp_path / "good"
    good.mkdir()
    (good / "db-secret.env").write_text("SR_PG_SECRET_URL=x\n")
    (good / "db-secret.env").chmod(0o600)
    assert secret_file_boundary_problems(good) == []
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "db-secret.env").write_text("SR_PG_SECRET_URL=x\n")
    (bad / "db-secret.env").chmod(0o640)   # the OLD 0640 root:srrange
    problems = secret_file_boundary_problems(bad)
    assert problems, "a group-readable credential store must be a finding"
    assert any("0600" in p for p in problems)
    missing = secret_file_boundary_problems(tmp_path / "none",
                                            require=True)
    assert missing, "an unprovisioned credential store must be reported"


def test_posix_math_uses_exact_access_semantics_for_service_uids(tmp_path):
    """The math, not os.access (which lies about every file as root):
    a 0600 file is unreadable by every uid/gid that is not the owner's,
    including any group membership; the exact POSIX ordering is applied.
    The probe uids are derived from the file's ACTUAL owner so the same
    assertions hold unprivileged (dev box) and as root (CI runner) —
    a literal uid 0 would silently be the owner when running as root."""
    f = tmp_path / "db-secret.env"
    f.write_text("x")
    f.chmod(0o600)
    st = f.stat()
    foreign_root = 0 if st.st_uid != 0 else 1001  # never the owner
    for uid, gid, groups in ((1001, 1001, {100, 101}),
                             (foreign_root, 100, {0}),   # wrong-uid root-group
                             (st.st_gid + 900, 5, {5})):
        assert not svc._posix_readable(st, uid, gid, groups)
    assert svc._posix_readable(st, st.st_uid, st.st_gid, set())
    # and the SAME math proves the OLD shape leaked to the group:
    old = tmp_path / "old"
    old.write_text("x")
    old.chmod(0o640)
    st_old = old.stat()
    assert svc._posix_readable(
        st_old, 999 if st_old.st_uid != 999 else 998,
        st_old.st_gid, set()) is True


# --------------------------------------------------------------------------- #
# appliance rendering: the installed ingest unit is its own identity           #
# --------------------------------------------------------------------------- #

def test_appliance_ingest_unit_is_a_separate_identity():
    from deploy.appliance import render_ingest_unit
    from tests.test_appliance_service_contract import _fake_manifest
    m = _fake_manifest()
    text = render_ingest_unit(m)
    assert "User=sringest" in text and "User=srrange" not in text
