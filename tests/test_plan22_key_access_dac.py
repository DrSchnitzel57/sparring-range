"""Plan 22 LIVE-01 (practice layer): the named-ACL credential grant under
REAL kernel DAC across distinct UIDs.

The codec's unit tests (tests/test_plan22_posixacl.py) cannot prove the
thing that actually matters — that the kernel ENFORCES the bytes and that
the API identity alone reads the operator's root-owned 0600 credential
while every other service identity is still refused. This file runs the
real provisioning entry point inside an unprivileged user namespace with
FOUR mapped UIDs (root = the installer, plus API, ingest and worker
stand-ins) and asserts the live DAC decisions by forking and reading.

Prerequisites: unprivileged user namespaces and a subuid/subgid range (the
same ones the containment lane already relies on). Required mode
(SR_REQUIRE_PRACTICE=1) fails instead of skipping.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

pytestmark = pytest.mark.practice

HERE = pathlib.Path(__file__).resolve()
SECRET = b"sk-THE-OPERATORS-MODEL-CREDENTIAL\n"


def _namespace_prereq() -> str | None:
    """Why the namespace fixture cannot run, or None when it can."""
    import shutil

    if shutil.which("unshare") is None:
        return "the unshare binary is absent"
    ranges = pathlib.Path("/etc/subuid")
    me = None
    if ranges.is_file():
        import getpass
        for line in ranges.read_text().splitlines():
            if line.split(":", 1)[0] == getpass.getuser():
                me = line
                break
    if me is None:
        return f"no subuid range for {getpass.getuser()!r} in /etc/subuid"
    r = subprocess.run(
        ["unshare", "--user",
         f"--map-users=0:{os.getuid()}:1", "--map-users=1:10000:3",
         f"--map-groups=0:{os.getgid()}:1", "--map-groups=1:10000:3",
         "true"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return ("multi-UID user namespaces refused: "
                f"{(r.stderr or r.stdout).strip()[:200]}")
    return None


def _run_in_namespace(stage: pathlib.Path) -> str:
    """Run this file's helper as namespace root over the prepared stage."""
    import getpass

    sub = None
    for line in pathlib.Path("/etc/subuid").read_text().splitlines():
        if line.split(":", 1)[0] == getpass.getuser():
            sub = int(line.split(":")[1])
            break
    assert sub is not None
    cmd = ["unshare", "--user",
           f"--map-users=0:{os.getuid()}:1", f"--map-users=1:{sub}:3",
           f"--map-groups=0:{os.getgid()}:1", f"--map-groups=1:{sub}:4",
           sys.executable, "-Bu", str(HERE), str(stage)]
    env = {**os.environ, "SR_DAC_HELPER": "1",
           "PYTHONPATH": str(HERE.parents[1])}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                       env=env)
    assert r.returncode == 0, (
        f"namespace helper exit {r.returncode}\n"
        f"--- stdout ---\n{r.stdout[-3000:]}\n--- stderr ---\n{r.stderr[-2000:]}")
    return r.stdout


def test_named_acl_grants_only_the_api_identity(tmp_path):
    reason = _namespace_prereq()
    if reason:
        msg = f"namespace DAC fixture unavailable: {reason}"
        if os.environ.get("SR_REQUIRE_PRACTICE") == "1":
            pytest.fail(msg)
        pytest.skip(msg)

    stage = tmp_path / "stage"
    secrets = stage / "secrets"
    secrets.mkdir(parents=True)
    # the pytest tmp tree is 0700 all the way up; the production path
    # (/etc/sparring-range/secrets) is traversable, and the DAC assertions
    # below are about the SECRETS objects, so open the fixture ancestors
    # for traversal only (never for listing)
    p = tmp_path
    while str(p) != "/tmp" and len(p.parts) > 1:
        p.chmod(0o711)
        p = p.parent
    stage.chmod(0o755)
    key = secrets / "model.key"
    key.write_bytes(SECRET)
    key.chmod(0o600)
    secrets.chmod(0o750)

    out = _run_in_namespace(stage)
    # every claim comes from a REAL read attempt by a REAL uid
    assert "API-READ-OK" in out, out
    assert "INGEST-READ-DENIED" in out, out
    assert "WORKER-READ-DENIED" in out, out
    assert "WITHOUT-DIR-GRANT-DENIED" in out, out
    assert "IDEMPOTENT-OK" in out, out
    assert "AFTER-DRIFT-REPAIR-OK" in out, out
    assert "BYTES-KEPT owner-kept" in out, out
    assert "AFTER-ACL-REMOVAL-DENIED" in out, out


def _helper_main(stage: pathlib.Path) -> None:
    """Executed as namespace root (== the invoking host user)."""
    import pwd

    from deploy import appliance_services as svc
    from deploy import posixacl

    secrets = stage / "secrets"
    key = secrets / "model.key"
    API, INGEST, WORKER = 1, 2, 3
    # production shape: root-owned, and an owning group NO service identity
    # belongs to (the host's own group would be an inherited supplementary
    # group inside the namespace and would leak group-class access)
    os.chown(secrets, 0, 4)
    os.chown(key, 0, 4)

    class _Pw:
        pw_uid = API

    def fake_getpwnam(name):
        assert name == "srrange"
        return _Pw()

    pwd.getpwnam = fake_getpwnam  # the ns has no appliance users; the uid is the point
    run = lambda *a, **k: subprocess.CompletedProcess(a, 0, "", "")  # noqa: E731
    action = svc.ensure_model_key_access(run, key_file=key,
                                         secrets_dir=secrets)
    assert action["uid"] == API and action["mode"] == "named-posix-acl"

    def read_as(uid: int) -> tuple[bool, str]:
        pid = os.fork()
        if pid == 0:
            try:
                os.setgid(uid)
                os.setuid(uid)
                data = key.read_bytes()
                os._exit(0 if data == SECRET else 2)
            except PermissionError:
                os._exit(3)
            except OSError:
                os._exit(4)
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        return code == 0, {0: "OK", 2: "WRONG-BYTES", 3: "DENIED"}.get(
            code, f"ERR-{code}")

    ok, how = read_as(API)
    print(f"API-READ-{how}")
    ok, how = read_as(INGEST)
    print(f"INGEST-READ-{how}")
    ok, how = read_as(WORKER)
    print(f"WORKER-READ-{how}")

    # the directory traverse is load-bearing: with the file grant but no
    # directory grant, even the API uid cannot reach the file
    dir_acl = posixacl.get_acl(secrets)
    posixacl.set_acl(secrets, [(t, p, i) for t, p, i in dir_acl
                               if not (t == posixacl._USER and i == API)])
    ok, how = read_as(API)
    print(f"WITHOUT-DIR-GRANT-{how}")
    posixacl.set_acl(secrets, dir_acl)          # restore

    # idempotence at the byte level
    before = os.getxattr(str(key), posixacl.XATTR_NAME)
    svc.ensure_model_key_access(run, key_file=key, secrets_dir=secrets)
    if os.getxattr(str(key), posixacl.XATTR_NAME) == before:
        print("IDEMPOTENT-OK")

    # operator drift: hand-removing the grant is REPAIRED by the next run
    os.removexattr(str(key), posixacl.XATTR_NAME)
    ok, how = read_as(API)
    assert not ok, "the file ACL alone must gate the file"
    svc.ensure_model_key_access(run, key_file=key, secrets_dir=secrets)
    ok, how = read_as(API)
    if ok:
        print("AFTER-DRIFT-REPAIR-OK")

    st = key.stat()
    if key.read_bytes() == SECRET and st.st_uid == 0 \
            and st.st_mode & 0o700 == 0o600:
        print("BYTES-KEPT owner-kept")

    # removing the ACL returns to the strict 0600 root-only default
    os.removexattr(str(key), posixacl.XATTR_NAME)
    os.removexattr(str(secrets), posixacl.XATTR_NAME)
    ok, how = read_as(API)
    print(f"AFTER-ACL-REMOVAL-{how}")


if os.environ.get("SR_DAC_HELPER") == "1":
    _helper_main(pathlib.Path(sys.argv[1]))
    sys.exit(0)
