"""Plan 18 review — private staging, never shared-temp trust (fast layer).

Two hazards the reviewer found, both in code that runs AS ROOT during
installation or as the operator's CLI:

* ``ensure_node_runtime`` fetched the Node tarball to the PREDICTABLE
  ``/tmp/node-v<VERSION>-linux-x64.tar.xz`` before verifying it — a
  planted symlink or a colliding download from another application was
  what root wrote through and hashed.  Provisioning now stages in a
  private, owned, unguessable ``mkdtemp`` directory (0700) that is
  removed whatever happens, and never touches a shared path.
* ``rangectl db`` cached its alembic config at the predictable
  ``$TMPDIR/sr-alembic-<digest>.ini`` and REUSED whatever sat there —
  trusting pre-existing content planted by another local user.  The
  config is now a fresh 0600 ``mkstemp`` file owned by the invocation
  and removed when the alembic run ends.
"""
from __future__ import annotations

import os
import pathlib
import stat
import tempfile

import pytest

_ISDIR = os.path.isdir  # captured BEFORE tests patch os.path.isdir


# --------------------------------------------------------------------------- #
# node runtime: private staging                                                #
# --------------------------------------------------------------------------- #

class _Res:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


def _node_run_recorder(monkeypatch, tmp_path, *, digest_ok: bool):
    from deploy import appliance_services as svc

    calls: list[tuple] = []
    staged: dict[str, str] = {}

    def run(cmd, *args, check=True, **kw):
        calls.append((cmd, *args))
        if cmd == "curl":
            out = args[args.index("-o") + 1]
            d = os.path.dirname(out)
            # the staging dir must exist and be private BEFORE the download
            assert _ISDIR(d), "staging dir missing at download time"
            mode = stat.S_IMODE(os.stat(d).st_mode)
            assert mode == 0o700, f"staging dir mode {mode:o}"
            staged["dir"] = d
            staged["tarball"] = out
            pathlib.Path(out).write_bytes(b"tarball-bytes")
        elif cmd == "sha256sum":
            target = args[0]
            assert "tarball-bytes" in pathlib.Path(target).read_bytes().decode()
            good = svc.NODE_PIN_SHA256_LINUX_X64
            return _Res((good if digest_ok else "b" * 64) + " x\n")
        elif cmd == "tar":
            staged["tar"] = args[args.index("-xJf") + 1]
        return _Res()

    monkeypatch.setattr(os.path, "isdir",
                        lambda p: not str(p).startswith("/usr/local/lib"))
    monkeypatch.setattr(svc, "_node_version", lambda: svc.NODE_MIN_VERSION)
    real_mkdtemp = tempfile.mkdtemp

    def mkdtemp(**kw):
        return real_mkdtemp(dir=str(tmp_path), **kw)
    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    return run, calls, staged


def test_node_provision_stages_privately_and_cleans_up(monkeypatch, tmp_path):
    from deploy import appliance_services as svc
    run, calls, staged = _node_run_recorder(monkeypatch, tmp_path,
                                            digest_ok=True)
    out = svc.ensure_node_runtime(run, mode="provision")
    assert out["node"] == "provisioned"
    curl = next(c for c in calls if c[0] == "curl")
    target = curl[curl.index("-o") + 1]
    # NOT the old predictable shared path, and inside the private dir
    assert target != f"/tmp/node-v{svc.NODE_PIN_VERSION}-linux-x64.tar.xz"
    assert target.startswith(str(tmp_path))
    assert staged["tar"] == target          # tar read exactly what we staged
    # cleanup: the staging directory is gone after success
    assert not _ISDIR(staged["dir"])
    # and nothing was ever asked to rm a shared node path
    assert not any(c[0] == "rm" and "/tmp/node-" in " ".join(map(str, c))
                   for c in calls)


def test_node_integrity_failure_still_cleans_staging(monkeypatch, tmp_path):
    from deploy import appliance_services as svc
    run, calls, staged = _node_run_recorder(monkeypatch, tmp_path,
                                            digest_ok=False)
    with pytest.raises(RuntimeError, match="integrity"):
        svc.ensure_node_runtime(run, mode="provision")
    assert not _ISDIR(staged["dir"])
    assert not any(c[0] == "tar" for c in calls), \
        "unverified archive must never be extracted"


# --------------------------------------------------------------------------- #
# rangectl db: owned per-invocation config                                     #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def tmpdir_env(monkeypatch, tmp_path):
    (tmp_path / "tmp").mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    # gettempdir() caches: force it to re-read TMPDIR
    monkeypatch.setattr(tempfile, "tempdir", None, raising=False)
    return tmp_path / "tmp"


def _old_cache_path(db, root, tmpdir_env):
    import hashlib
    migrations = db._migrations_dir(root)
    digest = hashlib.sha256(str(migrations).encode()).hexdigest()[:12]
    return tmpdir_env / f"sr-alembic-{digest}.ini"


def test_alembic_config_never_reuses_planted_shared_content(tmpdir_env):
    from rangectl.commands import db
    root = db._alembic_root()
    # plant hostile content where the OLD cache would have lived
    old_path = _old_cache_path(db, root, tmpdir_env)
    old_path.write_text("[alembic]\nscript_location = /attacker/migrations\n")

    with db._alembic_config_path(root) as cfg:
        assert cfg != str(old_path)
        text = pathlib.Path(cfg).read_text()
        assert "/attacker" not in text
        assert "script_location" in text
        mode = stat.S_IMODE(os.stat(cfg).st_mode)
        assert mode == 0o600, f"config mode {mode:o}"
        # the planted file is untouched — we neither read nor replaced it
        assert "attacker" in old_path.read_text()
    assert not pathlib.Path(cfg).exists(), "private config must not outlive"
    # repeated invocations each get their own fresh file
    with db._alembic_config_path(root) as c1:
        pass
    with db._alembic_config_path(root) as c2:
        pass
    assert c1 != c2


def test_alembic_config_ignores_symlink_at_old_path(tmpdir_env):
    from rangectl.commands import db
    root = db._alembic_root()
    victim = tmpdir_env / "victim"
    victim.write_text("someone else's file")
    link = _old_cache_path(db, root, tmpdir_env)
    link.symlink_to(victim)
    with db._alembic_config_path(root):
        pass
    assert link.is_symlink()
    assert victim.read_text() == "someone else's file"
