"""M01-R1 regressions: the browser E2E build is RUN-OWNED, never shared.

Pure-logic checks on the browser fixture's dist-dir selection and lifecycle
— no browser, npm or network is invoked (build/serve are mocked), and the
module-level WEB is redirected to a temp dir, so the real web/ tree is
never written. Fast layer by design: these must run on every push, not
only in the browser gate.
"""
from __future__ import annotations

import subprocess

import pytest

import tests.test_stage5_browser_e2e as m


@pytest.fixture()
def fake_web(tmp_path, monkeypatch):
    """A stand-in web/ project: node_modules present, builds land in tmp."""
    web = tmp_path / "web"
    (web / "node_modules" / ".bin").mkdir(parents=True)
    (web / "node_modules" / ".bin" / "next").write_text("#!/bin/sh\n")
    monkeypatch.setattr(m, "WEB", web)
    return web


def test_run_dist_dirs_are_unique_per_call(fake_web):
    a = m._run_dist_dir(".e2e-builds")
    b = m._run_dist_dir(".e2e-builds")
    assert a != b, "two fixture calls shared one build directory"
    assert a.parent == b.parent == fake_web / ".e2e-builds"
    assert a.is_dir() and b.is_dir()


@pytest.mark.parametrize("bad", [
    "",                                  # empty
    "/abs/path/build",                   # absolute (next would treat as relative)
    "../outside",                        # escapes web/
    ".next",                             # the developer's build
    ".next-e2e",                         # the old shared e2e dir
    "node_modules", ".git", "pages",     # project directories
    ".next/leaf",                        # inside the developer's build
])
def test_unsafe_dist_overrides_rejected(fake_web, bad, monkeypatch):
    monkeypatch.delenv("SR_E2E_DIST_DIR", raising=False)
    with pytest.raises(pytest.fail.Exception):
        m._run_dist_dir(bad)
    monkeypatch.setenv("SR_E2E_DIST_DIR", bad)
    with pytest.raises(pytest.fail.Exception):
        m._run_dist_dir()  # the env override itself is rejected


def test_default_base_is_build_only(fake_web, monkeypatch):
    monkeypatch.delenv("SR_E2E_DIST_DIR", raising=False)
    d = m._run_dist_dir()
    try:
        assert d != fake_web / ".next"
        assert (fake_web / ".e2e-builds") in d.parents
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


class _FakeProc:
    terminated = False

    def terminate(self):
        type(self).terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def _drive_fixture(monkeypatch, fake_web, build_envs, *, build_fails=False):
    """Run the real fixture generator with npm/next/httpx mocked.

    Yields the fixture's proc; StopIteration means teardown completed.
    """
    _FakeProc.terminated = False

    def fake_run(cmd, **kw):
        build_envs.append(kw["env"]["SR_NEXT_DIST_DIR"])
        if build_fails:
            raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0)

    class _Resp:
        status_code = 200

    import httpx
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m.subprocess, "Popen",
                        lambda cmd, **kw: _FakeProc())
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp())
    gen = m.web_app.__wrapped__({"api": 8001, "web": 3001}, None)
    return gen


def test_fixture_builds_fresh_relative_and_cleans_up(monkeypatch, fake_web):
    builds: list[str] = []
    gen = _drive_fixture(monkeypatch, fake_web, builds)
    proc = next(gen)
    assert proc is not None
    assert len(builds) == 1
    dist_rel = builds[0]
    assert not dist_rel.startswith("/"), "next was handed an absolute distDir"
    dist = fake_web / dist_rel
    assert dist.is_dir(), "run-owned build dir missing while served"
    with pytest.raises(StopIteration):
        next(gen)  # teardown
    assert not dist.exists(), "run-owned build dir survived teardown"
    assert _FakeProc.terminated, "next server was not terminated"


def test_fixture_never_reuses_another_runs_build(monkeypatch, fake_web):
    builds: list[str] = []
    gen1 = _drive_fixture(monkeypatch, fake_web, builds)
    next(gen1)
    first = fake_web / builds[0]
    # first run still serving; a second fixture call starts concurrently
    gen2 = _drive_fixture(monkeypatch, fake_web, builds)
    next(gen2)
    second = fake_web / builds[1]
    assert first != second, "concurrent fixture calls shared one build dir"
    assert first.is_dir() and second.is_dir()
    with pytest.raises(StopIteration):
        next(gen1)
    with pytest.raises(StopIteration):
        next(gen2)
    assert not first.exists() and not second.exists()


def test_build_failure_cleans_the_run_dir(monkeypatch, fake_web):
    builds: list[str] = []
    gen = _drive_fixture(monkeypatch, fake_web, builds, build_fails=True)
    with pytest.raises(subprocess.CalledProcessError):
        next(gen)
    assert len(builds) == 1
    base = (fake_web / builds[0]).parent
    leftovers = [p for p in base.iterdir()] if base.exists() else []
    assert not leftovers, f"failed build left {leftovers} behind"
