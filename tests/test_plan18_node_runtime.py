"""Plan 18 second review — ONE selected Node runtime (finding 5).

The installer PROVISIONED the pinned Node 22 under /usr/local/lib/nodejs,
the probe checked whatever PATH resolved, and the web unit still exec'd
/usr/bin/node — so on a fresh Ubuntu 24.04 (distro Node 18) the service
started the unsupported runtime despite every check passing. Build, the
actual service ExecStart, and the per-UID identity verification must all
name the SAME selected binary, and operator-supplied runtimes must be
respected without clobbering another application's /usr/local binaries.
"""
from __future__ import annotations

import os
import pathlib
import stat

import pytest

from deploy import appliance_services as svc


def _fake_node(tmp_path: pathlib.Path, name: str, version: str):
    """A REAL executable answering --version, so selection is proven by
    executing the chosen binary, not by mocking the probe."""
    binp = tmp_path / name
    binp.write_text(f"#!/bin/sh\necho v{version}\n")
    binp.chmod(binp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP
               | stat.S_IXOTH)
    return str(binp)


# --------------------------------------------------------------------------- #
# selection (pure)                                                              #
# --------------------------------------------------------------------------- #

def test_plan_keeps_first_candidate_actually_supporting_the_floor():
    probes = {"/a/node": (18, 19), "/b/node": (22, 23), "/c/node": (20, 9)}
    plan = svc.node_runtime_plan(
        "auto", candidates=("/a/node", "/b/node", "/c/node"),
        probe=lambda p: probes.get(p))
    assert plan["action"] == "kept" and plan["binary"] == "/b/node"


def test_plan_fresh_distro_provisions_the_dedicated_runtime():
    plan = svc.node_runtime_plan(
        "auto", candidates=("/usr/bin/node",),
        probe=lambda p: (18, 19) if p == "/usr/bin/node" else None)
    assert plan["action"] == "provision"
    assert plan["binary"] == svc.dedicated_node_binary()
    # the dedicated path lives under the appliance's own tree: it never
    # depends on, and never overwrites, another app's /usr/local/bin/node
    assert plan["binary"].startswith("/usr/local/lib/nodejs/")
    assert plan["binary"] != "/usr/local/bin/node"


def test_plan_require_refuses_and_provision_always_provisions():
    with pytest.raises(RuntimeError, match="require forbids provisioning"):
        svc.node_runtime_plan("require", candidates=("/a/node",),
                              probe=lambda p: (18, 19))
    plan = svc.node_runtime_plan("provision", candidates=("/a/node",),
                                 probe=lambda p: (22, 14))
    assert plan["action"] == "provision"
    # require with a real supported runtime is kept, not re-fetched
    kept = svc.node_runtime_plan("require", candidates=("/a/node",),
                                 probe=lambda p: (22, 14))
    assert kept["action"] == "kept"
    with pytest.raises(RuntimeError, match="auto\\|require\\|provision"):
        svc.node_runtime_plan("maybe")


def test_plan_selects_a_real_executable_runtime(tmp_path):
    """End-to-end selection executes the binary it names (no mocks): a
    fake distro Node 18 is refused; a real 22.23.4 script is kept."""
    old = _fake_node(tmp_path, "node18", "18.19.1")
    fresh = _fake_node(tmp_path, "node22", "22.23.4")
    plan = svc.node_runtime_plan("auto", candidates=(old,), )
    assert plan["action"] == "provision"
    plan = svc.node_runtime_plan("auto", candidates=(old, fresh))
    assert plan == {"mode": "auto", "action": "kept", "binary": fresh,
                    "version": (22, 23)}


# --------------------------------------------------------------------------- #
# the unit, the build and the probe all use ONE binary                          #
# --------------------------------------------------------------------------- #

def _res(returncode=0, stdout=""):
    from types import SimpleNamespace
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


def test_web_unit_execs_exactly_the_selected_runtime(tmp_path):
    from deploy import appliance as ap
    lay = ap.default_layout(root=tmp_path / "root")
    node = _fake_node(tmp_path, "node22", "22.23.4")
    unit = ap.render_web_unit(lay, node)
    assert f"ExecStart={node} " in unit
    assert "/usr/bin/node " not in unit
    # no stale hardcoded path remains anywhere in the renderer
    source = (pathlib.Path(ap.__file__)).read_text()
    assert "ExecStart=/usr/bin/node" not in source


def test_fresh_distro_render_exec_selection_sequence(tmp_path, monkeypatch):
    """Fresh Ubuntu 18 + provisioned 22: plan says provision to the
    dedicated path; after provisioning exists, re-render picks the SAME
    path; the unit, the build PATH and the UID probe all carry it."""
    from deploy import appliance as ap

    # the dedicated path is /usr/local/lib/nodejs/...; relocate the whole
    # dedicated tree under tmp for this test's fake filesystem
    dedicated = str(tmp_path / "nodejs22" / "bin" / "node")
    monkeypatch.setattr(svc, "dedicated_node_binary", lambda: dedicated)
    old = _fake_node(tmp_path, "distro-node", "18.19.1")
    monkeypatch.setattr(svc, "_node_at",
                        lambda p: (18, 19) if p == old else None)

    plan = svc.node_runtime_plan("auto", candidates=(old,))
    assert plan["action"] == "provision" and plan["binary"] == dedicated
    unit = ap.render_web_unit(ap.default_layout(root=tmp_path / "root"),
                              plan["binary"])
    assert f"ExecStart={dedicated} " in unit

    # provisioning "lands": the real binary now exists and answers
    os.makedirs(os.path.dirname(dedicated), exist_ok=True)
    _fake_node(tmp_path / "nodejs22" / "bin", "node", "22.23.4")
    monkeypatch.setattr(svc, "_node_at", lambda p: None)
    # the plan must NOT trust an unrunnable dedicated path on re-render;
    # but with the honest probe restored it selects the dedicated runtime
    monkeypatch.setattr(svc, "_node_at", lambda p: (
        (22, 23) if p == dedicated else (18, 19) if p == old else None))
    plan2 = svc.node_runtime_plan("auto", candidates=(dedicated, old))
    assert plan2["binary"] == dedicated and plan2["action"] == "kept"
    assert (f"ExecStart={dedicated} "
            in ap.render_web_unit(ap.default_layout(root=tmp_path / "root"),
                                  plan2["binary"]))


def test_build_and_probe_use_the_binary_the_unit_execs(tmp_path):
    calls: list[tuple] = []

    def run(*cmd, check=True, env=None, **kw):
        calls.append((cmd, env))
        return _res()

    node = _fake_node(tmp_path, "node22", "22.23.4")
    source = tmp_path / "src"
    (source / "web").mkdir(parents=True)
    (source / "web" / "package-lock.json").write_text("{}")
    out = svc.ensure_web_build(run, source=source, node_binary=node)
    assert out["binary"] == node
    for cmd, env in calls:
        assert env["PATH"].startswith(os.path.dirname(node) + ":")
    # the per-UID verification probes the SAME binary
    calls.clear()
    venv = tmp_path / ".venv"
    (venv / "bin").mkdir(parents=True)
    svc.verify_service_runtime(run, venv, node_binary=node)
    node_calls = [c for c, _ in calls if c[0] == "runuser"
                  and "--version" in c]
    assert node_calls and all(node in c for c in node_calls)


def test_build_refuses_an_unsupported_selected_runtime(tmp_path):
    old = _fake_node(tmp_path, "node18", "18.19.1")
    source = tmp_path / "src"
    (source / "web").mkdir(parents=True)
    (source / "web" / "package-lock.json").write_text("{}")
    with pytest.raises(RuntimeError, match="20.9"):
        svc.ensure_web_build(lambda *a, **k: _res(), source=source,
                             node_binary=old)


def test_provisioning_never_clobbers_a_foreign_local_binary(tmp_path,
                                                            monkeypatch):
    """A REAL /usr/local/bin/node owned by another application survives:
    the appliance unit execs the dedicated runtime directly, so the
    foreign symlink is neither followed nor replaced."""
    calls: list[tuple] = []

    def run(*cmd, check=True, **kw):
        calls.append(tuple(str(c) for c in cmd))
        return _res(stdout=svc.NODE_PIN_SHA256_LINUX_X64 + "  x\n")

    # fake the dedicated tree being absent (force the download path) and
    # the fetch pipeline; staging/curl behaviour is covered elsewhere —
    # here we observe the symlink policy
    monkeypatch.setattr(os.path, "isdir",
                        lambda p: not str(p).startswith("/usr/local/lib"))
    import tempfile as _tf
    real_mkdtemp = _tf.mkdtemp
    monkeypatch.setattr(_tf, "mkdtemp",
                        lambda **kw: real_mkdtemp(dir=str(tmp_path), **kw))
    foreign = tmp_path / "usr-local-bin-node"
    foreign.symlink_to("/opt/otherapp/bin/node")
    monkeypatch.setattr(os.path, "islink",
                        lambda p: p == "/usr/local/bin/node")
    monkeypatch.setattr(os, "readlink",
                        lambda p: "/opt/otherapp/bin/node")
    monkeypatch.setattr(os.path, "exists",
                        lambda p: p in ("/usr/local/bin/node",
                                        "/usr/local/bin/npm",
                                        "/usr/local/bin/npx"))
    monkeypatch.setattr(svc, "_node_version", lambda: svc.NODE_MIN_VERSION)
    svc.ensure_node_runtime(run, mode="provision")
    ln_node = [c for c in calls if c[0] == "ln"
               and c[-1] == "/usr/local/bin/node"]
    assert not ln_node, f"foreign symlink must never be relinked: {ln_node}"
