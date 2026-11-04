"""The build preflight: one QEMU at a time, and memory to spare.

Learned twice on 2026-11-04: the appliance left the network while a build ran
with a leftover guest spinning. Refusing BEFORE qemu starts keeps the box
clean and the reason readable.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

from infra.images.windows_build import qemu_alone_preflight


def _fake_ps(monkeypatch, lines: list[str]) -> None:
    class R:
        stdout = "\n".join(lines)
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R())


def _mem(tmp_path: pathlib.Path, avail_mb: int) -> pathlib.Path:
    p = tmp_path / "meminfo"
    p.write_text(f"MemTotal:  61000000 kB\nMemAvailable: {avail_mb * 1024} kB\n")
    return p


def test_an_empty_box_with_memory_passes(tmp_path, monkeypatch):
    _fake_ps(monkeypatch, ["1 /sbin/init", "42 sshd", "77 python3 x"])
    qemu_alone_preflight(6144, meminfo=_mem(tmp_path, 40000))


def test_another_qemu_is_refused_by_name(tmp_path, monkeypatch):
    _fake_ps(monkeypatch, ["1 /sbin/init",
                           "90 qemu-system-x86_64 -name sr-winbuild"])
    with pytest.raises(RuntimeError, match="serialized"):
        qemu_alone_preflight(6144, meminfo=_mem(tmp_path, 40000))


def test_short_memory_is_refused_before_starting(tmp_path, monkeypatch):
    _fake_ps(monkeypatch, ["1 /sbin/init"])
    with pytest.raises(RuntimeError, match="MiB available"):
        qemu_alone_preflight(6144, meminfo=_mem(tmp_path, 8000))
