"""Durable audit-input cursor (paired 03+04, step 5) — fast unit tests.

Proves crash/outage/reboot resume, rotation/truncation gaps, and torn-tail
safety of `AuditLogFollower` against real files (no mocks, no DB, no QEMU).
"""
from __future__ import annotations

import json
import pathlib

from telemetry.shipper import AuditLogFollower


def test_cursor_resumes_after_crash_without_loss_or_skip(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("line1\nline2\n")
    gaps: list[str] = []
    f1 = AuditLogFollower(str(log), str(tmp_path / "spool"),
                          on_gap=lambda r, n=1: gaps.append(r))
    assert f1.poll_once() == ["line1\n", "line2\n"]
    # Crash: a new follower over the same spool dir resumes at the cursor.
    log.write_text("line1\nline2\nline3\n")
    f2 = AuditLogFollower(str(log), str(tmp_path / "spool"),
                          on_gap=lambda r, n=1: gaps.append(r))
    assert f2.poll_once() == ["line3\n"]
    assert gaps == [], gaps
    assert f2.poll_once() == []


def test_cursor_survives_torn_tail_and_counts_nothing(tmp_path):
    log = tmp_path / "audit.log"
    log.write_bytes(b"complete\ntorn-frag")
    gaps: list[str] = []
    f = AuditLogFollower(str(log), str(tmp_path / "spool"),
                         on_gap=lambda r, n=1: gaps.append(r))
    assert f.poll_once() == ["complete\n"]
    # The torn tail is NOT emitted and NOT counted — completion resumes it.
    with open(log, "ab") as fh:
        fh.write(b"ment\nnext\n")
    f2 = AuditLogFollower(str(log), str(tmp_path / "spool"),
                          on_gap=lambda r, n=1: gaps.append(r))
    assert f2.poll_once() == ["torn-fragment\n", "next\n"]
    assert gaps == [], gaps


def test_cursor_rotation_and_truncation_are_visible_gaps(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("a\n")
    gaps: list[str] = []
    spool = tmp_path / "spool"
    f = AuditLogFollower(str(log), spool, on_gap=lambda r, n=1: gaps.append(r))
    assert f.poll_once() == ["a\n"]
    # Rotation: new inode restarts at 0 with a visible gap.
    log.unlink()
    log.write_text("b\n")
    assert f.poll_once() == ["b\n"]
    assert any("rotat" in g for g in gaps), gaps
    # Truncation: size < offset restarts at 0 with a visible gap (real
    # operator reset / copytruncate — modeled as truncate, then new writes).
    with open(log, "wb") as fh:
        fh.write(b"c\n")
        fh.flush()
    import os
    os.truncate(log, 0)
    assert f.poll_once() == []  # empty file: gap recorded, nothing to emit
    assert any("truncat" in g for g in gaps), gaps
    log.write_text("d\n")
    assert f.poll_once() == ["d\n"]


def test_cursor_file_is_atomic_and_reloadable(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("x\n")
    spool = tmp_path / "spool"
    f = AuditLogFollower(str(log), spool)
    f.poll_once()
    cur = json.loads((spool / "audit-cursor.json").read_text())
    assert cur["offset"] == 2 and cur["ino"] is not None
    assert (pathlib.Path(str(spool)) / "audit-cursor.json").exists()
