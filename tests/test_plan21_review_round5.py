"""Milestone-21 review round 5 — fence ownership fast proofs.

Round-5 finding 1: the upgrade engine used to OVERWRITE any existing
admission fence at acquisition and cleared fences whose ``attempt`` key
was MISSING at completion (reproduced by the reviewer through the actual
CLI: a foreign-owned fence was replaced and stamped done; a fence
stripped to ``{}`` during readiness was removed and stamped). The fence
is now a mutex TOKEN: identity is validated before any mutation,
acquisition of an absent fence is an exclusive create, ownership is
re-required at finalization, and completion clears ONLY a fence owned
exactly by the completing attempt.

These are the deterministic unit-level contracts; the actual-CLI
acquisitions (foreign/anonymous/corrupt refusals, ownership swap during a
run, verified-own resume, fresh absent-fence positive) are proven by the
`upgrade` acceptance gate.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from deploy import upgrade as up


def _f(tmp_path) -> pathlib.Path:
    return tmp_path / "maintenance"


def test_identity_classification(tmp_path):
    f = _f(tmp_path)
    assert up._fence_identity(f) == ("absent", None)
    f.write_text(json.dumps({"attempt": "att-1"}) + "\n")
    assert up._fence_identity(f) == ("owned", "att-1")
    for bad in ("{}\n", '{"attempt": null}\n', '{"attempt": ""}\n',
                '{"attempt": 7}\n'):
        f.write_text(bad)
        assert up._fence_identity(f) == ("anonymous", None), bad
    for bad in ("{ not json\n", "", "[\"array\"]\n"):
        f.write_text(bad)
        assert up._fence_identity(f) == ("unreadable", None), repr(bad)


def test_takeable_refuses_every_existing_identity_byte_exact(tmp_path):
    f = _f(tmp_path)
    for body in (json.dumps({"attempt": "manual-op-42"}),
                 "{}", "{ corrupt", '{"attempt": ""}'):
        f.write_text(body)
        kind, owner = up._fence_identity(f)
        with pytest.raises(up.UpgradeError):
            up._require_fence_takeable(kind, owner)
        assert f.read_text() == body  # refusal never rewrites
    # absent is takeable
    f.unlink()
    kind, owner = up._fence_identity(f)
    up._require_fence_takeable(kind, owner)


def test_exclusive_create_never_races_over_a_concurrent_fence(tmp_path):
    f = _f(tmp_path)
    up._write_fence_exclusive(f, "att-new")
    doc = json.loads(f.read_text())
    assert doc["attempt"] == "att-new" and doc["reason"]
    before = f.read_bytes()
    # any fence that exists (e.g. the operator's, created between a
    # check and this call) is refused WITHOUT a write:
    with pytest.raises(up.UpgradeError, match="concurrently"):
        up._write_fence_exclusive(f, "att-other")
    assert f.read_bytes() == before


def test_finalize_requires_exact_ownership(tmp_path):
    f = _f(tmp_path)
    f.write_text(json.dumps({"attempt": "att-mine"}))
    up._require_fence_owner(f, "att-mine")  # ours: passes
    for body, why in ((json.dumps({"attempt": "att-other"}), "attempt"),
                      ("{}\n", "owning attempt"),
                      ("{ corrupt", "readable JSON")):
        f.write_text(body)
        with pytest.raises(up.UpgradeError, match="ownership is unresolved"):
            up._require_fence_owner(f, "att-mine")
        assert f.read_text() == body
    f.unlink()
    with pytest.raises(up.UpgradeError, match="disappeared"):
        up._require_fence_owner(f, "att-mine")


def test_completion_never_clears_none_or_foreign_ownership(tmp_path, monkeypatch):
    """The exact round-5 reproduction guard: the completion path clears
    only ``owned == attempt``; anonymous/foreign/corrupt/absent fences
    are reported RETAINED instead of removed."""
    f = _f(tmp_path)
    attempt = "att-mine"
    for body in ("{}\n", json.dumps({"attempt": "att-other"}) + "\n",
                 "{ corrupt\n"):
        f.write_text(body)
        kind, owner = up._fence_identity(f)
        assert not (kind == "owned" and owner == attempt)
        assert f.exists()  # nothing in the classification path touches it
