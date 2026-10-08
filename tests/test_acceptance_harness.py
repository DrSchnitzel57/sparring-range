"""Regressions for the acceptance harness itself (milestone-01 review).

The harness decides acceptance, so its own counting and audit-evaluation
logic must not fail open. These are fast, infrastructure-free unit tests
over the harness's pure functions.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


acc = _load("sr_acceptance", "infra/dev/acceptance.py")


def test_parse_counts_uses_pytest_labels_exactly():
    c = acc.parse_counts("1 failed, 2 passed, 3 skipped, 4 deselected, 5 errors "
                         "in 9.0s")
    assert c == {"failed": 1, "passed": 2, "skipped": 3, "deselected": 4,
                 "error": 5}
    # the exact key the skip gate reads — a renamed key fails the gate open
    assert c["skipped"] == 3


def test_skip_gate_reads_the_skipped_key_not_a_missing_one():
    # regression (review P2): counts.get("skip") never matched pytest's
    # "skipped" label, so a skipped fast test passed the infrastructure-free
    # gate. The harness must only ever ask for "skipped".
    src = (REPO / "infra" / "dev" / "acceptance.py").read_text()
    assert not re.search(r'counts\.get\(["\']skip["\']', src), \
        "harness asks for a nonexistent 'skip' count key again"


def test_require_selection_fails_on_empty_and_passes_on_any_selection():
    with pytest.raises(acc.Failed):
        acc.require_selection({"deselected": 100}, "db")
    with pytest.raises(acc.Failed):
        acc.require_selection({}, "packet")
    acc.require_selection({"passed": 1, "deselected": 10}, "db")
    acc.require_selection({"failed": 1}, "db")
    acc.require_selection({"skipped": 1}, "db")  # non-empty: the layer ran


def test_audit_evaluation_fails_closed():
    F = acc.Failed
    # error response (registry unreachable) is NEVER zero findings
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"error":{"code":"ENOTFOUND"}}', 1)
    # unparsable / empty output
    with pytest.raises(F):
        acc.audit_vulnerabilities("", 1)
    with pytest.raises(F):
        acc.audit_vulnerabilities("not json", 0)
    # structurally valid but missing the metadata the gate evaluates
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"advisories":{}}', 0)
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"metadata":{}}', 0)
    # clean and dirty metadata both parse to their severity map
    assert acc.audit_vulnerabilities(
        '{"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,'
        '"high":0,"critical":0}}}', 0) == {"info": 0, "low": 0, "moderate": 0,
                                           "high": 0, "critical": 0}
    v = acc.audit_vulnerabilities('{"metadata":{"vulnerabilities":{"high":2}}}', 1)
    assert v["high"] == 2
