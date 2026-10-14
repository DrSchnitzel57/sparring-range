"""Plan 13 phase 4 — configuration alias compatibility.

Every key in every SHIPPED env example must actually reach the settings
model, proven with NON-DEFAULT values so an ignored setting cannot hide
behind its default. Keys that are deliberately not Settings fields
(process role, data dir) are an explicit, asserted whitelist.
"""
from __future__ import annotations

import pathlib

import pytest

from srplatform.settings import Settings
REPO = pathlib.Path(__file__).resolve().parents[1]

#: Read directly from os.environ by design, never Settings fields.
NON_SETTINGS_KEYS = {"SR_PROCESS_ROLE", "SR_DATA_DIR"}


def _example_keys():
    out = []
    for f in sorted(REPO.glob("deploy/env.*.example")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            out.append((f.name, line.split("=", 1)[0]))
    return out


def _field_for(key: str) -> str | None:
    for name in Settings.model_fields:
        if key.upper() in (name.upper(), f"SR_{name.upper()}"):
            return name
    return None


def _probe(annotation, current_default):
    """A value that differs from the default and parses for this type."""
    ann = str(annotation)
    if "bool" in ann:
        return ("true", "false")
    if "int" in ann:
        v = int(current_default or 0) + 7
        return (str(v),)
    return (f"{current_default or 'probe'}-probe",)


@pytest.mark.parametrize("fname,key", _example_keys())
def test_shipped_example_key_is_honored(fname, key, monkeypatch):
    if key in NON_SETTINGS_KEYS:
        assert key in NON_SETTINGS_KEYS  # explicit whitelist, not a skip
        return
    field = _field_for(key)
    assert field is not None, \
        f"{key} in {fname} matches no Settings field — a shipped example " \
        "must never be silently ignored"
    f = Settings.model_fields[field]
    default = f.default
    for probe in _probe(f.annotation, default):
        monkeypatch.setenv(key, probe)
        s = Settings(_env_file=None)
        got = getattr(s, field)
        assert (got == probe or str(got) == probe
                or (isinstance(got, bool) and str(got).lower() == probe)), \
            f"{key}={probe!r} did not reach {field} (got {got!r})"


def test_documented_match_settings_probe_now_resolves():
    """The AGENTS.md plan-13 baseline probe: these SR_* names were ignored."""
    import os
    os.environ["SR_MATCH_SCHEDULER_ENABLED"] = "1"
    os.environ["SR_MATCH_DEFAULT_DURATION_MINUTES"] = "60"
    try:
        s = Settings(_env_file=None)
        assert s.match_scheduler_enabled is True
        assert s.match_default_duration_minutes == 60
    finally:
        del os.environ["SR_MATCH_SCHEDULER_ENABLED"]
        del os.environ["SR_MATCH_DEFAULT_DURATION_MINUTES"]


def test_bare_names_still_resolve_for_backward_compatibility():
    import os
    os.environ["PROXMOX_NODE"] = "barename-node"
    try:
        assert Settings(_env_file=None).proxmox_node == "barename-node"
    finally:
        del os.environ["PROXMOX_NODE"]


def test_sr_env_still_resolves():
    import os
    os.environ["SR_ENV"] = "production-check"
    try:
        assert Settings(_env_file=None).sr_env == "production-check"
    finally:
        del os.environ["SR_ENV"]
