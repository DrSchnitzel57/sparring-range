"""The token endpoint serves only the FULL pinned host key (live find 2026-10-16).

Serving the truncated `host_key_ref` produced a known_hosts line asyncssh
silently skips (zero trusted keys), so every bastion dial failed
HostKeyNotVerifiable while the deployment reported ready. Fast-layer contract
test for `dial_pin_for` — the single door between stored pins and the bastion.
"""
from __future__ import annotations

import asyncssh
import pytest

from srplatform.api.app import dial_pin_for

_PIN_KEY = asyncssh.generate_private_key("ssh-ed25519")
FULL = _PIN_KEY.export_public_key().decode().strip()
_B64 = FULL.split()[1]
REF = f"ssh-ed25519 {_B64[:24]}…{_B64[-8:]}"  # orchestrator._pin_host_key shape


def test_serves_full_pin_never_the_display_ref():
    resources = [{"ip": "10.66.0.9", "host_key_ref": REF, "host_key_pin": FULL}]
    assert dial_pin_for(resources, "10.66.0.9") == FULL
    assert dial_pin_for(resources, "10.66.0.9") != REF


def test_ref_only_row_serves_nothing():
    # Legacy rows (pre-2026-10-16 writer) carry only the display ref: the
    # API must serve None so the bastion refuses instead of dialing with a
    # silently-ignored line.
    resources = [{"ip": "10.66.0.9", "host_key_ref": REF}]
    assert dial_pin_for(resources, "10.66.0.9") is None


def test_other_target_and_missing_resources_serve_nothing():
    resources = [{"ip": "10.66.0.10", "host_key_pin": FULL}]
    assert dial_pin_for(resources, "10.66.0.9") is None
    assert dial_pin_for(None, "10.66.0.9") is None


def test_display_ref_is_not_a_parseable_key():
    # Mechanizes WHY only the full pin may be served: asyncssh cannot parse
    # the truncated ref, and an unparseable known_hosts line is dropped.
    assert asyncssh.import_public_key(FULL) is not None
    with pytest.raises(asyncssh.KeyImportError):
        asyncssh.import_public_key(REF)
