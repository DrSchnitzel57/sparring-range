"""Installed-appliance journey gate (milestone 15).

The actual workflow lives in :mod:`infra.dev.journey`; this test only supplies
the live inputs and fails closed when they are absent in required mode.  It has
no fake broker, fake guest or in-process API: the URL is the installed
appliance.
"""
from __future__ import annotations

import json
import os

import pytest

pytestmark = pytest.mark.journey


def test_installed_appliance_full_practice_journey(tmp_path):
    required = ("SR_JOURNEY_BASE_URL", "SR_JOURNEY_OPERATOR_TOKEN",
                "SR_JOURNEY_MEMBER_TOKEN")
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        message = ("installed-appliance journey inputs missing: "
                   + ", ".join(missing))
        if os.environ.get("SR_REQUIRE_JOURNEY") == "1":
            pytest.fail(message)
        pytest.skip(message)
    from infra.dev.journey import PRESETS, run_journey
    presets = tuple(x.strip() for x in os.environ.get(
        "SR_JOURNEY_PRESET", ",".join(PRESETS)).split(",") if x.strip())
    out = run_journey(
        base_url=os.environ["SR_JOURNEY_BASE_URL"],
        operator_token=os.environ["SR_JOURNEY_OPERATOR_TOKEN"],
        member_token=os.environ["SR_JOURNEY_MEMBER_TOKEN"],
        ca_file=os.environ.get("SR_JOURNEY_CA_FILE") or None,
        presets=presets,
        duration=int(os.environ.get("SR_JOURNEY_DURATION_MINUTES", "30")),
        pace=int(os.environ.get("SR_JOURNEY_PACE_SECONDS", "30")),
        ssh_key=os.environ.get("SR_JOURNEY_SSH_KEY") or None,
        bastion_known_hosts=os.environ.get(
            "SR_JOURNEY_BASTION_KNOWN_HOSTS") or None,
        reuse=os.environ.get("SR_JOURNEY_REUSE", "1") != "0")
    evidence = tmp_path / "journey-evidence.json"
    evidence.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    assert out["ok"] is True
    assert len(out["sessions"]) >= len(presets)
    for session in out["sessions"]:
        assert session["ready"] is True
        assert session["launch_state"] == "succeeded"
        assert session["end_status"] in ("complete", "torn_down")
        assert session["score_status"] in ("scored", "partial", "unscored")
    if os.environ.get("SR_JOURNEY_SSH_KEY"):
        assert any((s.get("ssh") or {}).get("output") for s in out["sessions"])
        assert any(s.get("casts", 0) >= 1 for s in out["sessions"])
