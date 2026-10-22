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
    # The member SSH rehearsal, the browser journey and the incident
    # workflow are part of the acceptance: a journey that could pass
    # without them was not the acceptance the release promised.
    required = ("SR_JOURNEY_BASE_URL", "SR_JOURNEY_OPERATOR_TOKEN",
                "SR_JOURNEY_MEMBER_TOKEN", "SR_JOURNEY_SSH_KEY",
                "SR_JOURNEY_BASTION_KNOWN_HOSTS", "SR_JOURNEY_BROWSER_URL",
                "SR_JOURNEY_BROWSER_USER", "SR_JOURNEY_BROWSER_PASSWORD")
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
        browser_url=os.environ.get("SR_JOURNEY_BROWSER_URL", ""),
        browser_user=os.environ.get("SR_JOURNEY_BROWSER_USER", ""),
        browser_password=os.environ.get("SR_JOURNEY_BROWSER_PASSWORD", ""),
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
    assert any((s.get("ssh") or {}).get("output") for s in out["sessions"])
    assert any(s.get("casts", 0) >= 1 for s in out["sessions"])
    # the incident (break) -> submission -> decision workflow
    incidents = [s.get("incident") for s in out["sessions"] if s.get("incident")]
    assert incidents, "no session exercised the incident workflow"
    assert incidents[0]["submission_status"], incidents[0]
    assert "duplicate" in str(incidents[0].get("duplicate_note") or ""), \
        incidents[0]
    # the failure workflows: the API refused what it could not do
    for session in out["sessions"]:
        refusals = session.get("refusals") or {}
        assert refusals.get("unknown_session") == 404, refusals
        assert refusals.get("unknown_release") == 404, refusals
        assert refusals.get("operator_only_view") == 403, refusals
    # the browser journey
    assert (out.get("browser") or {}).get("logged_in") is True, out.get("browser")
    # the break/repair proof: a real break observed through the API's trusted
    # checks and a real repair, verified the same way
    repairs = [s.get("break_repair") for s in out["sessions"]
               if s.get("break_repair")]
    assert repairs, "no session exercised the break/repair proof"
    assert repairs[0].get("verified") is True, repairs[0]
