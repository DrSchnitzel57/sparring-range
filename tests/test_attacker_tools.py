"""Attacker tool-inventory contract tests."""
from infra.images.attacker_tools import (ATTACKER_PROFILES,
                                         REQUIRED_CATEGORIES,
                                         validate_inventory, verify_report)


def test_inventory_well_formed():
    assert validate_inventory() == []
    for cats in ATTACKER_PROFILES.values():
        for category in REQUIRED_CATEGORIES:
            assert cats.get(category), category


def test_verify_report_is_honest_about_gaps():
    full = {name: True for cats in ATTACKER_PROFILES.values()
            for bins in cats.values() for name in bins}
    assert verify_report("attacker-debian", full)["ok"] is True
    broken = dict(full)
    broken.pop("nmap")
    res = verify_report("attacker-debian", broken)
    assert res["ok"] is False and res["missing"] == ["nmap"]
    assert verify_report("nope", {})["ok"] is False
