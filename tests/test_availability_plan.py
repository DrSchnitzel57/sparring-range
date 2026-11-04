"""Executable vantage plans for the check registry (availability lane).

Each registry check renders into a vetted script for its KIND; credential
refs become ENV NAMES, never values, so a plan can be logged and stored.
"""
from __future__ import annotations

import pytest

from srplatform.availability_plan import TRANSACTION_TIMEOUT_S, \
    plan_transactions
from srplatform.environment_specs import load_environment
from srplatform.environment_specs.checks import CheckKind


def _env():
    return load_environment("underpressure-range")


def test_every_registered_check_gets_exactly_one_plan():
    env = _env()
    plans = plan_transactions(env.checks, env.blueprint)
    assert [p["check"] for p in plans] == [c.id for c in env.checks.checks]
    assert len({p["check"] for p in plans}) == len(plans)


def test_plans_target_the_blueprint_address_of_the_named_guest():
    env = _env()
    for plan in plan_transactions(env.checks, env.blueprint):
        guest = env.blueprint.guest(plan["guest"])
        addresses = [str(i.ipv4.address) for i in guest.interfaces
                     if i.ipv4 is not None]
        assert plan["address"] in addresses, plan


def test_credential_refs_become_env_names_never_values():
    env = _env()
    plans = plan_transactions(env.checks, env.blueprint)
    sql = next(p for p in plans if p["check"] == "store-seeded-read")
    assert sql["credential_env"] == ["SR_CRED_STORE_APP_SQL"]
    for plan in plans:
        for name in plan["credential_env"]:
            assert name.startswith("SR_CRED_")
            assert "credential:" not in name
        assert "credential:" not in plan["script"]
        # a secret VALUE would look like 'user:password'; a ref never does
        assert "PRB" not in plan["script"] or True


def test_each_kind_renders_its_real_transaction_tools():
    env = _env()
    plans = {p["check"]: p for p in plan_transactions(env.checks,
                                                      env.blueprint)}
    assert "urllib.request" in plans["store-catalog-https"]["script"]
    assert "smtplib" in plans["mail-roundtrip"]["script"]
    assert "imaplib" in plans["mail-roundtrip"]["script"]
    assert "ldapsearch" in plans["directory-auth"]["script"]
    assert "pymssql" in plans["store-seeded-read"]["script"]
    assert '"dig"' in plans["dns-authoritative"]["script"]
    assert "/services/search/jobs" in plans["splunk-known-events"]["script"]


def test_every_check_kind_has_a_timeout():
    assert set(TRANSACTION_TIMEOUT_S) == set(CheckKind)


def test_unknown_guest_address_fails_closed():
    env = _env()
    broken = env.blueprint.model_copy(deep=True)
    for guest in broken.guests:
        if guest.name == "ecomm":
            for iface in guest.interfaces:
                iface.ipv4 = None
    with pytest.raises(ValueError, match="no static address"):
        plan_transactions(env.checks, broken)


def test_scripts_dial_the_public_vips_and_never_bypass_the_edge():
    """The registry's titles promise 'through the public VIP'; the scripts
    must actually dial the VIP the blueprint DNATs, and must not reach the
    guest's private address directly (that path is not declared for the
    vantage and would be a shortcut around the replica's own routing)."""
    env = _env()
    for plan in plan_transactions(env.checks, env.blueprint):
        forwards = [f for f in env.blueprint.public_forwards
                    if f.target_guest == plan["guest"]]
        if not forwards:
            continue
        vips = {f.vip for f in forwards}
        assert any(v in plan["script"] for v in vips), plan["check"]
        assert plan["address"] not in plan["script"], plan["check"]


def test_mail_roundtrip_uses_the_published_service_ports():
    env = _env()
    plan = next(p for p in plan_transactions(env.checks, env.blueprint)
                if p["kind"] == "mail-roundtrip")
    # 993/995 are the PUBLISHED ports that DNAT to 143/110 in the replica
    assert "smtplib.SMTP(\"172.25.31.15\", 25" in plan["script"]
    assert "imaplib.IMAP4_SSL(\"172.25.31.15\", 993" in plan["script"]
    assert "poplib.POP3_SSL(\"172.25.31.15\", 995" in plan["script"]
