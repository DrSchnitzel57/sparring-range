"""Per-role provisioning: plans are data, and only exit 0 means ready.

No appliance and no guest runs here: the transport is a fake that records
argv, so these tests pin the CONTRACT (plan purity, fail-closed credentials,
idempotent step text, evidence without secrets) rather than an appliance's
live behaviour — that is the availability gate's job.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from srplatform.environment_specs import load_environment
from srplatform.scenario_engine import env_provision as ep

BP = load_environment("underpressure-range").blueprint

#: Synthetic values in the shape the protected store holds them. The DSRM
#: entry is reserved for the forest install (see OPERATOR_RUNBOOK).
CREDS = {
    "SR_CRED_DIRECTORY_DSRM": "dsrm:DsrmP@ss1",
    "SR_CRED_DIRECTORY_JOIN": "UNDERPRESSURE\\administrator:AdminP@ss1",
    "SR_CRED_PRB_DIRECTORY": "UNDERPRESSURE\\prb-directory:DirP@ss1",
    "SR_CRED_STORE_APP_SQL": "store:StoreP@ss1",
    "SR_CRED_RC_APP_SQL": "rc-app:RcP@ss1",
    "SR_CRED_SPLUNK_ADMIN": "admin:Changeme123",
    "SR_CRED_SPLUNK_PRB": "splunk-prb:SplunkP@ss1",
    "SR_CRED_PRB_MAIL_SENDER": "prb-sender@underpressure.local:SenderP@ss1",
    "SR_CRED_PRB_MAIL_READER": "prb-reader@underpressure.local:ReaderP@ss1",
    "SR_CRED_PRB_ROUNDCUBE": "prb-roundcube@underpressure.local:RoundP@ss1",
}


def _tmp_pki():
    import tempfile
    from srplatform.labs.pki import LabPKI
    d = pathlib.Path(tempfile.mkdtemp(prefix="sr-pki-"))
    return LabPKI(d / "pki")


def resolver(name: str) -> str | None:
    return CREDS.get(name)


class FakeTransport:
    def __init__(self, responder=None):
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.reboots: list[str] = []
        self._responder = responder or (lambda guest, argv: ep.ExecResult(0, "", ""))

    def exec(self, guest, argv, timeout_s):
        self.calls.append((guest, tuple(argv)))
        return self._responder(guest, tuple(argv))

    def reboot(self, guest):
        self.reboots.append(guest)


def _plan(gen="g1", res=resolver):
    return ep.build_plan(BP, generation=gen, resolver=res)


def _pem_b64(step_text: str, dest: str) -> str:
    import re
    for line in step_text.splitlines():
        if f"base64 -d > {dest}" in line:
            return re.findall(r"'([A-Za-z0-9+/=]{16,})'", line)[0]
    raise AssertionError(f"no base64 for {dest}")


def _services(plans, guest):
    for gp in plans:
        if gp.guest == guest:
            return {s.service: s for s in gp.services}
    raise AssertionError(f"{guest} not planned")


# ------------------------------------------------------------ plan shape


def test_plans_follow_dependency_order_and_only_serviced_guests():
    plans = _plan()
    assert [p.guest for p in plans] == [
        g for g in BP.provision_order() if BP.guest(g).services]
    assert plans[0].guest == "ad-dns"  # declared first and dependency-free


def test_declared_service_order_is_preserved():
    svc = _services(_plan(), "ad-dns")
    assert [s.service for s in svc.values()] == [
        "active-directory", "dns", "winrm", "ca-fileshare"]
    assert svc["ca-fileshare"].state == "unimplemented"
    assert svc["active-directory"].state == "ready"
    assert svc["dns"].state == "ready"
    assert svc["winrm"].state == "ready"


def test_unimplemented_is_not_ready():
    ad = _services(_plan(), "ad-dns")
    assert ad["ca-fileshare"].state == "unimplemented"
    assert _services(_plan(), "ecomm")["ssh"].state == "ready"


# --------------------------------------------------------- credentials


def test_missing_credential_fails_closed_with_the_variable_name():
    plans = ep.build_plan(BP, generation="g1", resolver=lambda name: None)
    ad = {s.service: s for s in _services(plans, "ad-dns").values()}
    assert ad["active-directory"].state == "failed"
    assert "SR_CRED_DIRECTORY_DSRM" in (ad["active-directory"].error or "")
    # the DNS handler needs no secret and still plans
    assert ad["dns"].state == "ready"
    # and the winrm handler needs no credential either
    assert ad["winrm"].state == "ready"


def test_credential_variable_naming():
    assert ep.credential_var("credential:store-app-sql") == \
        "SR_CRED_STORE_APP_SQL"
    assert ep.credential_var("prb.directory") == "SR_CRED_PRB_DIRECTORY"


def test_split_credential_keeps_the_domain_side():
    assert ep.split_credential("UNDERPRESSURE\\prb-directory:DirP@ss1") == (
        "UNDERPRESSURE\\prb-directory", "DirP@ss1")
    with pytest.raises(ep.ProvisionError):
        ep.split_credential("no-password")


# ------------------------------------------------------------- AD plan


def test_ad_plan_promotes_once_reboots_and_seeds_the_domain():
    ad = _services(_plan(), "ad-dns")["active-directory"]
    assert [s.id for s in ad.steps] == [
        "ad-roles", "ad-promote", "ad-seed", "ad-verify"]
    promote = next(s for s in ad.steps if s.id == "ad-promote")
    assert promote.reboot is True
    assert "-NoRebootOnCompletion" in promote.argv[-1]
    assert "underpressure.local" in promote.argv[-1]
    seed = next(s for s in ad.steps if s.id == "ad-seed")
    assert "OU=Lab,DC=underpressure,DC=local" in seed.argv[-1]
    assert "prb-directory" in seed.argv[-1]


def test_ad_plan_is_idempotent_by_construction():
    """Every step asks the guest what exists before acting; the strings that
    make it true are part of the contract, not incidental."""
    ad = _services(_plan(), "ad-dns")["active-directory"]
    promote = next(s for s in ad.steps if s.id == "ad-promote").argv[-1]
    assert "Get-ADDomain" in promote and "if (-not $done)" in promote
    seed = next(s for s in ad.steps if s.id == "ad-seed").argv[-1]
    assert "Get-ADOrganizationalUnit" in seed and "Get-ADUser" in seed


# ------------------------------------------------------------ DNS plan


def test_dns_records_come_from_blueprint_addresses():
    dns = _services(_plan(), "ad-dns")["dns"]
    text = "\n".join(" ".join(s.argv) for s in dns.steps)
    for guest in ("ecomm", "webmail", "splunk", "ad-dns"):
        assert BP.guest(guest).interfaces[0].ipv4.address in text
    assert "shop" in text and "mail" in text
    assert "_ldap._tcp.dc._msdcs" in text


# ---------------------------------------------------------- SQL plan


def test_mssql_creates_both_databases_with_the_app_accounts():
    mssql = _services(_plan(), "mssql")["mssql"]
    text = "\n".join(" ".join(s.argv) for s in mssql.steps)
    assert "UnderpressureStore" in text and "roundcube" in text
    for user in ("store", "rc-app"):
        assert f"[{user}]" in text
    verify = next(s for s in mssql.steps if s.id == "mssql-verify")
    # the verify logs in AS the store app account (proof of authentication)
    assert "-U" in verify.argv[-1] and "store" in verify.argv[-1]


# ---------------------------------------------------------- execution


def test_every_step_exiting_zero_means_ready():
    transport = FakeTransport()
    outcomes = ep.run_plan(_plan(), transport)
    for guest, outs in outcomes.items():
        for out in outs:
            if out.state == "ready":
                assert all(s.returncode == 0 for s in out.steps)
    assert transport.reboots == ["ad-dns"]
    assert any(c[0] == "ad-dns" for c in transport.calls)


def test_a_failed_step_stops_the_service_and_the_guest():
    def responder(guest, argv):
        if guest == "ad-dns" and "New-ADOrganizationalUnit" in argv[-1]:
            return ep.ExecResult(1, "", "The specified account already exists")
        return ep.ExecResult(0, "", "")

    outcomes = ep.run_plan(_plan(), FakeTransport(responder))
    ad = {o.service: o for o in outcomes["ad-dns"]}
    assert ad["active-directory"].state == "failed"
    assert "ad-seed exited 1" in (ad["active-directory"].error or "")
    assert "already exists" in ad["active-directory"].steps[-1].stderr_tail
    # later services of a broken guest do not run at all
    assert ad["dns"].state == "failed"
    assert "not run" in (ad["dns"].error or "")
    assert ad["winrm"].state == "failed"
    assert "not run" in (ad["winrm"].error or "")
    assert ad["ca-fileshare"].state == "unimplemented"


def test_transport_error_is_failed_evidence_never_success():
    def responder(guest, argv):
        raise RuntimeError("guest agent did not accept guest-exec")

    out = ep.run_plan(_plan(), FakeTransport(responder))["ad-dns"][0]
    assert out.state == "failed"
    assert "transport error" in (out.error or "")
    assert "did not accept" in (out.error or "")


def test_reboot_happens_after_the_promote_step_only():
    transport = FakeTransport()
    ep.run_plan(_plan(), transport)
    assert transport.reboots == ["ad-dns"]


# ------------------------------------------------------------ evidence


def test_evidence_carries_no_secret_and_no_command_text():
    outcomes = ep.run_plan(_plan(), FakeTransport())
    evidence = ep.outcome_evidence(outcomes)
    blob = json.dumps(evidence)
    for secret in ("StoreP@ss1", "RcP@ss1", "DirP@ss1", "DsrmP@ss1"):
        assert secret not in blob
    assert "powershell" not in blob.lower()
    assert evidence["ad-dns"]["services"]["active-directory"]["state"] == "ready"
    assert evidence["ad-dns"]["ready"] is False  # winrm unimplemented


# ----------------------------------------------------- broker transport


class FakeBroker:
    def __init__(self, returncode=0):
        self.calls = []
        self._rc = returncode

    def guest_exec(self, node, vmid, argv, session_id=None, generation=1,
                   timeout_s=30.0):
        self.calls.append({"node": node, "vmid": int(vmid), "argv": list(argv),
                           "generation": str(generation)})
        return {"returncode": self._rc, "stdout": "", "stderr": ""}

    def stop_and_confirm(self, node, vmid, session_id=None):
        self.calls.append({"op": "stop", "vmid": int(vmid)})

    def start_and_wait(self, node, vmid, timeout=90, session_id=None):
        self.calls.append({"op": "start", "vmid": int(vmid)})


def test_broker_transport_uses_the_deploy_generation():
    resources = [
        {"host": "ad-dns", "vmid": 213, "generation_attempt": 2},
        {"host": "ecomm", "vmid": 214, "generation_attempt": 0},
    ]
    broker = FakeBroker()
    t = ep.BrokerProvisionTransport(broker, node="r740", resources=resources,
                                    session_id="ses1",
                                    deployment_id="dep-1")
    out = t.exec("ad-dns", ("/bin/true",), 30)
    assert out.returncode == 0
    assert broker.calls[0]["generation"] == "dep-1:a2"
    assert broker.calls[0]["vmid"] == 213
    t.exec("ecomm", ("/bin/true",), 30)
    assert broker.calls[1]["generation"] == "dep-1"
    t.reboot("ad-dns")
    assert [c.get("op") for c in broker.calls[-2:]] == ["stop", "start"]


def test_broker_transport_refuses_a_guest_without_a_vmid():
    t = ep.BrokerProvisionTransport(FakeBroker(), node="r740",
                                    resources=[{"host": "ad-dns"}],
                                    session_id="s", deployment_id="d")
    with pytest.raises(ep.ProvisionError, match="no deployed VMID"):
        t.exec("ad-dns", ("/bin/true",), 30)


# ------------------------------------------------------ handler registry


def test_registering_a_second_handler_is_a_loud_error():
    with pytest.raises(ValueError, match="already has a handler"):
        ep.handler(ep.ServiceId.SSH)(lambda ctx: [])


# ------------------------------------------------------- winrm (opening state)


def test_winrm_reproduces_the_weak_http_listener():
    winrm = _services(_plan(), "ad-dns")["winrm"]
    assert [s.id for s in winrm.steps] == ["winrm-enable", "winrm-verify"]
    enable = winrm.steps[0].argv[-1]
    assert "AllowUnencrypted -Value $true" in enable
    assert "Auth\\Basic -Value $true" in enable
    assert "5985" in winrm.steps[1].argv[-1]


# ------------------------------------------------------- linux domain join


def test_sssd_join_points_at_ad_dns_and_verifies_by_name():
    sssd = _services(_plan(), "ecomm")["sssd-ad"]
    assert [s.id for s in sssd.steps] == [
        "sssd-dns-client", "sssd-packages", "sssd-join", "sssd-verify"]
    text = "\n".join(" ".join(s.argv) for s in sssd.steps)
    assert BP.guest("ad-dns").interfaces[0].ipv4.address in text
    assert "search underpressure.local" in text
    assert "realm join" in text
    assert "prb-directory@underpressure.local" in text


def test_sssd_join_password_reaches_the_guest_but_not_the_evidence():
    sssd = _services(_plan(), "ecomm")["sssd-ad"]
    join = next(s for s in sssd.steps if s.id == "sssd-join")
    assert "AdminP@ss1" in join.argv[-1]      # it must authenticate
    evidence = ep.outcome_evidence(ep.run_plan(_plan(), FakeTransport()))
    assert "AdminP@ss1" not in json.dumps(evidence)


def test_sssd_join_fails_closed_without_the_admin_credential():
    def missing(name):
        return None if name == "SR_CRED_DIRECTORY_JOIN" else resolver(name)

    sssd = _services(_plan(res=missing), "ecomm")["sssd-ad"]
    assert sssd.state == "failed"
    assert "SR_CRED_DIRECTORY_JOIN" in (sssd.error or "")


# ------------------------------------------------------------- splunk


def test_splunk_enables_the_receiver_and_a_search_account():
    splunk = _services(_plan(), "splunk")["splunk"]
    assert [s.id for s in splunk.steps] == [
        "splunk-listen", "splunk-user", "splunk-verify"]
    text = "\n".join(" ".join(s.argv) for s in splunk.steps)
    assert "enable listen 9997" in text
    assert "services/authentication/users" in text
    assert "splunk-prb" in text


def test_syslog_receiver_seeds_an_event_and_finds_it_by_search():
    syslog = _services(_plan(), "splunk")["syslog-receiver"]
    assert [s.id for s in syslog.steps] == ["syslog-input", "syslog-seed"]
    text = "\n".join(" ".join(s.argv) for s in syslog.steps)
    assert "5514" in text and "splunk search" in text
    assert "sendto" in text            # the seed really transmits


def test_splunk_missing_admin_credential_is_failed_not_ready():
    def missing(name):
        return None if name == "SR_CRED_SPLUNK_ADMIN" else resolver(name)

    for guest in ("splunk",):
        svc = _services(_plan(res=missing), guest)
        assert svc["splunk"].state == "failed"
        assert "SR_CRED_SPLUNK_ADMIN" in (svc["splunk"].error or "")


# ------------------------------------------------------ store role + PKI


def test_store_tls_is_signed_for_the_guest_address_not_just_the_name(tmp_path):
    from srplatform.labs.pki import LabPKI
    from cryptography import x509
    import base64

    pki = LabPKI(tmp_path / "pki")
    plans = ep.build_plan(BP, generation="g1", resolver=resolver, pki=pki)
    nginx = _services(plans, "ecomm")["nginx"]
    assert [s.id for s in nginx.steps] == [
        "store-tls", "store-front", "store-tls-verify"]
    b64 = _pem_b64(nginx.steps[0].argv[-1], "/etc/pki/sr/shop.crt")
    cert = x509.load_pem_x509_certificate(base64.b64decode(b64))
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    ips = {str(i) for i in sans.get_values_for_type(x509.IPAddress)}
    assert BP.guest("ecomm").interfaces[0].ipv4.address in ips
    assert "shop.underpressure.local" in {
        n for n in sans.get_values_for_type(x509.DNSName)}


def test_store_plan_uses_the_front_end_the_golden_carries():
    plans = ep.build_plan(BP, generation="g", resolver=resolver,
                          pki=_tmp_pki())
    nginx = _services(plans, "ecomm")["nginx"]
    text = "\n".join(" ".join(s.argv) for s in nginx.steps)
    assert "command -v nginx" in text and "httpd -t" in text
    assert "--cacert /etc/pki/sr/ca.crt" in text


def test_tls_without_a_ca_is_failed_evidence_not_plain_http():
    nginx = _services(_plan(), "ecomm")["nginx"]
    assert nginx.state == "failed"
    assert "no CA" in (nginx.error or "")


def test_store_content_carries_the_catalogue_text_the_check_reads():
    nop = _services(_plan(), "ecomm")["nopcommerce"]
    text = "\n".join(" ".join(s.argv) for s in nop.steps)
    assert "Underpressure Water Authority Store" in text
    assert 'data-sku="WATER-KIT-01"' in text


# ------------------------------------------------------- mail role


def test_mail_hands_share_one_identity_set_between_guest_and_vantage():
    postfix = _services(_plan(), "webmail")["postfix"]
    dovecot = _services(_plan(), "webmail")["dovecot"]
    for plan in (postfix, dovecot):
        text = "\n".join(" ".join(s.argv) for s in plan.steps)
        assert "prb-mail-sender" in text or "prb-sender" in text
        assert "prb-mail-reader" in text or "prb-reader" in text
    # plaintext auth is the reported opening state, deliberately kept
    dtext = "\n".join(" ".join(s.argv) for s in dovecot.steps)
    assert "disable_plaintext_auth = no" in dtext


def test_roundcube_substitute_accepts_the_full_address_the_check_posts():
    plans = ep.build_plan(BP, generation="g", resolver=resolver,
                          pki=_tmp_pki())
    rc = _services(plans, "webmail")["roundcube"]
    text = "\n".join(" ".join(s.argv) for s in rc.steps)
    assert "preg_replace('/@.*$/', '', $user)" in text
    assert "Inbox" in text
    assert "--resolve mail.underpressure.local" in text


def test_mail_tls_certificate_covers_the_webmail_address(tmp_path):
    from srplatform.labs.pki import LabPKI
    from cryptography import x509
    import base64

    pki = LabPKI(tmp_path / "pki")
    plans = ep.build_plan(BP, generation="g", resolver=resolver, pki=pki)
    rc = _services(plans, "webmail")["roundcube"]
    b64 = _pem_b64(rc.steps[0].argv[-1], "/etc/pki/sr/mail.crt")
    cert = x509.load_pem_x509_certificate(base64.b64decode(b64))
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    ips = {str(i) for i in sans.get_values_for_type(x509.IPAddress)}
    assert BP.guest("webmail").interfaces[0].ipv4.address in ips


def test_mail_passwords_never_reach_the_evidence():
    plans = ep.build_plan(BP, generation="g", resolver=resolver,
                          pki=_tmp_pki())
    evidence = ep.outcome_evidence(ep.run_plan(plans, FakeTransport()))
    blob = json.dumps(evidence)
    for secret in ("SenderP@ss1", "ReaderP@ss1", "RoundP@ss1"):
        assert secret not in blob
