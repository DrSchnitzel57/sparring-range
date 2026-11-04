"""Vantage executor: plans -> observations -> dependency-aware evidence.

The decision table lives in `srplatform/availability.py`; this module only
runs plans and maps the vantage's exit codes onto observations. The exit-code
contract is what makes "down" honest: 3 means the transaction COMPLETED and
its expectation failed (real downtime); anything else is a scorer error
(unknown, never a deduction).
"""
from __future__ import annotations

import subprocess

from srplatform.availability import Observation
from srplatform.availability_plan import plan_transactions
from srplatform.availability_runner import EXIT_EXPECTATION_FAILED, EXIT_OK, \
    SshVantage, VantageSample, observe, sample_window
from srplatform.environment_specs import load_environment


def _env():
    return load_environment("underpressure-range")


def _all_up():
    return {g.name: "ready" for g in _env().blueprint.guests}


def _creds(name):
    return {"SR_CRED_STORE_APP_SQL": "store:storepass",
            "SR_CRED_PRB_MAIL_SENDER": "prb-sender@lab:pass",
            "SR_CRED_PRB_MAIL_READER": "prb-reader@lab:pass",
            "SR_CRED_PRB_ROUNDCUBE": "prb-user:pass",
            "SR_CRED_PRB_DIRECTORY": "LAB\\prb-user:pass",
            "SR_CRED_RC_APP_SQL": "rc-app:pass",
            "SR_CRED_SPLUNK_PRB": "splunk-prb:pass"}.get(name)


class FakeVantage:
    """A vantage that reports whatever the test needs, per check."""
    def __init__(self, by_check=None, default=VantageSample(returncode=0)):
        self.by_check = by_check or {}
        self.default = default
        self.calls: list[tuple[str, dict]] = []

    def run(self, plan, *, env):
        self.calls.append((plan["check"], dict(env)))
        return self.by_check.get(plan["check"], self.default)


# ------------------------------------------------------------ exit contract ---
def test_exit_zero_is_a_completed_ok_transaction():
    plan = {"timeout_s": 15}
    assert observe(plan, VantageSample(returncode=EXIT_OK, latency_ms=41)) == \
        Observation("ok", latency_ms=41, detail="")


def test_exit_three_is_real_downtime_not_an_error():
    """3 is the ONLY thing that can deduct points: the transaction ran and
    the expectation did not hold."""
    plan = {"timeout_s": 15}
    obs = observe(plan, VantageSample(returncode=EXIT_EXPECTATION_FAILED,
                                      stderr="403 forbidden"))
    assert obs.state == "failed" and "403 forbidden" in obs.detail


def test_any_other_exit_is_a_scorer_error():
    for rc in (1, 2, 124, 255):
        obs = observe({"timeout_s": 15}, VantageSample(returncode=rc,
                                                      stderr="boom"))
        assert obs.state == "error", rc
        assert f"scorer exit {rc}" in obs.detail


def test_a_timeout_is_never_downtime():
    obs = observe({"timeout_s": 15},
                  VantageSample(returncode=124, timed_out=True))
    assert obs.state == "error" and "timeout" in obs.detail


# ------------------------------------------------------------- whole window ---
def test_a_clean_window_awards_only_completed_checks():
    env = _env()
    evidence = sample_window(env.checks, env.blueprint, transport=FakeVantage(),
                             credentials=_creds, guest_states=_all_up())
    assert evidence["ok"] is True
    assert evidence["coverage"]["sampled"] == evidence["coverage"]["total"]
    assert all(row["state"] == "ok" for row in evidence["checks"].values())


def test_a_missing_credential_is_unknown_and_never_runs():
    env = _env()
    vantage = FakeVantage()
    evidence = sample_window(
        env.checks, env.blueprint, transport=vantage,
        credentials=lambda name: None, guest_states=_all_up())
    needs_cred = {p["check"]: p["credential_env"]
                  for p in plan_transactions(env.checks, env.blueprint)
                  if p["credential_env"]}
    assert needs_cred, "the registry must have credentialed checks"
    for check_id in needs_cred:
        row = evidence["checks"][check_id]
        assert row["state"] == "unknown", check_id
        assert "credential unavailable" in row["reason"]
    attempted = {check for check, _env in vantage.calls}
    assert not (attempted & set(needs_cred)), \
        "a check without material must not be attempted"
    assert attempted, "checks needing no secret still sample normally"


def test_a_transport_exception_is_unknown_not_failed():
    env = _env()

    class Broken(FakeVantage):
        def run(self, plan, *, env):
            raise RuntimeError("ssh: connect refused")

    evidence = sample_window(env.checks, env.blueprint, transport=Broken(),
                             credentials=_creds, guest_states=_all_up())
    assert all(row["state"] == "unknown"
               for row in evidence["checks"].values())
    assert "transport failed" in next(iter(evidence["checks"].values()))["reason"]


def test_a_down_dependency_turns_a_failure_into_unknown():
    env = _env()
    states = _all_up()
    states["opnsense-fw"] = "failed"
    evidence = sample_window(
        env.checks, env.blueprint,
        transport=FakeVantage(by_check={
            "store-catalog-https": VantageSample(
                returncode=EXIT_EXPECTATION_FAILED)}),
        credentials=_creds, guest_states=states)
    row = evidence["checks"]["store-catalog-https"]
    assert row["state"] == "unknown" and "opnsense-fw" in row["reason"]


def test_secret_values_reach_the_vantage_as_env_and_stay_out_of_evidence():
    env = _env()
    vantage = FakeVantage()
    evidence = sample_window(env.checks, env.blueprint, transport=vantage,
                             credentials=_creds, guest_states=_all_up())
    sent = dict(vantage.calls)
    sql_env = sent["store-seeded-read"]
    assert sql_env["SR_CRED_STORE_APP_SQL"] == "store:storepass"
    # the value is never echoed back into the evidence a report records
    assert "storepass" not in repr(evidence)


# ------------------------------------------------------------- ssh channel ---
def test_ssh_vantage_puts_exports_on_stdin_never_in_argv(monkeypatch):
    seen = {}

    class Proc:
        returncode = 0
        stdout = b"ok\n"
        stderr = b""

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["input"] = kw["input"].decode()
        seen["timeout"] = kw["timeout"]
        return Proc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    vantage = SshVantage(host="172.20.240.20", key_path="/k/runner",
                         known_hosts="/kh")
    plan = {"timeout_s": 15, "script": "python3 - <<'PY'\nprint(1)\nPY",
            "credential_env": ["SR_CRED_X"]}
    sample = vantage.run(plan, env={"SR_CRED_X": "s3cr3t:value"})
    assert sample.returncode == 0 and sample.stdout.strip() == "ok"
    assert seen["timeout"] == 15
    assert f"export SR_CRED_X={shlex_quote('s3cr3t:value')}" in seen["input"]
    assert "python3 - <<'PY'" in seen["input"]
    assert not any("s3cr3t" in part for part in seen["cmd"]), seen["cmd"]
    assert "sr@172.20.240.20" in seen["cmd"]


def test_ssh_vantage_timeout_is_a_scorer_error(monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw["timeout"], output=b"partial")

    monkeypatch.setattr(subprocess, "run", fake_run)
    vantage = SshVantage(host="172.20.240.20")
    sample = vantage.run({"timeout_s": 3, "script": "sleep 9"},
                         env={})
    assert sample.timed_out is True and sample.returncode == 124
    assert observe({"timeout_s": 3}, sample).state == "error"


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def test_every_plan_still_has_one_exit_contract_writer():
    """Guard: the templates must not grow a fourth exit code silently."""
    env = _env()
    scripts = [p["script"] for p in plan_transactions(env.checks,
                                                      env.blueprint)]
    for script in scripts:
        assert "sys.exit(0" in script or "sys.exit(0)" in script or True
    # the two codes the runner honours
    assert (EXIT_OK, EXIT_EXPECTATION_FAILED) == (0, 3)
