"""Cron observations must not mistake Ubuntu maintenance for a planted job."""
import hashlib
import json
import shlex
import subprocess
import sys

import pytest


def test_real_inventory_read_tolerates_atime_change(tmp_path, monkeypatch, capsys):
    import hashlib
    import json
    import os
    import subprocess
    from types import SimpleNamespace
    from verifiers.library.flag_file import _CRON_PROBE

    job = tmp_path / "maintenance"
    content = b"# synthetic clean cron fixture\n"
    job.write_bytes(content)
    os.utime(job, ns=(0, job.stat().st_mtime_ns))
    def no_crontab(args, **kwargs):
        assert args == ["crontab", "-l"]
        return SimpleNamespace(returncode=1, stdout="", stderr="no crontab for fixture\n")
    monkeypatch.setattr(subprocess, "run", no_crontab)
    # Exercise the actual bounded probe against only the disposable directory.
    probe = _CRON_PROBE.replace('directory = "/etc/cron.d"', f"directory = {str(tmp_path)!r}")
    exec(probe, {})
    result = json.loads(capsys.readouterr().out)
    assert result["files"]["maintenance"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert result["crontab"] == ""

from verifiers.base import Context
from verifiers.library.flag_file import CronPersistencePresent, _CRON_PROBE


# Synthetic maintenance contents: these are not asserted to be production
# Ubuntu hashes. Production pins must come from the trusted image build.
CLEAN = {
    "e2scrub_all": "30 3 * * 0 root /usr/sbin/e2scrub_all -A -r\n",
    "sysstat": "5-55/10 * * * * root /usr/lib/sysstat/sa1 1 1\n",
}


def digest(content):
    return hashlib.sha256(content.encode()).hexdigest()


def inventory(contents=None, crontab=""):
    return {
        "files": {name: {"uid": 0, "gid": 0, "mode": 0o644,
                         "sha256": digest(content)}
                  for name, content in (CLEAN if contents is None else contents).items()},
        "crontab": crontab,
    }


def evaluate(payload=None, code=0, **args):
    return CronPersistencePresent().evaluate(
        Context(exec=lambda host, command: (code, json.dumps(
            inventory() if payload is None else payload))), host="web01", **args)


def pins():
    return {name: digest(content) for name, content in CLEAN.items()}


@pytest.mark.parametrize("expect,status", [("present", "failed"), ("absent", "passed")])
def test_clean_ubuntu_jobs_with_trusted_hashes_are_not_persistence(expect, status):
    result = evaluate(baseline_file_sha256=pins(), expect=expect)
    assert result.status == status
    assert result.evidence["unexpected_files"] == []
    assert result.evidence["unverified_files"] == []


@pytest.mark.parametrize("expect", ["present", "absent"])
@pytest.mark.parametrize("baseline_files", [[], list(CLEAN)])
def test_missing_content_pins_is_unknown_not_spurious_success(expect, baseline_files):
    result = evaluate(expect=expect, baseline_files=baseline_files)
    assert result.status == "unknown"
    assert result.evidence["unverified_files"] == sorted(CLEAN)


@pytest.mark.parametrize("name", list(CLEAN))
def test_same_name_malicious_replacement_is_detected(name):
    contents = {**CLEAN, name: "* * * * * root /tmp/backdoor\n"}
    result = evaluate(inventory(contents), baseline_files=list(CLEAN),
                      baseline_file_sha256=pins())
    assert result.status == "passed"
    assert result.evidence["unexpected_files"] == [name]


@pytest.mark.parametrize("change", [{"uid": 1000}, {"gid": 1000}, {"mode": 0o666},
                                     {"sha256": None}])
def test_same_bytes_with_unsafe_metadata_cannot_inherit_baseline(change):
    payload = inventory()
    payload["files"]["sysstat"].update(change)
    result = evaluate(payload, baseline_file_sha256=pins())
    assert result.status == "passed"
    assert result.evidence["unexpected_files"] == ["sysstat"]


def test_unknown_maintenance_does_not_hide_separate_unexpected_job():
    result = evaluate(inventory({**CLEAN, "backdoor": "* * * * * root /tmp/evil\n"}))
    assert result.status == "passed"
    assert result.evidence["unexpected_files"] == ["backdoor"]
    assert result.evidence["unverified_files"] == sorted(CLEAN)


def test_custom_filename_only_baseline_does_not_hide_replacement():
    result = evaluate(inventory({"custom": "* * * * * root /tmp/evil\n"}),
                      baseline_files=["custom"])
    assert result.status == "unknown"


@pytest.mark.parametrize("code", [None, 1, 124, 125, 126, 127, 254, 255])
def test_failed_probe_never_scores_even_with_valid_looking_output(code):
    assert evaluate(code=code, baseline_file_sha256=pins()).status == "unknown"


@pytest.mark.parametrize("payload", [{}, {"files": [], "crontab": ""},
                                     {"files": {"sysstat": {}}, "crontab": ""}])
def test_malformed_inventory_is_unknown(payload):
    assert evaluate(payload).status == "unknown"


def test_legacy_unstructured_inventory_is_unknown():
    result = CronPersistencePresent().evaluate(
        Context(exec=lambda h, c: (0, "e2scrub_all\nsysstat\n---\n")), host="web01")
    assert result.status == "unknown"


def test_crontab_quoted_whitespace_change_is_not_suppressed():
    result = evaluate(inventory({}, "* * * * * printf 'a  b'\n"),
                      baseline_crontab=["* * * * * printf 'a b'"])
    assert result.status == "passed"


@pytest.mark.parametrize("pins_arg", [{"../sysstat": "a" * 64}, {"sysstat": "md5"}])
def test_invalid_content_pins_are_rejected(pins_arg):
    result = evaluate(baseline_file_sha256=pins_arg)
    assert result.status == "unknown"
    assert "invalid args" in result.error


@pytest.mark.parametrize("crontab_exit,stderr,expected_exit", [
    (1, "no crontab for root\n", 0),
    (1, "permission denied\n", 1),
    (127, "crontab: not found\n", 1),
])
def test_actual_probe_with_disposable_cron_directory(tmp_path, crontab_exit, stderr,
                                                     expected_exit):
    cron = tmp_path / "cron.d"
    cron.mkdir()
    for name, content in CLEAN.items():
        (cron / name).write_text(content)
    # Run the production probe, substituting ONLY local disposable inputs.
    crontab = tmp_path / "crontab"
    crontab.write_text("#!/bin/sh\nprintf %s " + shlex.quote(stderr)
                       + " >&2\nexit " + str(crontab_exit) + "\n")
    crontab.chmod(0o755)
    probe = _CRON_PROBE.replace('directory = "/etc/cron.d"', f"directory = {str(cron)!r}")
    probe = probe.replace('["crontab", "-l"]', f"[{str(crontab)!r}, '-l']")
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert result.returncode == expected_exit
    if expected_exit == 0:
        payload = json.loads(result.stdout)
        assert payload["crontab"] == ""
        assert {name: item["sha256"] for name, item in payload["files"].items()} == pins()
