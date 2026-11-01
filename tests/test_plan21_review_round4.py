"""Runbook boot-check pipeline guard (survives the upgrade-engine removal).

The documented units+journal pipeline in ``docs/OPERATOR_RUNBOOK.md`` must
never print "clean boot" when journal retrieval FAILS — the script is
extracted VERBATIM from the runbook and executed against fakes (all-active
+clean, retrieval failure, error lines, missing unit).

The rest of this file's original round-4 subjects (the preserving-upgrade
readiness contract and the ``--db-url-env`` credential scrub) retired with
the upgrade engine; git history keeps their proofs.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess

import pytest


def _extract_runbook_pipeline() -> str:
    text = (pathlib.Path(__file__).resolve().parents[1]
            / "docs" / "OPERATOR_RUNBOOK.md").read_text()
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines)
                     if l.startswith("for u in sr-appliance-broker.service"))
        end = next(i for i in range(start, len(lines))
                   if lines[i].strip() == "```")
    except StopIteration:
        pytest.fail("the documented unit+journal pipeline disappeared "
                    "from OPERATOR_RUNBOOK.md")
    return "\n".join(lines[start:end]) + "\n"


def _run_pipeline(fake_dir: pathlib.Path, env_extra: dict) -> subprocess.CompletedProcess:
    script = fake_dir / "pipeline.sh"
    script.write_text(_extract_runbook_pipeline())
    return subprocess.run(["bash", str(script)], capture_output=True,
                          text=True, timeout=30,
                          env={**os.environ,
                               "PATH": f"{fake_dir}{os.pathsep}"
                                       + os.environ["PATH"],
                               **env_extra})


def _fake_units(fake_dir: pathlib.Path):
    (fake_dir / "systemctl").write_text(
        "#!/usr/bin/env bash\n"
        'for u in "${@:2}"; do\n'
        '  if [[ -n "${SR_MISSING_UNIT:-}" && "$u" == *"$SR_MISSING_UNIT"* ]]'
        '; then echo inactive; exit 3; fi\n'
        "done\nexit 0\n")
    (fake_dir / "journalctl").write_text(
        "#!/usr/bin/env bash\n"
        'if [[ -n "${SR_JOURNAL_FAIL:-}" ]]; then '
        'echo "journalctl: cannot connect to journal" >&2; exit 1; fi\n'
        'if [[ -n "${SR_JOURNAL_ERR:-}" ]]; then '
        'echo "sr-api: ERROR boom" ; exit 0; fi\n'
        'echo "sr-api: started cleanly"\nexit 0\n')
    (fake_dir / "systemctl").chmod(0o755)
    (fake_dir / "journalctl").chmod(0o755)


def test_documented_pipeline_never_prints_clean_on_journal_failure(tmp_path):
    _fake_units(tmp_path)
    # positive: all units active, retrieval succeeds, no error lines
    ok = _run_pipeline(tmp_path, {})
    assert ok.returncode == 0 and "clean boot" in ok.stdout, ok.stdout
    # retrieval FAILS -> must NOT be clean, must fail non-zero
    jf = _run_pipeline(tmp_path, {"SR_JOURNAL_FAIL": "1"})
    assert jf.returncode != 0 and not re.search(r"^clean boot$", jf.stdout,
                                                re.M), (jf.stdout, jf.stderr)
    assert "RETRIEVAL FAILED" in jf.stdout
    # error lines present -> reported, never "clean boot"
    je = _run_pipeline(tmp_path, {"SR_JOURNAL_ERR": "1"})
    assert je.returncode == 0 and "investigate" in je.stdout \
        and not re.search(r"^clean boot$", je.stdout, re.M)
    # a MISSING/inactive unit -> hard fail before any journal reading
    mu = _run_pipeline(tmp_path, {"SR_MISSING_UNIT": "sr-web"})
    assert mu.returncode != 0 and "NOT ACTIVE: sr-web.service" in mu.stdout
