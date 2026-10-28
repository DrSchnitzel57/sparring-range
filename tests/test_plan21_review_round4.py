"""Milestone-21 review round 4 — contract-level fast proofs.

Round-4 finding 1: ``/readyz`` answers HTTP 200 with ``ready:false`` —
the upgrade readiness gate must parse the REAL production readiness
contract (exact ``ready is True``, empty ``issues``, the expected
``migration_version``) and fail closed on malformed/missing/contradictory
reports.  These tests drive ``deploy.upgrade._readiness_probe`` and
``wait_for_readiness`` against real local HTTP servers producing the
exact response shapes.

Round-4 finding 5: the runbook's post-upgrade pipeline must not print
"clean boot" when journal retrieval FAILS — the documented script is
extracted VERBATIM from ``docs/OPERATOR_RUNBOOK.md`` and executed
against fakes (all-active+clean, retrieval failure, error lines,
missing unit).

Round-4 finding 3: the SELECTED credential variable name (``--db-url-
env`` accepts any name) must never reach a Runner child environment.
"""
from __future__ import annotations

import http.server
import json
import os
import pathlib
import re
import subprocess
import threading

import pytest

from deploy import upgrade as up


def _serve(handler_cls) -> tuple[http.server.ThreadingHTTPServer, int]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _handler(responses: dict[str, tuple[int, bytes, str]]):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            code, body, ctype = responses.get(
                self.path, (404, b"{}", "application/json"))
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


HEAD = "0027"
OK = json.dumps({"ready": True, "migration_version": HEAD,
                 "issues": []}).encode()


@pytest.mark.parametrize(
    "path,status,body,ctype,expect_ready",
    [
        ("/readyz", 200, OK, "application/json", True),
        # the reproduced production shape: 200 with ready:false
        ("/readyz", 200, json.dumps(
            {"ready": False, "migration_version": "0019",
             "issues": ["schema 0019 behind head 0027"]}).encode(),
         "application/json", False),
        # ready:true but a contradiction: issues non-empty -> NOT ready
        ("/readyz", 200, json.dumps(
            {"ready": True, "migration_version": HEAD,
             "issues": ["controller: lost the lock"]}).encode(),
         "application/json", False),
        # stale OLD process: ready:true, issues empty, WRONG head
        ("/readyz", 200, json.dumps(
            {"ready": True, "migration_version": "0019",
             "issues": []}).encode(),
         "application/json", False),
        # missing migration_version -> fail closed
        ("/readyz", 200, json.dumps(
            {"ready": True, "issues": []}).encode(),
         "application/json", False),
        # non-bool truthy "true" -> fail closed
        ("/readyz", 200, json.dumps(
            {"ready": "true", "migration_version": HEAD,
             "issues": []}).encode(),
         "application/json", False),
        # HTML (proxy page etc.) -> fail closed
        ("/readyz", 200, b"<html>maintenance</html>", "text/html", False),
        # classic 503 -> not ready
        ("/readyz", 503, b"{}", "application/json", False),
    ],
)
def test_readiness_probe_parses_the_real_contract(path, status, body, ctype,
                                                  expect_ready):
    srv, port = _serve(_handler({path: (status, body, ctype)}))
    try:
        ok, why = up._readiness_probe(f"http://127.0.0.1:{port}{path}",
                                      timeout_s=2, expected_head=HEAD)
        assert ok is expect_ready, why
        if not expect_ready:
            assert why  # always explains the refusal
    finally:
        srv.shutdown()


def test_wait_for_readiness_healthy_and_stale(tmp_path):
    # stale old process reporting ready at the OLD head must time out
    srv, port = _serve(_handler({
        "/readyz": (200, json.dumps(
            {"ready": True, "migration_version": "0019",
             "issues": []}).encode(), "application/json"),
        "/": (200, b"<html>web</html>", "text/html"),
    }))
    m = type("M", (), {"internal_url": f"http://127.0.0.1:{port}"})()
    with pytest.raises(up.UpgradeError, match="readiness CONTRACT"):
        up.wait_for_readiness(m, web_url=f"http://127.0.0.1:{port}/",
                              expected_head=HEAD, timeout_s=2)
    # then the transition to healthy satisfies the contract and returns
    srv2, port2 = _serve(_handler({
        "/readyz": (200, OK, "application/json"),
        "/": (200, b"web", "text/html"),
    }))
    m2 = type("M", (), {"internal_url": f"http://127.0.0.1:{port2}"})()
    out = up.wait_for_readiness(m2, web_url=f"http://127.0.0.1:{port2}/",
                                expected_head=HEAD, timeout_s=5)
    assert out == {"api": "ready", "web": "ready"}
    srv.shutdown()
    srv2.shutdown()


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


def test_selected_credential_env_name_never_reaches_children():
    from deploy import appliance_services as svc
    svc.note_credential_env_names(["REVIEW_PRIVATE_OWNER_R4"])
    assert "REVIEW_PRIVATE_OWNER_R4" in svc.credential_env_names()
    from deploy.appliance import Runner
    probe = (
        "import os, sys; sys.stdout.write("
        "'owner:' + ('LEAK' if 'REVIEW_PRIVATE_OWNER_R4' in os.environ "
        "else 'clean') + ' pass:' + ('LEAK' if 'PGPASSFILE' in os.environ "
        "else 'clean'))")
    # AMBIENT path: variables the operator exported for the CLI process
    # must not survive into Runner children once registered/known.
    os.environ["REVIEW_PRIVATE_OWNER_R4"] = "postgresql://u:s3cr3t@h/db"
    os.environ["PGPASSFILE"] = "/tmp/nope"
    try:
        proc = Runner(dry_run=False)("python3", "-c", probe, check=False)
        assert (proc.stdout or "") == "owner:clean pass:clean", proc.stdout
    finally:
        os.environ.pop("REVIEW_PRIVATE_OWNER_R4", None)
        os.environ.pop("PGPASSFILE", None)
