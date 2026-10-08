"""Regressions for the acceptance harness itself (milestone-01 review).

The harness decides acceptance, so its own counting, audit-evaluation,
fixture-ownership and CI-workflow logic must not fail open. These are fast,
infrastructure-free unit tests over the harness's pure functions (docker is
fault-injected, never required).
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import subprocess

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


acc = _load("sr_acceptance", "infra/dev/acceptance.py")
pgf = _load("sr_pg_fixture", "infra/dev/pg_fixture.py")


def test_parse_counts_uses_pytest_labels_exactly():
    c = acc.parse_counts("1 failed, 2 passed, 3 skipped, 4 deselected, 5 errors "
                         "in 9.0s")
    assert c == {"failed": 1, "passed": 2, "skipped": 3, "deselected": 4,
                 "error": 5}
    # the exact key the skip gate reads — a renamed key fails the gate open
    assert c["skipped"] == 3


def test_skip_gate_reads_the_skipped_key_not_a_missing_one():
    # regression (review P2): counts.get("skip") never matched pytest's
    # "skipped" label, so a skipped fast test passed the infrastructure-free
    # gate. The harness must only ever ask for "skipped".
    src = (REPO / "infra" / "dev" / "acceptance.py").read_text()
    assert not re.search(r'counts\.get\(["\']skip["\']', src), \
        "harness asks for a nonexistent 'skip' count key again"


def test_require_selection_fails_on_empty_and_passes_on_any_selection():
    with pytest.raises(acc.Failed):
        acc.require_selection({"deselected": 100}, "db")
    with pytest.raises(acc.Failed):
        acc.require_selection({}, "packet")
    acc.require_selection({"passed": 1, "deselected": 10}, "db")
    acc.require_selection({"failed": 1}, "db")
    acc.require_selection({"skipped": 1}, "db")  # non-empty: the layer ran


CLEAN = ('{"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,'
         '"high":0,"critical":0}}}')


def test_interpreter_spec_matches_the_running_interpreter(monkeypatch):
    # CI matrix jobs run the gate ON the requested interpreter; GitHub
    # runners have neither uv nor a bare `3.12` binary on PATH, so the
    # running interpreter must count as the spec it names.
    import sys
    cur = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert acc._interpreter_for(cur) == sys.executable
    assert acc._interpreter_for(f"{cur}.{sys.version_info.micro}") == sys.executable
    # an unrelated spec with no binary and no uv is a prerequisite failure
    monkeypatch.setattr(acc.shutil, "which", lambda n: None)
    assert acc._interpreter_for("9.99") is None


def test_audit_evaluation_fails_closed():
    F = acc.Failed
    # error response (registry unreachable) is NEVER zero findings
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"error":{"code":"ENOTFOUND"}}', 1)
    # unparsable / empty output
    with pytest.raises(F):
        acc.audit_vulnerabilities("", 1)
    with pytest.raises(F):
        acc.audit_vulnerabilities("not json", 0)
    # structurally valid but missing the metadata the gate evaluates
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"advisories":{}}', 0)
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"metadata":{}}', 0)
    # clean and dirty metadata both parse to their severity map
    assert acc.audit_vulnerabilities(CLEAN, 0) == {"info": 0, "low": 0,
                                                   "moderate": 0, "high": 0,
                                                   "critical": 0}
    v = acc.audit_vulnerabilities(
        '{"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,'
        '"high":2,"critical":0}}}', 1)
    assert v["high"] == 2


def test_audit_evaluation_rejects_incomplete_or_inconsistent_reports():
    # review P2 round 3: an EMPTY severity map and an impossible exit status
    # must not read as clean
    F = acc.Failed
    with pytest.raises(F):
        acc.audit_vulnerabilities('{"metadata":{"vulnerabilities":{}}}', 0)
    with pytest.raises(F):  # missing severity keys is an incomplete report
        acc.audit_vulnerabilities('{"metadata":{"vulnerabilities":{"high":0}}}', 0)
    with pytest.raises(F):  # exit 2 is an audit ERROR, not a clean run
        acc.audit_vulnerabilities(CLEAN, 2)
    with pytest.raises(F):
        acc.audit_vulnerabilities(CLEAN, -1)
    with pytest.raises(F):  # exit 0 (clean) yet findings reported
        acc.audit_vulnerabilities(
            '{"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,'
            '"high":1,"critical":0}}}', 0)
    with pytest.raises(F):  # exit 1 (findings) yet all counts zero
        acc.audit_vulnerabilities(CLEAN, 1)
    with pytest.raises(F):  # negative / non-integer counts
        acc.audit_vulnerabilities(
            '{"metadata":{"vulnerabilities":{"info":-1,"low":0,"moderate":0,'
            '"high":0,"critical":0}}}', 1)
        acc.audit_vulnerabilities(
            '{"metadata":{"vulnerabilities":{"info":"0","low":0,"moderate":0,'
            '"high":0,"critical":0}}}', 0)


class _FakeR:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


NO_SUCH_CONTAINER = "Error response from daemon: No such container: xyz"
NO_SUCH_VOLUME = "Error response from daemon: No such volume: xyz"


def _fake_docker(monkeypatch, *, nonce, volume="absent", container="absent",
                 fail_on=None, timeout_on=None, planted=False,
                 volume_planted=False, identity_error=False):
    """Fault-inject pg_fixture's docker calls; returns the call log.

    Resources come into existence through THIS fixture's own create calls
    (carrying `nonce`), so cleanup identity checks see reality: our creates
    match, a `planted` run conflict carries someone else's nonce, and
    `identity_error` makes every nonce lookup fail. `volume_planted`
    reproduces docker's real idempotence: `volume create` SUCCEEDS for an
    existing volume but keeps the FOREIGN label.
    """
    calls: list[list[str]] = []
    state = {"volume": volume, "container": container,
             "volume_nonce": None, "container_nonce": None}

    def fake(args, timeout=120, check=False):
        calls.append(list(args))
        head = args[:2]
        if head == ["volume", "create"]:
            if timeout_on == ["volume", "create"]:
                raise subprocess.TimeoutExpired(cmd=["docker", *args], timeout=1)
            if fail_on == ["volume", "create"]:
                return _FakeR(1, "", "injected failure")
            state["volume"] = "exists"
            state["volume_nonce"] = ("someone-else" if volume_planted
                                     else nonce)
            return _FakeR(0)
        if head == ["run", "-d"]:
            if planted:
                # raced collision: a FOREIGN container takes the name
                state["container"] = "exists"
                state["container_nonce"] = "someone-else"
                return _FakeR(1, "", "Conflict. The container name is already in use")
            state["container"], state["container_nonce"] = "exists", nonce
            if timeout_on == ["run", "-d"]:
                raise subprocess.TimeoutExpired(cmd=["docker", *args], timeout=1)
            if fail_on == ["run", "-d"]:
                return _FakeR(1, "", "injected failure")
            return _FakeR(0)
        if identity_error and "-f" in args[:3]:
            return _FakeR(1, "", "Error response from daemon: cannot connect")
        if head == ["volume", "inspect"]:
            if len(args) > 3 and args[2] == "-f":  # identity check
                if state["volume"] != "exists":
                    return _FakeR(1, "", NO_SUCH_VOLUME)
                return _FakeR(0, state["volume_nonce"] or "")
            return _state_r(state, "volume")
        if args[0] == "inspect":
            if len(args) > 3 and args[1] == "-f":  # identity check
                if state["container"] != "exists":
                    return _FakeR(1, "", NO_SUCH_CONTAINER)
                return _FakeR(0, state["container_nonce"] or "")
            return _state_r(state, "container")
        if args[0] in ("version", "image"):
            return _FakeR(0)
        return _FakeR(0)

    monkeypatch.setattr(pgf, "_docker", fake)
    return calls


def _state_r(state, kind):
    v = state[kind]
    if v == "exists":
        return _FakeR(0)
    if v == "absent":
        return _FakeR(1, "", NO_SUCH_VOLUME if kind == "volume"
                      else NO_SUCH_CONTAINER)
    return _FakeR(1, "", "Error response from daemon: cannot connect to the "
                         "docker daemon")  # error, NOT absence


def test_pg_fixture_timeout_cleans_up_every_partial_state(monkeypatch):
    # a TimeoutExpired (not just a nonzero exit) during startup must still
    # clean up everything already claimed — when it exists under OUR nonce
    calls = _fake_docker(monkeypatch, nonce="t1",
                         timeout_on=["volume", "create"])
    fx = pgf.PgFixture(run_id="t1")
    with pytest.raises(RuntimeError):
        fx.start()
    # volume create timed out and the volume does not exist: nothing to rm
    assert not any(c[:2] == ["volume", "rm"] for c in calls)
    assert not any(c[0] == "rm" for c in calls)

    # timeout during `run` AFTER the container was created (nonce matches)
    calls = _fake_docker(monkeypatch, nonce="t2",
                         timeout_on=["run", "-d"])
    fx = pgf.PgFixture(run_id="t2")
    with pytest.raises(RuntimeError):
        fx.start()
    assert ["rm", "-f", fx.container] in calls
    assert ["volume", "rm", fx.volume] in calls


def test_pg_fixture_nonzero_exit_cleans_up(monkeypatch):
    calls = _fake_docker(monkeypatch, nonce="t3", fail_on=["run", "-d"])
    fx = pgf.PgFixture(run_id="t3")
    with pytest.raises(RuntimeError):
        fx.start()
    assert ["rm", "-f", fx.container] in calls
    assert ["volume", "rm", fx.volume] in calls


def test_pg_fixture_refuses_foreign_names_and_never_removes_them(monkeypatch):
    # a name collision is NOT ownership — refuse, and cleanup must never
    # rm the foreign resource
    calls = _fake_docker(monkeypatch, nonce="t4", volume="exists")
    fx = pgf.PgFixture(run_id="t4")
    with pytest.raises(RuntimeError, match="already exists"):
        fx.start()
    assert not any(c[0] == "rm" or c[:2] == ["volume", "rm"] for c in calls)
    assert fx.cleanup() == []  # nothing claimed, nothing touched

    calls = _fake_docker(monkeypatch, nonce="t5", container="exists")
    fx = pgf.PgFixture(run_id="t5")
    with pytest.raises(RuntimeError, match="already exists"):
        fx.start()
    assert ["volume", "rm", fx.volume] in calls  # OUR volume, our nonce
    assert ["rm", "-f", fx.container] not in calls  # foreign container kept
    fx.cleanup()


def test_pg_fixture_raced_collision_is_never_deleted(monkeypatch):
    # review P2 round 4: inspection says absent, then `docker run` fails
    # because someone planted a container with our name in the race window.
    # Cleanup must NOT delete it — identity (nonce) is verified first.
    calls = _fake_docker(monkeypatch, nonce="t6", planted=True)
    fx = pgf.PgFixture(run_id="t6")
    with pytest.raises(RuntimeError, match="left in place"):
        fx.start()
    assert ["rm", "-f", fx.container] not in calls  # foreign kept
    # review P2 round 5: the unresolved foreign resource keeps the cleanup
    # obligation — a second cleanup must RETRY/RE-REPORT, not silence it
    problems = fx.cleanup()
    assert problems and "left in place" in problems[0]
    assert ["rm", "-f", fx.container] not in calls
    # ...and once it is genuinely gone, the obligation resolves
    calls2 = _fake_docker(monkeypatch, nonce="t6")  # everything absent
    assert fx.cleanup() == []


def test_pg_fixture_raced_volume_is_never_mounted(monkeypatch):
    # review P2 round 5: docker volume create SUCCEEDS for an existing
    # volume and keeps its foreign label. The fixture must verify its nonce
    # landed BEFORE mounting the volume into postgres — and must never
    # remove the foreign volume.
    calls = _fake_docker(monkeypatch, nonce="t9", volume_planted=True)
    fx = pgf.PgFixture(run_id="t9")
    with pytest.raises(RuntimeError, match="refusing to mount"):
        fx.start()
    assert not any(c[:2] == ["run", "-d"] for c in calls)  # never mounted
    assert ["volume", "rm", fx.volume] not in calls  # foreign kept
    problems = fx.cleanup()  # obligation retained
    assert problems and "left in place" in problems[0]
    assert ["volume", "rm", fx.volume] not in calls


def test_pg_fixture_inspection_error_is_not_absence(monkeypatch):
    # review P2 round 4: a failed inspection (daemon error) must NOT be
    # treated as a free name — ownership is never claimed, nothing removed
    calls = _fake_docker(monkeypatch, nonce="t7", volume="error")
    fx = pgf.PgFixture(run_id="t7")
    with pytest.raises(RuntimeError, match="cannot verify"):
        fx.start()
    assert not any(c[:2] == ["volume", "create"] for c in calls)
    assert not any(c[0] == "rm" or c[:2] == ["volume", "rm"] for c in calls)
    assert fx.cleanup() == []


def test_pg_fixture_unconfirmable_identity_is_not_deleted(monkeypatch):
    # cleanup verifies the nonce BEFORE deleting; if that check errors, the
    # resource is left in place, the problem is surfaced, and the claim is
    # RETAINED for retry (review P2 round 5)
    calls = _fake_docker(monkeypatch, nonce="t8", fail_on=["run", "-d"],
                         identity_error=True)
    fx = pgf.PgFixture(run_id="t8")
    with pytest.raises(RuntimeError, match="NOT removed"):
        fx.start()
    assert ["rm", "-f", fx.container] not in calls
    problems = fx.cleanup()  # retry obligation retained
    assert problems and "retry pending" in problems[0]
    _fake_docker(monkeypatch, nonce="t8")  # identity resolvable, gone
    assert fx.cleanup() == []  # resolved: obligation cleared


# ---------------------------------------------------------------- cgroup wrapper
WRAPPER = REPO / "infra" / "dev" / "run_in_cgroup.sh"


def test_cgroup_wrapper_refuses_non_root_and_bad_usage():
    # the privileged phase must never run unprivileged
    r = subprocess.run(["bash", str(WRAPPER), "/tmp", "someuser", "true"],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "sudo" in (r.stderr + r.stdout)
    r = subprocess.run(["bash", str(WRAPPER)], capture_output=True, text=True)
    assert r.returncode != 0  # missing arguments


def test_cgroup_wrapper_dropped_probe_needs_real_cgroup(tmp_path):
    # the unprivileged probe must FAIL (not silently pass) when the target
    # is not a cgroup — a missing cgroup.procs is a hard error
    r = subprocess.run(["bash", str(WRAPPER), "--dropped", str(tmp_path),
                        "true"], capture_output=True, text=True)
    assert r.returncode != 0
    # and it must leave nothing behind
    assert not list(tmp_path.iterdir())


# ---------------------------------------------------------------- workflow
WORKFLOW_ALLOWED_TOP = {"name", "on", "permissions", "env", "defaults",
                        "concurrency", "jobs"}
WORKFLOW_ALLOWED_JOB = {"needs", "name", "if", "runs-on", "steps", "strategy",
                        "timeout-minutes", "env", "permissions", "container",
                        "services", "continue-on-error", "timeout-minutes"}
WORKFLOW_ALLOWED_STEP = {"id", "name", "uses", "with", "run", "env",
                         "continue-on-error", "timeout-minutes", "if",
                         "working-directory", "shell"}


def test_ci_workflow_is_schema_valid():
    # review P1 round 3: YAML anchors alone do not validate an Actions
    # workflow — unknown top-level keys (e.g. a bare anchor carrier) are
    # rejected by GitHub's schema. Structural validation runs here so the
    # mistake cannot silently return.
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    assert isinstance(doc, dict)
    # YAML 1.1 folds the `on:` key to boolean True — normalise before checking
    top_keys = {("on" if k is True else k) for k in doc}
    unknown = top_keys - WORKFLOW_ALLOWED_TOP
    assert not unknown, f"invalid top-level workflow keys: {unknown}"
    assert "jobs" in doc and doc["jobs"]
    for job_id, spec in doc["jobs"].items():
        assert isinstance(spec, dict), job_id
        bad = set(spec) - WORKFLOW_ALLOWED_JOB
        assert not bad, f"{job_id}: invalid job keys {bad}"
        assert "runs-on" in spec, job_id
        steps = spec.get("steps")
        assert isinstance(steps, list) and steps, job_id
        for step in steps:
            # an aliased step must expand to a flat mapping, never a list
            assert isinstance(step, dict), f"{job_id}: nested step list {step}"
            bad = set(step) - WORKFLOW_ALLOWED_STEP
            assert not bad, f"{job_id}: invalid step keys {bad}"
            assert ("uses" in step) != ("run" in step), \
                f"{job_id}: step needs exactly one of uses/run: {step}"
            if "uses" in step:
                assert isinstance(step["uses"], str) and step["uses"]
