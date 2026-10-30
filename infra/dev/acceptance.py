#!/usr/bin/env python3
"""Milestone-01 acceptance harness — real checks, exact results.

Every subcommand executes the REAL commands for one acceptance gate, prints
exact pass/fail/skip/deselect counts and the exact environment used, and
exits non-zero on ANY unresolved prerequisite, failed check, or cleanup
problem. Nothing here fabricates a verdict: a layer whose prerequisites are
absent FAILS (required-mode semantics), it never silently passes.

Privilege discipline: the packet layer applies rules ONLY inside disposable
network namespaces (its tests do this by construction); this developer host
is not an approved privileged fixture, so `packet` correctly FAILS here when
root/nft are absent. compose/browser touch only run-owned names/ports and
clean exactly what they created.

Usage:
    python infra/dev/acceptance.py <check>

Checks: selection | python | db | containment | authority | packet
        | frontend | compose | browser | images | capture
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

REPO = pathlib.Path(__file__).resolve().parents[2]
PY = sys.executable
LAYERS = ("db", "containment", "packet", "authority", "browser", "live",
          "images", "capture", "hypervisor", "access", "journey", "agent",
          "practice")
COUNT_RE = re.compile(r"(\d+) (passed|failed|errors?|skipped|deselected)")


# -------------------------------------------------------------------------- #
# plumbing                                                                     #
# -------------------------------------------------------------------------- #

class Failed(Exception):
    pass


class PrerequisiteMissing(Failed):
    """A gate that could not run because the ENVIRONMENT lacks something.

    It is NOT a pass and NOT a product failure: the release matrix reports
    it as pending with the exact missing prerequisite, so a gate can never
    be quietly dropped from the aggregate.
    """


AUDIT_SEVERITIES = ("info", "low", "moderate", "high", "critical")


def audit_vulnerabilities(stdout: str, returncode: int) -> dict:
    """Strictly evaluate `npm audit --json` output. FAILS on an error
    response (registry unreachable, bad lockfile...), unparsable output,
    missing/incomplete severity metadata, or an exit status inconsistent
    with the reported findings — an audit that never ran, ran partially,
    or disagrees with itself must never read as zero findings (review P2:
    fail closed)."""
    if returncode not in (0, 1):
        raise Failed(f"production audit exited {returncode} — only 0 (clean) "
                     "and 1 (findings present) are valid audit outcomes")
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        raise Failed(f"production audit produced unparsable JSON "
                     f"(exit {returncode}): {stdout[:300]!r}")
    if not isinstance(data, dict) or "error" in data:
        err = data.get("error") if isinstance(data, dict) else data
        raise Failed(f"production audit errored (exit {returncode}): "
                     f"{str(err)[:300]}")
    meta = data.get("metadata")
    if not isinstance(meta, dict) or not isinstance(meta.get("vulnerabilities"), dict):
        raise Failed(f"production audit JSON lacks metadata.vulnerabilities "
                     f"(exit {returncode}) — refusing to treat it as clean")
    vulns = meta["vulnerabilities"]
    missing = [s for s in AUDIT_SEVERITIES if s not in vulns]
    if missing:
        raise Failed(f"production audit metadata lacks severity counts {missing} "
                     f"(exit {returncode}) — incomplete report is not clean")
    for key, val in vulns.items():
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise Failed(f"production audit severity count {key}={val!r} is not "
                         f"a nonnegative integer (exit {returncode})")
    total = sum(vulns[s] for s in AUDIT_SEVERITIES)
    if returncode == 0 and total != 0:
        raise Failed(f"audit exited 0 (clean) yet reports {total} findings — "
                     "inconsistent result is not accepted")
    if returncode == 1 and total == 0:
        raise Failed("audit exited 1 (findings present) yet every severity is "
                     "zero — inconsistent result is not accepted")
    return vulns


def env_summary(extra: dict | None = None) -> str:
    keys = ("SR_PG_ADMIN_URL", "SR_REQUIRE_DB", "SR_REQUIRE_CONTAINMENT",
            "SR_REQUIRE_PACKET", "SR_REQUIRE_AUTHORITY", "SR_REQUIRE_BROWSER",
            "SR_REQUIRE_IMAGES", "SR_REQUIRE_CAPTURE", "SR_REQUIRE_HYPERVISOR",
            "SR_REQUIRE_ACCESS", "SR_REQUIRE_JOURNEY", "SR_REQUIRE_AGENT",
            "SR_APPLIANCE_BASE_IMAGE",
            "RUNNER_CGROUP_ROOT",
            "SR_E2E_API_PORT", "SR_E2E_WEB_PORT", "SR_COMPOSE_PROJECT")
    env = {k: os.environ.get(k, "") for k in keys if os.environ.get(k)}
    if extra:
        env.update(extra)
    # never echo credentials
    if "SR_PG_ADMIN_URL" in env:
        env["SR_PG_ADMIN_URL"] = re.sub(r":[^/@]+@", ":***@", env["SR_PG_ADMIN_URL"])
    return json.dumps(env, sort_keys=True)


def run(cmd: list[str], env: dict | None = None, cwd=None, timeout: int = 3600,
        echo: bool = True):
    if echo:
        print(f"$ {' '.join(str(c) for c in cmd)}"
              + (f"   [cwd={cwd}]" if cwd else ""), flush=True)
    return subprocess.run([str(c) for c in cmd], env=env, cwd=cwd,
                          capture_output=True, text=True, timeout=timeout)


def parse_counts(out: str) -> dict:
    counts: dict[str, int] = {}
    for value, label in COUNT_RE.findall(out):
        counts["error" if label == "errors" else label] = int(value)
    return counts


def require_selection(counts: dict, layer: str) -> None:
    """A required layer that selects NOTHING is never acceptance."""
    if counts.get("passed", 0) + counts.get("failed", 0) + \
            counts.get("skipped", 0) == 0:
        fail(f"required layer {layer} selects tests",
             f"empty selection ({counts}) — a required layer must execute")


def pytest_run(args: list[str], env: dict | None = None, timeout: int = 3600):
    e = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    if env:
        e.update(env)
    # --tb=line: every failure contributes ONE traceback line (file:line:
    # message). Without it a -q run's tracebacks sit far above the failure
    # tail this gate prints, and a red CI job shows only test NAMES with no
    # reason — undiagnosable (learned the hard way on the first CI run).
    r = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--tb=line", *args], env=e, cwd=REPO, timeout=timeout)
    counts = parse_counts(r.stdout)
    print(f"  -> exit {r.returncode}; counts {counts or '{}'}")
    return r, counts


def collect(args: list[str], env: dict | None = None) -> set[str]:
    e = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    if env:
        e.update(env)
    r = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--collect-only", *args], env=e, cwd=REPO, timeout=300, echo=False)
    ids = {line.strip() for line in r.stdout.splitlines() if "::" in line}
    # exit 5 = "no tests collected" — a legitimate empty layer selection
    if r.returncode not in (0, 5) and not ids:
        raise Failed(f"collection failed ({r.returncode}):\n{r.stdout[-600:]}")
    return ids


def ok(name: str, detail: str = "") -> None:
    print(f"[PASS] {name}" + (f" — {detail}" if detail else ""))


def fail(name: str, detail: str = "") -> None:
    print(f"[FAIL] {name}" + (f" — {detail}" if detail else ""))
    raise Failed(name)


def prereq_fail(name: str, detail: str = "") -> None:
    """The gate did not run: the ENVIRONMENT lacks a prerequisite."""
    print(f"[PENDING] {name}" + (f" — {detail}" if detail else ""))
    raise PrerequisiteMissing(f"{name}: {detail}" if detail else name)


# -------------------------------------------------------------------------- #
# selection: every test classified; required modes fail closed                 #
# -------------------------------------------------------------------------- #

def check_selection() -> None:
    all_ids = collect(["-m", ""])
    default_ids = collect([])
    layer_ids: dict[str, set[str]] = {}
    for layer in LAYERS:
        layer_ids[layer] = collect(["-m", layer])
        print(f"  layer {layer}: {len(layer_ids[layer])} tests")

    integration = set().union(*layer_ids.values())
    unclassified = all_ids - default_ids - integration
    if unclassified:
        fail("all tests classified",
             f"{len(unclassified)} unclassified, e.g. "
             f"{sorted(unclassified)[:5]}")
    leaked = default_ids & integration
    if leaked:
        fail("fast default excludes every integration layer",
             f"{len(leaked)} integration tests in default selection, e.g. "
             f"{sorted(leaked)[:5]}")
    for layer in ("db", "containment", "packet", "authority", "browser",
                  "images", "capture", "hypervisor", "access", "journey",
                  "agent", "practice"):
        if not layer_ids[layer]:
            fail(f"layer {layer} non-empty", "layer selection is empty")
    ok("all tests classified",
       f"{len(all_ids)} total = {len(default_ids)} fast + "
       f"{len(integration)} integration (live may be empty until milestone 11)")

    # The default run must be infrastructure-free: zero prerequisite skips.
    r, counts = pytest_run(["-ra"])
    if r.returncode != 0:
        fail("fast default passes", f"exit {r.returncode}: {r.stdout[-4000:]}")
    if counts.get("skipped", 0):
        fail("fast default has no prerequisite skips", f"{counts}")
    ok("fast default passes without integration prerequisite skips",
       f"{counts.get('passed', 0)} passed, 0 skipped, "
       f"{counts.get('deselected', 0)} deselected")

    # Required-mode mechanisms must FAIL CLOSED:
    # (a) absent prerequisite — containment with a broken cgroup root
    r, _ = pytest_run(["-m", "containment and not db"],
                      env={"SR_REQUIRE_CONTAINMENT": "1",
                           "RUNNER_CGROUP_ROOT": str(pathlib.Path(tempfile.gettempdir()) /
                                                     "sr-acceptance-not-a-cgroup")},
                      timeout=300)
    if r.returncode == 0:
        fail("required mode fails for an absent prerequisite",
             "containment layer PASSED with an unusable cgroup root")
    ok("required mode fails for an absent prerequisite",
       "containment + broken RUNNER_CGROUP_ROOT -> exit "
       f"{r.returncode}")

    # (b) skipped required tests — db layer without any admin configured
    env = {k: v for k, v in os.environ.items()
           if k not in ("SR_PG_ADMIN_URL", "SR_PG_ADMIN_CMD")}
    r, _ = pytest_run(["-m", "db"],
                      env={**env, "SR_REQUIRE_DB": "1"}, timeout=600)
    if r.returncode == 0:
        fail("required mode fails for skipped required tests",
             "db layer PASSED with no admin configured")
    ok("required mode fails for skipped required tests",
       f"db + SR_REQUIRE_DB=1 without admin -> exit {r.returncode}")

    # (c) empty selection — a required layer that selects nothing is a failure
    r, counts = pytest_run(["-m", "packet and not packet"],
                           env={"SR_REQUIRE_PACKET": "1"}, timeout=120)
    selected = counts.get("passed", 0) + counts.get("failed", 0) + \
        counts.get("skipped", 0)
    if selected != 0:
        fail("empty-selection detection", "expected zero selected tests")
    ok("required mode fails for an empty selection",
       "empty selection detected (0 selected -> harness would fail)")


# -------------------------------------------------------------------------- #
# python: fresh locked installs, dependency checks, imports                    #
# -------------------------------------------------------------------------- #

IMPORTS = ("srplatform.api.app", "srplatform.bastion.proxy",
           "telemetry.shipper", "rangectl.cli")


def _interpreter_for(spec: str) -> str | None:
    """Resolve an interpreter spec (path or version like 3.12). The CURRENT
    interpreter counts when it matches the spec: the CI matrix job already
    runs on the requested version with a fresh run-owned locked install, and
    GitHub runners have neither `uv` nor a bare `3.12` binary on PATH.
    uv-managed downloads are allowed otherwise (fresh run-owned envs); a
    missing spec is a prerequisite failure the caller reports."""
    cur = f"{sys.version_info.major}.{sys.version_info.minor}"
    if spec == cur or spec == sys.executable or (
            spec == f"{cur}.{sys.version_info.micro}"):
        return sys.executable
    p = shutil.which(spec)
    if p:
        return p
    if shutil.which("uv"):
        r = run(["uv", "python", "find", spec], echo=False)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()[-1]
        r = run(["uv", "python", "install", spec], echo=False, timeout=600)
        if r.returncode == 0:
            r = run(["uv", "python", "find", spec], echo=False)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().splitlines()[-1]
    return None


def check_python() -> None:
    specs = [s.strip() for s in
             os.environ.get("SR_ACCEPTANCE_PYTHONS", "").split(",") if s.strip()] \
        or [f"{sys.version_info.major}.{sys.version_info.minor}"]
    lock = REPO / "requirements.lock"
    uv = shutil.which("uv")
    checked = 0
    for spec in specs:
        interp = _interpreter_for(spec)
        if not interp:
            fail(f"interpreter {spec} available",
                 "install it (CI matrix provides 3.11-3.13) — required")
        with tempfile.TemporaryDirectory(prefix="sr-acc-venv-") as td:
            venv = pathlib.Path(td) / "venv"
            if uv:
                r = run([uv, "venv", str(venv), "--python", interp])
            else:
                r = run([interp, "-m", "venv", str(venv)])
            if r.returncode != 0:
                fail(f"fresh venv for {spec}", r.stderr[-400:])
            py = venv / "bin" / "python"
            # locked install WITHOUT re-resolving app deps: every lock entry is
            # an exact pin; the project itself installs --no-deps.
            if uv:
                lock_cmd = [uv, "pip", "install", "--python", str(py), "--no-deps",
                            "-r", str(lock)]
                proj_cmd = [uv, "pip", "install", "--python", str(py), "--no-deps",
                            "-e", "."]
            else:
                lock_cmd = [py, "-m", "pip", "install", "--no-deps", "-r", str(lock)]
                proj_cmd = [py, "-m", "pip", "install", "--no-deps", "-e", "."]
            r = run(lock_cmd, timeout=1200)
            if r.returncode != 0:
                fail(f"locked install for {spec}", (r.stderr or r.stdout)[-500:])
            r = run(proj_cmd, cwd=REPO, timeout=600)
            if r.returncode != 0:
                fail(f"project install (--no-deps) for {spec}",
                     (r.stderr or r.stdout)[-500:])
            check = ([uv, "pip", "check", "--python", str(py)] if uv
                     else [py, "-m", "pip", "check"])
            r = run(check, cwd=REPO)
            if r.returncode != 0:
                fail(f"dependency consistency for {spec}",
                     (r.stdout + r.stderr)[-400:])
            for mod in IMPORTS:
                r = run([py, "-c", f"import {mod}"], cwd=REPO, timeout=120)
                if r.returncode != 0:
                    fail(f"import {mod} on {spec}", (r.stderr or r.stdout)[-400:])
            ver = run([py, "--version"], echo=False).stdout.strip()
            checked += 1
            ok(f"fresh locked install + deps check + imports on {ver}",
               f"{len(IMPORTS)} entrypoint imports")
    if not checked:
        fail("at least one interpreter checked", "none were available")


# -------------------------------------------------------------------------- #
# db: disposable cluster, fresh + forward migrations, DB regressions           #
# -------------------------------------------------------------------------- #

def _pg_fixture():
    sys.path.insert(0, str(REPO / "infra" / "dev"))
    import pg_fixture
    port = os.environ.get("SR_TEST_PG_PORT")
    print(f"  starting disposable {pg_fixture.IMAGE} "
          f"(run-owned container/volume, loopback port {port or 'auto'})")
    return pg_fixture.PgFixture(port=int(port) if port else None).start()


def _fixture_collision_probe() -> None:
    """Foreign-resource regression (review P2): a pre-existing container or
    volume under the fixture's names must be REFUSED, never adopted and
    never removed by the fixture. The probe itself tracks exactly which
    resources it created, verifies its OWN ownership nonce before deleting
    them, and fails acceptance when its teardown does not complete."""
    import pg_fixture
    fx = pg_fixture.PgFixture(run_id="col" + uuid.uuid4().hex[:5])
    marker = f"sr-acc-foreign={fx.run_id}"
    # (kind, create args, removal args) for resources THIS probe creates
    plan = [
        ("volume",
         ["volume", "create", "--label", marker, fx.volume],
         ["volume", "rm", fx.volume]),
        ("container",
         ["create", "--label", marker, "--name", fx.container,
          pg_fixture.IMAGE, "true"],
         ["rm", "-f", fx.container]),
    ]
    created: list[tuple[str, list[str]]] = []
    try:
        for kind, mk, rm in plan:
            r = subprocess.run(["docker", *mk], capture_output=True, text=True)
            if r.returncode != 0:
                fail("fixture collision probe setup",
                     f"docker {kind} create: "
                     f"{(r.stderr or r.stdout).strip()[:200]}")
            created.append((kind, rm))
        try:
            fx.start()
            started_ok = True
        except RuntimeError:
            started_ok = False
        if started_ok:
            fail("fixture refuses pre-existing names", "start() succeeded")
        problems = fx.cleanup()
        if problems:
            fail("fixture collision cleanup", "; ".join(problems))
        if _docker_probe(["inspect", fx.container]) != 0:
            fail("collision refusal leaves foreign resources untouched",
                 f"foreign container {fx.container} was removed")
        if _docker_probe(["volume", "inspect", fx.volume]) != 0:
            fail("collision refusal leaves foreign resources untouched",
                 f"foreign volume {fx.volume} was removed")
        ok("DB fixture refuses pre-existing names and never removes "
           "resources it did not create")
    finally:
        leftovers = []
        for kind, rm in created:
            name = rm[-1]
            # verify the probe's OWN nonce before deleting: never remove a
            # resource this probe did not (still) own
            fmt = ('{{ index .Config.Labels "sr-acc-foreign" }}'
                   if kind == "container"
                   else '{{ index .Labels "sr-acc-foreign" }}')
            probe_args = (["inspect", "-f", fmt, name] if kind == "container"
                          else ["volume", "inspect", "-f", fmt, name])
            r = subprocess.run(["docker", *probe_args],
                               capture_output=True, text=True)
            if r.returncode != 0:
                if "no such" not in (r.stderr or "").lower():
                    leftovers.append(f"{kind} {name}: identity check failed: "
                                     f"{(r.stderr or r.stdout).strip()[:150]}")
                continue  # already gone
            if r.stdout.strip() != fx.run_id:
                leftovers.append(f"{kind} {name}: nonce {r.stdout.strip()!r} "
                                 "is not this probe's — left in place")
                continue
            r = subprocess.run(["docker", *rm], capture_output=True, text=True)
            err = (r.stderr or "").lower()
            if (r.returncode != 0 and "no such" not in err
                    and "not found" not in err):
                leftovers.append(f"{kind} {name}: "
                                 f"{(r.stderr or r.stdout).strip()[:150]}")
        if leftovers:
            fail("collision probe teardown (only probe-owned resources)",
                 "; ".join(leftovers))


def _fixture_failure_probe() -> None:
    """Failure-path regression (review P2): a start that fails partway (here:
    an occupied port) must surface the error AND strand nothing — the run's
    unique container/volume names must be gone afterwards."""
    import pg_fixture
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    port = blocker.getsockname()[1]
    fx = pg_fixture.PgFixture(port=port)
    try:
        try:
            fx.start()
            started_ok = True
        except RuntimeError:
            started_ok = False
        if started_ok:
            fail("DB fixture fails on an occupied port", "start() succeeded")
        problems = fx.cleanup()
        if problems:
            fail("DB fixture partial-startup cleanup", "; ".join(problems))
        if _docker_probe(["inspect", fx.container]) == 0:
            fail("DB fixture partial-startup cleanup",
                 f"container {fx.container} survived the failed start")
        if _docker_probe(["volume", "inspect", fx.volume]) == 0:
            fail("DB fixture partial-startup cleanup",
                 f"volume {fx.volume} survived the failed start")
        ok("DB fixture failure path: occupied port fails and strands nothing")
    finally:
        problems = fx.cleanup()
        blocker.close()
        if problems:
            fail("DB fixture failure-probe teardown", "; ".join(problems))


def _docker_probe(args: list[str]) -> int:
    return subprocess.run(["docker", *args], capture_output=True).returncode


def check_agent() -> None:
    """Conversational agent + model administration (plan 19): the pinned
    Pydantic AI layer, the durable one-slot queue, pins/rotation/rebind and
    cancellation obligations, exercised against the REAL wire (a local
    scripted OpenAI-compatible server) and a disposable PostgreSQL. A skip
    is never acceptance: SR_REQUIRE_AGENT converts skips to failures."""
    fx = _pg_fixture()
    try:
        env = {"SR_PG_ADMIN_URL": fx.admin_url(), "SR_REQUIRE_DB": "1",
               "SR_REQUIRE_AGENT": "1"}
        r, counts = pytest_run(["-m", "agent"], env=env, timeout=1800)
        require_selection(counts, "agent")
        if r.returncode != 0:
            fail("conversational agent + model administration layer",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        ok("agent layer passes in required mode",
           f"{counts.get('passed', 0)} passed, {counts.get('failed', 0)} "
           f"failed, {counts.get('skipped', 0)} skipped, "
           f"{counts.get('deselected', 0)} deselected")
    finally:
        fx.cleanup()


def check_practice() -> None:
    """Plan 22 installed-practice repair batch (required mode).

    Reproduces the installed findings against REAL enforcement instead of
    mocks — kernel DAC across distinct UIDs in unprivileged user
    namespaces, disposable DB and browser lanes where a practice test needs
    them. A required layer never passes on skips: SR_REQUIRE_PRACTICE is
    set, any skipped test fails, and an environment without the namespace
    prerequisites FAILS the gate with the exact missing piece rather than
    vacuously passing. AC-2 additionally runs the plan-22 regression matrix
    (admission unchanged/aged vs changed/failed/unknown, enrollment merge,
    role policy, canonical citations) inside the same required-mode gate.
    """
    import os
    import shutil
    import subprocess

    if shutil.which("unshare") is None:
        prereq_fail("practice prerequisites", "the unshare binary is absent")
    probe = subprocess.run(
        ["unshare", "--user",
         f"--map-users=0:{os.getuid()}:1", "--map-users=1:10000:2",
         f"--map-groups=0:{os.getgid()}:1", "--map-groups=1:10000:2",
         "true"],
        capture_output=True, text=True, timeout=30)
    if probe.returncode != 0:
        prereq_fail(
            "practice prerequisites (unprivileged user namespaces + "
            "subuid/subgid mappings)",
            f"unshare probe exit {probe.returncode}: "
            f"{(probe.stderr or probe.stdout).strip()[:200]}")
    fx = None
    env = {"SR_REQUIRE_PRACTICE": "1"}
    try:
        fx = _pg_fixture()
        env["SR_PG_ADMIN_URL"] = fx.admin_url()
        env["SR_REQUIRE_DB"] = "1"
    except Exception as exc:  # noqa: BLE001 — no docker: db practice tests decide
        print(f"  (no disposable DB for the practice lane: {str(exc)[:120]})")
    try:
        r, counts = pytest_run(["-m", "practice"], env=env, timeout=1800)
        require_selection(counts, "practice")
        if r.returncode != 0:
            fail("installed-practice repairs (real DAC/namespaces/DB)",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        if counts.get("skipped", 0):
            fail("practice layer never accepts skips", str(counts))
        # AC-2: the gate must ALSO run, in required mode, the LIVE-regression
        # and admission-matrix cases (unchanged/aged versus changed/failed/
        # unknown, enrollment merge + hot reload, role policy, canonical
        # citations). They belong to the fast lane (no infra) and carry no
        # practice marker, so they are named explicitly here; db rows in the
        # same files stay out, and any skip is a failure.
        r2, counts2 = pytest_run(
            ["-m", "not db and not browser and not live",
             "tests/test_plan22_safety_qualification.py",
             "tests/test_plan22_bastion_enrollment.py",
             "tests/test_plan22_coach_provenance.py"],
            env=env, timeout=1200)
        require_selection(counts2, "practice regression matrix")
        if r2.returncode != 0 or counts2.get("skipped", 0):
            fail("installed-practice regression matrix",
                 f"exit {r2.returncode}, counts {counts2}:\n"
                 f"{r2.stdout[-6000:]}")
        ok("practice layer passes in required mode",
           f"{counts.get('passed', 0)} + {counts2.get('passed', 0)} passed "
           f"(layer + regression matrix), 0 skipped, "
           f"{counts.get('deselected', 0) + counts2.get('deselected', 0)} "
           "deselected")
    finally:
        if fx is not None:
            problems = fx.cleanup()
            if problems:
                fail("practice DB fixture cleanup", "; ".join(problems))


def check_db() -> None:
    _fixture_failure_probe()
    _fixture_collision_probe()
    fx = _pg_fixture()
    try:
        env = {"SR_PG_ADMIN_URL": fx.admin_url(), "SR_REQUIRE_DB": "1"}
        r, counts = pytest_run(["-m", "db and not browser"], env=env, timeout=3600)
        require_selection(counts, "db")
        if r.returncode != 0:
            fail("disposable DB layer (fresh + forward migrations + regressions)",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        ok("disposable DB layer passes in required mode",
           f"{counts.get('passed', 0)} passed, {counts.get('deselected', 0)} "
           f"deselected, {counts.get('skipped', 0)} skipped")
        leftovers = fx.leftover_test_databases()
        if leftovers:
            fail("owned DB resources cleaned", f"leftovers: {leftovers}")
        ok("owned DB resources cleaned", "no srtest_*/sr_* databases or roles remain")
    finally:
        problems = fx.cleanup()
        if problems:
            fail("DB fixture cleanup", "; ".join(problems))
        ok("DB fixture container/volume removed", fx.container)


# -------------------------------------------------------------------------- #
# containment: required-mode regressions on a real delegated root              #
# -------------------------------------------------------------------------- #

def _cgroup_root() -> str:
    root = os.environ.get("RUNNER_CGROUP_ROOT")
    if root:
        return root
    with open("/proc/self/cgroup") as f:
        path = next(l.split("::", 1)[1].strip() for l in f if l.startswith("0::"))
    return "/sys/fs/cgroup" + path


def _migration_probe(root: str) -> None:
    """Positive control (review P2/B10): prove the delegated subtree grants
    REAL process-migration permission — ownership of a created directory is
    not proof the kernel permits moving processes into it."""
    op = f"probe{uuid.uuid4().hex[:8]}"
    d = pathlib.Path(root) / f"sr-{op}"
    d.mkdir()
    p = subprocess.Popen(["sleep", "30"])
    try:
        try:
            (d / "cgroup.procs").write_text(str(p.pid))
        except OSError as e:
            fail("delegated cgroup permits process migration",
                 f"writing a pid into cgroup.procs failed: {e} — directory "
                 "ownership alone is not migration permission; delegate the "
                 "subtree properly (controllers enabled, writable domain)")
        deadline = time.time() + 5
        while time.time() < deadline:
            if p.pid in [int(x) for x in (d / "cgroup.procs").read_text().split()]:
                break
            time.sleep(0.1)
        else:
            fail("delegated cgroup permits process migration",
                 f"pid {p.pid} never appeared in {d}/cgroup.procs")
        ok("delegated cgroup subtree permits real process migration (positive control)")
    finally:
        p.kill()
        p.wait()
        for _ in range(50):  # cgroup rmdir only succeeds once fully empty
            try:
                d.rmdir()
                break
            except OSError:
                time.sleep(0.1)


def check_containment() -> None:
    root = _cgroup_root()
    if not os.path.isdir(root) or not os.access(root, os.W_OK):
        fail("containment prerequisite", f"no writable delegated cgroup v2 root at {root!r}")
    if not shutil.which("unshare"):
        fail("containment prerequisite", "unshare missing (namespace boundary)")
    # The supervisor REFUSES every start (exit 4) unless the trusted
    # user+mount+cgroup+pid boundary can actually be created AND its two
    # inner mounts succeed: BINDing the operation's own cgroup directory
    # onto /sys/fs/cgroup, and the tmpfs state mask. BIND, not a fresh
    # cgroup2 superblock mount — kernels before the 6.13-era kernfs userns
    # rework refuse that EBUSY from a non-init user namespace (Ubuntu
    # 24.04). Ubuntu 24.04+ also restricts unprivileged user namespaces
    # via AppArmor, and a profile that only grants userns while leaving
    # the process "unconfined" still has capability stripped inside the
    # new namespace — so probe the FULL boundary here, mounts included,
    # instead of letting every test fail on exit 96.
    probe = os.path.join(root, ".sr-boundary-probe")
    os.mkdir(probe)
    try:
        boundary = ["unshare", "--user", "--map-root-user", "--mount",
                    "--cgroup", "--pid", "--fork", "--mount-proc",
                    "sh", "-c", f"mount --bind {probe} /sys/fs/cgroup "
                                "&& mount -t tmpfs tmpfs /mnt"]
        r = run(boundary, echo=False, timeout=60)
    finally:
        os.rmdir(probe)
    if r.returncode != 0:
        fail("trusted command boundary (unshare userns + bind/tmpfs mounts)",
             "the boundary or its inner mounts were refused — unprivileged "
             "user namespaces are restricted here (Ubuntu AppArmor?); the "
             "supervisor would refuse every start. In CI the workflow loads "
             "the scoped CONFINED /usr/bin/unshare AppArmor profile (a "
             "flags=(unconfined) profile is NOT enough — capability is "
             "stripped inside the namespace); do NOT disable the "
             "restriction globally.")
    ok("trusted command boundary (namespaces + cgroup bind + tmpfs mask) creatable")
    _migration_probe(root)
    # full wrapper path (review P1): the UNPRIVILEGED phase of
    # infra/dev/run_in_cgroup.sh — create a child cgroup, migrate a real
    # process into it as the delegatee, verify, kill+wait, rmdir. In CI the
    # wrapper itself is the entry point, so this is the same code path that
    # guards every required containment run.
    wrapper = REPO / "infra" / "dev" / "run_in_cgroup.sh"
    r = subprocess.run([str(wrapper), "--dropped", root, "true"],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        fail("run_in_cgroup.sh unprivileged migration probe",
             f"exit {r.returncode}: {(r.stderr or r.stdout).strip()[-300:]}")
    ok("run_in_cgroup.sh dropped-phase migration probe passes in the subtree")
    before = {p for p in pathlib.Path(root).glob("sr-*")}
    r, counts = pytest_run(["-m", "containment and not db"],
                           env={"SR_REQUIRE_CONTAINMENT": "1"}, timeout=1800)
    if r.returncode != 0:
        fail("containment regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    ok("namespace/recursive-membership/cancellation regressions pass (required mode)",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")
    leaked = {p for p in pathlib.Path(root).glob("sr-*")} - before
    if leaked:
        fail("containment fixture cleanup", f"leftover operation cgroups: {leaked}")
    ok("no run-owned cgroups leaked", root)


# -------------------------------------------------------------------------- #
# packet: real isolated packet tests, disposable namespaces only               #
# -------------------------------------------------------------------------- #

def check_packet() -> None:
    missing = [n for n, have in (("root", os.geteuid() == 0),
                                 ("nft", bool(shutil.which("nft"))),
                                 ("ip", bool(shutil.which("ip")))) if not have]
    if missing:
        prereq_fail("packet prerequisites (root + nft + iproute2)",
                    f"missing {missing} — required layer; run in the approved CI "
                    "packet job (rules only inside disposable netns, never host "
                    "namespaces)")
    r, counts = pytest_run(["-m", "packet"], env={"SR_REQUIRE_PACKET": "1"},
                           timeout=1800)
    if r.returncode != 0:
        fail("packet regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    ok("real isolated packet tests pass without host-namespace rules",
       f"{counts.get('passed', 0)} passed")
    # no sr test namespaces may survive the layer
    r = run(["ip", "netns", "list"], echo=False)
    leaked = [n.split(":")[0].strip() for n in r.stdout.splitlines()
              if re.match(r"^\s*(sr|tp|srtest)[_a-z0-9]*:", n)]
    if leaked:
        fail("disposable netns cleanup", f"surviving namespaces: {leaked}")
    ok("no test network namespaces leaked")


# -------------------------------------------------------------------------- #
# frontend: npm ci, production build, production audit gate                    #
# -------------------------------------------------------------------------- #

def check_frontend() -> None:
    web = REPO / "web"
    if not shutil.which("npm"):
        fail("frontend prerequisite", "npm missing")
    r = run(["npm", "ci"], cwd=web, timeout=1800)
    if r.returncode != 0:
        fail("npm ci", (r.stderr or r.stdout)[-600:])
    ok("npm ci (lockfile-faithful install)")
    r = run(["npm", "run", "build"], cwd=web,
            env={**os.environ, "NEXT_TELEMETRY_DISABLED": "1"}, timeout=1800)
    if r.returncode != 0:
        fail("production build", (r.stderr or r.stdout)[-800:])
    ok("production build (next build)")
    r = run(["npm", "audit", "--omit=dev", "--json"], cwd=web, timeout=300)
    vulns = audit_vulnerabilities(r.stdout, r.returncode)
    high, critical = vulns.get("high", 0), vulns.get("critical", 0)
    if not all(isinstance(v, int) for v in vulns.values()):
        fail("production audit metadata", f"non-integer severity counts: {vulns}")
    if high or critical:
        fail("production audit zero high/critical",
             f"high={high} critical={critical} — run `npm audit --omit=dev`")
    ok("production audit: zero high/critical findings",
       f"moderate={vulns.get('moderate', 0)} low={vulns.get('low', 0)} "
       "(applicability documented in docs/FINDINGS_CHECKLIST.md)")


# -------------------------------------------------------------------------- #
# compose: real build + bootstrap + idempotent rerun, run-owned resources      #
# -------------------------------------------------------------------------- #

def _compose_base(project: str, env: dict) -> list[str]:
    return ["docker", "compose", "-p", project]


def check_compose() -> None:
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        fail("compose prerequisite", "docker daemon not reachable")
    project = f"sracc{uuid.uuid4().hex[:8]}"
    run_env = {
        **os.environ,
        "COMPOSE_PROJECT_NAME": project,
        "SR_DEV_OWNER_PASSWORD": "acc-owner-" + uuid.uuid4().hex[:8],
        "SR_DEV_APP_PASSWORD": "acc-app-" + uuid.uuid4().hex[:8],
        "SR_DEV_BASTION_TOKEN": uuid.uuid4().hex,
        "SR_ENV": "dev",
        "SR_COMPOSE_PROJECT": project,
    }
    # Occupy the BASE compose ports (5432/8000/2222) for the whole run: the
    # stack must come up entirely on run-specific ports while the defaults are
    # taken, proving the override REPLACES (not appends to) the mappings.
    held = []
    for port in (5432, 8000, 2222):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            held.append(s)
        except OSError:
            print(f"  note: default port {port} already occupied by another "
                  "process — isolation is still exercised, just not by us")
    # run-specific LOOPBACK ports so parallel/occupied hosts never collide;
    # !override REPLACES the base port list (plain lists merge/append)
    override_dir = tempfile.mkdtemp(prefix="sr-acc-compose-")
    override = pathlib.Path(override_dir) / "override.yml"
    api_port, pg_port, bastion_port = (_free() for _ in range(3))
    override.write_text(
        "services:\n"
        "  postgres:\n"
        "    ports: !override\n"
        f"      - '127.0.0.1:{pg_port}:5432'\n"
        "  api:\n"
        "    ports: !override\n"
        f"      - '127.0.0.1:{api_port}:8000'\n"
        "  bastion:\n"
        "    ports: !override\n"
        f"      - '127.0.0.1:{bastion_port}:2222'\n")
    keys_dir = _synthetic_operator_keys(tempfile.mkdtemp(prefix="sr-acc-keys-"))
    run_env["SR_DEPLOY_KEYS_DIR"] = str(keys_dir)

    def compose(*args, timeout=1800):
        return run([*_compose_base(project, run_env), *args],
                   env=run_env, cwd=REPO, timeout=timeout)

    # the merged config must publish ONLY the run's ports
    r = compose("-f", "docker-compose.yml", "-f", str(override), "config")
    for base_mapping in ("5432:5432", "8000:8000", "2222:2222"):
        if f"127.0.0.1:{base_mapping}" in r.stdout:
            fail("compose port override replaces base mappings",
                 f"merged config still publishes 127.0.0.1:{base_mapping}")
    ok("compose config publishes only run-owned loopback ports",
       f"api {api_port}, pg {pg_port}, bastion {bastion_port}")

    # exact expected migration head, from this checkout's migration tree
    r = run([PY, "-m", "alembic", "heads"], cwd=REPO, timeout=120)
    m = re.search(r"(\S+) \(head\)", r.stdout)
    if r.returncode != 0 or not m:
        fail("resolve alembic head", (r.stdout + r.stderr)[-300:])
    head = m.group(1)

    cleanup_problems: list[str] = []
    try:
        r = compose("-f", "docker-compose.yml", "-f", str(override),
                    "build", timeout=3600)
        if r.returncode != 0:
            fail("compose build", (r.stderr or r.stdout)[-800:])
        ok("compose build (real images from infra/dev/Dockerfile)")

        for attempt in (1, 2):
            r = compose("-f", "docker-compose.yml", "-f", str(override),
                        "up", "-d", "--wait", "--wait-timeout", "120",
                        timeout=600)
            if r.returncode != 0:
                fail(f"compose bootstrap attempt {attempt}",
                     (r.stderr or r.stdout)[-800:])
            ok(f"compose bootstrap attempt {attempt} "
               f"({'fresh' if attempt == 1 else 'idempotent rerun'})")
            _verify_compose_stack(compose, api_port, head, attempt, run_env)
        r = compose("ps", "--format", "json")
        states = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                svc = json.loads(line)
                states[svc.get("Service", "?")] = svc.get("State", "?")
            except json.JSONDecodeError:
                continue
        if states.get("bastion") not in ("running",):
            fail("bastion started after key seeding", str(states))
        ok("bastion running after seed-bastion-keys success gate", str(states))
    finally:
        for s in held:
            s.close()
        r = compose("down", "-v", "--remove-orphans", timeout=300)
        if r.returncode != 0:
            cleanup_problems.append(f"compose down: {(r.stderr or r.stdout)[-200:]}")
        r = run(["docker", "volume", "ls", "-q",
                 "--filter", f"label=com.docker.compose.project={project}"],
                echo=False)
        for vol in r.stdout.split():
            rr = run(["docker", "volume", "rm", vol], echo=False)
            if rr.returncode != 0:
                cleanup_problems.append(f"volume {vol}")
        shutil.rmtree(override_dir, ignore_errors=True)
        shutil.rmtree(keys_dir, ignore_errors=True)
    if cleanup_problems:
        fail("compose cleanup (only run-owned resources)", "; ".join(cleanup_problems))
    ok("compose resources cleaned", f"project {project} fully removed")


def _free() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _synthetic_operator_keys(dirpath: str) -> pathlib.Path:
    """Synthetic key material ONLY (never live infrastructure credentials)."""
    d = pathlib.Path(dirpath)
    d.mkdir(parents=True, exist_ok=True)
    if shutil.which("ssh-keygen"):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C",
                        "synthetic-acceptance", "-f", str(d / "member_acc")],
                       capture_output=True, check=True, timeout=60)
        (d / "authorized_keys").write_text(
            f"{(d / 'member_acc.pub').read_text().strip()} synthetic-acceptance\n")
        (d / "target_known_hosts").write_text(
            "target.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAASyntheticAcceptance\n")
    else:  # ssh-keygen absent: structurally-valid synthetic material
        (d / "authorized_keys").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAASyntheticAcceptance synthetic\n")
        (d / "target_known_hosts").write_text(
            "target.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n")
    return d


def _http_json(method: str, url: str, body: dict | None = None,
               headers: dict | None = None, timeout: int = 10) -> tuple[int, dict]:
    import urllib.error
    import urllib.request
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw.decode(errors="replace")[:200]}


def _verify_compose_stack(compose, api_port: int, head: str, attempt: int,
                          run_env: dict) -> None:
    # 1. migrations applied at bootstrap: EXACT expected head, via the OWNER
    r = compose("exec", "-T", "postgres", "psql", "-U", "sr_owner",
                "-d", "sparring_range", "-tAc",
                "SELECT version_num FROM alembic_version", timeout=60)
    got = r.stdout.strip()
    if r.returncode != 0 or got != head:
        fail("compose migrations at exact head",
             f"want {head!r}, got {got!r} (rc {r.returncode}) "
             f"{(r.stderr or '')[-200:]}")
    ok(f"migrations applied at bootstrap (attempt {attempt})",
       f"alembic version == head {head}")

    # 2. the API runtime must hold app-role credentials ONLY (audit R12)
    r = compose("exec", "-T", "api", "env", timeout=60)
    env_lines = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
    app_pw = run_env["SR_DEV_APP_PASSWORD"]
    if "POSTGRES_URL_OWNER" in env_lines:
        fail("compose credential split", "API env contains POSTGRES_URL_OWNER")
    api_db_url = env_lines.get("POSTGRES_URL", "")
    if ("sr_app:" not in api_db_url or app_pw not in api_db_url
            or "sr_owner" in api_db_url):
        fail("compose credential split",
             f"API POSTGRES_URL is not the interpolated app role: {api_db_url[:80]}")
    ok("API runtime holds app-role credentials only (no owner URL)")

    # 3. DB-backed readiness: /readyz actually queries the DB and the schema
    api = f"http://127.0.0.1:{api_port}"
    deadline = time.time() + 90
    last = None
    while time.time() < deadline:
        try:
            code, body = _http_json("GET", f"{api}/readyz")
            last = (code, body)
            if code == 200 and body.get("ready"):
                break
        except Exception as e:  # noqa: BLE001
            last = str(e)
        time.sleep(2)
    else:
        fail("app-role API readiness (/readyz)", str(last))
    code, body = last
    if body.get("migration_version") != head or body.get("issues"):
        fail("/readyz reports the migrated schema at head",
             f"{code} {json.dumps(body)[:400]}")
    ok(f"/readyz ready with DB + schema at head (attempt {attempt})",
       f"migration_version={body.get('migration_version')}")

    # 4. authenticated app-role account operations + idempotent behavior.
    #    Every write below goes through the API's sr_app connection.
    op_pw = "acc-operator-pw-9"
    code, body = _http_json("POST", f"{api}/auth/bootstrap",
                            {"username": "drew", "password": op_pw})
    if attempt == 1:
        if code != 201:
            fail("operator bootstrap through app-role API", f"{code} {str(body)[:200]}")
    elif code != 403:
        fail("bootstrap stays closed once provisioned (idempotent rerun)",
             f"expected 403, got {code} {str(body)[:200]}")
    code, body = _http_json("POST", f"{api}/auth/login",
                            {"username": "drew", "password": op_pw})
    if code != 200 or "token" not in body:
        fail("operator login through app-role API", f"{code} {str(body)[:200]}")
    op = {"Authorization": f"Bearer {body['token']}"}
    code, body = _http_json("POST", f"{api}/users",
                            {"username": "acc-member", "password": "acc-member-pw-9",
                             "role": "member"}, op)
    if attempt == 1 and code != 201:
        # the body names the REASON ("authentication required" vs "token
        # expired or revoked" vs "bad token") — without it a 401 is
        # unclassifiable after the fact
        fail("member account creation through app-role API",
             f"{code} {str(body)[:200]}")
    if attempt == 2 and code != 409:
        fail("account creation is idempotent-visible (409 on rerun)",
             f"{code} {str(body)[:200]}")
    # the write is really in the DB, readable via the app role
    r = compose("exec", "-T", "postgres", "psql", "-U", "sr_app",
                "-d", "sparring_range", "-tAc",
                "SELECT count(*) FROM users WHERE username = 'acc-member'",
                timeout=60)
    if r.returncode != 0 or r.stdout.strip() != "1":
        fail("app-role account write visible in DB",
             f"rc {r.returncode} out {r.stdout.strip()!r}")
    ok(f"authenticated app-role account ops + idempotence (attempt {attempt})")

    # 5. bastion capability: the stack hands the bastion container
    #    SR_BASTION_TOKEN, but a running bastion proves nothing until that
    #    capability EXISTS in service_tokens and authenticates a scoped
    #    call. Provision the synthetic capability (operator bootstrap path,
    #    owner role) and verify the bastion's target-resolution endpoint
    #    accepts it — before AND after the idempotent rerun.
    tok = run_env["SR_DEV_BASTION_TOKEN"]
    if not re.fullmatch(r"[0-9a-f]{32}", tok):
        fail("bastion token shape", f"expected 32 hex chars, got {tok!r}")
    r = compose("exec", "-T", "postgres", "psql", "-U", "sr_owner",
                "-d", "sparring_range", "-c",
                "INSERT INTO service_tokens (token, scope) "
                f"VALUES ('{tok}', 'bastion') ON CONFLICT (token) DO NOTHING",
                timeout=60)
    if r.returncode != 0:
        fail("provision bastion capability", (r.stderr or r.stdout)[-300:])
    # scoped operation WITH the capability: authenticated, login token
    # absent -> 404. Without it the same call must be refused outright.
    probe = f"{api}/tokens/{uuid.uuid4()}"
    code, _ = _http_json("GET", probe, headers={"Authorization": f"Bearer {tok}"})
    if code != 404:
        fail("bastion capability authenticates a scoped call "
             f"(attempt {attempt})",
             f"expected 404 (authenticated, login token absent), got {code}")
    code, _ = _http_json("GET", probe)
    if code not in (401, 403):
        fail("scoped call without the capability is refused",
             f"expected 401/403, got {code}")
    ok(f"bastion capability issued + scoped call authenticated "
       f"(attempt {attempt})")


# -------------------------------------------------------------------------- #
# browser: isolated real-browser workflow + replay                             #
# -------------------------------------------------------------------------- #

def check_browser() -> None:
    fx = _pg_fixture()
    try:
        env = {"SR_PG_ADMIN_URL": fx.admin_url(),
               "SR_REQUIRE_BROWSER": "1", "SR_REQUIRE_DB": "1"}
        r, counts = pytest_run(["-m", "browser"], env=env, timeout=3600)
        require_selection(counts, "browser")
        if r.returncode != 0:
            fail("isolated real-browser workflow/replay + model-admin GUI",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        ok("isolated real-browser workflows pass (required mode)",
           f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")
    finally:
        problems = fx.cleanup()
        if problems:
            fail("browser DB fixture cleanup", "; ".join(problems))


# -------------------------------------------------------------------------- #
# authority: broker private boundary, durability, cessation (infra-free)      #
# -------------------------------------------------------------------------- #

def check_authority() -> None:
    # The authority layer needs no external service (real policy/ledger/mTLS
    # over loopback), so required mode here mainly pins the selection itself:
    # an empty selection or any skip is a failure, never acceptance.
    r, counts = pytest_run(["-m", "authority"],
                           env={"SR_REQUIRE_AUTHORITY": "1"}, timeout=1200)
    if r.returncode != 0:
        fail("authority regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    if not counts.get("passed"):
        fail("authority layer non-empty", f"selection counts {counts}")
    ok("broker boundary/durability/cessation regressions pass (required mode)",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")


# -------------------------------------------------------------------------- #
# pve-contract (plan 13 phase 2): REAL pinned proxmoxer over synthetic HTTPS  #
# -------------------------------------------------------------------------- #

def check_pve_contract() -> None:
    # The real ProxmoxAPI/requests stack against a local PVE dialect server:
    # /api2/json prefix, PVEAPIToken header, form encoding, task/UPID
    # lifecycle, malformed replies, and the source-checked PVE 9.2 error
    # dialects (absence vs uncertainty) over real HTTP. Infrastructure-free
    # (loopback HTTPS, ephemeral CA), so required mode pins the selection:
    # an empty selection or any skip is a failure, never acceptance.
    r, counts = pytest_run(["-m", "adapter"],
                           env={"SR_REQUIRE_ADAPTER": "1"}, timeout=1200)
    if r.returncode != 0:
        fail("pve-contract regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    if not counts.get("passed"):
        fail("pve-contract layer non-empty", f"selection counts {counts}")
    ok("real-proxmoxer PVE contract regressions pass (required mode)",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")


# -------------------------------------------------------------------------- #
# images (03): real builds/boots/services/seeds/flaws/fixes/readiness         #
# capture (04): installed auditd/srshipper/negatives/recovery/access/replay   #
# -------------------------------------------------------------------------- #
# Both gates boot the ACTUAL built artifacts in isolated QEMU (synthetic
# API/DB/SSH, no host shares, no general egress, run-owned disks/processes,
# bounded cleanup). Max 3 VMs / 6 GiB guest RAM / 60-minute job; KVM optional,
# software emulation (TCG) is the fallback. A missing QEMU prerequisite, an
# empty selection, or a skipped required test FAILS the gate — never a silent
# skip. QEMU is installed in the CI images/capture jobs; on hosts without it
# the gate fails closed with the exact missing prerequisite.

def _qemu_prereqs() -> list[str]:
    missing = []
    if not shutil.which("qemu-system-x86_64") and not shutil.which("qemu-system-x86"):
        missing.append("qemu-system-x86_64 (QEMU with TCG software emulation)")
    if not shutil.which("qemu-img"):
        missing.append("qemu-img (run-owned disk creation)")
    return missing


def check_images() -> None:
    missing = _qemu_prereqs()
    if missing:
        fail("images prerequisites (QEMU for isolated artifact boot)",
             f"missing {missing} — required layer; run in the CI images job "
             "(isolated QEMU, run-owned disks, synthetic secrets, no host shares)")
    fx = _pg_fixture()
    try:
        env = {"SR_PG_ADMIN_URL": fx.admin_url(), "SR_REQUIRE_IMAGES": "1",
               "SR_REQUIRE_DB": "1"}
        r, counts = pytest_run(["-m", "images"], env=env, timeout=3600)
        require_selection(counts, "images")
        if r.returncode != 0:
            fail("images regressions in required mode",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        ok("mojang image builds/boots/services/seeds/flaws/fixes/readiness pass",
           f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")
        leftovers = fx.leftover_test_databases()
        if leftovers:
            fail("owned DB resources cleaned", f"leftovers: {leftovers}")
        ok("owned DB resources cleaned", "no srtest_*/sr_* databases or roles remain")
    finally:
        problems = fx.cleanup()
        if problems:
            fail("images DB fixture cleanup", "; ".join(problems))
        ok("images DB fixture container/volume removed", fx.container)
    _assert_no_owned_qemu_leftovers()


def check_capture() -> None:
    missing = _qemu_prereqs()
    if missing:
        fail("capture prerequisites (QEMU for installed-capture boot)",
             f"missing {missing} — required layer; run in the CI capture job "
             "(installed auditd/srshipper under QEMU, synthetic API/DB/SSH)")
    fx = _pg_fixture()
    try:
        env = {"SR_PG_ADMIN_URL": fx.admin_url(), "SR_REQUIRE_CAPTURE": "1",
               "SR_REQUIRE_DB": "1"}
        r, counts = pytest_run(["-m", "capture"], env=env, timeout=3600)
        require_selection(counts, "capture")
        if r.returncode != 0:
            fail("capture regressions in required mode",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        ok("installed auditd/srshipper negatives/recovery/access/replay pass",
           f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")
        leftovers = fx.leftover_test_databases()
        if leftovers:
            fail("owned DB resources cleaned", f"leftovers: {leftovers}")
        ok("owned DB resources cleaned", "no srtest_*/sr_* databases or roles remain")
    finally:
        problems = fx.cleanup()
        if problems:
            fail("capture DB fixture cleanup", "; ".join(problems))
        ok("capture DB fixture container/volume removed", fx.container)
    _assert_no_owned_qemu_leftovers()


def _assert_no_owned_qemu_leftovers() -> None:
    import glob
    leftovers = [p for p in glob.glob("/tmp/sr-qemu-*")]
    if leftovers:
        fail("QEMU owned-disk/process cleanup", f"leftovers: {leftovers[:5]}")
    ok("no QEMU owned run-dirs leaked")


# -------------------------------------------------------------------------- #

def check_install() -> None:
    """Plan 13 phase 8 — installer gate.

    Sandbox-provable here: manifest validation fails CLOSED before any
    effect; the dry-run is idempotent (byte-identical twice); existing key
    material is preserved. The MANAGED-SERVICE half (clean VM install,
    idempotent rerun, reboot, populated upgrade, failure recovery) needs a
    disposable service VM — the CI/VM job sets SR_INSTALL_VM_EVIDENCE=1
    only after running the full sequence; without it this gate FAILS,
    because a sandbox pass never accepts the VM contract."""
    import subprocess
    import tempfile
    import shutil as _sh

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sr-install-gate-"))
    try:
        manifest = tmp / "manifest.json"
        shutil.copyfile(REPO / "deploy/manifest.example.json", manifest)
        prefix = tmp / "prefix"
        prefix.mkdir()
        cmd = ["bash", str(REPO / "deploy/install.sh"), "--manifest",
               str(manifest), "--prefix", str(prefix), "--dry-run"]
        env = {**os.environ, "SR_PYTHON": sys.executable}
        r1 = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=REPO, env=env, timeout=120)
        if r1.returncode != 0:
            fail("installer dry-run (example manifest)",
                 f"exit {r1.returncode}:\n{(r1.stdout + r1.stderr)[-1500:]}")
        r2 = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=REPO, env=env, timeout=120)
        if r2.returncode != 0 or r2.stdout != r1.stdout:
            fail("installer idempotent rerun (dry-run)",
                 f"exit {r2.returncode} or output drift:\n"
                 f"{(r2.stdout + r2.stderr)[-1500:]}")
        ok("installer dry-run + idempotent rerun (example manifest)")

        # existing generation key material must be preserved, never
        # regenerated or shadowed: the canonical bastion key lives in
        # etc/sparring-range/ssh (owned by bootstrap_tls.sh); the installer
        # enforces traversal only and must leave the bytes untouched.
        (prefix / "etc/sparring-range/ssh").mkdir(parents=True)
        key = prefix / "etc/sparring-range/ssh/bastion_ed25519"
        key.write_text("EXISTING-KEY\n")
        r3 = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=REPO, env=env, timeout=120)
        if "etc/sparring-range/ssh" not in r3.stdout \
                or not key.read_text().startswith("EXISTING"):
            fail("installer preserves existing private keys",
                 r3.stdout[-800:])
        if "tls/bastion_ed25519" in r3.stdout:
            fail("installer must not shadow generation keys under tls/",
                 r3.stdout[-800:])
        ok("installer preserves existing private keys (dry-run)")

        # invalid manifest fails BEFORE any effect
        bad = tmp / "bad.json"
        bad.write_text(json.dumps({"schema_version": 99}))
        r4 = subprocess.run(
            ["bash", str(REPO / "deploy/install.sh"), "--manifest", str(bad),
             "--prefix", str(tmp / "p2"), "--dry-run"],
            capture_output=True, text=True, cwd=REPO, env=env, timeout=120)
        if r4.returncode == 0 or (tmp / "p2/var").exists():
            fail("invalid manifest refused before any effect",
                 f"exit {r4.returncode}")
        ok("invalid manifest refused before any effect")

        # REAL (non-dry) runs with stubbed privileged commands: proves the
        # TLS-preservation and manifest-rendering logic actually executes
        # (dry-run only echoes). Stubs fake id/useradd/install/chown/chmod/
        # systemctl; openssl + ssh-keygen run for real.
        stub = tmp / "stubbin"
        stub.mkdir()
        (stub / "calls.log").write_text("")
        for name, body in {
            "id": 'echo "id $*" >> "$STUB_CALLS"; exit 1',
            "useradd": 'echo "useradd $*" >> "$STUB_CALLS"; exit 0',
            "chown": 'echo "chown $*" >> "$STUB_CALLS"; exit 0',
            "chmod": 'echo "chmod $*" >> "$STUB_CALLS"; exit 0',
            "systemctl": 'echo "systemctl $*" >> "$STUB_CALLS"; exit 0',
        }.items():
            (stub / name).write_text("#!/bin/bash\n" + body + "\n")
            (stub / name).chmod(0o755)
        (stub / "install").write_text(
            "#!/usr/bin/env python3\n"
            "import os, shutil, sys\n"
            "open(os.environ['STUB_CALLS'], 'a').write('install ' + ' '.join(sys.argv[1:]) + '\\n')\n"
            "args = [a for a in sys.argv[1:] if not a.startswith('-') or len(a) > 3 or a[1:].isdigit()]\n"
            "# minimal coreutils-compatible subset: install [-d] [-m MODE] [-o O] [-g G] SRC DST\n"
            "args = [a for a in sys.argv[1:]]\n"
            "dodir = '-d' in args\n"
            "paths = []\n"
            "skip = False\n"
            "for i, a in enumerate(args):\n"
            "    if skip:\n"
            "        skip = False\n"
            "        continue\n"
            "    if a in ('-m', '-o', '-g'):\n"
            "        skip = True\n"
            "        continue\n"
            "    if a.startswith('-'):\n"
            "        continue\n"
            "    paths.append(a)\n"
            "if dodir:\n"
            "    [os.makedirs(p, exist_ok=True) for p in paths]\n"
            "else:\n"
            "    dst = paths[-1]\n"
            "    if dst.endswith('/') or os.path.isdir(dst):\n"
            "        os.makedirs(dst, exist_ok=True)\n"
            "        dst = os.path.join(dst, os.path.basename(paths[-2]))\n"
            "    else:\n"
            "        os.makedirs(os.path.dirname(dst), exist_ok=True)\n"
            "    shutil.copyfile(paths[-2], dst)\n")
        (stub / "install").chmod(0o755)
        renv = {**env, "PATH": f"{stub}:{os.environ['PATH']}",
                "STUB_CALLS": str(stub / "calls.log")}
        rp = tmp / "real"
        real = ["bash", str(REPO / "deploy/install.sh"), "--manifest",
                str(manifest), "--prefix", str(rp)]
        rr1 = subprocess.run(real, capture_output=True, text=True,
                             cwd=REPO, env=renv, timeout=300)
        if rr1.returncode != 0:
            fail("installer real run (stubbed privileges)",
                 f"exit {rr1.returncode}:\n{(rr1.stdout + rr1.stderr)[-1500:]}")
        pol = rp / "etc/sparring-range/broker-policy.json"
        try:
            sys.path.insert(0, str(REPO))
            from infra.broker.policy import BrokerPolicy
            loaded = BrokerPolicy.from_dict(
                json.loads(pol.read_text()), source="install-gate")
            assert loaded.vmid_min == 9100 and loaded.vmid_max == 9199, \
                (loaded.vmid_min, loaded.vmid_max)
            assert set(loaded.templates) >= {9005, 9011}, loaded.templates
            limits = json.loads(pol.read_text())["limits"]
            assert limits["max_total_disk_gb"] == 44, limits
            assert limits["max_total_disk_gb"] <= 44, \
                "rendered ceiling must never exceed the manifest budget"
        except Exception as e:  # noqa: BLE001
            fail("installer renders broker policy from the manifest",
                 f"{e}\n{(rr1.stdout + rr1.stderr)[-800:]}")
        ok("installer real run renders manifest-derived broker policy")
        derived = rp / "etc/sparring-range/control-plane.derived.env"
        text = derived.read_text()
        for want in ("PROXMOX_NODE=pve", "RANGE_BRIDGE=srrange",
                     "RANGE_VLAN=66", "RANGE_CIDR=10.66.0.0/24",
                     "DEPLOY_VMID_BASE=9100", "DEPLOY_CLONE_MODE=full",
                     "API_BASE_URL=https://10.60.0.11:8443",
                     "LLM_BASE_URL=http://10.60.0.20:8080/v1",
                     "LLM_MODEL_RED=qwen3.8-flash-next",
                     "LLM_MODEL_COACH=qwen3.8-flash-next",
                     f"BROKER_POLICY_FILE={pol}"):
            assert want in text, f"derived env missing {want}:\n{text[:600]}"
        assert "CHANGE" not in text, "derived config must not carry placeholders"
        unit = (REPO / "deploy/systemd/sr-api.service").read_text()
        assert "control-plane.derived.env" in unit, \
            "shipped unit must load the derived environment"
        assert "User=srrange" in unit, "unit identity must match installer"
        ok("installer renders manifest-derived service environment")
        # ingest plane driven by manifest urls/trust: unit installed, env
        # rendered, dedicated API CA + SAN-bound server cert provisioned
        tlsd = rp / "etc/sparring-range/tls"
        assert (rp / "etc/systemd/system/sr-api-ingest.service").exists()
        ing_env = (rp / "etc/sparring-range/ingest-listener.env").read_text()
        assert "SR_API_INGEST_ONLY=1" in ing_env, ing_env[:300]
        assert "SR_API_BASE_URL=https://10.66.0.2:8444" in ing_env, ing_env[:300]
        assert (tlsd / "api-ca.crt").exists(), "API CA missing — guestscoe trust anchor unprovisioned"
        assert (tlsd / "ingest-server.crt").exists()
        sans = subprocess.run(
            ["openssl", "x509", "-in", str(tlsd / "ingest-server.crt"),
             "-noout", "-ext", "subjectAltName"],
            capture_output=True, text=True, timeout=60).stdout
        assert "10.66.0.2" in sans and "10.60.0.11" in sans, sans[:300]
        ok("installer provisions the manifest-driven ingest plane + trust")
        # least-privilege TLS map: every service key names its consumer
        # group; CA signing keys must NEVER appear as group-readable.
        inst = (REPO / "deploy/install.sh").read_text()
        m = __import__("re").search(
            r"declare -A TLS_KEY_GROUPS=\((.*?)\)", inst, __import__("re").S)
        assert m, "TLS_KEY_GROUPS map missing from installer"
        body = m.group(1)
        assert "ingest-server.key" in body and "api-client.key" in body, body
        assert "broker-server.key" in body, body
        assert "ca.key" not in body and "api-ca.key" not in body, \
            f"CA signing keys must stay root-only: {body}"
        ok("installer scopes TLS key ownership per service (CA root-only)")
        # generation keys: bootstrap owns generation into the canonical ssh
        # dir with an EXPLICIT entitled group (review find 2026-10-15:
        # ssh-keygen's default root-only 0600 silently denied services).
        boot = (REPO / "deploy/bootstrap_tls.sh").read_text()
        assert 'SR_SSH_GROUP' in boot, "entitled group must be explicit"
        assert 'chown root:"$SR_SSH_GROUP" "$SR_SSH_DIR/bastion_ed25519"' in boot, \
            "generated dial key must be group-readable by its consumer"
        sshd = rp / "etc/sparring-range/ssh/bastion_ed25519"
        assert sshd.exists(), \
            "generation dial key missing from the canonical ssh dir"
        ok("bootstrap generates the dial key service-readable with explicit group")
        # traversal + ownership model (from the stub call log — the real
        # commands execute on the VM job; here we prove the installer
        # INVOKES the right ownership on the right paths, never assumes it)
        calls = (stub / "calls.log").read_text()
        for want in ("install -d -m 0755",
                     "chown root:srrange",
                     "chown root:srbroker",
                     "chown root:root"):
            assert want in calls, f"ownership call missing: {want}\n{calls[-800:]}"
        assert "chown " in calls and "srbroker" in calls
        ok("installer sets traversable dirs + per-service ownership")
        before = {(p.name, p.read_bytes()) for p in
                  (rp / "etc/sparring-range/tls").glob("*.key")}
        assert before, "first real run must generate TLS identities"
        (stub / "calls.log").write_text("")
        rr2 = subprocess.run(real, capture_output=True, text=True,
                             cwd=REPO, env=renv, timeout=300)
        if rr2.returncode != 0:
            fail("installer real rerun",
                 f"exit {rr2.returncode}:\n{(rr2.stdout + rr2.stderr)[-1500:]}")
        calls = (stub / "calls.log").read_text()
        after = {(p.name, p.read_bytes()) for p in
                 (rp / "etc/sparring-range/tls").glob("*.key")}
        if after != before:
            fail("installer rerun preserves TLS identities",
                 "private key bytes changed without --rotate-tls")
        if (rp / "etc/sparring-range/broker-policy.json").read_bytes() != \
                pol.read_bytes():
            fail("installer re-render is deterministic",
                 "broker policy drifted between identical runs")
        ok("installer rerun preserves TLS identities + deterministic render")
        rr3 = subprocess.run(real + ["--rotate-tls"], capture_output=True,
                             text=True, cwd=REPO, env=renv, timeout=300)
        if rr3.returncode != 0:
            fail("installer explicit rotation",
                 f"exit {rr3.returncode}:\n{(rr3.stdout + rr3.stderr)[-800:]}")
        rotated = {(p.name, p.read_bytes()) for p in
                   (rp / "etc/sparring-range/tls").glob("*.key")}
        if rotated == before:
            fail("installer explicit rotation",
                 "--rotate-tls left all identities unchanged")
        ok("installer explicit --rotate-tls rotates identities")
        # partial recovery: deleting ONE disposable key regenerates only
        # it — surviving identities are preserved without any flag
        doomed = rp / "etc/sparring-range/tls/broker-server.key"
        survivor = (rp / "etc/sparring-range/tls/api-client.key").read_bytes()
        doomed.unlink()
        rr4 = subprocess.run(real, capture_output=True,
                             text=True, cwd=REPO, env=renv, timeout=300)
        if rr4.returncode != 0 or not doomed.exists():
            fail("installer partial recovery regenerates only the missing",
                 f"exit {rr4.returncode}:\n{(rr4.stdout + rr4.stderr)[-800:]}")
        if (rp / "etc/sparring-range/tls/api-client.key").read_bytes() != survivor:
            fail("installer partial recovery regenerates only the missing",
                 "a SURVIVING identity rotated without --rotate-tls")
        ok("installer partial recovery preserves survivors")
        # missing CERTIFICATE (key survives): the identity is incomplete,
        # so reinstall regenerates exactly the missing half — never a
        # false-successful install with a dangling key
        (rp / "etc/sparring-range/tls/broker-server.crt").unlink()
        rr6 = subprocess.run(real, capture_output=True,
                             text=True, cwd=REPO, env=renv, timeout=300)
        if rr6.returncode != 0 or not (
                rp / "etc/sparring-range/tls/broker-server.crt").exists():
            fail("installer recovers missing certificates",
                 f"exit {rr6.returncode}:\n{(rr6.stdout + rr6.stderr)[-800:]}")
        ok("installer recovers missing certificates")
        # HTTPS identity: missing certificate with a surviving key
        # re-issues onto the SAME key (pinning-safe, rotation untouched)
        import os as _os
        henv = dict(renv)
        henv["HTTPS_IP"] = "10.60.0.11"
        rr7 = subprocess.run(
            ["bash", str(REPO / "deploy/bootstrap_tls.sh")],
            capture_output=True, text=True, cwd=REPO,
            env={**henv, "SR_TLS_DIR": str(rp / "etc/sparring-range/tls"),
                 "SR_SSH_DIR": str(rp / "etc/sparring-range/ssh")},
            timeout=300)
        hcert = rp / "etc/sparring-range/tls/https.crt"
        hkey = rp / "etc/sparring-range/tls/https.key"
        assert rr7.returncode == 0 and hcert.exists(), \
            (rr7.returncode, (rr7.stdout + rr7.stderr)[-500:])
        fp1 = subprocess.run(
            ["openssl", "x509", "-in", str(hcert), "-noout", "-fingerprint",
             "-sha256"], capture_output=True, text=True,
            timeout=60).stdout
        hcert.unlink()
        rr8 = subprocess.run(
            ["bash", str(REPO / "deploy/bootstrap_tls.sh")],
            capture_output=True, text=True, cwd=REPO,
            env={**henv, "SR_TLS_DIR": str(rp / "etc/sparring-range/tls"),
                 "SR_SSH_DIR": str(rp / "etc/sparring-range/ssh")},
            timeout=300)
        fp2 = subprocess.run(
            ["openssl", "x509", "-in", str(hcert), "-noout", "-fingerprint",
             "-sha256"], capture_output=True, text=True,
            timeout=60).stdout
        assert rr8.returncode == 0 and hcert.exists(), \
            (rr8.returncode, (rr8.stdout + rr8.stderr)[-500:])
        assert fp1 != fp2, "re-issued certificate must differ"
        ok("installer re-issues HTTPS certificate onto surviving key")
        # explicit rotation takes precedence over preservation: with
        # FRESH=1 a surviving key must be REPLACED, not kept
        before = hkey.read_bytes()
        renv_rot = dict(henv, SR_TLS_ROTATE="1")
        rr9 = subprocess.run(
            ["bash", str(REPO / "deploy/bootstrap_tls.sh")],
            capture_output=True, text=True, cwd=REPO,
            env={**renv_rot, "SR_TLS_DIR": str(rp / "etc/sparring-range/tls"),
                 "SR_SSH_DIR": str(rp / "etc/sparring-range/ssh")},
            timeout=300)
        assert rr9.returncode == 0, \
            (rr9.returncode, (rr9.stdout + rr9.stderr)[-500:])
        assert hkey.read_bytes() != before, \
            "explicit rotation must replace the surviving private key"
        ok("installer explicit rotation replaces surviving HTTPS key")
        # partial state with a missing CA key beside surviving certificates
        # is refused explicitly (exit 1), never silently orphaned
        (rp / "etc/sparring-range/tls/ca.key").unlink()
        rr5 = subprocess.run(real, capture_output=True,
                             text=True, cwd=REPO, env=renv, timeout=300)
        if rr5.returncode == 0:
            fail("installer refuses CA-less partial TLS state",
                 "missing ca.key with surviving certificates was accepted")
        ok("installer refuses CA-less partial TLS state")
        # API CA partial state refuses the same way (guest trust already
        # installed must never be silently orphaned)
        (rp / "etc/sparring-range/tls/api-ca.key").unlink()
        rr9 = subprocess.run(real, capture_output=True,
                             text=True, cwd=REPO, env=renv, timeout=300)
        if rr9.returncode == 0:
            fail("installer refuses API-CA-less partial TLS state",
                 "missing api-ca.key with surviving certificates was accepted")
        ok("installer refuses API-CA-less partial TLS state")

        # MILESTONE 14: the appliance installer's REAL sequences.  The old
        # environment attestation is gone — a flag was never evidence.  The
        # sequences run the actual installer against a sandbox root and
        # observe the outcome: clean install, rerun (nothing changes, the
        # capability is preserved), reboot (runtime restored, data and keys
        # preserved), populated upgrade (the changed configuration is
        # rewritten, the data and the capability survive) and drift detection
        # with repair (a foreign file is never touched).
        sys.path.insert(0, str(REPO / "infra" / "dev"))
        import install_sequences
        sandbox = tmp / "appliance-sandbox"
        manifest_path = install_sequences.build_manifest(tmp / "appliance-input")
        try:
            evidence = install_sequences.run_sequences(sandbox, manifest_path)
        except Exception as exc:  # noqa: BLE001 — the gate reports the reason
            fail("appliance installer real sequences (clean/rerun/reboot/"
                 "upgrade/drift)", str(exc)[:1800])
        ok("appliance installer real sequences pass",
           f"clean={evidence['clean']['changed']} files, "
           f"rerun={evidence['rerun']['changed']} changed, "
           f"upgrade={evidence['upgrade']['changed']} changed, "
           f"drift detected and repaired")
        ok("managed-service install (systemd units in a real appliance VM) "
           "stays the operator's sequence",
           "documented in docs/OPERATOR_RUNBOOK.md; it is NOT accepted from "
           "any environment flag")
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


def check_release() -> None:
    """Plan 13 phase 8 — release-level workflow gate (both presets, start
    conditions, snapshots, duplicate/crash/timeout recovery, injects,
    scorer/model failures, competition filtering, reports, reuse). This is
    the LIVE layer: it drives the deployed lab through the API and refuses
    to run without an explicitly configured live fixture — there is no
    fake or skipped acceptance here."""
    if not os.environ.get("SR_LIVE_BASE_URL"):
        fail("release workflow gate",
             "requires SR_LIVE_BASE_URL (deployed lab) — operator/CI live "
             "job; nothing about a release is accepted from a sandbox")
    env = {"SR_REQUIRE_LIVE": "1",
           "SR_LIVE_BASE_URL": os.environ["SR_LIVE_BASE_URL"]}
    r, counts = pytest_run(["-m", "live"], env=env, timeout=3600)
    require_selection(counts, "live")
    if r.returncode != 0:
        fail("live release regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    ok("release workflows pass against the deployed lab",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")



# -------------------------------------------------------------------------- #
# hypervisor (14/15): real libvirt lifecycle, QGA readiness and ownership     #
# -------------------------------------------------------------------------- #

def _hypervisor_prereqs() -> list[str]:
    missing = []
    if not shutil.which("qemu-img"):
        missing.append("qemu-img")
    try:
        import libvirt  # noqa: F401
        import libvirt_qemu  # noqa: F401
    except Exception:  # noqa: BLE001
        missing.append("libvirt Python bindings (libvirt + libvirt_qemu)")
    base = os.environ.get("SR_APPLIANCE_BASE_IMAGE", "").strip()
    if not base or not pathlib.Path(base).is_file():
        missing.append("SR_APPLIANCE_BASE_IMAGE (bootable Ubuntu qcow2)")
    if not os.path.exists("/dev/kvm") and \
            os.environ.get("SR_HYPERVISOR_ALLOW_TCG") != "1":
        missing.append("/dev/kvm (nested KVM) or explicit SR_HYPERVISOR_ALLOW_TCG=1 "
                       "for a LABELED software-emulation gate")
    if missing and not os.environ.get("LIBVIRT_DRIVER_DIR"):
        # An unprivileged libvirt needs its own driver directory and its
        # runtime dir; without them the import fails and the reason is
        # invisible.
        missing.append("an unprivileged libvirt environment "
                       "(LD_LIBRARY_PATH, PYTHONPATH, LIBVIRT_DRIVER_DIR, "
                       "XDG_RUNTIME_DIR) or a system libvirt")
    return missing


def check_hypervisor() -> None:
    missing = _hypervisor_prereqs()
    if missing:
        fail("hypervisor prerequisites (libvirt/KVM + Ubuntu base image)",
             f"missing {missing} — required layer; install nested KVM and a "
             "bootable appliance base image, or explicitly allow labeled TCG")
    env = {"SR_REQUIRE_HYPERVISOR": "1",
           "SR_APPLIANCE_BASE_IMAGE": os.environ.get("SR_APPLIANCE_BASE_IMAGE", ""),
           "SR_HYPERVISOR_URI": os.environ.get("SR_HYPERVISOR_URI", "qemu:///session")}
    for key in ("SR_HYPERVISOR_ALLOW_TCG", "SR_QEMU_IMG", "LD_LIBRARY_PATH",
                "PYTHONPATH", "XDG_RUNTIME_DIR", "LIBVIRT_DEFAULT_URI"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    r, counts = pytest_run(["-m", "hypervisor"], env=env, timeout=3600)
    require_selection(counts, "hypervisor")
    if r.returncode != 0:
        fail("real libvirt lifecycle/QGA/ownership/destroy",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    ok("real libvirt clone/start/QGA host key/ownership/stop/destroy pass",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped; "
       f"accelerator={os.environ.get('SR_HYPERVISOR_ALLOW_TCG') and 'explicit-TCG' or 'KVM'}")
    _assert_no_owned_qemu_leftovers()


# -------------------------------------------------------------------------- #
# access (14/15): real guest SSH and recorded bastion replay                  #
# -------------------------------------------------------------------------- #

def check_access() -> None:
    missing = _qemu_prereqs()
    base = os.environ.get("SR_APPLIANCE_BASE_IMAGE", "").strip()
    if not base or not pathlib.Path(base).is_file():
        missing.append("SR_APPLIANCE_BASE_IMAGE (bootable Ubuntu qcow2)")
    if not shutil.which("ssh-keygen"):
        missing.append("ssh-keygen")
    try:
        import asyncssh  # noqa: F401
    except Exception:  # noqa: BLE001
        missing.append("asyncssh (bastion/client transport)")
    if missing:
        fail("access prerequisites (real guest SSH + recording bastion)",
             f"missing {missing} — required layer; boot a real Ubuntu image "
             "and install the SSH/asyncssh runtime")
    env = {"SR_REQUIRE_ACCESS": "1", "SR_APPLIANCE_BASE_IMAGE": base}
    if os.path.exists("/dev/kvm"):
        env["SR_ACCESS_KVM"] = "1"
    for key in ("SR_QEMU_KVM", "LD_LIBRARY_PATH", "PYTHONPATH"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    r, counts = pytest_run(["-m", "access"], env=env, timeout=3600)
    require_selection(counts, "access")
    if r.returncode != 0:
        fail("real guest SSH + bastion cast replay",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
    ok("real guest SSH, pinned target key and .cast replay pass",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")
    _assert_no_owned_qemu_leftovers()


# -------------------------------------------------------------------------- #
# journey (15): installed appliance, real services, member workflow           #
# -------------------------------------------------------------------------- #

def check_journey() -> None:
    required = ("SR_JOURNEY_BASE_URL", "SR_JOURNEY_OPERATOR_TOKEN",
                "SR_JOURNEY_MEMBER_TOKEN", "SR_JOURNEY_SSH_KEY",
                "SR_JOURNEY_BASTION_KNOWN_HOSTS", "SR_JOURNEY_BROWSER_URL",
                "SR_JOURNEY_BROWSER_USER", "SR_JOURNEY_BROWSER_PASSWORD")
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        prereq_fail("journey prerequisites (installed appliance + authenticated members)",
                    f"missing {missing} — required live gate; point it at the "
                    "installed appliance and provide operator/member bearer tokens")
    env = {"SR_REQUIRE_JOURNEY": "1"}
    for key in ("SR_JOURNEY_BASE_URL", "SR_JOURNEY_OPERATOR_TOKEN",
                "SR_JOURNEY_MEMBER_TOKEN", "SR_JOURNEY_SSH_KEY",
                "SR_JOURNEY_BASTION_KNOWN_HOSTS", "SR_JOURNEY_BROWSER_URL",
                "SR_JOURNEY_BROWSER_USER", "SR_JOURNEY_BROWSER_PASSWORD",
                "SR_JOURNEY_CA_FILE", "SR_JOURNEY_DURATION_MINUTES",
                "SR_JOURNEY_PACE_SECONDS", "SR_JOURNEY_PRESET"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    r, counts = pytest_run(["-m", "journey"], env=env, timeout=7200)
    require_selection(counts, "journey")
    if r.returncode != 0:
        fail("installed-appliance practice journey",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-8000:]}")
    ok("installed-appliance journey (lifecycle/SSH/replay/history) passes",
       f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")


# -------------------------------------------------------------------------- #
# bundle (16): the release bundle's digests, completeness and secret-freedom  #
# -------------------------------------------------------------------------- #

def _role_images(tmp: pathlib.Path) -> tuple[dict, dict]:
    """The ROLE artifacts a release bundle must carry.

    They must be the REAL artifacts: a bundle that ships placeholder bytes
    proves nothing about the guests it would install.  When they are
    missing the gate fails with the exact prerequisite — the `images` gate
    builds them.
    """
    roles = ("attacker", "mojang-web-local", "mojang-web-db")
    out: dict = {}
    real: dict = {}
    dirs = []
    env_dir = os.environ.get("SR_APPLIANCE_ROLE_IMAGE_DIR", "").strip()
    if env_dir:
        dirs.append(pathlib.Path(env_dir))
    dirs += [REPO / ".cache/images", REPO / ".cache/appliance",
             pathlib.Path("/tmp/sr-guest-cache")]
    for role in roles:
        found = None
        for d in dirs:
            if not d.is_dir():
                continue
            for p in sorted(d.rglob("*.qcow2")):
                if role in p.name:
                    found = p
                    break
            if found is not None:
                break
        if found is None:
            fail("release bundle role artifacts",
                 f"no {role} image found in {dirs} — build the role images "
                 "first (the images gate) or point SR_APPLIANCE_ROLE_IMAGE_DIR "
                 "at them. A bundle with placeholder image bytes would prove "
                 "nothing about the guests it installs.")
        real[role] = True
        out[role] = found
    return out, real


def _build_disposable_bundle(tmp: pathlib.Path, target: pathlib.Path) -> None:
    """Build a small, SELF-CONTAINED bundle for the destructive test.

    It carries real (tiny) qcow2 images, so it verifies exactly like the
    release bundle: the negative test then fails for the tampering and not
    for a missing file.
    """
    import shutil as _sh
    import subprocess as _sp

    images = tmp / "tiny-images"
    images.mkdir(parents=True, exist_ok=True)
    roles = ("attacker", "mojang-web-local", "mojang-web-db")
    args: list[str] = []
    for role in ("appliance-base",) + roles:
        path = images / f"{role}.qcow2"
        r = _sp.run(["qemu-img", "create", "-f", "qcow2", str(path), "8M"],
                    capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            fail("the disposable bundle is valid",
                 f"cannot create the tiny image {path}: {r.stderr[-200:]}")
        if role == "appliance-base":
            args += ["--base-image", str(path)]
        else:
            args += ["--role-image", f"{role}={path}"]
    r = _sp.run([sys.executable, str(REPO / "deploy/bundle.py"), "build",
                 "--output", str(target), *args],
                capture_output=True, text=True, cwd=REPO, timeout=3600)
    if r.returncode != 0:
        fail("the disposable bundle is valid",
             f"the fixture could not be built: {(r.stdout + r.stderr)[-600:]}")
    _sh.rmtree(images, ignore_errors=True)


def _bind_bundle_to_candidate(bundle: pathlib.Path) -> None:
    """The packaged runtime must BE the checkout under test.

    A bundle verifies against itself: a bundle built from an older revision
    would pass every internal check while shipping yesterday's code.  The
    comparison is therefore COMPLETE and BIDIRECTIONAL:

    * every runtime file the checkout has must be IN the bundle with the
      same digest (a bundle that omits ``srplatform/settings.py`` is not
      the checkout), and
    * every runtime file the bundle has must be IN the checkout (a stale
      login page or an old module is not the checkout either).

    The frontend's source and configuration are part of the runtime: the
    browser loads the bundle's web files, so they are compared like the
    rest.
    """
    import hashlib

    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from deploy.bundle import app_file_relpaths, is_runtime

    manifest_path = bundle / "MANIFEST.json"
    if not manifest_path.is_file():
        fail("release bundle binding", f"{bundle} has no MANIFEST.json")
    files = json.loads(manifest_path.read_text()).get("files") or {}
    packaged = {rel for rel in files if is_runtime(rel)}
    expected = {rel for rel in app_file_relpaths(REPO) if is_runtime(rel)}
    missing = sorted(expected - packaged)
    extra = sorted(packaged - expected)
    changed: list[str] = []
    for rel in sorted(expected & packaged):
        source = REPO / rel
        if not source.is_file():
            extra.append(rel)
            continue
        h = hashlib.sha256()
        with source.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        if h.hexdigest() != files[rel].get("sha256"):
            changed.append(rel)
    if missing or extra or changed:
        fail("release bundle binding",
             f"the release bundle is not the checkout under test: "
             f"{len(missing)} missing (first: {missing[:3]}), "
             f"{len(extra)} not in the checkout (first: {extra[:3]}), "
             f"{len(changed)} changed (first: {changed[:3]}) — rebuild the "
             "bundle before accepting it")
    ok("the release bundle is bound to the checkout under test",
       f"{len(packaged)} runtime files compared (missing, stale and changed "
       "all checked)")


def _wait_guest_ready(qga_sock: pathlib.Path, proc: subprocess.Popen,
                      timeout_s: float = 1500) -> str:
    """Wait for the guest agent and the appliance readiness marker.

    ONE connection is held for the whole wait: a QEMU socket chardev carries
    the guest's agent transport over the connected client.
    """
    import time as _time

    from infra.appliance.seed import marker_path
    from infra.dev.qga import QgaClient

    deadline = _time.monotonic() + timeout_s
    last = ""
    agent = QgaClient(str(qga_sock), timeout=15)
    try:
        while _time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"QEMU exited {proc.returncode} before the "
                                   "guest was ready")
            try:
                agent.connect()
                marker = agent.read_file(marker_path())
                if marker and marker.strip():
                    return str(marker).strip()
            except Exception as exc:  # noqa: BLE001 — the agent is not up yet
                last = str(exc)
                agent.close()
            _time.sleep(5)
    finally:
        agent.close()
    raise RuntimeError(f"the guest was not ready within {timeout_s:.0f}s: "
                       f"{last}")


def _shipped_image_boots(tmp: pathlib.Path, bundle: pathlib.Path) -> None:
    """Boot one of the bundle's images, from the bundle, after relocation.

    The images are copied to the operator's machine: the copy must still
    boot, and it must boot with the role's own readiness marker.
    """
    import shutil as _sh
    from infra.appliance.manifest import ApplianceManifest
    from infra.appliance.seed import (SeedInputs, render_network_config,
                                      render_user_data)
    from infra.dev import qemu_guest
    from infra.images.guest_seed import build_seed_iso, meta_data

    if not shutil.which("qemu-system-x86_64"):
        fail("shipped image boot",
             "qemu-system-x86_64 is missing — the bundle's images cannot be "
             "proven to boot")
    manifest_path = tmp / "manifest.json"
    if not manifest_path.is_file():
        fail("shipped image boot", "the operator manifest was not rendered")
    m = ApplianceManifest.load(manifest_path)
    image = m.image_for_role("mojang-web-local")
    shipped = bundle / "images" / pathlib.Path(image.path).name
    if not shipped.is_file():
        fail("shipped image boot", f"the bundle does not carry {image.path}")
    inp = SeedInputs(manifest=m, image=image, vmid=231,
                     session_id="bundle-gate", hostname="sr-bundle",
                     address="10.0.2.15", prefix=24, gateway="10.0.2.2")
    seed = tmp / "bundle-seed.iso"
    build_seed_iso(seed, render_user_data(inp),
                   meta_data(f"iid-bundle-{os.getpid()}", "sr-bundle"),
                   network_config=render_network_config(inp))
    # The boot writes to a THROWAWAY OVERLAY on top of the shipped image:
    # a released artifact must not be modified by its own acceptance test.
    overlay = tmp / "boot.qcow2"
    r = subprocess.run(["qemu-img", "create", "-f", "qcow2", "-b",
                        str(shipped), "-F", "qcow2", str(overlay), "16G"],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        fail("shipped image boot",
             f"cannot open the shipped image: {(r.stderr or r.stdout)[-300:]}")
    # The guest agent is how the appliance proves readiness, so the boot
    # carries the agent's virtio-serial port (without it the guest never
    # becomes ready and the check would only prove that QEMU starts).
    sock_dir = pathlib.Path(f"/tmp/sr-bundle-boot-{os.getpid()}")
    sock_dir.mkdir(parents=True, exist_ok=True)
    qga_sock = sock_dir / "qga.sock"
    serial = tmp / "boot.serial.log"
    use_kvm = (os.environ.get("SR_QEMU_KVM") == "1"
               and pathlib.Path("/dev/kvm").exists())
    accel = ["-accel", "kvm"] if use_kvm else ["-accel", "tcg,thread=multi"]
    cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "2048", "-smp", "2",
           "-drive", f"file={overlay},format=qcow2,if=virtio",
           "-drive", f"file={seed},format=raw,media=cdrom,readonly=on",
           "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
           "-device", "virtio-serial-pci,id=vser0",
           "-chardev", f"socket,id=qga0,path={qga_sock},server=on,wait=off",
           "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
           "-nographic", "-serial", f"file:{serial}", "-no-reboot",
           "-display", "none", *accel]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        marker = _wait_guest_ready(qga_sock, proc)
    except Exception as exc:  # noqa: BLE001 — a boot failure is a failure
        fail("shipped image boot",
             f"the shipped mojang-web-local image did not become ready from "
             f"the bundle: {exc}")
    finally:
        if proc.poll() is None:
            proc.kill()
        shutil.rmtree(sock_dir, ignore_errors=True)
    ok("the shipped image boots from the bundle",
       f"{shipped.name} (through a throwaway overlay), marker "
       f"{str(marker)[:40]!r}, "
       f"accelerator={'KVM' if use_kvm else 'TCG'}")


def check_bundle() -> None:
    """The release bundle is what the operator carries into their own VM.

    The gate builds the REAL bundle from the flattened guest base AND the
    role artifacts, verifies every digest, renders the operator's manifest
    from it, and then proves that a tampered bundle is refused.  A bundle
    that cannot be verified is never installed.
    """
    import subprocess
    import tempfile
    import shutil as _sh

    base = os.environ.get("SR_APPLIANCE_BASE_IMAGE", "").strip()
    if not base or not pathlib.Path(base).is_file():
        fail("release bundle (digests, completeness, secret-freedom)",
             f"requires SR_APPLIANCE_BASE_IMAGE (the flattened guest base) - "
             f"not found: {base or '(unset)'}")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sr-bundle-gate-"))
    try:
        # The gate NEVER holds a second copy of the bundle: the images are
        # gigabytes and the disk cannot carry a duplicate.  It verifies the
        # RELEASE bundle where it lives, and it builds one only when there
        # is no bundle yet (and only with room for it).
        release = pathlib.Path(
            os.environ.get("SR_APPLIANCE_BUNDLE", "").strip()
            or str(REPO / ".cache/bundle/sparring-range-appliance"))
        bundle = release
        if not release.exists():
            role_images, real_roles = _role_images(tmp)
            free = shutil.disk_usage(REPO).free
            needed = sum(p.stat().st_size for p in role_images.values())
            needed += pathlib.Path(base).stat().st_size
            if free < needed * 2:
                fail("release bundle build",
                     f"not enough free space for a second copy of the bundle "
                     f"(need ~{needed // (1 << 30)}GiB, {free // (1 << 30)}GiB "
                     "free) — verify the existing bundle instead")
            bundle = tmp / "bundle"
            cmd = [sys.executable, str(REPO / "deploy/bundle.py"), "build",
                   "--output", str(bundle), "--base-image", base]
            for role, path in sorted(role_images.items()):
                cmd += ["--role-image", f"{role}={path}"]
            r = subprocess.run(cmd,
                capture_output=True, text=True, cwd=REPO, timeout=3600)
            if r.returncode != 0:
                fail("release bundle build",
                     f"exit {r.returncode}:\n{(r.stdout + r.stderr)[-1500:]}")
        else:
            print(f"  (verifying the release bundle at {bundle})")
        v = subprocess.run(
            [sys.executable, str(REPO / "deploy/bundle.py"), "verify",
             str(bundle)], capture_output=True, text=True, cwd=REPO,
            timeout=1800)
        if v.returncode != 0:
            fail("release bundle verify",
                 f"exit {v.returncode}:\n{(v.stdout + v.stderr)[-1500:]}")
        report = json.loads(v.stdout)
        ok("release bundle verifies", f"{report['files']} files, "
                                     f"{report['images']} image(s), "
                                     f"revision {report['revision'][:12]}")
        # the release must BE the candidate under test: a bundle built from
        # an older revision verifies against itself and would pass here.
        _bind_bundle_to_candidate(bundle)

        # the operator's manifest is RENDERED from the bundle, never hand
        # written: it must satisfy the strict appliance schema.
        keys = tmp / "keys"
        keys.mkdir()
        for role in ("runner", "bastion", "mgmt"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(keys / role)], check=True,
                           capture_output=True)
        model = tmp / "model.key"
        model.write_text("gate-model-key\n")
        m = subprocess.run(
            [sys.executable, str(REPO / "deploy/bundle.py"), "manifest",
             str(bundle), "--out", str(tmp / "manifest.json"),
             "--installation-id", "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c444",
             "--lan-address", "10.10.10.50", "--range-cidr", "10.66.0.0/24",
             "--public-url", "https://sr.example.edu",
             "--internal-url", "http://127.0.0.1:8000",
             "--ingest-url", "https://10.66.0.1:8443",
             "--model-api-key-file", str(model),
             "--access-key", f"runner={keys/'runner.pub'}",
             "--access-key", f"bastion={keys/'bastion.pub'}",
             "--access-key", f"mgmt={keys/'mgmt.pub'}"],
            capture_output=True, text=True, cwd=REPO, timeout=1800)
        if m.returncode != 0:
            fail("operator manifest rendered from the bundle",
                 f"exit {m.returncode}:\n{(m.stdout + m.stderr)[-1500:]}")
        ok("operator manifest renders from the bundle and validates")

        # the SHIPPED image must still boot after the relocation into the
        # bundle: a released artifact that cannot boot is not an artifact.
        # This proof is MANDATORY — a bundle whose images cannot boot is not
        # accepted, and it is never skipped into a pass.
        _shipped_image_boots(tmp, bundle)

        # a tampered bundle is refused — on a DISPOSABLE bundle of its own
        # (never on the release: a cancelled gate must not leave a damaged
        # artifact behind).  The fixture is verified FIRST: it must be
        # internally valid, so the refusal below is caused by the tampering
        # and not by a missing file.
        disposable = tmp / "tamper-bundle"
        _build_disposable_bundle(tmp, disposable)
        positive = subprocess.run(
            [sys.executable, str(REPO / "deploy/bundle.py"), "verify",
             str(disposable)], capture_output=True, text=True, cwd=REPO,
            timeout=1800)
        if positive.returncode != 0:
            fail("the disposable bundle is valid",
                 f"the fixture the negative test uses does not verify: "
                 f"{positive.stdout[-600:]}")
        ok("the disposable bundle is valid before it is tampered with")
        victim = disposable / "requirements.lock"
        victim.write_bytes(b"tampered\n")
        t = subprocess.run(
            [sys.executable, str(REPO / "deploy/bundle.py"), "verify",
             str(disposable)], capture_output=True, text=True, cwd=REPO,
            timeout=1800)
        if t.returncode == 0:
            fail("a tampered bundle is refused",
                 "verify accepted a bundle whose file no longer matches "
                 "its digest")
        problems = (json.loads(t.stdout or "{}").get("problems") or [])
        if not any("drift" in p for p in problems):
            fail("a tampered bundle is refused for the right reason",
                 f"the refusal was not a digest mismatch: {problems[:5]}")
        ok("a tampered bundle is refused",
           f"digest drift detected: {problems[0][:80]}")
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


# -------------------------------------------------------------------------- #
# upgrade (21): the preserving in-place upgrade, end to end                   #
# -------------------------------------------------------------------------- #

LOGIN_USER = "p21-login"
LOGIN_PW = "Upgrade-Browser-2026!"


def _upgrade_browser_login(tmp: pathlib.Path, rootA: pathlib.Path,
                           receipt: dict, owner_url: str,
                           pubport: int) -> str:
    """Plan-22 AC-5 (review round 1): after the REAL upgrade a REAL browser
    logs in against the upgraded code, end to end.

    Reconstructs the installed shape with three REAL parts and ONE fixed
    shim, nothing else:

    * the API runs from the UPGRADED PAYLOAD'S OWN venv against the
      upgraded database — the same code and interpreter the activated
      service unit runs, started here as ``uvicorn``;
    * a fixed ``/api``-stripping proxy answers at the manifest's public
      URL, where the provisioned web bundle's BAKED address points. The
      installed appliance's nginx applies this one same rewrite; the
      proxy stands in for it (a fixed prefix strip, not a second
      router), which is why the browser gate's prefix-free API base and
      this gate's ``/api``-baked bundle can both be true;
    * ``next start`` serves the web build the upgrade provisioned inside
      the activated payload;
    * the PINED playwright-cli (same web/ pin as the browser gate)
      drives the real form login and waits for the authenticated
      surface.

    The page is served from its own loopback port while the baked API
    address is the proxy port — a cross-origin artifact of a gate
    without nginx; the API allowlist therefore names the PAGE origin,
    the minimal honest stand-in for the single-origin installed front
    door. A missing prerequisite fails the gate: this is the promotion
    gate, there is no skip.
    """
    import http.client
    import http.server
    import threading

    def free_port() -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    payload = rootA / "opt/sparring-range"
    venv_py = pathlib.Path(receipt["venv"]) / "bin" / "python"
    web_dir = payload / "web"
    web_receipt = receipt.get("web") or {}
    node_binary = web_receipt.get("binary") or shutil.which("node") or ""
    if not venv_py.is_file():
        fail("upgraded venv exists for the browser login", str(venv_py))
    if not (web_dir / "node_modules" / ".bin" / "next").is_file():
        fail("upgraded payload carries the provisioned web build",
             str(web_dir))
    if not node_binary or not pathlib.Path(node_binary).is_file():
        fail("provisioned node runtime is runnable for next start",
             repr(node_binary))
    pw_cli = REPO / "web" / "node_modules" / ".bin" / "playwright-cli"
    if not pw_cli.is_file():
        found = shutil.which("playwright-cli")
        pw_cli = pathlib.Path(found) if found else pathlib.Path("")
    if not pw_cli.is_file():
        prereq_fail("real browser login after the upgrade",
                    "pinned playwright-cli missing — run `npm ci` in web/")

    api_port, web_port = free_port(), free_port()
    api_log = (tmp / "login-api.log").open("w")
    web_log = (tmp / "login-web.log").open("w")
    api = proc_web = None
    proxy_srv = pw_session = None
    try:
        api = subprocess.Popen(
            [str(venv_py), "-m", "uvicorn", "srplatform.api.app:app",
             "--host", "127.0.0.1", "--port", str(api_port),
             "--log-level", "warning"],
            cwd=str(payload),
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp),
                 "SR_ENV": "dev",
                 "POSTGRES_URL": owner_url,
                 "POSTGRES_URL_OWNER": owner_url,
                 "SAFETY_STATE_FILE": str(tmp / "login-safety.json"),
                 "RECORDINGS_DIR": str(tmp / "login-rec"),
                 "API_ALLOWED_ORIGINS": f"http://127.0.0.1:{web_port}",
                 "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=api_log, stderr=subprocess.STDOUT)

        class _StripApi(http.server.BaseHTTPRequestHandler):
            """The installed nginx rule, verbatim: location /api/ {
            proxy_pass http://127.0.0.1:<api>/; } — strip the prefix,
            forward everything else unchanged."""

            def _do(self, verb: str):
                path = self.path
                if path.startswith("/api"):
                    path = path[len("/api"):] or "/"
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    body = self.rfile.read(n) if n else b""
                    hdrs = {k: v for k, v in self.headers.items()
                            if k.lower() not in ("host", "content-length")}
                    up = http.client.HTTPConnection("127.0.0.1", api_port,
                                                    timeout=20)
                    up.request(verb, path, body=body or None, headers=hdrs)
                    res = up.getresponse()
                    data = res.read()
                    self.send_response(res.status)
                    for k, v in res.getheaders():
                        if k.lower() not in ("transfer-encoding",
                                             "connection"):
                            self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    up.close()
                except Exception as exc:  # noqa: BLE001 — 502, then assert
                    self.send_response(502)
                    self.end_headers()
                    self.wfile.write(str(exc).encode())

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

            def do_OPTIONS(self):
                self._do("OPTIONS")

            def log_message(self, *args):  # silence
                pass

        proxy_srv = http.server.ThreadingHTTPServer(
            ("127.0.0.1", pubport), _StripApi)
        threading.Thread(target=proxy_srv.serve_forever,
                         daemon=True).start()

        proc_web = subprocess.Popen(
            [str(web_dir / "node_modules" / ".bin" / "next"), "start",
             "-H", "127.0.0.1", "-p", str(web_port)],
            cwd=str(web_dir),
            env={"PATH": (pathlib.Path(node_binary).parent.as_posix()
                          + ":/usr/local/bin:/usr/bin:/bin"),
                 "HOME": str(tmp)},
            stdout=web_log, stderr=subprocess.STDOUT)

        def _wait(url: str, note: str, log) -> None:
            import urllib.request
            deadline = time.time() + 60
            while time.time() < deadline:
                for p in (api, proc_web):
                    if p is not None and p.poll() is not None:
                        log.flush()
                        fail(note, f"process died early:\n"
                                   f"{log_path(log).read_text()[-800:]}")
                try:
                    with urllib.request.urlopen(url, timeout=3) as r:
                        if r.status == 200:
                            return
                except Exception:  # noqa: BLE001 — still booting
                    pass
                time.sleep(0.5)
            fail(note, f"\n{log_path(log).read_text()[-800:]}")

        def log_path(log):
            return (tmp / "login-api.log" if log is api_log
                    else tmp / "login-web.log")

        # the public URL the bundle baked answers through the proxy
        _wait(f"http://127.0.0.1:{pubport}/healthz",
              "upgraded API answers at the baked public URL (/api strip)",
              api_log)
        _wait(f"http://127.0.0.1:{web_port}/",
              "upgraded web build serves the login page", web_log)

        session = f"sr-upg-{os.getpid()}"

        def pw(*args, timeout=120):
            r = subprocess.run([str(pw_cli), f"-s={session}", *args],
                               capture_output=True, text=True,
                               timeout=timeout, cwd=str(REPO))
            if r.returncode != 0:
                raise AssertionError(
                    f"playwright-cli {' '.join(str(a) for a in args)} -> "
                    f"{r.returncode}\n{r.stdout[-500:]}\n{r.stderr[-500:]}")
            return r

        pw_session = session
        pw("open", "about:blank", "--browser=chromium", timeout=240)
        pw("goto", f"http://127.0.0.1:{web_port}/")
        pw("fill", 'input[placeholder="username"]', LOGIN_USER)
        pw("fill", 'input[placeholder="password"]', LOGIN_PW)
        pw("click", 'button[type="submit"]')
        # success = the form navigated to the authenticated dashboard AND
        # the identity stored by the app is the upgraded DB's own user.
        deadline = time.time() + 45
        body = who = ""
        while time.time() < deadline:
            body = pw("--raw", "eval", "document.body.innerText").stdout
            who = pw("--raw", "eval",
                     "localStorage.getItem('sr_user') || ''").stdout
            if "dashboard" in body and LOGIN_USER in who:
                break
            time.sleep(0.5)
        else:
            api_log.flush()
            fail("browser login reached the authenticated surface",
                 f"page never showed the dashboard for {LOGIN_USER!r}; "
                 f"sr_user={who!r}; body:\n{body[:1200]}\napi tail:\n"
                 f"{tmp.joinpath('login-api.log').read_text()[-600:]}")
        if "Failed to fetch" in body:
            fail("browser login reached the authenticated surface",
                 "page shows a failed sign-in")
        # The token the form flow stored must work on the proxied PUBLIC
        # door too — proving the browser truly spoke to the upgraded API
        # (not a stale localhost default).
        token = pw("--raw", "eval",
                   "localStorage.getItem('sr_token') || ''").stdout
        token = token.strip().strip('"')
        if not token or token == "null":
            fail("login stored the API token", "localStorage empty")
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{pubport}/api/sessions",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status != 200:
                fail("token accepted through the public /api door",
                     f"HTTP {r.status}")
        return (f"form login as {LOGIN_USER} on the provisioned bundle "
                f"(baked {web_receipt.get('next_public_api_url')}) via "
                f"the nginx-equivalent /api strip; token works on "
                f"/api/sessions")
    finally:
        if pw_session:
            subprocess.run([str(pw_cli), f"-s={pw_session}", "close"],
                           capture_output=True, timeout=30, check=False)
        for p in (api, proc_web):
            if p is None:
                continue
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        if proxy_srv is not None:
            proxy_srv.shutdown()
            proxy_srv.server_close()
        for log in (api_log, web_log):
            log.close()


def check_upgrade() -> None:
    """The REAL preserving upgrade through the REAL CLI, in sandboxes.

    Fresh install -> populated database at the PREVIOUS migration head ->
    the actual `appliance.py upgrade` against a real built bundle and a
    real disposable PostgreSQL: payload verification, journal, admission
    fence, durable-work quiescence (a queued or cessation_unknown model
    job BLOCKS even --dry-run), private config backup (journal tree
    excluded; original modes/ownership recorded), database dump through
    the PGPASSFILE channel (the wrapper FAILS the gate if the synthetic
    secret ever appears in argv — exit 47), digest-verified staging,
    per-file atomic activation, real provisioning of the activated
    payload (locked venv deps + entrypoint import + frontend build),
    proven forward-only migrations, and a CHECKED restart against a
    `systemctl` service double — the version stamp only after it
    succeeded. Negatives: rerun no-op; a second attempt refused while one
    is in progress; SIGKILL interruption keeps fence+journal until resume
    completes; provision failure and restart failure never complete and
    never stamp; restore is two-pass (corrupt late file = ZERO changes)
    and restores modes exactly; tampered bytes, contract mismatch,
    duplicate manifest keys and pre-21 bundles are refused BEFORE any
    side effect and the no-op answer cannot bypass them.

    Prerequisite: docker (the fixture owns its postgres:16 container
    `sr-upg-pg-*`; the pg_dump wrapper runs the real pg_dump INSIDE that
    fixture — the dumped artifact is the real database, never synthetic).
    The `systemctl` double and fake systemctl logs are owned by the run
    directory; nothing external is touched.
    """
    import subprocess as sp
    import hashlib as _hl
    import signal
    import tempfile
    import shutil as _sh
    sys.path.insert(0, str(REPO / "infra" / "dev"))
    sys.path.insert(0, str(REPO))  # deploy/srplatform imports below
    import install_sequences as iseq  # noqa: E402
    from sqlalchemy import create_engine as sa_create
    from sqlalchemy import text as sa_text

    if shutil.which("docker") is None:
        prereq_fail("preserving upgrade sequences",
                    "requires docker for the disposable postgres:16 "
                    "fixture (the gate owns sr-upg-pg-<run>; nothing "
                    "external is selected)")
    run_id = _hl.sha256(str(time.time()).encode()).hexdigest()[:8]
    cname = f"sr-upg-pg-{run_id}"
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sr-upgrade-gate-"))
    fake_secret = "SrGateFake$9e2f1c"  # SYNTHETIC; proves the argv channel
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("SR_PG_ADMIN", "SR_PG_UPGRADE",
                                "POSTGRES_URL"))}
    env.update(DB_APP_ROLE="sr_uapp", DB_SECRET_ROLE="sr_usecret")
    env["NPM_CONFIG_FUND"] = "false"
    # round-6 launch contract: the release bundle is a SEALED tree and
    # its verify refuses unlisted files (including __pycache__/*.pyc).
    # Operators run every payload-tree command with -B; the gate mirrors
    # that for the CLI parent via the env (the engine's own alembic
    # child carries the guard in code), and scenario A asserts the
    # payload stayed byte-clean through the real upgrade.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # round-4 finding 3: the su-shim installer channel appends its own
    # environment KEYS here; scenario A asserts the SELECTED credential
    # name never appears (private to the CLI + authorized channels only).
    su_env_capture = tmp / "su-env-capture.txt"
    env["SR_ENV_CAPTURE"] = str(su_env_capture)
    port = None
    # a `systemctl` service DOUBLE on PATH: the engine's restart path is
    # the REAL checked one; only the service manager itself is a double.
    fake_bin = tmp / "bin"
    fake_bin.mkdir()
    ctl = fake_bin / "systemctl"
    ctl.write_text(
        "#!/usr/bin/env bash\n"
        'echo "$@" >> "${SR_FAKE_SYSTEMCTL_LOG:-/dev/null}"\n'
        'unit=""; quiet=0\n'
        'if [[ "$2" == "--quiet" ]]; then unit="$3"; quiet=1; '
        'else unit="$2"; fi\n'
        'stfile="${SR_FAKE_STATE_DIR:-.}/unit-$unit"\n'
        'case "$1" in\n'
        '  stop)\n'
        '    if [[ -n "${SR_FAKE_STOP_FAIL:-}" ]]; then '
        'echo "double: refusing stop" >&2; exit 5; fi\n'
        '    mkdir -p "${SR_FAKE_STATE_DIR:-.}"; echo inactive > '
        '"$stfile"; exit 0;;\n'
        '  restart)\n'
        '    if [[ -n "${SR_FAKE_RESTART_FAIL:-}" ]]; then '
        'echo "double: refusing restart" >&2; exit 5; fi\n'
        '    mkdir -p "${SR_FAKE_STATE_DIR:-.}"; echo active > "$stfile"; '
        'exit 0;;\n'
        '  daemon-reload)\n'
        '    if [[ -n "${SR_FAKE_RELOAD_FAIL:-}" ]]; then '
        'echo "double: daemon-reload failed" >&2; exit 5; fi\n'
        '    exit 0;;\n'
        '  is-active)\n'
        '    s=active; [[ -f "$stfile" ]] && s=$(cat "$stfile")\n'
        '    if [[ "$quiet" == 1 ]]; then [[ "$s" == active ]] && exit 0 '
        '|| exit 3; else echo "$s"; [[ "$s" == active ]] && exit 0 '
        '|| exit 3; fi;;\n'
        "esac\n"
        "exit 0\n")
    ctl.chmod(0o755)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["SR_FAKE_STATE_DIR"] = str(tmp / "ctl-state")

    def docker(*args: str, timeout: int = 120) -> sp.CompletedProcess:
        return sp.run(["docker", *args], capture_output=True, text=True,
                      timeout=timeout)

    def cli(*args: str, timeout: int = 2400, extra_env: dict | None = None,
            proc: bool = False):
        cmd = [sys.executable, str(REPO / "deploy/appliance.py"), *args]
        e = {**env, **(extra_env or {})}
        if proc:
            return sp.Popen(cmd, cwd=REPO, env=e,
                            stdout=sp.PIPE, stderr=sp.STDOUT, text=True,
                            start_new_session=True)
        r = sp.run(cmd, cwd=REPO, env=e, capture_output=True, text=True,
                   timeout=timeout)
        return r

    try:
        d = docker("run", "-d", "--name", cname,
                   "-e", f"POSTGRES_PASSWORD={fake_secret}",
                   "-p", "127.0.0.1::5432", "postgres:16")
        if d.returncode != 0:
            prereq_fail("preserving upgrade sequences",
                        f"postgres:16 fixture could not start: "
                        f"{(d.stdout + d.stderr)[-300:]}")
        # readiness = a real SQL roundtrip, not pg_isready (the image's
        # initdb phase runs a TEMPORARY server whose socket disappears on
        # restart; pg_isready alone can succeed against the transient one)
        for _ in range(120):
            r = docker("exec", cname, "psql", "-U", "postgres", "-v",
                       "ON_ERROR_STOP=1", "-tAc", "SELECT 1", timeout=15)
            if r.returncode == 0 and r.stdout.strip() == "1":
                break
            time.sleep(1)
        else:
            fail("postgres fixture readiness", "psql SELECT 1 never succeeded")
        port = docker("port", cname, "5432/tcp").stdout.split()[0]
        host_port = int(str(port).rsplit(":", 1)[1])
        for stmt in (
                'CREATE ROLE sr_uapp',
                'CREATE DATABASE srupg OWNER postgres ENCODING \'UTF8\' '
                "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'",
                'CREATE DATABASE srupg2 OWNER postgres ENCODING \'UTF8\' '
                "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'",
                'CREATE DATABASE srupg3 OWNER postgres ENCODING \'UTF8\' '
                "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'",
                'CREATE DATABASE srupg4 OWNER postgres ENCODING \'UTF8\' '
                "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'",
                'CREATE DATABASE srupg5 OWNER postgres ENCODING \'UTF8\' '
                "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"):
            r = docker("exec", cname, "psql", "-U", "postgres", "-v",
                       "ON_ERROR_STOP=1", "-c", stmt, timeout=60)
            if r.returncode != 0:
                fail("postgres fixture bootstrap",
                     f"{stmt[:40]}: {r.stderr[-200:]}")
        # NO sr_usecret here (round-3 finding 1): the gate no longer
        # manufactures the secret-role prerequisite — the ENGINE must
        # bootstrap it through the installer-equivalent channel, which in
        # the sandbox is the same `su postgres -c psql` path a real
        # appliance uses, shimmed into the fixture container.
        su_shim = fake_bin / "su"
        su_shim.write_text(
            "#!/usr/bin/env python3\n"
            "import os, shlex, subprocess, sys\n"
            "# round-4 finding 3: capture the FULL environment keys this "
            "authorized-channel child received, so the gate can prove the "
            "SELECTED --db-url-env credential name never reached it.\n"
            "cap = os.environ.get('SR_ENV_CAPTURE')\n"
            "if cap:\n"
            "    with open(cap, 'a') as fh:\n"
            "        fh.write('\\n'.join(sorted(os.environ)) + '\\n')\n"
            "assert sys.argv[1] == 'postgres', sys.argv[1:2]\n"
            "cmd = shlex.split(sys.argv[3])\n"
            "assert cmd[0] == 'psql' and '-f' in cmd, cmd\n"
            "sql = open(cmd[cmd.index('-f') + 1]).read()\n"
            f"p = subprocess.run(['docker', 'exec', '-i', '{cname}', "
            "'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-d', "
            "'postgres', '-f', '-'], "
            " input=sql, capture_output=True, text=True)\n"
            "sys.stderr.write(p.stderr)\n"
            "sys.exit(p.returncode)\n")
        su_shim.chmod(0o755)

        # ---- readiness fixtures (round-4 finding 1): PRODUCTION SHAPES --- #
        # The installed /readyz answers HTTP 200 with ready:false when the
        # schema is behind — the engine must parse the JSON contract, and
        # the gate reproduces the REAL shapes: 200/ready-false (old
        # service mid-upgrade), 200/ready-true with a WRONG
        # migration_version (stale old process), and the healthy
        # production shape at the payload head. Fake 503s no longer model
        # anything here.
        import http.server
        import threading
        # the payload's expected schema head, DERIVED not hardcoded: a
        # new migration must never silently turn the readiness stub and
        # the head assertions into false negatives.
        head_rev = max(p.name.split("_")[0] for p in
                       (REPO / "srplatform" / "db" / "migrations" /
                        "versions").glob("[0-9][0-9][0-9][0-9]_*.py"))
        ready_flag = tmp / "readyz-not-ready"       # 200 ready:false
        badhead_flag = tmp / "readyz-wrong-head"    # 200 ready:true 0019

        class _ReadyHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path.startswith("/readyz"):
                    code = 200
                    if ready_flag.exists():
                        body = json.dumps({
                            "ready": False, "migration_version": "0019",
                            "issues": [f"schema 0019 behind head {head_rev}"],
                            "controller": {"ok": True, "detail": ""},
                            "runner": {"ok": True, "detail": ""},
                            "recordings_writable": True,
                            "safety": {}}).encode()
                    elif badhead_flag.exists():
                        body = json.dumps({
                            "ready": True, "migration_version": "0019",
                            "issues": []}).encode()
                    else:
                        body = json.dumps({
                            "ready": True, "migration_version": head_rev,
                            "issues": []}).encode()
                    ctype = "application/json"
                elif self.path == "/":
                    code, body = 200, b'{"page": "frontend"}'
                    ctype = "application/json"
                else:
                    code, body, ctype = 404, b"{}", "application/json"
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence
                pass

        ready_srv = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _ReadyHandler)
        threading.Thread(target=ready_srv.serve_forever,
                         daemon=True).start()
        ready_port = ready_srv.server_address[1]
        url = (f"postgresql://postgres:{fake_secret}@127.0.0.1:{host_port}"
               "/srupg")
        url2 = url.replace("/srupg", "/srupg2")
        url3 = url.replace("/srupg", "/srupg3")
        url4 = url.replace("/srupg", "/srupg4")
        url5 = url.replace("/srupg", "/srupg5")

        # pg_dump WRAPPER around the real pg_dump INSIDE the fixture. NEW
        # credential contract: endpoint FLAGS in argv, password via
        # PGPASSFILE in the environment; if the secret ever appears in the
        # wrapper's argv the gate dies with 47 (argv-leak tripwire).
        wrapper = tmp / "pg_dump-wrapper.sh"
        wrapper.write_text(
            "#!/usr/bin/env bash\n"
            "for a in \"$@\"; do\n"
            f"  if [[ \"$a\" == *'{fake_secret}'* ]]; then\n"
            "    echo 'ARGV SECRET LEAK' >&2; exit 47; fi\n"
            "done\n"
            # round-3 finding 5: the OWNER URL must never travel in this
            # child's environment either — only endpoint argv + PGPASSFILE.
            "for k in POSTGRES_URL_OWNER SR_POSTGRES_URL_OWNER "
            "SR_PG_UPGRADE_URL SR_PG_SECRET_URL REVIEW_PRIVATE_OWNER; do\n"
            '  if [[ -n "${!k:-}" ]]; then\n'
            "    echo \"CHILD ENV SECRET LEAK: $k\" >&2; exit 48; fi\n"
            "done\n"
            '[[ -z "${PGPASSFILE:-}" || ! -r "${PGPASSFILE}" ]] && '
            '{ echo "PGPASSFILE channel missing" >&2; exit 46; }\n'
            "db=''; out=''\n"
            "while [[ $# -gt 0 ]]; do\n"
            "  case \"$1\" in\n"
            "    -d) db=\"$2\"; shift 2;;\n"
            "    --file) out=\"$2\"; shift 2;;\n"
            "    --format=custom) shift;;\n"
            "    -h|-p|-U) shift 2;;\n"
            "    *) shift;;\n"
            "  esac\n"
            "done\n"
            "pw=$(cut -d: -f5- \"${PGPASSFILE}\" | tail -1)\n"
            f"docker exec -e PGPASSWORD=\"$pw\" {cname} pg_dump "
            "-h localhost -U postgres "
            f"-d \"$db\" --format=custom --file=/tmp/srupg.dump || exit 1\n"
            f"docker cp {cname}:/tmp/srupg.dump \"$out\" || exit 1\n")
        wrapper.chmod(0o755)

        def alembic(url_x: str, *args: str):
            return sp.run([sys.executable, "-m", "alembic", *args],
                          cwd=REPO, capture_output=True, text=True,
                          timeout=900,
                          env={**env, "POSTGRES_URL_OWNER": url_x})

        # ---- payload: a REAL bundle built from this candidate ---------- #
        fake_base = tmp / "upg-base.qcow2"
        sp.run(["qemu-img", "create", "-f", "qcow2", str(fake_base), "64M"],
               capture_output=True, check=True, timeout=60)
        payload = tmp / "payload-bundle"
        b = sp.run([sys.executable, str(REPO / "deploy/bundle.py"), "build",
                    "--output", str(payload), "--base-image", str(fake_base)],
                   cwd=REPO, capture_output=True, text=True, timeout=1800,
                   env=env)
        if b.returncode != 0:
            fail("upgrade payload bundle build", (b.stdout + b.stderr)[-500:])
        payload_manifest = json.loads(
            (payload / "MANIFEST.json").read_text())
        ok("payload bundle built from the candidate",
           f"revision {payload_manifest['revision'][:12]}, upgrade contract "
           f"for head-driven migration")

        def db_q(url_x: str, sql: str):
            eng = sa_create(url_x)
            with eng.connect() as c:
                r = c.execute(sa_text(sql)).fetchall()
            eng.dispose()
            return r

        def apply_sandbox(root: pathlib.Path, manifest: pathlib.Path):
            r = cli("apply", "--manifest", str(manifest),
                    "--system-root", str(root))
            if r.returncode != 0:
                fail("sandbox fresh install", (r.stdout + r.stderr)[-500:])

        def seed(url_x: str, tag: str, *, coach: bool = True) -> None:
            from srplatform.api.auth import hash_password
            eng = sa_create(url_x)
            with eng.begin() as c:
                c.execute(sa_text(
                    "INSERT INTO users (user_id, username, password_hash, "
                    "role) VALUES (gen_random_uuid(), :u, "
                    "'scrypt$witness$keep', 'operator')"),
                    {"u": f"p21-witness-{tag}"})
                # AC-5: a member whose hash REAL code can verify — the
                # witness hash proves only that upgrades preserve bytes,
                # it can never authenticate. The post-upgrade browser
                # login signs in as this user.
                c.execute(sa_text(
                    "INSERT INTO users (user_id, username, password_hash, "
                    "role) VALUES (gen_random_uuid(), :u, :h, 'member')"),
                    {"u": LOGIN_USER, "h": hash_password(LOGIN_PW)})
                sid = c.execute(sa_text(
                    "INSERT INTO sessions (session_id, scenario_id, status) "
                    "VALUES (gen_random_uuid(), 'web-foothold-01', "
                    "'complete') RETURNING session_id"
                )).scalar()
                if coach:
                    c.execute(sa_text(
                        "INSERT INTO coach_messages (session_id, role, body) "
                        "VALUES (:sid, 'coach', 'P21-SEALED-HISTORY-KEEP')"),
                        {"sid": sid})
            eng.dispose()

        def upgrade_cli(root, manifest, db_url, *, resume=None, extra=(),
                        extra_env=None, fresh=True, allow_fail=False,
                        url_env=None):
            args = ["upgrade", "--manifest", str(manifest),
                    "--system-root", str(root), "--payload", str(payload),
                    "--pg-dump-bin", str(wrapper),
                    "--web-url", f"http://127.0.0.1:{ready_port}/", *extra]
            if url_env:
                # round-4 finding 3: --db-url-env accepts ANY name; the
                # engine must register it and scrub it from every
                # unauthorized child by that explicit name
                args += ["--db-url-env", url_env]
            if fresh:
                args += ["--allow-fresh-install"]
            if resume:
                args += ["--resume", resume]
            e = {url_env or "SR_PG_UPGRADE_URL": db_url}
            if extra_env:
                e.update(extra_env)
            r = cli(*args, extra_env=e, timeout=2400)
            if r.returncode != 0 and not allow_fail:
                fail("upgrade CLI unexpectedly failed",
                     (r.stdout + r.stderr)[-1200:])
            return r

        # ---- scenario A: real preserving upgrade, provisioned + restarted #
        # Starts at the REAL deployed-52ae355 revision (0019): old schema,
        # old config, app role only — NO sr_secret role and no db-secret
        # file exist here (round-3 finding 1: the gate must not manufacture
        # the prereqs the engine is supposed to satisfy).
        manifest_path = iseq.build_manifest(tmp / "appliance-input")
        man_raw = json.loads(manifest_path.read_text())
        man_raw["urls"]["internal"] = f"http://127.0.0.1:{ready_port}"
        # AC-5/LIVE-05 (review round 1): the gate must prove a REAL
        # browser login after the upgrade, so the manifest carries a
        # loopback PUBLIC url (the schema allows http; a real appliance
        # uses its LAN address). The web bundle bakes it at provision,
        # and after the upgrade a fixed /api-stripping proxy answers on
        # this very port — the installed nginx's one rule — so the
        # browser's baked address reaches the upgraded API.
        with socket.socket() as _s:
            _s.bind(("127.0.0.1", 0))
            pubport = _s.getsockname()[1]
        man_raw["urls"]["public"] = f"http://127.0.0.1:{pubport}"
        manifest_path.write_text(json.dumps(man_raw))
        rootA = tmp / "rootA"
        apply_sandbox(rootA, manifest_path)
        # LIVE-04 reproduction shape: the installed upgrade carried a
        # configuration change, so finalize re-renders files the OLD
        # install receipt still baselines. Capture the pre-upgrade
        # baseline, then change the manifest exactly like a real operator
        # upgrade would.
        old_receipt_text = (iseq._manifest_paths(rootA)["receipt"]
                            .read_text())
        man_raw = json.loads(manifest_path.read_text())
        man_raw["appliance"]["timezone"] = "Europe/Berlin"
        manifest_path.write_text(json.dumps(man_raw))
        assert alembic(url, "upgrade", "0019").returncode == 0
        seed(url, "a", coach=False)
        secret_roles_before = db_q(
            url, "SELECT count(*) FROM pg_roles WHERE rolname='sr_usecret'")
        if secret_roles_before != [(0,)]:
            fail("scenario A starts WITHOUT the secret role (real 0019 "
                 "prereq state)", str(secret_roles_before))
        paths = iseq._manifest_paths(rootA)
        token_bytes = paths["token"].read_bytes()
        sentinel = paths["state"] / "sentinel.db"
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_text("history-and-data\n")
        # mode witnesses: a service-readable 0640 and a plain 0644 file
        # must survive backup+restore with their ORIGINAL bits (F4)
        svc_read = paths["etc"] / "svc-read.txt"
        svc_read.write_text("service-readable\n")
        svc_read.chmod(0o640)
        plain = paths["etc"] / "plain.txt"
        plain.write_text("plain\n")
        plain.chmod(0o644)
        ctl_log_a = tmp / "ctlA.log"
        # round-4 finding 3 end-to-end: the owner URL travels in a
        # CUSTOM-named variable (--db-url-env REVIEW_PRIVATE_OWNER). The
        # pg_dump wrapper aborts with 48 if it ever sees that name in a
        # child env, and the su-shim captures every installer-channel
        # child's environment keys for the assertion after this block.
        r = upgrade_cli(rootA, manifest_path, url,
                        url_env="REVIEW_PRIVATE_OWNER",
                        extra_env={"SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_a)})
        outA = json.loads(r.stdout)
        stages = outA.get("stages", {})
        missing = [s for s in ("quiesce", "backup", "stage", "activate",
                               "provision", "secrets", "migrate",
                               "finalize", "restart")
                   if stages.get(s, {}).get("status") != "done"]
        if outA.get("status") != "done" or missing:
            fail("preserving upgrade journal completeness "
                 "(quiesce..backup..provision..secrets..restart)",
                 f"status={outA.get('status')} missing={missing}")
        heads = {row[0] for row in
                 db_q(url, "SELECT version_num FROM alembic_version")}
        if heads != {head_rev}:
            fail("preserving upgrade reached head", f"heads {heads}")
        # round-3 finding 1: the ENGINE bootstrapped the 0021 prerequisite
        # itself — role created through the installer channel, API-only
        # 0600 file, and no other role re-keyed.
        secret_roles = db_q(
            url, "SELECT count(*) FROM pg_roles WHERE rolname='sr_usecret'")
        if secret_roles != [(1,)]:
            fail("upgrade bootstrapped the credential-store role",
                 f"sr_usecret count {secret_roles}")
        secret_file = paths["etc"] / "secrets" / "db-secret.env"
        if not secret_file.is_file() or \
                secret_file.stat().st_mode & 0o777 != 0o600 or \
                "SR_PG_SECRET_URL=postgresql+psycopg2://sr_usecret:" \
                not in secret_file.read_text():
            fail("credential-store file is API-only 0600 and complete",
                 f"mode {secret_file.stat().st_mode & 0o777:04o}")
        if stages.get("secrets", {}).get("status") != "done" or \
                stages.get("quiesce", {}).get("status") != "done":
            fail("journal carries the quiesce + secret-bootstrap stages",
                 str({k: v.get("status") for k, v in stages.items()}))
        mj_now = db_q(url, "SELECT count(*) FROM information_schema.tables "
                           "WHERE table_name = 'model_jobs'")
        if mj_now != [(1,)]:
            fail("old-schema upgrade created the newer tables", str(mj_now))
        users = db_q(url, "SELECT password_hash FROM users "
                          "WHERE username = 'p21-witness-a'")
        if users != [("scrypt$witness$keep",)]:
            fail("preserving upgrade preserved the operator user", str(users))
        if paths["token"].read_bytes() != token_bytes:
            fail("preserving upgrade preserved the capability key")
        if sentinel.read_text() != "history-and-data\n":
            fail("preserving upgrade left data alone")
        att_dir = (paths["etc"] / "upgrade" / outA["attempt"])
        dump = att_dir / "database.dump"
        if not dump.is_file() or dump.stat().st_size == 0:
            fail("preserving database backup exists", str(dump))
        if _hl.sha256(dump.read_bytes()).hexdigest() != \
                stages["backup"].get("db_sha256"):
            fail("database backup digest matches its journal entry")
        docker("cp", str(dump), f"{cname}:/tmp/check.dump")
        lst = docker("exec", cname, "pg_restore", "--list", "/tmp/check.dump",
                     timeout=120)
        if lst.returncode != 0 or "TABLE DATA public users" not in lst.stdout:
            fail("database backup is a restore-listable artifact",
                 (lst.stdout + lst.stderr)[-300:])
        # F3: the mutable journal tree is NOT config and must be excluded
        backup_files = json.loads(
            (att_dir / "config-backup-manifest.json").read_text())["files"]
        if any(str(k).startswith("upgrade") for k in backup_files):
            fail("config backup excludes the journal tree",
                 str([k for k in backup_files if str(k).startswith("upgrade")
                      ][:3]))
        # F1: provisioning produced a real receipt and the installed venv
        # imports the entrypoints (the provision stage executed them)
        receipt = json.loads((att_dir / "provision-receipt.json").read_text())
        venv_py = pathlib.Path(receipt["venv"]) / "bin" / "python"
        chk = sp.run([str(venv_py), "-c",
                      "import srplatform.api.app, infra.appliance.brokerd"],
                     cwd=str(rootA / "opt/sparring-range"),
                     capture_output=True, text=True, timeout=120)
        if chk.returncode != 0:
            fail("installed venv runs the release entrypoints",
                 (chk.stdout + chk.stderr)[-300:])
        # LIVE-05: the upgrade-time frontend build must bake the MANIFEST's
        # public API URL (NEXT_PUBLIC_API_URL). The installed defect was an
        # upgrade that provisioned with an empty URL: the browser then
        # posted login to localhost:8000 and every sign-in "Failed to
        # fetch" despite a healthy appliance. The receipt is the proof.
        web_receipt = receipt.get("web") or {}
        if web_receipt.get("next_public_api_url") != f"http://127.0.0.1:{pubport}/api":
            fail("upgrade frontend baked the manifest's public API URL",
                 f"receipt next_public_api_url="
                 f"{web_receipt.get('next_public_api_url')!r}")
        ok("upgrade provisioned the frontend with the public API URL",
           str(web_receipt.get("next_public_api_url")))
        # ---- AC-5 / LIVE-05 (review round 1): the baked URL must not
        # merely be present — a real browser must sign in through it
        # against the upgraded code. Fails the gate on any missing piece.
        login_note = _upgrade_browser_login(tmp, rootA, receipt, url,
                                            pubport)
        ok("real browser login against the upgraded appliance", login_note)
        # F5: the CHECKED restart ran against the service double — every
        # unit restarted and then verified active; stamp only after that
        ctl_lines = ctl_log_a.read_text().splitlines() if \
            ctl_log_a.is_file() else []
        restarted = [l.split()[1] for l in ctl_lines
                     if l.startswith("restart ")]
        verified = [l.split()[2] for l in ctl_lines
                    if l.startswith("is-active --quiet ")]
        if not restarted or set(restarted) - set(verified):
            fail("restart verified every unit active",
                 f"restarted={restarted} verified={verified}")
        # round-3 findings 2+3: the admission services were STOPPED (the
        # barrier an old fence-unaware process cannot bypass), and the
        # manager RELOADED the rewritten units before any restart.
        stops = [l.split()[1] for l in ctl_lines if l.startswith("stop ")]
        for u in ("sr-api.service", "sr-worker-supervisor.service"):
            if u not in stops:
                fail("upgrade stopped the admission services before "
                     "mutating anything", f"{u} not stopped: {stops}")
        idx_first = lambda pref: min(
            (i for i, l in enumerate(ctl_lines) if l.startswith(pref)),
            default=-1)
        if not (0 <= idx_first("stop sr-api.service")
                < idx_first("daemon-reload")
                < idx_first("restart sr-api.service")):
            fail("order: stop -> daemon-reload -> restart", str(idx_first))
        stamp = json.loads((paths["etc"] / "release-version.json")
                           .read_text())
        if stamp.get("attempt") != outA["attempt"] or \
                stamp.get("revision") != payload_manifest["revision"]:
            fail("version stamp names the completed attempt and revision",
                 str(stamp)[:200])
        # fence dropped only on completion
        if (paths["state"] / "maintenance").exists():
            fail("admission fence released on completion",
                 "fence file remains after a completed attempt")
        ok("preserving upgrade (journal, fence, backups, provisioning, "
           "migrations, verified restart, users, keys, restore-listable "
           "dump)", f"attempt {outA['attempt']}, heads {sorted(heads)}")

        # ---- LIVE-04: a SUCCESSFUL upgrade re-versions the verified
        # baseline; the previous receipt is archived (evidence kept) and
        # a genuine CURRENT drift still fails.
        ver = sp.run(
            [sys.executable, str(REPO / "deploy/appliance.py"), "verify",
             "--manifest", str(manifest_path), "--system-root",
             str(rootA), "--json"],
            capture_output=True, text=True, timeout=120)
        vout = json.loads(ver.stdout or "{}")
        if ver.returncode != 0 or not vout.get("ok"):
            fail("post-upgrade verify is clean against the refreshed "
                 "baseline (LIVE-04)",
                 json.dumps({"code": ver.returncode,
                             "drift": vout.get("drift", [])[:5]})[:500])
        archived = (paths["etc"] / "install-receipts"
                    / f"{outA['attempt']}.json")
        if not archived.is_file() or archived.read_text() != old_receipt_text:
            fail("previous install receipt archived byte-identically, "
                 "never deleted", str(archived))
        victim = paths["env"]
        original_env = victim.read_text()
        victim.write_text(original_env + "\n# drifted\n")
        ver2 = sp.run(
            [sys.executable, str(REPO / "deploy/appliance.py"), "verify",
             "--manifest", str(manifest_path), "--system-root", str(rootA),
             "--json"],
            capture_output=True, text=True, timeout=120)
        vout2 = json.loads(ver2.stdout or "{}")
        victim.write_text(original_env)
        if ver2.returncode == 0 or not any(
                d.get("path") == str(victim) for d in vout2.get("drift", [])):
            fail("the refreshed baseline still detects CURRENT drift",
                 json.dumps(vout2.get("drift", []))[:300])
        ok("LIVE-04: verified baseline re-versioned on success, prior "
           "receipt archived, current drift still detected")

        # round-4 finding 3 (REAL child envs): the installer-channel child
        # actually ran (the capture is not empty), and NONE of them saw an
        # owner credential — the custom name the CLI was invoked with, the
        # fixed names, or the PGPASSFILE channel.
        captured = (su_env_capture.read_text().splitlines()
                    if su_env_capture.is_file() else [])
        if not captured:
            fail("installer-channel environments were captured",
                 "the su-shim never ran during scenario A")
        forbidden = {"REVIEW_PRIVATE_OWNER", "SR_PG_UPGRADE_URL",
                     "SR_POSTGRES_URL_OWNER", "POSTGRES_URL_OWNER",
                     "SR_PG_SECRET_URL", "PGPASSFILE", "PGPASSWORD"}
        leaked = sorted(forbidden.intersection(captured))
        if leaked:
            fail("named --db-url-env credential reached an unauthorized "
                 "child environment", str(leaked))
        ok("the SELECTED credential name never reached an installer-channel "
           f"child ({len(set(captured))} distinct env keys captured, zero "
           "credential names)")

        # round-6: the real upgrade left the SEALED payload tree byte-
        # clean — no unlisted bytecode from the CLI, alembic, or any
        # other child (that pollution used to break the operator's next
        # `bundle.py verify`).
        strays = sorted({str(p.relative_to(payload))
                         for p in payload.rglob("__pycache__")} |
                        {str(p.relative_to(payload))
                         for p in payload.rglob("*.pyc")})
        if strays:
            fail("real upgrade leaves ZERO bytecode in the sealed payload",
                 str(strays[:6]))
        ok("sealed payload tree byte-clean after the real upgrade "
           "(no __pycache__/*.pyc anywhere)")

        r2 = upgrade_cli(rootA, manifest_path, url)
        if r2.returncode != 0 or '"no_op"' not in r2.stdout:
            fail("rerun at the payload revision answers no-op",
                 (r2.stdout + r2.stderr)[-300:])
        ok("rerun at the same revision is a truthful no-op")

        # F4: corrupt config + flip modes, restore, ORIGINAL bits return
        svc_read.write_text("CORRUPT\n")
        svc_read.chmod(0o600)
        envf = paths["env"]
        envf.write_text("CORRUPTED BY THE UPGATE\n")
        rr = cli("upgrade", "--manifest", str(manifest_path),
                 "--system-root", str(rootA),
                 "--restore-config", outA["attempt"])
        rr_out = json.loads(rr.stdout) if rr.returncode == 0 else {}
        if rr.returncode != 0 or rr_out.get("service_actions") != [] \
                or "CORRUPTED" in envf.read_text():
            fail("config-only restore from the attempt backup",
                 (rr.stdout + rr.stderr)[-400:])
        if (svc_read.stat().st_mode & 0o777 != 0o640
                or svc_read.read_text() != "service-readable\n"):
            fail("restore preserves the original 0640 service mode",
                 f"mode {svc_read.stat().st_mode & 0o777:04o}")
        if plain.stat().st_mode & 0o777 != 0o644:
            fail("restore preserves 0644", f"{plain.stat().st_mode & 0o777:04o}")
        ok("config-only restore repairs bytes AND original modes, "
           "no service action")

        # F7: at head (a would-be no-op), tampered bytes must REFUSE, not
        # no-op; contract mismatch and duplicate keys likewise, before
        # any side effect.
        victim = payload / "srplatform/settings.py"
        keep = victim.read_bytes()
        victim.write_bytes(b"# tampered by the upgrade gate\n")
        neg = upgrade_cli(rootA, manifest_path, url, allow_fail=True)
        victim.write_bytes(keep)
        if neg.returncode == 0 or "digest" not in (neg.stdout + neg.stderr) \
                or '"no_op"' in neg.stdout:
            fail("tampered payload refused before the no-op answer",
                 (neg.stdout + neg.stderr)[-300:])
        ok("payload tampering is refused even where a no-op would answer")

        lie = tmp / "contract-lie-bundle"
        lie.mkdir()
        man = json.loads((payload / "MANIFEST.json").read_text())
        shutil.copytree(payload / "srplatform", lie / "srplatform")
        man["upgrade"]["revision"] = "deadbeefdeadbeefdeadbeefdeadbeefdead"
        (lie / "MANIFEST.json").write_text(json.dumps(man))
        neg3 = upgrade_cli(rootA, manifest_path, url, allow_fail=True,
                           extra=("--payload", str(lie)))
        if neg3.returncode == 0 or "contract" not in (
                (neg3.stdout + neg3.stderr).lower()):
            fail("contract revision mismatch refused",
                 (neg3.stdout + neg3.stderr)[-300:])
        ok("upgrade contract disagreeing with the manifest is refused")

        dup = tmp / "dup-manifest-bundle"
        dup.mkdir()
        shutil.copytree(payload / "srplatform", dup / "srplatform")
        (dup / "pyproject.toml").write_bytes(b"a\n")
        # hand-written raw JSON with the SAME key twice: last-wins parsing
        # must not smuggle an unchecked runtime path past verification
        digest_a = _hl.sha256(b"a\n").hexdigest()
        (dup / "MANIFEST.json").write_text(
            '{"bundle_version": 2, "revision": "cafe", "upgrade": '
            '{"engine": "deploy/upgrade.py", "migrations": "srplatform", '
            '"bundle_version": 2, "revision": "cafe"}, "files": {'
            f'"pyproject.toml": {{"sha256": "{digest_a}", "bytes": 2}}, '
            f'"pyproject.toml": {{"sha256": "{"0" * 64}", "bytes": 2}}}}')
        neg4 = upgrade_cli(rootA, manifest_path, url, allow_fail=True,
                           extra=("--payload", str(dup)))
        if neg4.returncode == 0 or "duplicate" not in (
                neg4.stdout + neg4.stderr):
            fail("duplicate manifest keys refused",
                 (neg4.stdout + neg4.stderr)[-300:])
        ok("a MANIFEST with duplicate keys is refused before parsing wins")

        # F2: --dry-run must NOT claim quiesced while durable work exists.
        # Scenario B's database gets real jobs; unknown cessation is the
        # loudest case. No mutation, no journal, no fence on dry-run.
        rootB = tmp / "rootB"
        apply_sandbox(rootB, manifest_path)
        assert alembic(url2, "upgrade", "0025").returncode == 0
        seed(url2, "b")
        pathsB = iseq._manifest_paths(rootB)

        def insert_job(state: str) -> None:
            eng = sa_create(url2)
            with eng.begin() as c:
                jid = c.execute(sa_text(
                    "INSERT INTO model_jobs (job_id, kind, priority, state, "
                    "payload, requested_at) VALUES (gen_random_uuid(), "
                    "'probe', 5, :st, '{}'::jsonb, now()) "
                    "RETURNING job_id"), {"st": state}).scalar()
            eng.dispose()
            return str(jid)

        jid = insert_job("queued")
        dneg = upgrade_cli(rootB, manifest_path, url2, extra=("--dry-run",),
                           allow_fail=True)
        if dneg.returncode == 0 or "model job" not in (
                dneg.stdout + dneg.stderr):
            fail("dry-run REFUSES while a model job is queued",
                 (dneg.stdout + dneg.stderr)[-400:])
        eng = sa_create(url2)
        with eng.begin() as c:
            c.execute(sa_text("DELETE FROM model_jobs WHERE job_id = :j"),
                      {"j": jid})
        eng.dispose()
        jid = insert_job("cessation_unknown")
        dneg2 = upgrade_cli(rootB, manifest_path, url2, extra=("--dry-run",),
                            allow_fail=True)
        if dneg2.returncode == 0 or "cessation" not in (
                dneg2.stdout + dneg2.stderr):
            fail("dry-run REFUSES cessation_unknown obligations",
                 (dneg2.stdout + dneg2.stderr)[-400:])
        eng = sa_create(url2)
        with eng.begin() as c:
            c.execute(sa_text("DELETE FROM model_jobs WHERE job_id = :j"),
                      {"j": jid})
        eng.dispose()
        if list((pathsB["etc"] / "upgrade").glob("*/journal.json")) \
                or (pathsB["state"] / "maintenance").exists():
            fail("dry-run performs no side effects",
                 "journal or fence appeared during --dry-run")
        ok("--dry-run refuses queued AND cessation_unknown durable work "
           "with zero side effects")

        # F2: without --allow-fresh-install a MISSING ledger is missing
        # evidence, not quiescence.
        dneg3 = upgrade_cli(rootB, manifest_path, url2,
                            extra=("--dry-run",), fresh=False,
                            allow_fail=True)
        if dneg3.returncode == 0 or "MISSING" not in (
                dneg3.stdout + dneg3.stderr):
            fail("missing broker ledger is not silent success",
                 (dneg3.stdout + dneg3.stderr)[-400:])
        ok("a missing ledger must be answered by --allow-fresh-install, "
           "never by silence")

        # ============ scenario B: interrupt, refuse, resume, restore ====== #
        drifted = rootB / "opt/sparring-range/srplatform/__init__.py"
        drifted.parent.mkdir(parents=True, exist_ok=True)
        drifted.write_text("# foreign drift injected by the upgrade gate\n")
        ctl_log_b = tmp / "ctlB.log"
        # deterministic interruption window: a 10-second ACCESS EXCLUSIVE
        # table lock makes the migration stage BLOCK (real lock wait), so
        # the SIGKILL lands mid-work, never after a lucky fast completion.
        sp.Popen(["docker", "exec", cname, "psql", "-U", "postgres",
                  "-d", "srupg2", "-c",
                  "LOCK TABLE coach_messages IN ACCESS EXCLUSIVE MODE; "
                  "SELECT pg_sleep(10);"],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        pB = cli("upgrade", "--manifest", str(manifest_path),
                 "--system-root", str(rootB), "--payload", str(payload),
                 "--pg-dump-bin", str(wrapper), "--allow-fresh-install",
                 "--web-url", f"http://127.0.0.1:{ready_port}/",
                 extra_env={"SR_PG_UPGRADE_URL": url2,
                            "SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_b)},
                 proc=True)
        journalB = None
        attempts_dir = pathsB["etc"] / "upgrade"
        deadline = time.time() + 240
        while time.time() < deadline:
            for j in attempts_dir.glob("*/journal.json"):
                data = json.loads(j.read_text())
                if data.get("stages"):
                    journalB = data
                    break
            if journalB:
                break
            time.sleep(0.02)
        if not journalB:
            fail("interruption fixture", "journal never appeared")
        os.killpg(os.getpgid(pB.pid), signal.SIGKILL)
        pB.wait(timeout=30)
        attempt_b = journalB["attempt"]
        if not (pathsB["state"] / "maintenance").is_file():
            fail("admission fence stays up while an attempt is unfinished",
                 "fence file absent after SIGKILL")
        ok("SIGKILL interruption is retained; new attempts REFUSED and the "
           "fence holds", f"attempt {attempt_b} in progress")
        refused = upgrade_cli(rootB, manifest_path, url2, allow_fail=True)
        if refused.returncode == 0 or "unknown" not in (
                refused.stdout + refused.stderr):
            fail("interrupted attempt blocks new upgrade work",
                 (refused.stdout + refused.stderr)[-400:])
        # F5: resuming an UNFINISHED attempt may never answer no-op even
        # though installed revision + schema could look up to date
        r3 = upgrade_cli(rootB, manifest_path, url2, resume=attempt_b,
                         extra_env={"SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_b)})
        outB = json.loads(r3.stdout)
        if outB.get("no_op") or outB.get("status") != "done":
            fail("resume of the unfinished attempt COMPLETES it (never "
                 "no-ops away)", json.dumps(outB)[:400])
        heads_b = {row[0] for row in
                   db_q(url2, "SELECT version_num FROM alembic_version")}
        if heads_b != {head_rev}:
            fail("resumed upgrade reached head exactly once", str(heads_b))
        if drifted.read_text().startswith("# foreign drift"):
            fail("activation replaced the drifted runtime file")
        if db_q(url2, "SELECT count(*) FROM users WHERE username="
                      "'p21-witness-b'") != [(1,)]:
            fail("interrupted+resumed upgrade preserved users")
        if (pathsB["state"] / "maintenance").exists():
            fail("resume completion releases the fence", "fence remains")
        ok("interruption -> refusal -> resume completes to head, drift "
           "repaired, fence released, users preserved")

        # F3 (two-pass restore): corrupt a LATE backup file -> the restore
        # refuses and changes EXACTLY ZERO live files.
        envfB = pathsB["env"]
        envfB.write_text("CORRUPTED BY THE UPGATE\n")
        before = {p: _hl.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(pathsB["etc"].rglob("*"))
                  if p.is_file() and "/upgrade/" not in str(p)}
        late = sorted((pathsB["etc"] / "upgrade" / attempt_b /
                       "config-backup").rglob("*"))[-1]
        late.write_bytes(b"# corrupted late backup file\n")
        rr2 = cli("upgrade", "--manifest", str(manifest_path),
                  "--system-root", str(rootB),
                  "--restore-config", attempt_b)
        after = {p: _hl.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(pathsB["etc"].rglob("*"))
                 if p.is_file() and "/upgrade/" not in str(p)}
        if rr2.returncode == 0 or "BEFORE any write" not in (
                rr2.stdout + rr2.stderr) or before != after:
            fail("corrupt late backup file -> ZERO changed files",
                 f"exit={rr2.returncode} changed="
                 f"{[str(p) for p in before if before[p] != after.get(p)][:3]}"
                 f" {(rr2.stdout + rr2.stderr)[-200:]}")
        if envfB.read_text().find("CORRUPTED") < 0:
            fail("refused restore left the tree untouched",
                 "env file changed despite refusal")
        ok("restore validates the COMPLETE backup before writing "
           "(late corruption = zero changes)")

        # journal survives its own restore (it is not config)
        jnow = json.loads((attempts_dir / attempt_b / "journal.json")
                          .read_text())
        if jnow.get("attempt") != attempt_b or jnow.get("status") not in (
                "done", "in-progress"):
            fail("attempt journal is never rolled back by a restore",
                 json.dumps(jnow)[:200])
        ok("the journal that records the restore is never restored over")

        # ============ scenario D: restart failure is never success ====== #
        rootD = tmp / "rootD"
        apply_sandbox(rootD, manifest_path)
        assert alembic(url3, "upgrade", "0025").returncode == 0
        seed(url3, "d")
        pathsD = iseq._manifest_paths(rootD)
        dfail = upgrade_cli(rootD, manifest_path, url3,
                            extra_env={"SR_FAKE_RESTART_FAIL": "1"},
                            allow_fail=True)
        if dfail.returncode == 0 or "restart" not in (
                dfail.stdout + dfail.stderr):
            fail("failed service restart fails the upgrade truthfully",
                 (dfail.stdout + dfail.stderr)[-600:])
        stampD = pathsD["etc"] / "release-version.json"
        if stampD.exists():
            fail("failed restart writes NO version stamp",
                 stampD.read_text()[:200])
        jD = next((json.loads(j.read_text())
                   for j in (pathsD["etc"] / "upgrade").glob(
                       "*/journal.json")), {})
        if jD.get("stages", {}).get("restart", {}).get("status") != "failed":
            fail("journal records the failed restart stage",
                 json.dumps(jD.get("stages", {}).get("restart")))
        if not (pathsD["state"] / "maintenance").is_file():
            fail("restart failure keeps the admission fence up",
                 "fence absent with services unverified")
        ok("restart failure: attempt in progress, fence up, NO stamp")
        dres = upgrade_cli(rootD, manifest_path, url3,
                           resume=jD["attempt"])
        outD = json.loads(dres.stdout)
        if outD.get("status") != "done":
            fail("resume after a fixed restart completes",
                 json.dumps(outD)[:300])
        aud = db_q(url3, "SELECT audience FROM coach_messages "
                         "WHERE body LIKE 'P21-SEALED%'")
        if aud != [("legacy",)]:
            fail("upgrade path fail-closed legacy relabel",
                 f"audience {aud} (sealed history must never default "
                 "member)")
        if not stampD.is_file():
            fail("version stamp written only after the verified restart",
                 "stamp missing after completed resume")
        ok("verified restart then (and only then) the version stamp")

        # LIVE-02: after the successful resume the journal's CURRENT view
        # of the restart stage is clean (status done, no `error` key), and
        # the failure remains visible as prior-attempt history — stale
        # errors must not read as unresolved after recovery, and recovery
        # must not delete the evidence.
        jD2 = json.loads((pathsD["etc"] / "upgrade" / jD["attempt"] /
                          "journal.json").read_text())
        restart_now = jD2.get("stages", {}).get("restart", {})
        if restart_now.get("status") != "done" or "error" in restart_now:
            fail("resumed stage presents a clean current view",
                 json.dumps(restart_now)[:300])
        if not [p for p in restart_now.get("prior", [])
                if p.get("status") == "failed" and p.get("error")]:
            fail("failed restart retained as prior history",
                 json.dumps(restart_now.get("prior"))[:300])
        ok("journal separates the historical restart failure from the "
           "successful current stage")

        # ===== round-3 finding 1: old-schema quiescence tells the truth == #
        # A REAL 0019 schema has no model_jobs; durable work must be proven
        # from the authorities that exist there (runs), and the missing
        # newer tables may never surface as unreadable-check errors.
        assert alembic(url4, "upgrade", "0019").returncode == 0
        rootR = tmp / "rootR"
        apply_sandbox(rootR, manifest_path)
        pathsR = iseq._manifest_paths(rootR)
        eng = sa_create(url4)
        with eng.begin() as c:
            sid_r = c.execute(sa_text(
                "INSERT INTO sessions (session_id, scenario_id, status) "
                "VALUES (gen_random_uuid(), 'web-foothold-01', 'active') "
                "RETURNING session_id")).scalar()
            rid_r = c.execute(sa_text(
                "INSERT INTO runs (run_id, session_id, scenario_id, status)"
                " VALUES (gen_random_uuid(), :sid, 'web-foothold-01', "
                "'queued') RETURNING run_id"), {"sid": sid_r}).scalar()
        eng.dispose()
        oldq = upgrade_cli(rootR, manifest_path, url4,
                           extra=("--dry-run",), allow_fail=True)
        oldq_all = oldq.stdout + oldq.stderr
        if oldq.returncode == 0 or "durable state" not in oldq_all:
            fail("0019-schema dry-run REFUSES a queued run (old-schema "
                 "authorities are read, not skipped)", oldq_all[-400:])
        if "model_jobs" in oldq_all:
            fail("old-schema check does not error on missing newer tables",
                 oldq_all[-400:])
        eng = sa_create(url4)
        with eng.begin() as c:
            c.execute(sa_text("DELETE FROM runs WHERE run_id = :r"),
                      {"r": rid_r})
        eng.dispose()
        oldok = upgrade_cli(rootR, manifest_path, url4,
                            extra=("--dry-run",))
        if "dry_run" not in oldok.stdout:
            fail("0019-schema dry-run passes once quiesced",
                 (oldok.stdout + oldok.stderr)[-300:])
        ok("real 0019 schema: quiescence refuses queued runs and passes "
           "truthfully when empty — no manual prereqs")

        # ===== round-3 findings 2/3/4: stop failure, readiness 503, and a
        # ===== config-only restore that KEEPS the fence on unfinished work #
        ctl_log_r = tmp / "ctlR.log"
        sfail = upgrade_cli(rootR, manifest_path, url4,
                            extra_env={"SR_FAKE_STOP_FAIL": "1",
                                       "SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_r)},
                            allow_fail=True)
        if sfail.returncode == 0 or "quiesce" not in (
                sfail.stdout + sfail.stderr):
            fail("a refusing admission-stop fails the upgrade before any "
                 "mutation", (sfail.stdout + sfail.stderr)[-400:])
        jR = next((json.loads(j.read_text())
                   for j in (pathsR["etc"] / "upgrade").glob(
                       "*/journal.json")), {})
        if not jR or not (pathsR["state"] / "maintenance").is_file():
            fail("failed admission-stop keeps the fence and journal",
                 json.dumps(jR)[:200])
        if list((pathsR["etc"] / "upgrade" / jR["attempt"]).glob(
                "database.dump")):
            fail("failed admission-stop mutated nothing", "dump exists")
        ok("admission services cannot be stopped -> refused, fenced, "
           "resumable, zero mutation")
        ready_flag.touch()  # the old service now answers 200 + ready:false
        rfail = upgrade_cli(rootR, manifest_path, url4, resume=jR["attempt"],
                            extra_env={"SR_FAKE_SYSTEMCTL_LOG":
                                       str(ctl_log_r)},
                            allow_fail=True)
        rfail_all = rfail.stdout + rfail.stderr
        # round-4 finding 1: the fixture answers HTTP 200 (like the real
        # /readyz) with ready:false + issues — the engine must PARSE the
        # contract, and an HTTP-success status alone may never pass.
        if rfail.returncode == 0 or "readiness CONTRACT" not in rfail_all \
                or "ready is False" not in rfail_all:
            fail("active-but-200-ready:false services fail the readiness "
                 "CONTRACT gate (status alone is not readiness)",
                 rfail_all[-400:])
        if (pathsR["etc"] / "release-version.json").exists():
            fail("readiness failure writes NO version stamp")
        if not (pathsR["state"] / "maintenance").is_file():
            fail("readiness failure keeps the fence")
        ok("real 200/ready:false after restart: fence UP, no stamp, "
           "resumable (the stamp is never advertised for an unhealthy "
           "release)")
        ctl_before_restore = (ctl_log_r.read_text().splitlines()
                              if ctl_log_r.is_file() else [])
        rrR = cli("upgrade", "--manifest", str(manifest_path),
                  "--system-root", str(rootR),
                  "--restore-config", jR["attempt"])
        outRR = json.loads(rrR.stdout) if rrR.returncode == 0 else {}
        if rrR.returncode != 0 or outRR.get("service_actions") != [] or \
                outRR.get("maintenance_fence_cleared") is not False:
            fail("config-only restore on an unfinished attempt keeps the "
                 "fence", (rrR.stdout + rrR.stderr)[-400:])
        if not (pathsR["state"] / "maintenance").is_file():
            fail("restore of an unfinished attempt must NOT open "
                 "admission — a config rollback cannot undo the runtime "
                 "or the schema")
        ctl_after_restore = (ctl_log_r.read_text().splitlines()
                             if ctl_log_r.is_file() else [])
        if ctl_after_restore != ctl_before_restore:
            fail("restore issues ZERO service commands",
                 str(ctl_after_restore[len(ctl_before_restore):])[:200])
        ok("restore-config on an unfinished attempt: config restored, "
           "fence KEPT, zero service actions")
        # round-4 finding 1 (stale OLD process): HTTP 200, ready:true,
        # issues empty — but reporting the OLD migration head. The parsed
        # contract must refuse THIS too: a ready process at a head the
        # payload did not install is not the upgraded release.
        ready_flag.unlink()
        badhead_flag.touch()
        bfail = upgrade_cli(rootR, manifest_path, url4, resume=jR["attempt"],
                            extra_env={"SR_FAKE_SYSTEMCTL_LOG":
                                       str(ctl_log_r)},
                            allow_fail=True)
        if bfail.returncode == 0 or "migration_version" not in (
                bfail.stdout + bfail.stderr):
            fail("ready:true at the WRONG migration head (stale old "
                 "process) fails the readiness CONTRACT gate",
                 (bfail.stdout + bfail.stderr)[-400:])
        if (pathsR["etc"] / "release-version.json").exists():
            fail("wrong-head readiness failure writes NO version stamp")
        if not (pathsR["state"] / "maintenance").is_file():
            fail("wrong-head readiness failure keeps the fence")
        ok("200/ready:true at the old head is refused — only the payload's "
           "own schema head counts as ready")
        badhead_flag.unlink()  # operator fixed the service
        rres = upgrade_cli(rootR, manifest_path, url4, resume=jR["attempt"],
                           extra_env={"SR_FAKE_SYSTEMCTL_LOG":
                                      str(ctl_log_r)})
        outR = json.loads(rres.stdout)
        if outR.get("status") != "done" or \
                (pathsR["state"] / "maintenance").exists() or \
                not (pathsR["etc"] / "release-version.json").is_file():
            fail("resume once readyz satisfies the contract completes, "
                 "stamps and unfences", json.dumps(outR)[:300])
        ok("unhealthy -> contract-satisfied transition: resume completes; "
           "the fence only ever drops on a READY, completed attempt")

        # ===== round-3 finding 6 / round-4 finding 4: the required runtime
        # ===== contract is not a self-declared manifest list, and it is
        # ===== derived from the EXECUTION SURFACE (locks, alembic env, the
        # ===== ExecStart modules). Dropping any of them from BOTH disk and
        # ===== manifest is refused before any side effect — env.py and
        # ===== worker_supervisor.py used to pass verification.
        attempts_before_inv = len(list(
            (paths["etc"] / "upgrade").glob("*/journal.json")))
        for rel in ("requirements.lock", "srplatform/db/migrations/env.py",
                    "srplatform/worker_supervisor.py"):
            inv = tmp / f"missing-contract-{rel.replace('/', '_')}"
            shutil.copytree(payload, inv)
            (inv / rel).unlink()
            man_i = json.loads((inv / "MANIFEST.json").read_text())
            man_i["files"].pop(rel)
            (inv / "MANIFEST.json").write_text(json.dumps(man_i))
            ineg = upgrade_cli(rootA, manifest_path, url,
                               extra=("--dry-run", "--payload", str(inv)),
                               allow_fail=True)
            if ineg.returncode == 0 or rel not in (ineg.stdout + ineg.stderr):
                fail(f"payload omitting {rel} (manifest AND disk) refused",
                     (ineg.stdout + ineg.stderr)[-400:])
            if len(list((paths["etc"] / "upgrade").glob(
                    "*/journal.json"))) != attempts_before_inv or \
                    (paths["state"] / "maintenance").exists():
                fail("required-contract refusal causes zero side effects")
        ok("required runtime contract (locks + alembic env + ExecStart "
           "modules) enforced against the manifest's own inventory, "
           "refused preflight with zero mutation")

        # ===== round-4 finding 2: a config restore of a COMPLETED attempt
        # ===== may NEVER release an admission fence owned by a DIFFERENT,
        # ===== unresolved attempt. REAL two-attempt reproduction in one
        # ===== sandbox: A completes normally; B (a second valid payload —
        # ===== same source, different revision stamp, exactly like the
        # ===== provisioning-failure bundle's build) is started and fails
        # ===== at the admission stop, so its fence stays up; restoring
        # ===== A's config must keep B's fence untouched.
        rootX = tmp / "rootX"
        apply_sandbox(rootX, manifest_path)
        assert alembic(url5, "upgrade", "0025").returncode == 0
        seed(url5, "x", coach=False)
        pathsX = iseq._manifest_paths(rootX)
        fenceX = pathsX["state"] / "maintenance"
        if fenceX.exists():
            fail("cross-attempt fixture must start with NO fence "
                 "(fresh-fence-absent positive precondition)")
        ctl_log_x = tmp / "ctlX.log"
        rx = upgrade_cli(rootX, manifest_path, url5,
                         extra_env={"SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_x)})
        outXA = json.loads(rx.stdout)
        attempt_xa = outXA.get("attempt")
        if outXA.get("status") != "done" or fenceX.exists() or not attempt_xa:
            fail("cross-attempt fixture: attempt A completes cleanly",
                 json.dumps(outXA)[:300])
        if json.loads((pathsX["etc"] / "release-version.json")
                      .read_text()).get("attempt") != attempt_xa:
            fail("cross-attempt fixture: A stamped its own attempt")

        # second payload: same runtime source, different revision (the
        # build tree is not a git checkout — the same stamp path the
        # provisioning-failure scenario already relies on), so the CLI
        # must treat it as a real upgrade, never a no-op.
        from deploy import bundle as _bundle
        src2 = tmp / "payload2-src"
        src2.mkdir()
        tar2 = sp.run(
            ["tar", "-C", str(REPO), "-cf", "-", "--exclude=node_modules",
             "--exclude=__pycache__", "--exclude=.next",
             *_bundle.APP_DIRS, *_bundle.APP_FILES],
            capture_output=True, timeout=300)
        if tar2.returncode != 0:
            fail("second payload source tree", tar2.stderr[-300:])
        sp.run(["tar", "-C", str(src2), "-xf", "-"], input=tar2.stdout,
               check=True, timeout=300)
        (src2 / "docs" / "CROSS-ATTEMPT-NOTE.md").write_text(
            "synthetic cross-attempt fixture marker\n")
        # round-5 finding 2: the revision MUST be independent of the
        # candidate even when TMPDIR points INSIDE the checkout (the
        # documented disk-backed mode: extracted trees otherwise
        # DISCOVER the parent repo and stamp the candidate's own HEAD —
        # reproduced FAIL "cross-attempt fixture needs a second revision
        # 85efa92…"). A proper isolated git fixture: its own ancestry,
        # so git discovery inside src2 stops at src2/.git. Production
        # packaging verification is untouched.
        for g in (["init", "-q"],
                  ["config", "user.email", "gate@invalid"],
                  ["config", "user.name", "sr-upgrade-gate"],
                  ["config", "commit.gpgsign", "false"],
                  ["add", "-A"], ["commit", "-qm", "cross-attempt fixture"]):
            gg = sp.run(["git", *g], cwd=str(src2), capture_output=True,
                        text=True, timeout=300)
            if gg.returncode != 0:
                fail("second-payload isolated git fixture",
                     f"{g[0]}: {(gg.stdout + gg.stderr)[-300:]}")
        payload2 = tmp / "payload2-bundle"
        b2 = sp.run([sys.executable, str(src2 / "deploy/bundle.py"), "build",
                     "--output", str(payload2), "--base-image",
                     str(fake_base)],
                    cwd=str(src2), capture_output=True, text=True,
                    timeout=1800, env=env)
        if b2.returncode != 0:
            fail("second payload bundle build", (b2.stdout + b2.stderr)[-400:])
        rev2 = json.loads((payload2 / "MANIFEST.json").read_text())["revision"]
        if not (len(rev2) == 40
                and all(c in "0123456789abcdef" for c in rev2)) or \
                rev2 == payload_manifest["revision"] or \
                rev2 == "unknown":
            fail("cross-attempt fixture needs a second DETERMINISTIC real "
                 "revision (isolated ancestry, not parent discovery)",
                 str(rev2))

        bstart = upgrade_cli(
            rootX, manifest_path, url5, extra=("--payload", str(payload2)),
            extra_env={"SR_FAKE_STOP_FAIL": "1",
                       "SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_x)},
            allow_fail=True)
        if bstart.returncode == 0 or "quiesce" not in (
                bstart.stdout + bstart.stderr):
            fail("cross-attempt fixture: attempt B fails at the stop",
                 (bstart.stdout + bstart.stderr)[-400:])
        jX = {path.parent.name: json.loads(path.read_text())
              for path in (pathsX["etc"] / "upgrade").glob("*/journal.json")}
        unfinished_x = [a for a, d in jX.items() if d.get("status") != "done"]
        if len(jX) != 2 or len(unfinished_x) != 1:
            fail("cross-attempt fixture: exactly one unresolved attempt B",
                 str({a: d.get("status") for a, d in jX.items()}))
        attempt_xb = unfinished_x[0]
        fence_doc = json.loads(fenceX.read_text())
        if fence_doc.get("attempt") != attempt_xb:
            fail("the admission fence records the attempt that OWNS it",
                 f"fence attempt {fence_doc.get('attempt')!r} != B "
                 f"{attempt_xb!r}")
        ok("fence ownership recorded: attempt B owns the admission fence")

        ctl_before_x = ctl_log_x.read_text() if ctl_log_x.is_file() else ""
        fence_bytes_before = fenceX.read_bytes()
        rrx = cli("upgrade", "--manifest", str(manifest_path),
                  "--system-root", str(rootX),
                  "--restore-config", attempt_xa)
        outRX = json.loads(rrx.stdout) if rrx.returncode == 0 else {}
        if rrx.returncode != 0 or outRX.get("service_actions") != [] or \
                outRX.get("maintenance_fence_cleared") is not False or \
                "unresolved" not in str(outRX.get("maintenance_fence", "")):
            fail("restore of a COMPLETED attempt while ANOTHER attempt is "
                 "unresolved must keep the fence",
                 (rrx.stdout + rrx.stderr)[-400:])
        if fenceX.read_bytes() != fence_bytes_before:
            fail("cross-attempt restore leaves the foreign fence "
                 "byte-identical")
        if (ctl_log_x.read_text() if ctl_log_x.is_file() else "") != \
                ctl_before_x:
            fail("cross-attempt restore issues ZERO service commands")
        ok("restore-config of completed A NEVER releases unfinished B's "
           "fence (config restored, zero service actions, fence intact)")

        # Completing B is what releases B's fence — completion checks the
        # OWNER and clears only its own.
        rxb = upgrade_cli(rootX, manifest_path, url5, resume=attempt_xb,
                          extra=("--payload", str(payload2)),
                          extra_env={"SR_FAKE_SYSTEMCTL_LOG":
                                     str(ctl_log_x)})
        outXB = json.loads(rxb.stdout)
        if outXB.get("status") != "done" or fenceX.exists():
            fail("resuming B completes it and B's own completion releases "
                 "B's fence", json.dumps(outXB)[:300])
        ok("attempt B's verified completion releases exactly its own fence")

        # With every attempt resolved and no fence present, a restore of
        # the done attempt reports admission clear...
        rr2x = cli("upgrade", "--manifest", str(manifest_path),
                   "--system-root", str(rootX),
                   "--restore-config", attempt_xa)
        out2x = json.loads(rr2x.stdout) if rr2x.returncode == 0 else {}
        if rr2x.returncode != 0 or \
                out2x.get("maintenance_fence_cleared") is not True:
            fail("with all attempts resolved and no fence, restoring the "
                 "done attempt reports admission clear",
                 (rr2x.stdout + rr2x.stderr)[-300:])
        # ...but an operator fence whose identity cannot be PROVEN to
        # belong to the restored attempt is never released by a restore:
        # corrupt identity first, foreign identity second.
        fenceX.parent.mkdir(parents=True, exist_ok=True)
        fenceX.write_text("{ not a fence\n")
        rr3x = cli("upgrade", "--manifest", str(manifest_path),
                   "--system-root", str(rootX),
                   "--restore-config", attempt_xa)
        out3x = json.loads(rr3x.stdout) if rr3x.returncode == 0 else {}
        if rr3x.returncode != 0 or \
                out3x.get("maintenance_fence_cleared") is not False or \
                "unreadable" not in str(out3x.get("maintenance_fence", "")) \
                or not fenceX.exists():
            fail("an unreadable fence identity is never released by a "
                 "config restore", (rr3x.stdout + rr3x.stderr)[-300:])
        fenceX.write_text(json.dumps({"reason": "manual operator fence",
                                      "attempt": "manual-op-9999"}))
        rr4x = cli("upgrade", "--manifest", str(manifest_path),
                   "--system-root", str(rootX),
                   "--restore-config", attempt_xa)
        out4x = json.loads(rr4x.stdout) if rr4x.returncode == 0 else {}
        if rr4x.returncode != 0 or \
                out4x.get("maintenance_fence_cleared") is not False or \
                "manual-op-9999" not in str(out4x.get("maintenance_fence",
                                                      "")) or \
                not fenceX.exists():
            fail("a fence owned by another identity is never released by "
                 "a config restore", (rr4x.stdout + rr4x.stderr)[-300:])
        fenceX.unlink()
        ok("unknown/foreign fence identity: restore fails closed and "
           "keeps admission refused")

        # ===== round-5 finding 1: fence ACQUISITION and FINALIZATION own- #
        # ===== ership through the actual CLI, with deterministic operator #
        # ===== interference (reproduced pre-fix: a foreign fence was      #
        # ===== overwritten and stamped done; a fence stripped to {}       #
        # ===== during the run was removed and stamped done).              #
        rootW = tmp / "rootW"
        apply_sandbox(rootW, manifest_path)
        pathsW = iseq._manifest_paths(rootW)
        fenceW = pathsW["state"] / "maintenance"
        ctl_log_w = tmp / "ctlW.log"
        fenceW.parent.mkdir(parents=True, exist_ok=True)
        foreign_w = json.dumps({"reason": "operator maintenance",
                                "attempt": "manual-op-4242"},
                               indent=2, sort_keys=True) + "\n"

        def _journal_ids(root):
            return sorted(p.parent.name for p in
                          (iseq._manifest_paths(root)["etc"]
                           / "upgrade").glob("*/journal.json"))

        # (a) a NEW upgrade may never adopt or overwrite a FOREIGN fence
        fenceW.write_text(foreign_w)
        wref = upgrade_cli(rootW, manifest_path, url5,
                           allow_fail=True)
        if wref.returncode == 0 or "manual-op-4242" not in (
                wref.stdout + wref.stderr):
            fail("an upgrade never adopts a FOREIGN-owned fence",
                 (wref.stdout + wref.stderr)[-400:])
        if fenceW.read_text() != foreign_w or _journal_ids(rootW) or \
                (pathsW["etc"] / "release-version.json").exists():
            fail("foreign-fence refusal is byte-exact with zero attempt "
                 "and no stamp")
        # (b) ANONYMOUS ({} / empty owner) and CORRUPT fences: identity
        #     cannot be proven — refuse, keep bytes, no destructive take
        for bad in ("{}\n", "{ this is not json\n", '{"attempt": ""}\n'):
            fenceW.write_text(bad)
            wb = upgrade_cli(rootW, manifest_path, url5, allow_fail=True)
            if wb.returncode == 0 or "cannot be proven" not in (
                    wb.stdout + wb.stderr):
                fail("anonymous/corrupt fences refuse acquisition",
                     bad + (wb.stdout + wb.stderr)[-300:])
            if fenceW.read_text() != bad or _journal_ids(rootW):
                fail("unprovable-fence refusal is byte-exact and creates "
                     "no attempt", bad)
        fenceW.unlink()
        # (c) fresh ABSENT-fence acquisition is the positive path: the
        #     stop-fail attempt records its OWN identity on the fence
        wstart = upgrade_cli(
            rootW, manifest_path, url5,
            extra_env={"SR_FAKE_STOP_FAIL": "1",
                       "SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_w)},
            allow_fail=True)
        if wstart.returncode == 0 or "quiesce" not in (
                wstart.stdout + wstart.stderr):
            fail("W fixture: stop-fail attempt starts and fails at the "
                 "stop", (wstart.stdout + wstart.stderr)[-300:])
        jw_ids = _journal_ids(rootW)
        if len(jw_ids) != 1:
            fail("W fixture: exactly one attempt", str(jw_ids))
        attempt_w = jw_ids[0]
        if json.loads(fenceW.read_text()).get("attempt") != attempt_w:
            fail("fresh acquisition records its own attempt on the fence")
        ok("fence acquisition: foreign/anonymous/corrupt refused "
           "byte-exact, zero attempt; fresh-absent acquires with identity")

        # (d) ownership swapped DURING a run (deterministic: the fence is
        #     replaced once the attempt's quiesce stage completes, well
        #     before finalization): the finalize guard must block — NO
        #     stamp, fence bytes kept, attempt truthfully resumable
        pW = cli("upgrade", "--manifest", str(manifest_path),
                 "--system-root", str(rootW), "--payload", str(payload),
                 "--pg-dump-bin", str(wrapper), "--allow-fresh-install",
                 "--web-url", f"http://127.0.0.1:{ready_port}/",
                 "--resume", attempt_w,
                 extra_env={"SR_PG_UPGRADE_URL": url5,
                            "SR_FAKE_SYSTEMCTL_LOG": str(ctl_log_w)},
                 proc=True)
        swapped = False
        deadline = time.time() + 600
        while time.time() < deadline and pW.poll() is None:
            if not swapped:
                try:
                    jnow = json.loads((pathsW["etc"] / "upgrade" /
                                       attempt_w / "journal.json")
                                      .read_text())
                except Exception:  # noqa: BLE001 — mid-write poll
                    jnow = {}
                if jnow.get("stages", {}).get("quiesce", {}).get(
                        "status") == "done":
                    fenceW.write_text("{}\n")  # operator interference
                    swapped = True
            time.sleep(0.05)
        outW = ""
        if pW.poll() is None:
            pW.kill()
        outW = pW.stdout.read() if pW.stdout else ""
        pW.wait(timeout=60)
        if not swapped:
            fail("mid-run fence swap fixture", "quiesce never completed")
        if pW.returncode == 0 or "ownership is unresolved" not in outW \
                or "NOT written" not in outW:
            fail("ownership swapped during the run must BLOCK finalize "
                 "(no stamp, no unfence)", outW[-500:])
        if fenceW.read_text() != "{}\n":
            fail("blocked finalize keeps the swapped fence byte-exact")
        if (pathsW["etc"] / "release-version.json").exists():
            fail("blocked finalize writes NO version stamp")
        jW2 = json.loads((pathsW["etc"] / "upgrade" / attempt_w /
                          "journal.json").read_text())
        if jW2.get("status") == "done":
            fail("blocked finalize keeps the attempt truthfully "
                 "in-progress and resumable")
        # (e) verified OWN resume: the operator restores the fence to
        #     this attempt's identity — completion then clears exactly it
        fenceW.write_text(json.dumps(
            {"reason": "operator restored ownership", "attempt": attempt_w},
            indent=2, sort_keys=True) + "\n")
        wres = upgrade_cli(rootW, manifest_path, url5, resume=attempt_w,
                           extra_env={"SR_FAKE_SYSTEMCTL_LOG":
                                      str(ctl_log_w)})
        outW2 = json.loads(wres.stdout)
        if outW2.get("status") != "done" or fenceW.exists() or \
                not (pathsW["etc"] / "release-version.json").is_file():
            fail("verified-own resume completes and clears exactly its "
                 "own fence", json.dumps(outW2)[:300])
        ok("mid-run ownership swap blocks finalize (no stamp/unfence, "
           "resumable); verified-own resume completes and clears only "
           "its own fence")

        # ============ provisioning failure never claims success ========= #
        bad_tree = tmp / "badlock-src"
        bad_tree.mkdir()
        # hardlinks cannot cross the tmpfs boundary; stream ONLY the
        # packaged source (node_modules and caches are not bundle inputs)
        from deploy import bundle as _bundle
        tar = sp.run(
            ["tar", "-C", str(REPO), "-cf", "-", "--exclude=node_modules",
             "--exclude=__pycache__", "--exclude=.next",
             *_bundle.APP_DIRS, *_bundle.APP_FILES],
            capture_output=True, timeout=300)
        if tar.returncode != 0:
            fail("bad-lock payload tree", tar.stderr[-300:])
        sp.run(["tar", "-C", str(bad_tree), "-xf", "-"], input=tar.stdout,
               check=True, timeout=300)
        (bad_tree / "requirements.lock").write_text(
            "nonexistent-pkg-srgate-9f3c==9.9.9\n")
        bad_payload = tmp / "badlock-bundle"
        bb = sp.run([sys.executable, str(bad_tree / "deploy/bundle.py"),
                     "build", "--output", str(bad_payload),
                     "--base-image", str(fake_base)],
                    cwd=str(bad_tree), capture_output=True, text=True,
                    timeout=1800, env=env)
        if bb.returncode != 0:
            fail("bad-lock payload build", (bb.stdout + bb.stderr)[-400:])
        rootP = tmp / "rootP"
        apply_sandbox(rootP, manifest_path)
        pf = cli("upgrade", "--manifest", str(manifest_path),
                 "--system-root", str(rootP), "--payload", str(bad_payload),
                 "--pg-dump-bin", str(wrapper), "--allow-fresh-install",
                 extra_env={"SR_PG_UPGRADE_URL": url},
                 timeout=2400)
        if pf.returncode == 0 or "provision" not in (
                pf.stdout + pf.stderr):
            fail("provisioning failure fails the upgrade",
                 (pf.stdout + pf.stderr)[-600:])
        pathsP = iseq._manifest_paths(rootP)
        if (pathsP["etc"] / "release-version.json").exists():
            fail("provision failure writes no version stamp")
        jP = next((json.loads(j.read_text())
                   for j in (pathsP["etc"] / "upgrade").glob(
                       "*/journal.json")), {})
        if jP.get("stages", {}).get("provision", {}).get("status") != "failed":
            fail("journal records the failed provision stage",
                 json.dumps(jP.get("stages", {}).get("provision")))
        if not (pathsP["state"] / "maintenance").is_file():
            fail("provision failure keeps the fence up (old runtime must "
                 "not silently resume under new bytes)", "fence absent")
        ok("provisioning failure: services NOT restarted, fence up, no "
           "stamp, attempt resumable")

        # F2 (API side): while the fence file exists the API refuses NEW
        # work with 503 but still serves health, login and the existing-
        # work internal callbacks — admission, not outage.
        flag = tmp / "fence-flag"
        flag.write_text('{"reason": "gate"}\n')
        os.environ["SR_MAINTENANCE_FLAG"] = str(flag)
        try:
            import srplatform.settings as _s
            _s.get_settings.cache_clear()
            from fastapi.testclient import TestClient
            from srplatform.api.app import app as _app
            client = TestClient(_app, raise_server_exceptions=False)
            r_new = client.post("/sessions", json={})
            r_login = client.post("/auth/login", json={})
            r_internal = client.post("/internal/runs/x/heartbeat", json={})
            r_health = client.get("/healthz")
            # round-3 finding 2: NEW generations inside /internal/ are
            # refused; only terminality callbacks stay exempt.
            r_gen = client.post("/internal/model/complete", json={})
            r_claim = client.post("/internal/worker/claim", json={})
            if r_new.status_code != 503:
                fail("fenced API refuses NEW work with 503",
                     f"POST /sessions -> {r_new.status_code}")
            if r_gen.status_code != 503 or "preserving upgrade" not in \
                    str(r_gen.json()):
                fail("fence refuses NEW internal generations",
                     f"POST /internal/model/complete -> {r_gen.status_code} "
                     f"{str(r_gen.json())[:120]}")
            if r_login.status_code == 503 or r_internal.status_code == 503 \
                    or r_health.status_code == 503:
                fail("fence exempts login, terminality callbacks and health",
                     f"login={r_login.status_code} "
                     f"internal={r_internal.status_code} "
                     f"health={r_health.status_code}")
            # claim reaches its OWN route (exempt), so any 503 it produces
            # must be the route's own condition, never the fence:
            if r_claim.status_code == 503 and "preserving upgrade" in \
                    str(r_claim.json()):
                fail("terminality callback was fence-refused",
                     str(r_claim.json())[:200])
            # transaction-boundary backstop: even a caller that bypasses
            # HTTP entirely cannot write a new durable generation while
            # the fence exists (and the refusal happens BEFORE any DB use)
            from srplatform import model_jobs as _mj

            class _NoDB:
                def execute(self, *a, **k):  # noqa: ANN401
                    raise AssertionError("db touched before fence check")
            try:
                _mj.enqueue(_NoDB(), kind="probe", priority=5, payload={})
                fail("enqueue refuses at the transaction boundary",
                     "AdmissionFenced not raised while fenced")
            except _mj.AdmissionFenced:
                pass
            flag.unlink()
            if client.post("/sessions", json={}).status_code == 503:
                fail("fence removal re-admits work", "still 503")
            ok("admission fence: 503 for new work AND internal generations,"
               " terminality/login/health unblocked, enqueue boundary holds,"
               " removal re-admits")
        finally:
            if "_s" in dir():
                _s.get_settings.cache_clear()
            os.environ.pop("SR_MAINTENANCE_FLAG", None)

        # ================= negatives (unchanged contract) ================ #
        old = tmp / "old-bundle"
        old.mkdir()
        (old / "pyproject.toml").write_bytes(b"x\n")
        (old / "MANIFEST.json").write_text(json.dumps({
            "bundle_version": 1, "revision": "deadbeef",
            "files": {"pyproject.toml": {"sha256":
                    _hl.sha256(b"x\n").hexdigest(), "bytes": 2}}}))
        neg2 = cli("upgrade", "--manifest", str(manifest_path),
                   "--system-root", str(rootA), "--payload", str(old),
                   extra_env={"SR_PG_UPGRADE_URL": url})
        if neg2.returncode == 0 or "predates" not in (neg2.stdout + neg2.stderr):
            fail("pre-21 bundle refused as an upgrade payload",
                 (neg2.stdout + neg2.stderr)[-300:])
        ok("pre-21 bundle without the upgrade contract is refused")

        # F6: the CLI itself refuses a credential-bearing argv contract
        leak = cli("upgrade", "--manifest", str(manifest_path),
                   "--system-root", str(rootA), "--payload", str(payload),
                   "--db-url", url)
        if leak.returncode == 0:
            fail("--db-url (credential in argv) is no longer accepted",
                 "CLI accepted a URL argument")
        ok("the CLI refuses --db-url: owner credentials travel by "
           "environment only")
    finally:
        sp.run(["docker", "rm", "-f", cname], capture_output=True,
               timeout=120)
        _sh.rmtree(tmp, ignore_errors=True)


# -------------------------------------------------------------------------- #
# appliance (16): the aggregate software gate at a pinned candidate         #
# -------------------------------------------------------------------------- #

APPLIANCE_GATES = ("selection", "python", "db", "authority", "agent",
                   "install", "hypervisor", "containment", "images",
                   "capture", "access", "frontend", "browser", "compose",
                   "bundle", "upgrade", "practice")

# The gates that need the OPERATOR's machine: root + nft for the packet
# layer, the INSTALLED appliance with operator/member tokens for the
# journey.  They are part of the release, so the aggregate ATTEMPTS them and
# reports the outcome: a missing prerequisite is reported as pending with
# its exact reason, and any real failure fails the aggregate.  Dropping them
# from the list would make the aggregate silently weaker than the release.
APPLIANCE_ENV_GATES = ("packet", "journey")


def check_appliance() -> None:
    """Run every software gate of the appliance release, in order.

    Each gate is the SAME gate the operator runs on its own, so the aggregate
    cannot accept anything the individual gates would refuse.  The revision
    and the digests are recorded with the result, so an evidence file is
    always bound to what was actually tested.  The live release gate is NOT
    part of this: it never runs implicitly.
    """
    import subprocess

    revision = "unknown"
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                                  capture_output=True, text=True,
                                  timeout=30).stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 — the label is best effort
        pass
    digests = {}
    base = os.environ.get("SR_APPLIANCE_BASE_IMAGE", "").strip()
    if base and pathlib.Path(base).is_file():
        import hashlib

        h = hashlib.sha256()
        with open(base, "rb") as fh:
            for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                h.update(chunk)
        digests["appliance-base"] = h.hexdigest()
    results = {}
    pending = {}
    for gate in APPLIANCE_GATES:
        print(f"\n--- appliance gate: {gate}")
        try:
            CHECKS[gate]()
        except Failed:
            results[gate] = "failed"
            raise
        results[gate] = "passed"
    for gate in APPLIANCE_ENV_GATES:
        print(f"\n--- appliance operator gate: {gate}")
        try:
            CHECKS[gate]()
        except PrerequisiteMissing as exc:
            pending[gate] = str(exc)
            results[gate] = "pending"
            print(f"[PENDING] {gate} — {exc}")
            continue
        except Failed:
            results[gate] = "failed"
            raise
        results[gate] = "passed"
    receipt = {"revision": revision, "digests": digests, "gates": results,
               "pending": pending}
    out = pathlib.Path(os.environ.get("SR_APPLIANCE_RECEIPT", "")) if \
        os.environ.get("SR_APPLIANCE_RECEIPT") else None
    if out:
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if pending:
        # A pending MANDATORY gate is not a pass: the release matrix is
        # incomplete, and the receipt says exactly what is missing.
        fail("appliance release matrix",
             f"the software matrix passed "
             f"({len([g for g in results.values() if g == 'passed'])} gates at "
             f"{revision[:12]}) but {len(pending)} mandatory gate(s) are still "
             "pending: " + "; ".join(f"{gate}: {reason}"
                                     for gate, reason in sorted(pending.items())))
    ok("appliance release matrix",
       f"{len([g for g in results.values() if g == 'passed'])} gates passed at "
       f"{revision[:12]}"
       + (f", base {digests['appliance-base'][:12]}" if digests else ""))


CHECKS = {
    "selection": check_selection,
    "python": check_python,
    "db": check_db,
    "agent": check_agent,
    "practice": check_practice,
    "containment": check_containment,
    "authority": check_authority,
    "pve-contract": check_pve_contract,
    "packet": check_packet,
    "frontend": check_frontend,
    "compose": check_compose,
    "browser": check_browser,
    "images": check_images,
    "capture": check_capture,
    "hypervisor": check_hypervisor,
    "access": check_access,
    "journey": check_journey,
    "install": check_install,
    "bundle": check_bundle,
    "upgrade": check_upgrade,
    "appliance": check_appliance,
    "release": check_release,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in CHECKS:
        print(__doc__)
        return 2
    check = argv[1]
    print(f"== acceptance: {check} ==\n   env {env_summary()}")
    started = time.time()
    try:
        CHECKS[check]()
    except Failed as e:
        print(f"== {check}: FAILED ({e}) after {time.time() - started:.1f}s ==")
        return 1
    except Exception as e:  # noqa: BLE001 — unexpected errors are also failures
        import traceback
        traceback.print_exc()
        print(f"== {check}: ERROR ({e}) after {time.time() - started:.1f}s ==")
        return 1
    print(f"== {check}: PASS after {time.time() - started:.1f}s ==")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
