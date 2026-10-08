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

Checks: selection | python | db | containment | packet | frontend
        | compose | browser
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
LAYERS = ("db", "containment", "packet", "browser", "live")
COUNT_RE = re.compile(r"(\d+) (passed|failed|errors?|skipped|deselected)")


# -------------------------------------------------------------------------- #
# plumbing                                                                     #
# -------------------------------------------------------------------------- #

class Failed(Exception):
    pass


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
            "SR_REQUIRE_PACKET", "SR_REQUIRE_BROWSER", "RUNNER_CGROUP_ROOT",
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
    r = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
            env=e, cwd=REPO, timeout=timeout)
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
    for layer in ("db", "containment", "packet", "browser"):
        if not layer_ids[layer]:
            fail(f"layer {layer} non-empty", "layer selection is empty")
    ok("all tests classified",
       f"{len(all_ids)} total = {len(default_ids)} fast + "
       f"{len(integration)} integration (live may be empty until milestone 11)")

    # The default run must be infrastructure-free: zero prerequisite skips.
    r, counts = pytest_run(["-ra"])
    if r.returncode != 0:
        fail("fast default passes", f"exit {r.returncode}: {r.stdout[-800:]}")
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
    """Resolve an interpreter spec (path or version like 3.12). uv-managed
    downloads are allowed (fresh run-owned envs); a missing spec is a
    prerequisite failure the caller reports."""
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
    never removed by cleanup."""
    import pg_fixture
    fx = pg_fixture.PgFixture(run_id="col" + uuid.uuid4().hex[:5])
    pre = []
    try:
        for args in (["volume", "create", fx.volume],
                     ["create", "--name", fx.container, pg_fixture.IMAGE,
                      "true"]):
            r = subprocess.run(["docker", *args], capture_output=True, text=True)
            if r.returncode != 0:
                fail("fixture collision probe setup",
                     f"docker {args[0]}: {(r.stderr or r.stdout).strip()[:200]}")
            pre.append(args)
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
        subprocess.run(["docker", "rm", "-f", fx.container],
                       capture_output=True)
        subprocess.run(["docker", "volume", "rm", fx.volume],
                       capture_output=True)


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
        fx.cleanup()
        blocker.close()


def _docker_probe(args: list[str]) -> int:
    return subprocess.run(["docker", *args], capture_output=True).returncode


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
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-1500:]}")
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
    _migration_probe(root)
    before = {p for p in pathlib.Path(root).glob("sr-*")}
    r, counts = pytest_run(["-m", "containment and not db"],
                           env={"SR_REQUIRE_CONTAINMENT": "1"}, timeout=1800)
    if r.returncode != 0:
        fail("containment regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-1500:]}")
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
        fail("packet prerequisites (root + nft + iproute2)",
             f"missing {missing} — required layer; run in the approved CI packet "
             "job (rules only inside disposable netns, never host namespaces)")
    r, counts = pytest_run(["-m", "packet"], env={"SR_REQUIRE_PACKET": "1"},
                           timeout=1800)
    if r.returncode != 0:
        fail("packet regressions in required mode",
             f"exit {r.returncode}, counts {counts}:\n{r.stdout[-1500:]}")
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
    code, _ = _http_json("POST", f"{api}/auth/bootstrap",
                         {"username": "drew", "password": op_pw})
    if attempt == 1:
        if code != 201:
            fail("operator bootstrap through app-role API", f"{code}")
    elif code != 403:
        fail("bootstrap stays closed once provisioned (idempotent rerun)",
             f"expected 403, got {code}")
    code, body = _http_json("POST", f"{api}/auth/login",
                            {"username": "drew", "password": op_pw})
    if code != 200 or "token" not in body:
        fail("operator login through app-role API", f"{code} {str(body)[:200]}")
    op = {"Authorization": f"Bearer {body['token']}"}
    code, _ = _http_json("POST", f"{api}/users",
                         {"username": "acc-member", "password": "acc-member-pw-9",
                          "role": "member"}, op)
    if attempt == 1 and code != 201:
        fail("member account creation through app-role API", f"{code}")
    if attempt == 2 and code != 409:
        fail("account creation is idempotent-visible (409 on rerun)", f"{code}")
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
        r, counts = pytest_run(["tests/test_stage5_browser_e2e.py", "-m", "browser"],
                               env=env, timeout=3600)
        if r.returncode != 0:
            fail("isolated real-browser workflow/replay",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-2000:]}")
        ok("isolated real-browser workflow + replay pass",
           f"{counts.get('passed', 0)} passed, {counts.get('skipped', 0)} skipped")
    finally:
        problems = fx.cleanup()
        if problems:
            fail("browser DB fixture cleanup", "; ".join(problems))


# -------------------------------------------------------------------------- #

CHECKS = {
    "selection": check_selection,
    "python": check_python,
    "db": check_db,
    "containment": check_containment,
    "packet": check_packet,
    "frontend": check_frontend,
    "compose": check_compose,
    "browser": check_browser,
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
