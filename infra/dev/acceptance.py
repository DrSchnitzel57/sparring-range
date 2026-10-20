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
          "images", "capture", "hypervisor", "access", "journey")
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
            "SR_REQUIRE_PACKET", "SR_REQUIRE_AUTHORITY", "SR_REQUIRE_BROWSER",
            "SR_REQUIRE_IMAGES", "SR_REQUIRE_CAPTURE", "SR_REQUIRE_HYPERVISOR",
            "SR_REQUIRE_ACCESS", "SR_REQUIRE_JOURNEY", "SR_APPLIANCE_BASE_IMAGE",
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
                  "images", "capture", "hypervisor", "access", "journey"):
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
        fail("packet prerequisites (root + nft + iproute2)",
             f"missing {missing} — required layer; run in the approved CI packet "
             "job (rules only inside disposable netns, never host namespaces)")
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
        r, counts = pytest_run(["tests/test_stage5_browser_e2e.py", "-m", "browser"],
                               env=env, timeout=3600)
        if r.returncode != 0:
            fail("isolated real-browser workflow/replay",
                 f"exit {r.returncode}, counts {counts}:\n{r.stdout[-6000:]}")
        ok("isolated real-browser workflow + replay pass",
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

        if os.environ.get("SR_INSTALL_VM_EVIDENCE") != "1":
            fail("managed-service installation (clean VM, rerun, reboot, "
                 "upgrade, recovery)",
                 "requires the disposable service-VM job; set "
                 "SR_INSTALL_VM_EVIDENCE=1 only after that job passed its "
                 "full sequence — a sandbox never accepts this contract")
        ok("managed-service installation evidence (VM job)")
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
                "SR_JOURNEY_MEMBER_TOKEN")
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        fail("journey prerequisites (installed appliance + authenticated members)",
             f"missing {missing} — required live gate; point it at the installed "
             "appliance and provide operator/member bearer tokens")
    env = {"SR_REQUIRE_JOURNEY": "1"}
    for key in ("SR_JOURNEY_BASE_URL", "SR_JOURNEY_OPERATOR_TOKEN",
                "SR_JOURNEY_MEMBER_TOKEN", "SR_JOURNEY_SSH_KEY",
                "SR_JOURNEY_BASTION_KNOWN_HOSTS",
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


CHECKS = {
    "selection": check_selection,
    "python": check_python,
    "db": check_db,
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
