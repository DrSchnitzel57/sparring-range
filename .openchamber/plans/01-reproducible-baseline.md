# 01 — Reproducible baseline and dependencies

Approved 2026-10-08. Contract: docs/ARCHITECTURE.md, docs/ROADMAP.md,
docs/FINDINGS_CHECKLIST.md.

Review `27e2624` (2026-10-08): **FIX/reopened**. Local gates and CI
37852029894 pass. Fix shared browser builds/edited migration; see findings.

## Goal and context

Reproducible tests/dependencies/dev-stack before gameplay expansion.
Baseline `7368782`: 10 failed, 106 passed, 115 skipped, 1 deselected;
audit three critical/one high. Preserve `.venv`; investigate PID assumptions,
DB marker leakage and prose-coupled readiness without weakening safety.

## Scope

In: tests/fixtures, forward migrations, locks, Compose/bootstrap, isolated
browser/packet fixtures, CI and obsolete doc references.
Out: gameplay, authority redesign, real Proxmox/live attacks, installed
systemd/auditd capture acceptance (milestone 04). Genuine safety defects keep
failing regressions and block acceptance; stop for agreement before widening scope.

## Steps

1. Investigate all ten failures using real host identities across PID namespaces.
   Preserve recursive containment, cancellation and unknown-state requirements;
   replace literal prose checks with installer/readiness-contract assertions.
   Never delete/weaken safety regressions for green results.
2. Default pytest is infrastructure-free. Classify DB/containment/packet/Compose/
   browser/live, including combined prerequisites. Required modes fail for absent
   prerequisites, empty selections or skipped required tests.
3. Add local PostgreSQL 16 Docker fixture: unique names/storage, configurable
   loopback port, synthetic credentials, readiness and scoped cleanup. Derive DB
   URLs from the endpoint; clean partial setup, surface cleanup failures. Never
   infer existing-cluster permission.
4. Test fresh migrations and populated pre-`0010` forward enrollment upgrades,
   app-role grants and append-only protections. Do not edit applied migrations.
5. Fresh run-owned locked installs, no app re-resolution; dependency checks/imports
   on Python 3.11–3.13 CI. Fix obsolete doc references.
6. Use patched stable Next 16, Pages Router/React 18 unless compatibility requires
   otherwise. Patch replay deps; pin local Playwright CLI. Require zero high/critical
   production audit findings; document lower-severity applicability. Test build/replay seek.
7. Exercise real Compose build/bootstrap with unique resources/configurable loopback
   ports. Fix app-password consistency; prove migrations, app-role API access,
   idempotent account/capability bootstrap, key seeding/bastion startup. Synthetic
   keys only; no live infrastructure/model credentials.
8. Run-owned browser builds/ports/processes/named sessions; API/worker workflow plus
   replay. Standard GitHub Linux CI VMs: containment unprivileged; packet rules only
   in disposable namespaces. Bound job time/artifact retention; no host firewall
   changes/privilege-bypass fallbacks. Preserve services/builds; owned cleanup only.
9. Record revision, commands/environment and pass/fail/skip/deselect counts in
   findings. Tick milestone 01 only after all gates pass; update architecture/runbook.

## Manual checks

- Operator verifies free allowance and $0 blocking budget before expanded Actions.
  No paid usage approved. Screenshot: 80/3,000 minutes, 0/2 GB; no billing-limit proof.
- User pushes, never agents. Unavailable required CI leaves acceptance pending;
  live R740 gates excluded.

## Acceptance criteria

Add `infra/dev/acceptance.py`: real checks, exact results; unresolved prerequisites/
cleanup fail. Privileged runs only in approved fixtures, not this host. CI must pass.

1. `python -m pytest -q -ra`: fast default passes without integration prerequisite skips.
2. `python infra/dev/acceptance.py selection`: all tests classified; absent prerequisites/empty/skipped required selections fail.
3. `python infra/dev/acceptance.py python`: fresh locked installs, dependency checks/imports pass on the supported CI matrix.
4. `python infra/dev/acceptance.py db`: disposable DB, fresh/forward migrations and DB regressions pass; owned resources cleaned.
5. `python infra/dev/acceptance.py containment`: namespace/recursive-membership/cancellation regressions run and pass in required mode.
6. `python infra/dev/acceptance.py packet`: real isolated packet tests pass without host-namespace rules.
7. `python infra/dev/acceptance.py frontend`: npm ci, production build and production audit pass; zero high/critical findings.
8. `python infra/dev/acceptance.py compose`: fresh build/bootstrap and idempotent rerun pass; only owned resources removed.
9. `python infra/dev/acceptance.py browser`: isolated real-browser workflow/replay pass; occupied services/developer builds untouched.
