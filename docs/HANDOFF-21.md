# Handoff — milestone 21 (preserving upgrade), round 1

Entry point for the parent's release-focused review and for the operator's
supervised-practice testing. Branch `practice-upgrades-18-21`; round-1 code
HEAD `3a4d927` (documentation commits follow). Milestone 20 is NOT accepted
and nothing here re-runs or claims its gates; the pulled blockers F1–F4 are fixed here, F5–F9 are the recorded
repository backlog (`docs/FINDINGS_CHECKLIST.md`).

## Commit map

| Commit | What |
|---|---|
| `3000361` | guest package pins repaired (live mirror dry-runs) + TCG ceilings — externally OBSERVED by the reviewer, not reviewed/accepted |
| `463e408` | second plan-20 review recorded; user reprioritization; F5–F9 backlog |
| `b3df934` | F1 fail-closed legacy audience + 0026 fence; F2 always-on quota; F3 engine prerequisite + forward guard; F4 bounded delivery |
| `b504a76` | 8 real db-layer proofs + explicit trigger-bracketed relabel (0027) |
| `f2d8e3b` | `appliance.py upgrade` drives the real engine; bundle `upgrade` contract (BUNDLE_VERSION 2) |
| `3a4d927` | required-mode `acceptance.py upgrade` gate; backup-snapshot integrity hardening |

## Verification commands (exact)

```bash
# fast, infrastructure-free — 661 passed, 0 failed, 0 skipped (480 deselected)
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -p no:cacheprovider

# the plan-21 proofs (needs a disposable admin; own fixture, cleaned up)
env SR_PG_ADMIN_URL=... SR_REQUIRE_DB=1 PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -p no:cacheprovider -o addopts= -m db \
  tests/test_plan21_upgrade_compat.py                      # 8 passed

# preserving-upgrade sequences (needs docker; owns sr-upg-pg-<run>, removes it)
.venv/bin/python infra/dev/acceptance.py upgrade           # PASS x2, ~21s

# full matrix (operator machine for packet/journey/release)
.venv/bin/python infra/dev/acceptance.py appliance
```

## What is claimed (and where it is proven)

* F1: sealed legacy history fails CLOSED across the real upgrade path and
  HTTP boundary; head-0026 schema refuses coach threads (0027, fence,
  `test_plan21_upgrade_compat.py`, gate scenario A).
* F2: quota admission always enforced (null/gap/marker alike), marker
  bytes reserved inside the budgets, duplicate marker never 500
  (`app.py`, updated plan-20 budget tests, gate layer).
* F3: a POPULATED 0025 DB with legacy duplicate markers upgrades to head
  through the RECORDED prerequisite; both markers survive byte-identical;
  applied 0026 untouched (test + engine + ARCHITECTURE decision table).
* F4: absolute per-delivery budget + process-wide bound; dribbling
  endpoints and idle consumers bounded with counted drops.
* Upgrade product: journal, real backups (restore-listable pg_dump),
  no-op rerun, interrupt→refuse→resume, drift replacement, config-only
  restore with zero service actions, tamper/pre-21 refusal
  (`acceptance.py upgrade`, `docs/OPERATOR_RUNBOOK.md` §7).

## What is NOT claimed

* Milestone 20 acceptance (parent owns it); F5–F9 remain open backlog.
* `images`/`capture`/`bundle` gates: the pin repair removed the mirror
  blocker, but role artifacts need cold TCG builds that exceeded this
  round's budget — recorded PENDING, never simulated. The `bundle` lane
  was attempted and refused the only on-disk role images (stale qcow2
  chains whose transient backing bases no longer exist) — correct
  fail-closed behavior, exact receipt in FINDINGS.
* `packet` (root+nft), `journey`/`release` (installed appliance):
  operator-machine gates, fail closed by design.
* Any live deployment, provider, or appliance operation was performed by
  this implementation; none was.
* Upgrade gate proof is sandbox + disposable PostgreSQL; the installed
  appliance's managed services are the operator's acceptance.

## Look hardest at

* `deploy/upgrade.py` `forward_migrate` — the ONLY tolerated failure is
  named, heads-re-proven, and data-proven; everything else propagates.
* Migration `0027` — trigger bracket around exactly one UPDATE; guard
  cutoff semantics; downgrade never relabels legacy→member.
* `coach_routes._require_audience_safe_schema` — fence is
  `heads == ["0026"]` only; empty/no-table states stay on the readiness
  path.
* The gate's kill timing: interruption is forced by a real lock wait, and
  every post-kill assertion holds for any interruption point.
