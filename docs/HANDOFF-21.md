# Handoff — milestone 21 (preserving upgrade), round 2 (review-corrected)

Entry point for the parent's release-focused re-review and the operator's
supervised-practice testing. Branch `practice-upgrades-18-21`. Round 1
(HEAD `2ba575e`) returned **VERDICT: FIX** with seven blockers; all seven
are fixed and re-proven here (round-2 code `431f2c1` + gate `a2ee8c9` +
supporting fixes `0a169e9`). Milestone 20 is NOT accepted; F5–F9 remain
the recorded repository backlog (`docs/FINDINGS_CHECKLIST.md`).

## Commit map

| Commit | What |
|---|---|
| `3000361` | guest package pins repaired (live-mirror verified) |
| `463e408` | second plan-20 review recorded; F5–F9 backlog |
| `b3df934`/`b504a76` | F1–F4 fixes + 8 real db-layer proofs |
| `fc025e7`…`2ba575e` | round-1 upgrade CLI/engine/gate/docs (see round-1 section in FINDINGS) |
| `431f2c1` | the seven review blockers: provisioning stage, durable quiescence + admission fence, journal exclusion + two-pass restore, original-mode restore, checked restart + stamp-last + resume-outranks-no-op, PGPASSFILE credential channel (CLI `--db-url` removed), verify-before-anything with contract validation |
| `a2ee8c9` | `upgrade` gate re-forged: argv-secret tripwire, durable-work and fence probes, provision/restart negatives, restore atomicity and mode proofs |
| `0a169e9` | durable-check column truth, sandbox venv boundary, `_create_venv` portability (production path unchanged), gate plumbing |

## Verification commands (exact)

```bash
# fast, infrastructure-free
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -p no:cacheprovider

# the plan-21 db proofs (disposable admin; own fixture, cleaned up)
env SR_PG_ADMIN_URL=... SR_REQUIRE_DB=1 PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -p no:cacheprovider -o addopts= -m db \
  tests/test_plan21_upgrade_compat.py                      # 8 passed

# preserving-upgrade sequences (docker; owns sr-upg-pg-<run>, removes it)
.venv/bin/python infra/dev/acceptance.py upgrade   # PASS x3, 93.5-94.6s

# full matrix (operator machine for packet/journey/release)
.venv/bin/python infra/dev/acceptance.py appliance
```

## What is claimed (and where it is proven)

* The round-2 finding→fix→proof table in `docs/FINDINGS_CHECKLIST.md`
  maps each of the seven blockers to a real-CLI gate probe that failed
  before the fix (or was structurally impossible to pass before it) and
  passes after, three consecutive deterministic runs.
* Round-1 claims (F1–F4, upgrade journal/backups/resume/restore/tamper)
  stand and are re-exercised by the same gate.
* Operator contract: `docs/OPERATOR_RUNBOOK.md` §7 (whole-VM snapshot
  first, environment-only credential, dry-run truth, fence semantics,
  resume/rollback discipline, post-upgrade operator checklist).

## What is NOT claimed

* Milestone 20 acceptance (parent owns it); F5–F9 remain open backlog.
* Round-1 upgrade-gate PASSes at `2ba575e` are RETRACTED as proof (the
  reviewer reproduced the journal-in-backup defect there; the gate has
  since been re-forged and re-run against the fix).
* `bundle` gate against final artifacts: the release bundle must be
  rebuilt from the corrected HEAD so its `upgrade` contract matches the
  fixed engine; receipt recorded when built (role images: see the
  artifact receipt in FINDINGS — built from the same role inputs).
* `packet` (root+nft), `journey`/`release`, installed systemd/Strata/
  nested-KVM: operator-machine gates, fail closed by design, never
  simulated here.
* Any live deployment, provider, or appliance operation; none performed.
* Upgrade gate proof is sandbox + disposable PostgreSQL with a
  `systemctl` service double; the installed appliance's real services
  are the operator's acceptance.

## Look hardest at

* `deploy/upgrade.py` `run_upgrade` ordering: resume-before-no-op, fence
  lifecycle (up at qualification, down only on completion), stamp-last.
* `_restore_tree`: validation-only first pass; ownership rules (root vs
  owner-only non-root; no guessing).
* `_OwnerCredential`: the ONLY paths the password takes (env PGPASSFILE
  → 0600 file → child env); everything else is endpoint data.
* `provision_release` + `ensure_venv`/`_create_venv`: production call
  unchanged; sandbox skips broker bindings, never dependencies.
* `srplatform/api/app.py` `_maintenance_fence`: exemption list (login,
  internal callbacks, health, ingest) is deliberate — blocking those
  would strand work un-terminalized; everything state-changing is 503.
* `forward_migrate` 0026 prerequisite discipline (round-1) — unchanged,
  still the only tolerated failure, heads-re-proven.
