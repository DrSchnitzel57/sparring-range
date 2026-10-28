# Handoff — milestone 21 (preserving upgrade), round 4 (review-corrected)

Entry point for the parent's release-focused re-review and the operator's
supervised-practice testing. Branch `practice-upgrades-18-21`. Rounds 1
(HEAD `2ba575e`) and 2 (`a2501c8`) each returned **VERDICT: FIX**
with seven blockers; every round-3 finding is fixed and re-proven below.
The round-4 review at `f6b57b3` returned **VERDICT: FIX** with five
findings (readiness contract, cross-attempt fence, named-env leak,
contract completeness, runbook journal pipeline) — all five are fixed and
re-proven in the round-4 section. Milestone 20 is NOT accepted; F5–F9
remain the recorded repository backlog (`docs/FINDINGS_CHECKLIST.md`).

## Round 4 (parent review of `f6b57b3`) — commits and proofs

| Commit | What |
|---|---|
| `2654683` | engine/CLI: readiness PARSES the production `/readyz` contract (exact `ready is True`, empty `issues`, `migration_version` == payload head; malformed/HTML/stale-head fail closed); fence records its owning attempt and completion clears only its own; `restore_config` keeps the fence across ANY unresolved attempt or unknown/foreign fence identity; the SELECTED `--db-url-env` name is registered and scrubbed from every unauthorized child by name; REQUIRED_RUNTIME_CONTRACT derived from the unit ExecStart execution surface; runbook journal pipeline never prints "clean boot" on retrieval failure; + 11 fast contract tests incl. the runbook pipeline executed VERBATIM |
| `8cbe932` | `upgrade` gate re-forged for the round-4 contract: readiness fixtures answer PRODUCTION shapes (200/ready-false, 200 ready-true at the old head, healthy 0027) with refusal+retention assertions; cross-attempt scenario X (two attempts, second valid payload, fence-ownership suite, byte-identical foreign fence, unreadable/foreign identities); scenario A end-to-end over `--db-url-env REVIEW_PRIVATE_OWNER` with the exit-48 wrapper tripwire and the su-shim env capture (54 keys captured, zero credential names); required-contract negatives loop lock + `env.py` + `worker_supervisor.py` |

Proofs: `upgrade` gate **32 probes PASS 407.1 s** (`.cache/gate_r16_upgrade.log`);
fast **672/0/0**; `db` 322/0/0; `selection`/`install`/`agent`/`python`/
`authority`/`containment` PASS; `bundle` **PASS 252.8 s** against the
repackaged runtime at revision `8cbe932d1c20…` (MANIFEST sha256
`cb5e4712e175…`, 375 files, 242 runtime files bound, images byte-identical
to the independently verified set, TCG boot, tamper refused). The
independently-positive round-3 behaviours (real 0019 bootstrap, stop-and-
drain barrier, same-attempt restore semantics, 0600 secret preservation,
special-password dumps) are preserved — the gate re-proves all of them in
the same run. The full finding→fix→proof table and lane receipts are in
`docs/FINDINGS_CHECKLIST.md` ("review round 4"). Operator procedure:
`docs/OPERATOR_RUNBOOK.md` §7 (the journal pipeline there is the one the
tests execute verbatim).

## Round 3 (parent review of `a2501c8`) — commits and proofs

| Commit | What |
|---|---|
| `ba6a4af` | engine/CLI/API: table-aware old-schema quiescence + engine-side 0021 secret-role/db-secret bootstrap; stop-and-drain admission barrier + transaction-boundary `AdmissionFenced` + middleware admission/terminality split; `daemon-reload` + bounded REAL-HTTP readiness before stamp; restore-config KEEPS the fence while unfinished; `make_url` URL normalization + PREFLIGHT credential validation + child-env secret stripping; `REQUIRED_RUNTIME_CONTRACT` inventory |
| `849066b` | `upgrade` gate re-forged around the REAL 0019 deployment (no manufactured prereqs), stateful systemctl double, real HTTP readiness fixture (503→ready + timeout negatives), restore-keeps-fence, env-leak exit-48 tripwire, required-inventory negatives, API generation-vs-terminality probes |

The finding→fix→proof table, round-3 lane receipts (upgrade 25/25
260.8 s, fast 661/0/0, selection PASS, db 322/0/0) and the parent-
recorded artifact truths (malformed TEST_KEYS blobs = supervised-practice
identity only, upgrade copies runtime not role images) are in
`docs/FINDINGS_CHECKLIST.md` ("review round 3"). Operator procedure:
`docs/OPERATOR_RUNBOOK.md` §7 (corrected manifest filename, real `sr-*`
units, no-false-clean log pipeline, fence-keeps-on-restore semantics,
member-vs-legacy history policy).

---

## Round 2 (HEAD `a2501c8`) — historical

Round 1 (HEAD `2ba575e`) returned **VERDICT: FIX** with seven blockers;
all seven were fixed and re-proven there (round-2 code `431f2c1` + gate
`a2ee8c9` + supporting fixes `0a169e9`).

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
.venv/bin/python infra/dev/acceptance.py upgrade   # round 4: 32 probes PASS 407.1 s

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
* THE release bundle is now built and gate-verified at
  `.cache/bundle/sparring-range-appliance` (4.5 GiB, BUNDLE_VERSION 2,
  revision `44ccdc89588d`): digests, candidate binding (242 runtime
  files), operator-manifest render, shipped-image boot from the bundle,
  tamper refusal — `images` 19/0/0 and `capture` PASS the same day.
  Exact receipts and digests in `docs/FINDINGS_CHECKLIST.md`.
* Operator reproduction needs disk-backed `TMPDIR` (this host's `/tmp`
  is RAM-backed); the bundle images carry SYNTHETIC attacker keys
  (supervised-practice identity, stated in FINDINGS).
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
