# 02 — Host-safe authority and fail-closed cessation

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

Approved 2026-10-09; clean master 9393a36. Contract: docs/ARCHITECTURE.md.

## Goal and context

No AI host authority or hidden work. Fast: 128 passed/139 deselected/no failures
or skips. CI 37860676959: two DB failures/111 passes, nine other jobs green.
Repair remains prerequisite.

## Scope and decisions

In: CI, broker/stop, containment/races, upgrades/tests. Out: live work, images
(03), timers (05), production packaging (10).
Separate broker/control VMs outside a dedicated VLAN; leave VLAN 30/model LXC.
Broker-only restricted PVE token, mutual-TLS HTTPS, protected SQLite independent
of app DB. No worker/member broker credentials or arbitrary commands/config.
5s heartbeat/30s expiry: latch/hard-stop, never resume.
Offline attacker enrollment/legacy reconciliation; no name/tag auto-adoption.
Local shells: isolated harmless fixtures only. Storage: SSD/verified NAS, not boot.
Why: independent stop/authority and workload protection.

## Steps

Paths below default to srplatform/.
1. Repair CI: tests/test_followup_regressions.py:1373 lacks login token;
   tests/test_stage5_acceptance.py:162 launch returns 404. Capture status/body;
   investigate state/DB/server cleanup; cause unknown. Add regressions, repeat
   gates, require CI green. No weaker tests, retry-until-green or migration edits.
   Wider defects require agreement.
2. Add infra/broker/ and role-separated settings.py. Required operator policy:
   node/templates/bounded VMIDs/storage/clone mode/exact NIC-VLAN/provisioning
   fields/aggregate CPU-RAM-disk limits. Reject missing policy, arbitrary PVE paths,
   config/mounts/passthrough/privilege expansion. API-only mutual-TLS client key.
3. Durable SQLite intent BEFORE effects, ownership/generation, idempotency/task IDs,
   lease/latch/obligations; serialize lifecycle. Verify exact identity/config before
   mutation. Unknown retains claims; restart/lost state latches. Reconcile, not replay.
4. api/deps.py and scenario_engine/orchestrator.py use typed broker calls;
   infra/proxmox_client.py is broker-private. Preserve task waits/lease/cleanup;
   bind SSH attacker to enrolled generation. Remove normal local-dev shells;
   update Compose/demo/browser synthetic fixtures, no production bypass/fallback.
5. Broker/safety/: persist latch/fence first; independently cancel workers/commands
   and hard-stop ALL owned attacker/target VMs, including pending creations.
   Confirm tasks AND stopped read-back; continue across failures. Healthy DB-backed
   control renews lease; expiry stops. Unknown/broker/PVE outages retain obligations
   and reservation. No runtime host nft/root/SSH/shell; static isolation stays.
6. api/{app,runs}.py, red_agent/runner.py, safety/runregistry.py, infra/runner/:
   prove protected recursive authority; kernel-scoped/stable-handle signals only;
   unsupported starts refuse. Barrier-test spawn/register/cancel/callback/watchdog/
   startup/emergency writers; terminal rows cannot hide ANY run's unresolved work.
7. Forward upgrades start legacy deployments latched pending offline reconciliation.
   Protected broker-local enrollment/status/stop/recovery tools plus manual PVE
   fallback. Release requires resolved obligations and fresh config/generation-bound
   isolation/stop evidence; never resumes attacks or removes isolation.
8. infra/dev/acceptance.py authority: real mutual-TLS/auth negatives, policy,
   durable restart/expiry/races and synthetic PVE faults; required CI wiring.
   Preserve DB/containment/packet/browser gates and owned-fixture cleanup.
9. Record findings; update runbook/architecture; tick roadmap 02 after software
   acceptance, keeping live gates open.

## Manual checks and risks

Operator: PVE/ACL denials, VLAN/flows, identity/stop, free CI/$0 budget. No pushes.
Capacity = templates + max clones + control/broker + evidence + free-space reserve.
Sizes/storage/quotas/addresses remain deployment inputs. Outages interrupt; unknown
stop blocks release. Hypervisor risk remains; live/packaging gates: 10/11.

## Acceptance criteria

Define `gate() { .venv/bin/python infra/dev/acceptance.py "$@"; }`.
Authority is a new required gate.
1. `.venv/bin/python -m pytest -q -ra`: fast passes, zero prerequisite skips.
2. `gate selection`: classification/required modes pass.
3. `gate python`: supported interpreter matrix passes.
4. `gate db`: fresh/forward upgrades and writer races pass.
5. `gate containment`: protection/signaling/cessation pass.
6. `gate authority`: private boundary/fault/race tests pass.
7. `gate packet`: isolated packet proofs pass.
8. `gate frontend` AND `gate compose` AND `gate browser`: each passes.
9. Required CI jobs pass at implementation revision, recorded in findings.
