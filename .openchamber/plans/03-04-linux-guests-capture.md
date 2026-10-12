# 03+04 — Linux guests, installed capture and access

Approved 2026-10-12; clean master cbaa3a0. Paired plan, separate gates.
Contract: docs/ARCHITECTURE.md.

## Goal and context

Mojang guests, installed capture, pinned SSH/replay.
Fast: 131 passed/164 deselected, 0 failed/skipped, 4 warnings, 14.80s.
Repair images/baselines/clone-mode/budgets/capture.

## Scope and decisions

In: guests/deployment/capture/access/replay/CI.
Out: live/game/real assets/timers/scores/injects/UI/production packaging.
Ubuntu 24.04 LTS cloud images; retire Packer. New mojang-web-01/mojang-web-db-01;
preserve legacy snapshots. nginx/Python: local data or PyMySQL/MySQL.
Three games (Minecraft/Dungeons/Legends), 12 fixed fictional purchases.
Diagnostic flaw gives web-user execution; maintenance helper gives guest root;
document fixes preserving services. Network-entry: no target credentials;
assumed-breach: disclosed web-user only. Defender+sudo; separate trusted keys.
Fresh attacker/session. Each guest 2 vCPU/2 GiB; disks attacker/web/DB 16/12/16
GiB. Explicit full/linked mode. Shared casts; spool 64 MiB, cast 32 MiB.
Why: reproducibility, role separation, honest checks.

## Steps

1. infra/images/, infra/cloud-init/: retain pinned image/package/build inputs,
   checksums/manifests; build attacker/web-local/web-DB/MySQL with services/seeds,
   firewall/auditd/shipper; prove supervisor/cgroup/AppArmor. Bake public keys only;
   scrub secrets/logs/spools/host keys/machine IDs. No runtime package fetching.
2. scenarios/, loader/verification_service, verifiers/: version seeds/image/user/
   cron/static baselines. HTTP content/authenticated read-only SQL/logical integrity,
   not DB disk hashes. App SELECT-only. Repairs stay ready; legacy without manifests
   isn't release-ready.
3. infra/broker/, proxmox_client, settings: initial typed guest-agent FileRead
   ONLY /etc/ssh/ssh_host_ed25519_key.pub; bound/validate response, verify owned
   VM/session/generation before/after read. Require scoped VM.GuestAgent.FileRead;
   no arbitrary paths/exec/host shell/broad ACL fallback/post-compromise re-pin.
   Fresh clone/reset pins; public build keys bootstrap pinned management.
4. orchestrator/broker/runner: fresh attacker inventory/fixed address/current pins;
   reserve/enforce guest/aggregate CPU/RAM/disk, template/storage/mode/exact NIC.
   Wait/read back tasks/config; preserve intents/conflicts/resume/reset/foreign-VM
   protection. Unknown retains obligations/lease; fence stale work.
5. telemetry/enrollment/ingest/verification: pinned management provisions current
   token/nonce/generation; distinct delivery/real capture. Stale/foreign/phase-only
   can't ready/run; populated upgrades/concurrent confirms/forward migrations.
   Durable audit cursor/rotation/spool replay/dedup/order/limits/gaps. Installed
   active-unit wrong API/token/input blocks readiness and recovers;
   test crashes/outages/reboots/overflow.
6. srplatform/bastion/, auth/recording/settings: explicit guest key/defender+sudo,
   pins/key/token revocation; protected shared casts. Prove
   interactive/exec/resize/reconnect/restart/replay, opaque IDs/path/symlink/size
   controls/missing files. No logged secrets; guest telemetry can be forged.
7. infra/dev/, tests/, CI: required images/capture gates boot actual artifacts in
   isolated QEMU, synthetic API/DB/SSH. Max 3 VMs/6 GiB guest RAM/60-minute job;
   optional KVM/software emulation. No host shares/general test egress; bound
   owned disks/processes/cleanup. Fake PVE tests modes/budgets/identity/partial
   deploy/reset/cleanup; preserve existing gates.
8. Record findings; update runbook/architecture; tick 03/04 separately after
   software acceptance; keep live gates open.

## Manual checks and risks

Later: PVE/storage/VMIDs/network/keys; live ACL/clone/budget/identity/transport/
isolation/stop proofs. Unsafe ACLs block deploy; no attacks before real gates.
Non-boot storage fits templates/clones/control/evidence/reserve. Free CI/$0 budget;
no paid runs. QEMU isn't PVE proof; missing CI blocks acceptance. No R740 mutations.

## Acceptance criteria

Named gates: `.venv/bin/python infra/dev/acceptance.py <gate>`.
1. AGENTS.md fast pytest: zero failures/skips.
2. selection/python: classification/required controls/matrix pass.
3. db: fresh/upgraded data/enrollment/lifecycle races pass.
4. authority/containment: budgets/identity/stop/runner faults pass.
5. images (03): real builds/boots/services/seeds/flaws/fixes/readiness pass.
6. capture (04): installed auditd/srshipper/negatives/recovery/access/replay pass.
7. packet: required isolated boundary proofs pass.
8. frontend/compose/browser: existing gates pass.
9. Required CI green at code revision; findings record counts/environment/owned
   cleanup; zero prerequisite skips.
