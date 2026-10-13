# 12 — Tomorrow pilot: deployable web-only AI-defense practice

**Type:** combined overnight delivery plan — authorized 2026-10-13 by the user
as an explicit exception to one-plan-per-milestone. It does **not** accept or
replace milestones 03–11; their acceptance states remain exactly as recorded
in `docs/FINDINGS_CHECKLIST.md`. Anything this plan does not verify stays
explicitly open.

**Contract:** `docs/ARCHITECTURE.md` (boundaries are non-negotiable: full-VM
targets, private broker authority, operator-owned isolation, no credentials
to the model, append-only evidence).

**Baseline (verified 2026-10-13):** clean `master` at `fe940fc`, equal to
`origin/master`. Fast suite: **135 passed / 0 failed / 0 skipped / 192
deselected** (15.6 s). CI run 38354019588 at `fe940fc`: 11 jobs green,
**images and capture failing** (03/04 rework in progress — stays open, not a
pilot blocker). Model endpoint `http://10.10.10.197:8096/v1` verified live:
`qwen3.8-flash-next` loaded, 262,144-token context, no API key.

## Goal

During the operator's five-hour window tomorrow, CCDC teammates take turns
on one LAN HTTPS site: log in → launch the **mojang-web-01** lab (fresh
attacker VM + web target on the operator's dedicated VLAN) → read server-
served SSH instructions → connect as defender → click **Begin** → defend a
server-timed **30-minute** round against the autonomous Qwen attacker →
observe live web-uptime status, hints, detections → end (early or on expiry)
→ honest final results, replay, history → automatic cleanup so the next
teammate can launch.

## Scope

**In:** web-only preset (`mojang-web-01`); one active range (existing lease);
take-turns member accounts with operator-provisioned public keys; sustained
autonomous AI attacks (dispatch pace configurable: **30 s default or no
intentional delay**, snapshotted per session, always sequential); explicit
Begin; 15-minute ready-idle expiry; web uptime scoring (optional, first to
drop); guided-practice hints; report/replay/history; deployment artifacts and
the operator access matrix.

**Out (stated, not silently dropped):** DB preset, timed injects,
competition-mode spoiler hardening, backup/restore, Windows, re-greening the
images/capture CI jobs, full milestone-05/06/07 acceptance.

## Decisions and why

| Chosen | Rejected | Why |
|---|---|---|
| Web-only preset, take turns | Both presets / shared-team session | Fits the one-lease architecture; only realistic path to a working demo |
| 30-min server-timed rounds, explicit Begin after connecting | Immediate attack on launch; browser-owned timers | Defender connects before the clock; reconnect-safe accounting |
| Pace 30 s default / no-delay option, sequential | Fixed 20-step runs; parallel actions | User control without losing cancellation/containment guarantees |
| Network entry (no target credentials) | Assumed-breach start | Honest red practice; no foothold-provisioning work |
| Repair the complete lab attack chain with real verified identities | Shipping the current fake flaw stubs | The documented chain does not exist today (allowlist-only `/diagnostic`; setuid ignored on scripts; `NoNewPrivileges=true`); arming an autonomous AI against a target whose objectives can never pass is worse than useless |
| Keep the existing agent loop | Hermes integration | Autonomy already exists (model chooses real shell commands on the isolated attacker VM); Hermes would bypass evidence, cancellation and stop controls |
| Control-plane VM + broker VM (fresh Ubuntu), inference LXC untouched | App on the Proxmox host / reusing the LXC | Milestone-02 authority design; model LXC stays inference-only and outside the range |
| Operator owns VLAN + firewall; agent ships the access matrix | Agent configuring host networking | Project boundary: no runtime host-firewall execution; user instruction |
| Uptime scoring optional, core-first | Everything mandatory | User instruction; unfinished work is never marked accepted |
| Focused automated tests overnight; live testing by the operator afterwards | Full CI/TCG gates as overnight blockers | User instruction; deadline reality — recorded honestly |

## Steps

1. **Repair the real attack chain** (blocker) in
   `infra/images/payloads/mojang-web-local/` and the shared build path:
   - Replace the allowlist-only `/diagnostic` stub in `srv/mojang-web/app.py`
     with a deliberately vulnerable feature granting genuine `web-user`
     command execution. Documented fix must disable it while the catalogue
     keeps serving (`http_content` verifier still passes).
   - Replace `usr/local/bin/mojang-maintenance` (setuid shell script — Linux
     ignores setuid on scripts) with a working, documented guest-root path
     (setuid binary or tightly scoped sudo rule); reconcile
     `NoNewPrivileges=true` in `mojang-web.service` with what the chain
     actually needs.
   - Update `FIXES.md`, verifier expectations, and the images-gate checks so
     acceptance proves **real identity changes** (web-user execution, then
     `uid=0` via the documented path) and that each defender fix blocks its
     path while services stay ready.
   - Add `qemu-guest-agent` to the pinned package set (required for broker
     guest-agent FileRead host-key pinning on fresh clones).
2. **PVE template build:** script producing import-ready qcow2 templates —
   9005 attacker, 9011 mojang-web-local — from the pinned noble base +
   payload using the existing QEMU overlay machinery
   (`infra/images/guest_build.py`); documented `qm importdisk` →
   template-convert steps for the operator; per-clone host-key regeneration
   and scrubbing preserved.
3. **Sustained attacker** (`srplatform/red_agent/loop.py`, `worker.py`):
   run until the match deadline instead of the 20-step/objective-complete
   exit; no overlapping actions; per-action dispatch throttle read from the
   session snapshot (30 s default or none). Preserve intent-before-dispatch,
   verifier-only objective truth, bounded command/output/time limits, and
   the cancellation/containment guarantees. Wire
   `LLM_BASE_URL=http://10.10.10.197:8096/v1`,
   `LLM_MODEL_RED=qwen3.8-flash-next`; gateway policy 60 s call timeout,
   three attempts, 5/15 s delays, then interrupt the match truthfully.
4. **Minimal durable lifecycle** (subset of milestone 05, forward migration):
   session snapshot (preset, 30-min duration, pace); **Begin** endpoint starts
   the server clock, attack schedule and uptime probes together; ready-but-
   unstarted labs expire after 15 minutes with safe cleanup; end/expiry stops
   and confirms the worker, captures final evidence, revokes capabilities,
   **tears down owned VMs and releases the lease**; API restart
   interrupts/reconciles, never resumes; connection instructions served from
   the API (replaces sessionStorage-only SSH info).
5. **Web uptime scoring** (first optional; drop before core if time
   threatens): control-plane HTTP+content probe every 10 s with 5 s timeout;
   identity-bound append-only samples; dashboard shows up/down/unknown,
   latest observation, freshness, coverage. Score = % up among **valid**
   checks; unknown/missed award nothing; zero valid checks = unscored;
   confirmed probe-infrastructure failure interrupts the match rather than
   fabricating downtime. Security-state score stays separate; no combined
   grade.
6. **Browser flow:** mojang-web-01 launch page with pace selector, live
   provisioning status, server-served SSH instructions, Begin button,
   2-second live refresh (attack activity, uptime, detections), end/cleanup
   states, report/replay/history; truthful `busy` / `cleaning up` /
   `recovery required` display.
7. **Deployment artifacts + operator handoff** (agent builds, operator
   executes): control-plane Ubuntu VM (PostgreSQL 16 owner/app roles, API,
   bastion, built frontend behind self-signed IP-SAN HTTPS with trust
   instructions); broker VM (`SR_PROCESS_ROLE=broker`, restricted PVE token,
   mutual-TLS material, policy-file generator for the operator's VLAN/bridge/
   storage/VMID range); member account + public-key onboarding steps; bastion
   dials guests as `defender` with a per-generation key (replaces the current
   root default); generated **access matrix** (below).
8. **Focused validation + records:** fast pytest, targeted unit/db/authority/
   frontend tests, local QEMU template build (QEMU 10.0.13 present); record
   findings with exact commands/counts/environment; update `docs/ROADMAP.md`
   to record this exception without ticking any milestone.

## Operator access matrix (operator configures; agent documents)

| Source → Destination | Purpose | Verdict |
|---|---|---|
| Teammate laptops → control plane HTTPS | Web UI/API | allow |
| Teammate laptops → bastion TCP 2222 | Recorded SSH | allow |
| Control plane → PVE API | Broker operations | allow |
| Control plane → broker | Mutually authenticated TLS | allow |
| Control plane → inference LXC `10.10.10.197:8096` | Model calls | allow |
| Control plane → range guests | Bastion 22, management SSH, telemetry ingest, HTTP probe | allow |
| Range guests ↔ each other | Attacker ↔ target only | allow |
| Range guests → telemetry ingest | Installed shipper | allow (narrow) |
| Range → WAN/DNS/IPv6, Proxmox mgmt, NAS, VLAN 30, inference LXC | — | **deny** |

## Acceptance criteria

Named gates: `.venv/bin/python infra/dev/acceptance.py <gate>`.
1. Fast pytest (AGENTS.md command): zero failures/skips.
2. Attack-chain test: isolated QEMU boot proves web-user execution and
   guest-root via the documented chain; each defender fix blocks its path
   while `http_content` still passes.
3. Pace/Begin tests: pace stored at session creation; Begin starts the clock;
   duplicate Begin idempotent; ready-idle expiry cleans up safely.
4. Sustained-loop tests: runs to the deadline with the configured throttle,
   no overlapping actions, cancellation confirmed.
5. Uptime tests: up/down/unknown, freshness, coverage, % among valid checks,
   zero-valid unscored, probe-infrastructure failure interrupts.
6. Lifecycle db tests: end/expiry tears down owned VMs and releases the lease
   so a second session can launch.
7. `frontend` gate: production build + audit zero findings (new pages
   included).
8. `compose` gate: fresh bootstrap + idempotent rerun.
9. Template build produces importable attacker/web qcow2 locally (QEMU).
10. Findings record exact commands/counts/environment; roadmap notes the
    exception; no milestone falsely ticked.

## Manual checks (operator-only, required BEFORE any attack)

- [ ] Dedicated VLAN verified default-deny for the range (positive controls:
      WAN/DNS/IPv6, Proxmox mgmt, NAS, VLAN 30, inference LXC unreachable
      from a booted range guest; management stays usable).
- [ ] Emergency-stop drill: broker `hard_stop_all` stops owned VMs with
      read-back; latch engages; release procedure works.
- [ ] Model smoke test through the gateway (valid tool-schema output,
      latency acceptable).
- [ ] One full rehearsal: launch → connect → Begin → end → cleanup → second
      teammate launches.
- [ ] PVE token/ACL created for the broker identity; templates 9005/9011
      imported; base-image SHA256 verified against published SHA256SUMS.

## Risks and assumptions

- **Deadline risk:** lifecycle + template build + deployment is a large
  overnight scope. Core-first ordering protects the demo; uptime scoring and
  browser polish are the designated cut points, reported honestly if cut.
- Isolation/emergency gates are manual operator checks — the pilot is not
  “safe by test suite,” and attacks stay latched until they pass.
- The attacker may legitimately fail against good defense in 30 minutes;
  that is practice, not a bug.
- Installed-capture (auditd/shipper) acceptance stays open; pilot command
  truth is events/casts, and the UI says so.
- images/capture CI failures at `fe940fc` remain open; the template build
  reuses that overlay machinery and must work locally, but CI re-greening is
  not a pilot gate.
- Assumes the operator VLAN can enforce default-deny; if it cannot, attacks
  remain latched off. No credential ever reaches the model; targets stay
  full VMs; the inference LXC is not modified.
