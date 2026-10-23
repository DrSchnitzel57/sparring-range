# Live-practice repairs — 2026-10-23

Branch `15`; source changes only, not deployed acceptance. The source baseline
was `5930c9d`. The user approved one supervised run, not general production
promotion. No model endpoint, appliance, live guest or outer host was contacted
by the repair agents. No image rebuild or host-security relaxation was performed.

## What reproduced and changed

- `e6f460e`: role-specific configurable completion budgets (red 2048, coach
  3072), explicit rejected/empty/truncated completion handling, labeled coach
  fallback, deterministic AAR preservation, permitted runner diagnostics,
  nonblank summary checkpoints and visible compression activity. Worker
  completion checks HTTP status; supervisor retries unresolved failure reports
  without redispatching. Model-unavailable completion is failed, not success.
- `6cb8ce7`: cron verifier v3 requires trusted content hashes and safe metadata;
  common maintenance filenames without trusted pins are UNKNOWN, not proof of
  persistence. Replaced hashes or unsafe metadata cannot inherit cleanliness by
  filename. Legacy verifier doubles now emit the structured probe contract.
- `370dadb`: separate attacker state/freshness from the match and HTTP uptime;
  refresh session state while running/completed; filter and expand API-authorized
  events; restore saved hints and expose blank historical hints. Coverage counts
  distinct current-generation target/time slots and reports duplicate/excluded
  samples. Next 16.4.0 -> 16.4.2, the same-major audit repair.
- `8bc7bb2`: correct the false Kali assumption in the prompt; discover available
  tools and adapt to missing executables, without installing packages or
  inventing successful output. Repair the pre-existing emergency-warning prose
  assertion without weakening its partial-failure invariant.
- `52ae355`: tolerate read-induced atime changes while still rejecting inode,
  content and permission races in the real cron probe. Registry failures cannot
  reuse old-generation uptime as healthy. Integration fixtures now supply trusted
  hashes before their immutable snapshot and valid generation/time-slot samples.

The exact cause of the installed worker stopping after its first action is not
established: deployed worker logs/full run status were not obtained. The invalid
diagnostic event, retry exception, empty summary and completion-report defects
were independently reproduced; they are not inferred from GPU request counts.

## Evidence and remaining limits

See the dated repair entry in `FINDINGS_CHECKLIST.md` for commands and results.
Final recorded checks: selection/fast **567 passed**, disposable DB **183 passed**,
browser **1 passed**, authority **25 passed**, containment **21 passed**;
frontend build/audit pass with zero vulnerabilities. Independent diff review found
no concrete regressions (118 narrow tests passed). No required-layer skips were
accepted. These are separate gate executions, not an aggregate appliance gate.
The initial no-admin baseline was 448 passed / 1 failed / 262 deselected; the
failure was the warning-text assertion. Test doubles do not prove real model
effectiveness, useful hints, sustained guest attacks or deployed cancellation.

Open work must not be hidden by these repairs:

- Existing role artifacts/scenarios do not provide trusted cron content hashes.
  Clean-state scoring may remain UNKNOWN until pins are captured during a trusted
  clean image build and bound to its artifact. Do not learn pins from an already
  compromised target or merely allowlist maintenance filenames.
- The recurring post-killswitch teardown/latch ordering defect is **not repaired**
  here. The documented scoped offline recovery worked; runtime destroy is still
  refused while the broker cessation latch is engaged.
- The previously broadened guest AppArmor profile still needs independent
  adversarial security acceptance. These tests do not certify that change.
- Exit 127 identifies a missing executable, not which package to install. The
  user redacted that executable; do not assume it was nmap or add an unrestricted
  package-install fallback.
- The Windows SSH client reached the bastion but failed public-key
  authentication. A token username is not a password. Enroll that device’s
  public key for member `sr`; keep its private key on Windows. The operator key
  file uses `username public-key` lines and is loaded on bastion startup. Preserve
  existing member keys and recordings; do not blindly restart an active bastion.

## Deployment boundary

The generated small source patch is `.cache/live-practice-repair.tar.gz`; it
contains changed runtime Python, web source and the frontend lockfile, with a
SHA-256 file manifest. It contains no guest disks, private keys or environment
credentials. It is **not** a replacement sealed release bundle.

Patch runtime revision: `52ae3551ca057d33673bb38a9bd52eb7c4ebedf7`;
16 files, 104142 bytes. Archive SHA-256:
`5593d1f58dfb7061918ba1c7da41604b4cb75b120a917cc8d8222847aed19f80`.
Archive membership and every embedded file hash were independently read back.

Before applying: confirm the red worker has stopped, retain evidence from the
failed session, complete ordinary cleanup if possible, and verify there is no
active assignment. Do not restart the API/supervisor over unknown remote work.
Back up the touched installed files; validate patch hashes; install only those
paths under `/opt/sparring-range`. Reinstall frontend dependencies from the
lockfile and build using the appliance’s existing public API URL. Keep every
service’s existing UID, environment ownership and secret boundaries. Reload the
changed services only after quiescence, then use a fresh session rather than
resuming the old false-positive phase. Collect real command/result progression,
nonempty hints, actual worker stop and cleanup evidence before promotion.

Changing token budgets requires no image rebuild. Defaults retain the existing
60-second per-call deadline: at the observed ~65 tokens/s the output portions
take ~32/~47 seconds, but model/prefill/queue latency is still a manual check.
Larger budgets require explicit latency/deadline coordination, not unlimited
waiting or global inference-server changes.

Reference: NVIDIA’s [llama.cpp serving instructions](https://build.nvidia.com/spark/llama-cpp/instructions)
show the exact empty `content` + `finish_reason=length` behavior when Qwen
reasoning consumes a small output budget. This corroborates the failure mode;
it does not prove the deployed server’s exact raw response.
