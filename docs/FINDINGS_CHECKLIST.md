# Current findings and validation evidence

## Review round — 2026-10-21, branch `15` (after the independent review)

An independent reviewer read milestone 15 and returned **VERDICT: FIX** with
17 findings (six security/lifecycle, nine installation/integration, two
acceptance). Every finding that reproduced was fixed on this branch; the
fixes are listed in `docs/HANDOFF-15.md` ("The independent review round").

**Environment (unchanged from the milestone run):** Debian 13 container, no
`/dev/kvm`, no root, no installed appliance, unprivileged libvirt from
extracted Debian packages. Every guest boot is **TCG software emulation**.
The two operator gates (`packet`, `journey`) are reported **pending with
their exact prerequisite** by the aggregate — they are attempted, not
omitted.

| Command (from the repository root) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **413 passed, 0 failed, 0 skipped**, 261 deselected, 4 warnings (65.5 s) |
| `… acceptance.py selection` | **PASS** — every test classified; the fast default selects 413 tests with 0 skips |
| `… acceptance.py python` | **PASS** — fresh locked install, dependency check, 4 entrypoint imports (including `telemetry.shipper`) |
| `… acceptance.py db` | **PASS** (467 s) — 177 db tests against a disposable PostgreSQL 16 container, 0 skipped. The new regressions: the fenced supervisor callbacks, the guarded terminal transition, the unstarted queued run, the cross-UID stop that keeps the obligation until the supervisor reports |
| `… acceptance.py authority` | **PASS** — 25 broker boundary/durability/cessation tests |
| `… acceptance.py containment` | **PASS** — 21 tests, no leaked cgroups |
| `… acceptance.py install` | **PASS** — the real install sequences in a sandbox root **plus the new managed-service contract check** (`infra/dev/service_contract.py`): the identities, the environments each unit loads, the readability of every credential, the front door's routing and the TLS artifacts the bootstrap creates |
| `… acceptance.py hypervisor` | **PASS** (254 s, 2 tests) — real libvirt lifecycle/QGA/ownership/destroy and the live broker authority path over the real Unix socket. The gate needs the unprivileged session daemon: `sh .cache/libvirt-debs/start-session.sh` first, then `sh -c '. .cache/libvirt-debs/env.sh && .venv/bin/python infra/dev/acceptance.py hypervisor'` |
| `… acceptance.py access` | **PASS** (155 s) — the real guest: readiness marker, pinned host key, real SSH, the recording bastion's `.cast`, `sudo`, an interactive PTY with a recorded resize, a reconnect and the refusal of an unauthorized key |
| `… acceptance.py images` | **PASS** (1871 s, 18 passed / 1 skipped) — the role images build, boot, serve, seed, expose the documented flaws and take the fixes. The skipped test is a DB test that needs an explicit PostgreSQL admin. The **role artifacts are now carried by the release bundle** |
| `… acceptance.py bundle` | **PASS** (23 s) — the REAL bundle with the **role artifacts** (306 files, 4 images: the appliance base + attacker + mojang-web-local + mojang-web-db), every digest verifies, the operator's manifest renders from it with **absolute** image paths and the canonical template ids, and a tampered bundle is refused |
| `… acceptance.py frontend` | **PASS** (7 s) — lockfile-faithful `npm ci`, the production build, `npm audit --omit=dev` with zero high/critical findings |
| `… acceptance.py browser` | **PASS** (46 s) — the isolated real-browser workflow and its replay |
| `… acceptance.py compose` | see the aggregate below |
| `… acceptance.py packet` | **PENDING (environment)** — needs root and `nft`. The aggregate now attempts it and reports the exact missing prerequisite instead of omitting it |
| `… acceptance.py journey` | **PENDING (environment)** — needs the installed appliance, the member's SSH key, the pinned bastion host key and the browser login. The journey now requires all of them, drives a real browser and walks the incident (break → submission → decision) and refusal paths |

**What the review found and what changed** (the full table is in
`docs/HANDOFF-15.md`): the supervisor's callbacks were unfenced; the API
signalled a worker it does not own; the controller kept acting after its
lock's session died; the Unix-socket deployment never armed the control
lease; the match scheduler was disabled in production; the schema-owner
credential travelled in an environment every service loads; the database
bootstrap split the URL on `/` and never created the owner role; the ingest
certificate was skipped (`INGEST_SANS` missing) and the telemetry trust
anchor named a file the bootstrap never creates; the member's keys were
written in a format the bastion cannot read; the capability and the machine
keys were unreachable by the identities that use them; the frontend build
passed an argument the runner rejects, baked no API URL and nginx kept a
prefix the API does not serve; the guest NIC carried a VLAN tag the broker
policy refuses; the bundle lacked `verifiers/` and `telemetry/` and gave
every role the bare base image; the hand-off passed a flag the CLI does not
have and `apply` demanded the venv it creates; and the aggregate omitted
the operator gates while `install` and `journey` checked less than they
promised.

## Second review round — 2026-10-22, branch `15`

A second reviewer read the first round's fixes and returned **VERDICT: FIX**
again, with 13 findings. Every reproduced one is fixed (commits `dd88707`,
`d36264a`, `45064d0` and the bundle/image commits below). What changed:

* **The supervisor's callbacks the first round missed.** Three failure-report
  paths did not present the claim credential (the endpoint refused them with
  422, so a run stopped between the claim and the assignment stayed
  unresolved); the HTTP helper raised a bare `RuntimeError`, so the 409
  handler was unreachable; a late heartbeat could clear the *next*
  assignment's run id; and the final UPDATEs were not fenced by the claim
  hash, so a claimant whose run was reclaimed could mark the new claim's run
  failed and revoke its credentials. The assignment's state is now immutable
  and belongs to that assignment; every report carries the credential; every
  final UPDATE is fenced by the claim hash.
* **The controller lock.** The scheduler kept dispatching duties after the
  lock was lost: it is now fenced by the same ownership check and stops.
* **The installation.** The hand-off still passed `--range-bridge` (the CLI
  takes `--bridge`) and exited 2; the database bootstrap wrote its SQL to a
  root-owned 0600 file the postgres user could not read and terminated
  `\gexec` with a semicolon; the bastion and the ingest listener validated
  the API's supervisor capability and the API validated the bastion's dial
  key; the members were onboarded under the machine role names, so no person
  could authenticate; the key pair was validated *after* the copy, so a
  mismatched half was installed and a rerun accepted it; a dry run changed
  the capability's permissions.
* **The shipped artifacts.** The three role images referenced the build
  machine's deleted backing files. They are now flattened and self-contained,
  the bundle verifies that what it ships stands alone, and the bundle gate
  **boots a shipped image from the bundle** (through a throwaway overlay, so
  the released artifact is not modified) and proves it becomes ready.
* **The acceptance.** The aggregate exited 0 while mandatory gates were
  pending; the bundle gate accepted placeholder image bytes; the journey
  answered an incident before its window opened and mistook the login page's
  own heading for a successful login, and it echoed the member's password
  in its diagnostics.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **424 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (66 s) |
| `… acceptance.py install` | **PASS** (7 s) — the real install sequences in a sandbox root + the managed-service contract check |
| `… acceptance.py bundle` | **PASS** (232 s) — the release bundle (306 files, 4 images) verifies in place, the operator manifest renders from it, **the shipped `mojang-web-local` image boots from the bundle and becomes ready** (TCG), and a tampered bundle is refused |
| `… acceptance.py db` | **PASS** (467 s) — 177 db tests, 0 skipped (the fenced callbacks, the guarded terminal transition, the cross-UID stop and the rotation-during-cancellation regression) |
| `… acceptance.py hypervisor` / `access` / `authority` / `containment` / `frontend` / `browser` | **PASS** — unchanged by this round (the hypervisor gate needs `sh .cache/libvirt-debs/start-session.sh` first) |
| `… acceptance.py images` | **PASS** (1871 s, 18 passed / 1 skipped) — the role images build and boot |
| `… acceptance.py packet` / `journey` | **PENDING (environment)** — root + `nft`; the installed appliance with the member's SSH key, the pinned bastion host key and the browser login. The aggregate now FAILS while a mandatory gate is pending |

## Third review round — 2026-10-22, branch `15`

A third review of the second round's fixes returned **VERDICT: FIX** with
seven findings. All of them are fixed (`51f4166`, `fec3f53`, `0a6638e`,
`818d99e`):

* **The bastion had lost its API credential.** Splitting the services'
  environments took the controller's environment — and the service token
  the bastion's callbacks need — away from the bastion, so every callback
  was unauthenticated and no member could authenticate. The bastion now
  owns its credential: a 0600 file (`SR_BASTION_TOKEN_FILE`), provisioned
  by the installer, named in the bastion's environment, and required by the
  production validation (an empty file fails loudly).
* **The password still leaked.** The redaction hid the *selector* of a
  `fill` command and left the password in the exception. The value is the
  secret; it is hidden now, in the command line and in the captured
  output, with execution-level tests.
* **The journey did not prove a break/repair.** It accepted a wrong
  answer and checked that a counter went up. The journey now stops the
  practice service on the defender guest, requires the API's trusted
  checks to FAIL, repairs the service and requires them to PASS — an
  observable failure → repair → verified success transition.
* **A corrupted private key was accepted.** The public-half derivation
  failed and the adjacent `.pub` file was used instead. A key that cannot
  produce its public half is now an error.
* **The gate could damage the release.** The tamper test overwrote the
  release's `requirements.lock`, and the write preceded the restoring
  `try`. The negative test now runs on a disposable copy.
* **A reused bundle was not bound to the candidate.** A bundle built from
  an older revision verifies against itself. The packaged runtime,
  configuration and lock file are compared with the checkout under test,
  digest by digest; a stale bundle is refused.
* **The shipped-image boot was skippable into a pass.** It is mandatory
  now: there is no skip, and the gate fails without the proof.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **432 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (73 s) |
| `… acceptance.py install` | **PASS** (8 s) — the real install sequences + the managed-service contract check |
| `… acceptance.py bundle` | **PASS** (207 s) — the release bundle (307 files, 4 images) verifies, **is bound to the checkout under test** (307 packaged files compared), the operator manifest renders, **the shipped `mojang-web-local` image boots from the bundle** (TCG) and reports its readiness marker, and a tampered bundle is refused (on a disposable copy) |
| `… acceptance.py db` / `authority` / `containment` / `frontend` / `browser` / `hypervisor` / `access` / `images` | **PASS** — unchanged by this round |
| `… acceptance.py packet` / `journey` | **PENDING (environment)** — root + `nft`; the installed appliance with the member's SSH key, the pinned bastion host key and the browser login |

## Fourth review round — 2026-10-22, branch `15`

A fourth review (VERDICT: FIX, four blockers and one non-blocker) is fixed
in `5b37915`:

* **The bastion could not read its own credential.** The token lived under
  the shared secrets directory (`root:sr-secrets 0750`, which `srbastion`
  may not traverse), and the runbook replaced it with a `0600 root`-owned
  file the service could not read either. It now lives in the bastion's
  own directory (`0750 root:srbastion`) as `0640 root:srbastion`; the
  effective permissions are tested.
* **A password-fill timeout disclosed the password.** The timeout escaped
  before the exit-status redaction and printed the whole command line. It
  is caught and replaced by a sanitized message, and the execution test
  now reaches the secret-bearing call instead of failing on the username
  fill.
* **The break/repair proof used a check that cannot see a stop.**
  `service_present` asks whether a unit *exists* — a stopped unit still
  exists — so the helper rejected a genuine stop. The break is now observed
  by the liveness check (`http_content`, which fails when the service is
  stopped), and the service is restored in a `finally` block even when the
  repair fails.
* **The candidate binding was incomplete.** It compared only the files the
  bundle declared and excluded the frontend's source, so a bundle with a
  stale login page — or one missing `srplatform/settings.py` — passed. The
  comparison is now complete and bidirectional over the runtime file set
  (frontend included): missing, stale and changed all fail the gate.
* **The tamper test passed for the wrong reason.** The disposable copy
  omitted the images but kept their manifest entries, so it already failed
  verification for missing images. The fixture is now a small, internally
  valid bundle that is verified **first** (the positive control), and the
  refusal must be a digest drift.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **437 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (87 s) |
| `… acceptance.py install` | **PASS** (9 s) — the real install sequences + the managed-service contract check |
| `… acceptance.py bundle` | **PASS** (276 s) — the release bundle (307 files, 4 images) verifies, **is bound to the checkout** (215 runtime files compared; missing, stale and changed all checked), the operator manifest renders, **the shipped `mojang-web-local` image boots from the bundle** (TCG), the disposable fixture verifies before it is tampered with, and the tampered bundle is refused for a digest drift |

## Milestone 15 implementation evidence — 2026-10-20/21, branch `15`

> Reviewer handoff (read this first): [docs/HANDOFF-15.md](HANDOFF-15.md) —
> the plan map, the commit map, the exact verification commands, what is
> claimed versus what is not, and where a critical reviewer should look.

**Environment (stated so no result is over-read):** Debian 13 (trixie)
container, 4 CPUs, 16 GiB RAM, **no `/dev/kvm`**, no root, no installed
appliance, and an unprivileged libvirt session assembled from extracted
Debian packages. Every guest boot below is **software emulation (TCG)** and is
labelled as such. **None of this is nested-KVM acceptance**: milestone 14's
promotion gate (real nested KVM, isolation, stop, member SSH rehearsal) stays
open for the operator.

| Command (from the repository root) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **386 passed, 0 failed, 0 skipped**, 254 deselected (~52 s) |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS** — 638 tests classified, fast default 386 passed / 0 skipped |
| `… acceptance.py python` | **PASS** — fresh locked install, dependency check, 4 entrypoint imports |
| `… acceptance.py db` | **PASS** — 172 db tests against a disposable PostgreSQL 16 container. Two failures were found and fixed: a spawn-race regression introduced in this milestone (the queued-run credential held a row lock across the spawn window, turning an unconfirmed queued stop into a confirmed kill) and a stale migration-head assertion |
| `… acceptance.py authority` | **PASS** — 25 broker boundary/durability/cessation tests |
| `… acceptance.py install` | **PASS** — the **real** appliance install sequences in a sandbox root: clean install, rerun (0 files changed, capability preserved byte for byte), reboot (runtime restored, data and keys preserved), populated upgrade, drift detected and repaired, foreign file untouched. The previous `SR_INSTALL_VM_EVIDENCE=1` environment attestation is **removed** |
| `… acceptance.py hypervisor` | **PASS** (250 s, 2 tests) — real libvirt: clone → start → guest-agent readiness marker → host-key read → ownership identity (a foreign installation is refused) → stop → destroy, and a repeated destroy of an absent guest is idempotent. The second test drives the **broker's own authority path**: the real `BrokerService` behind the real Unix peer-UID socket with the real libvirt backend, reserving a VMID, cloning, configuring, starting, pinning the host key through the agent, refusing a second session's claim on the same VMID, destroying and reading back that the domain and the guest's files are gone, and ending with no open obligation. Accelerator: explicit TCG |
| `… acceptance.py access` | **PASS** (≈130 s) — a real Ubuntu guest: guest-agent readiness marker and fixed host-key path read through the agent, real SSH with the role key, the **real recording bastion** writing `.cast` bytes, `sudo` for the management identity (and not for the attack identity), an interactive PTY **with a recorded terminal resize**, a reconnect to the same guest, and the refusal of an unauthorized key |
| `… acceptance.py bundle` | **PASS** (54 s) — the REAL bundle is built from the flattened base image (263 files), every digest verifies, the operator's manifest is rendered from it and satisfies the strict appliance schema, and a tampered bundle is refused |
| `… acceptance.py images` | **PASS** (1793 s, 19 tests) — the role images build, boot, serve, seed, expose the documented flaws, take the fixes and report readiness. On a COLD cache the build alone exceeds the 1500 s serial-marker timeout under software emulation (the preserved logs show `apt` still fetching); the gate then passes with the cache warm. A KVM runner removes the distinction |
| `… acceptance.py capture` | **PASS** (751 s, 11 tests) — the installed auditd/srshipper negatives, recovery, access and replay |
| `… acceptance.py capture` | not run — it depends on the image builds above |
| `… acceptance.py containment` / `packet` | not runnable here: they need cgroup delegation, root and `nft` |
| `… acceptance.py journey` | requires the **installed** appliance with operator/member tokens; it fails closed here by design |
| `… acceptance.py frontend` | **PASS** (9.5 s) — lockfile-faithful `npm ci`, the production Next build, and `npm audit --omit=dev` with **zero high/critical** findings |
| `… acceptance.py browser` | **PASS** (44.8 s) — the isolated real-browser workflow and its replay, against a disposable PostgreSQL 16 container |
| `… acceptance.py compose` | **PASS** (360.9 s) — the run-owned stack builds, the bastion capability is issued and scoped, the services come up, and every run-owned resource is removed |
| `… acceptance.py containment` | **PASS** (10.1 s) — namespace, recursive-membership and cancellation regressions, required mode, no leaked cgroups |
| `… acceptance.py packet` | **FAIL (environment)** — the gate needs root and `nft`, which this container does not have. It fails closed with the exact missing prerequisite and was not simulated |

**Defects this milestone found and fixed** (each with a regression test, each
found by inspecting a running guest rather than by reading code):

1. The guest agent was enabled in the base image, so the boot blocked on a
   device that never appears.
2. `systemctl --now` inside a cloud-init bootcmd hung the whole init stage
   (it waits for the agent device). The agent is now started with
   `--no-block` and is never *enabled*, so a later boot cannot block either.
3. The base image had **no machine-id**, so `systemd-networkd` could not
   configure even its DHCPv6 client and the link went to `failed` — the
   static address was never applied. The image now ships the cloud-image
   convention (a 32-zero-byte machine-id that systemd replaces per boot).
4. `sshd` was started before cloud-init generated the host keys, so the
   member's SSH never came up. Readiness now means "SSH is listening".
5. The guest-agent replies were read with the wrong protocol shape (the
   handle is the `return` value; the payload key is `buf-b64`), so the
   host-key read always came back empty.
6. A qcow2 overlay smaller than its backing image truncated the partition
   table and the guest dropped to an initramfs shell.
7. The bastion still accepted a **stale local known_hosts file** as a
   production fallback; production now refuses to dial without a
   deployment-served pin.
8. The cloud image's MOTD scripts run on every interactive login (one of them
   collects system information over the network), so an interactive member
   shell took minutes to appear — which looks exactly like a broken bastion.
   The appliance guest prints no MOTD.
9. The installed-migration lookup assumed a source checkout next to the
   working directory; it now follows the installed package.
10. asyncssh's `create_process()` sends **EOF on the remote stdin by
    default**, so the guest's login shell exited immediately and every
    interactive member session died before a command could be typed. The
    remote session is now created with `send_eof=False`, and the member's
    keystrokes are held until the guest's shell has produced output.
11. A terminal resize arrives as a `TerminalSizeChanged` **exception** from
    the reader; it was unhandled, so the session died on the first resize.
    The resize is now recorded in the cast and forwarded to the guest.

**Controller singleton:** the API process that serves requests also runs the
controller duties (reconciling interrupted runs, clearing dead operation
claims, heartbeating the control lease). It now takes a PostgreSQL advisory
lock — a lock the *database* holds, so it cannot leak and is released when a
crashed process's session dies. A process that does not hold it does not run
the duties and says so. The startup no longer swallows failures: every
startup problem is recorded and appears in the readiness report, so a
half-initialised controller is visible instead of looking healthy.

**Release bundle:** `deploy/bundle.py build|verify|manifest` produces the
artifact an operator carries into their own VM (the application, the locked
dependencies, the flattened guest base image, the installer and its fixed
artifacts, and a `MANIFEST.json` addressing every file by SHA-256). The
bundle is appliance-generic — the operator's addresses, ranges and
installation id are rendered from it — and it can never carry operator
material: secrets, keys, known_hosts, casts and the ledger are excluded and
configuration files are scanned for credential material. The built bundle
verifies against revision `5f018ad`.

**Still open and not claimed by this milestone:** nested-KVM promotion, the
isolation/emergency-stop rehearsal, the real-model and human gates, the
`images`/`capture` builds on a KVM runner, the browser/compose gates, and the
`journey` gate against an installed appliance.

## Current planning assessment — 2026-10-20

Source-inspected at `933f6a1`, clean `master`, equal to `origin/master`.
User selected a **single Ubuntu/KVM appliance with nested full VMs**, retaining
full individual-practice scope with no deadline-driven cuts. Draft plans 14–16
and the architecture's appliance section describe the completion sequence.

**No new test acceptance:** the user deferred tests and cancelled the started
fast suite. Cancellation is not a test failure. Existing counts below remain
historical and revision-bound; implementation must reproduce its own baseline.

**User-reported deployment blocker:** member SSH has not worked successfully.
Do not close this from the pin-fix claims below. Knowledge-panel field notes say
the old clones were destroyed; current inventory needs operator discovery, and
the next proof is a fresh deployment and real member login, not assumed resume.

Source-inspected remaining work (not claims of reproduced live behavior):

- `infra/broker/ledger.py::resolve_obligation` has no production callers;
  `service.py::release_latch` refuses open obligations. Add evidence-based,
  broker-local recovery including destroyed claims and foreign VMID handling.
- `deploy/install.sh` is a partial control-plane installer: it prints migration/
  backup instructions, enables only API/ingest and lacks complete web/DB/bastion/
  broker bootstrap. Its renderer duplicates `infra/release_manifest.py`.
- `deploy/systemd/` has no web unit; the separate deployed bastion described in
  field notes complicates the local-file recording contract in `web_routes.py`.
  Consolidation requires preservation/migration, not deletion of that installation.
- Bastion production dial still has a local-file pin fallback. The complete
  member → capability/API → pinned guest → recording/replay path needs one
  production contract and actual service-identity diagnostics.
- `rangectl/commands/db.py` derives the migration root from package location;
  non-editable installation layout needs explicit support.
- `infra/dev/acceptance.py::check_install` accepts the managed-service half from
  an environment assertion; it does not execute that VM sequence. The live
  release suite's HTTP checks do not establish all advertised SSH, actual
  service repair, model/scorer failure, replay-byte or mode-matrix behavior.
- API startup swallows controller-loop initialization failures. Controller
  singleton/health and a minimal separate ingest application need an explicit
  contract rather than additional full-app configuration combinations.
- `deploy/pve_broker_acl.sh` documents grants disappearing on VM deletion.
  The selected appliance removes that dependency; do not implement the discarded
  intermediate proposal for automatic outer-PVE ACL repair.
- Current-state prose is inconsistent with later evidence; the operator runbook
  even contains committed conflict markers. Preserve historical evidence while
  making current commands/status unambiguous in milestone 14.

Plans 14–16 inherit unresolved plan-13 requirements. A successful SSH check alone
does not accept plan 13 step 9 or the full release. Real isolation/emergency-stop
proof must still precede attacks. Backups remain optional/non-blocking but their
tooling and truthful status remain required.

The new libvirt adapter, domain-bound key acquisition, appliance installer,
role-isolated worker and actual nested-KVM/access acceptance do **not** exist yet.
The roadmap explicitly replaces PVE-only mechanisms/gates while carrying forward
their ownership, cessation, trust and failure invariants. Do not present existing
PVE test results as acceptance of the new architecture.

## Historical evidence (revision-bound)

Updated: 2026-10-08. Application revision inspected/tested: **`23de4f4`**
(planning baseline); milestone-01 implementation evidence recorded at **`ac5a61b`**.
Release contract: [ARCHITECTURE.md](ARCHITECTURE.md); ordered work:
[ROADMAP.md](ROADMAP.md); operator gates: [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md).

**Not release-ready.** This replaces accumulated remediation checkmarks. Existing
repairs and regression tests are valuable, but historical green totals and reports
are not fresh acceptance. Milestone 01 is accepted after independent review
reopened it and a repair round closed the findings (see below). No live attacks
are authorized; later milestones remain
unaccepted. Documentation changes do not repair the application.

## Evidence labels

- **Reproduced:** executed here at the stated revision/environment.
- **Inspected:** current source/artifacts support the observation; not a passing
  production integration test.
- **Missing software:** a required mechanism or acceptance fixture is absent.
- **Unverified:** required boundary has not been independently executed here.
- **Historical:** prior revision evidence/claims, recoverable from Git; not current
  acceptance. Reproduction assertions proving a bug are not acceptance passes.

## Fresh planning baseline

Checkout was clean on `master`, equal to `origin/master`, before documentation
work. Linux, existing `.venv`, Python **3.13.5**, Node **22.23.3**, npm **10.9.9**.
No disposable PostgreSQL admin configured; no user-approved live PVE/templates,
installed systemd/auditd fixture, packet or deployed-browser acceptance performed.

Executed in the repository root:

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Exit **1**: **9 failed, 107 passed, 115 skipped, 1 deselected, 4 warnings**,
**61.13s**. Default pytest selection excludes browser/live. DB cases mostly skip;
an unmarked case leaks a DB requirement. This is not DB, real SSH, installed
capture, privileged packet, browser or R740 acceptance.

| Failing test | Interpretation to investigate, not assumed vulnerability |
|---|---|
| `tests/test_fifth_followup_acceptance.py::test_f1_same_uid_escape_to_parent_cgroup_is_impossible` | Namespace-local child PID / changed leader-exit behavior; retain no-escape invariant |
| `tests/test_fifth_followup_acceptance.py::test_f1_nested_membership_is_running_not_gone` | Nested-survivor premise must match protected namespaces and actual host identities |
| `tests/test_fifth_followup_acceptance.py::test_f1_unreadable_membership_is_unknown_not_gone` | Current leader exit can remove the survivor; establish real live-authority failure before asserting unknown |
| `tests/test_fourth_followup_containment.py::test_t04_cleared_env_descendant_is_visible_and_contained` | Observe host identities and valid survivor conditions under new PID namespace |
| `tests/test_fourth_followup_containment.py::test_t04_normal_zero_exit_with_survivor_is_contained_not_blind` | Namespace PID 1 exit may terminate children; verify cessation, not an obsolete note alone |
| `tests/test_fourth_followup_containment.py::test_t04_failed_normal_exit_is_also_gated_on_containment` | Same issue for nonzero completion; preserve truthful exit and cessation |
| `tests/test_fourth_followup_containment.py::test_t04_unreachable_supervisor_at_completion_is_unknown` | Ensure test actually reaches an unresolved control boundary |
| `tests/test_third_followup_lifecycle.py::test_t01_descendant_survives_leader_exit_status_still_sees_it` | Legacy survivor expectation needs safe current-mechanism fixture |
| `tests/test_followup_regressions.py::test_r04_release_invalidates_previously_valid_evidence` | Unmarked DB dependence; PostgreSQL unavailable, not proof invalidation itself is broken |

Do not weaken containment to satisfy the eight old process assumptions. Fix tests
to independently observe real process identities and safety outcomes; if genuine
production defects emerge, repair them with negative-path regressions. Baseline
failure investigation belongs in milestone 01; full authority acceptance in 02.

Executed from `web/`:

```bash
npm audit --package-lock-only --json
```

Exit **1**: **4 affected packages, 3 critical / 1 high**: Next, PostCSS, Seroval,
Solid. No upgrade performed. Pages Router/Linux deployment applicability must be
triaged advisory-by-advisory; package severity alone is not exploitability proof.
Patch applicable issues and validate build/replay/browser behavior in milestone 01;
do not use blind major-version `audit fix --force`.

No fresh `npm ci`/build, Docker boot, Packer build, DB migration/concurrency,
privileged packet, installed capture or browser result is claimed by this planning
pass. Exact baseline is also recorded in `AGENTS.md`.

### Documentation-only validation

At `23de4f4` with this pass's documentation changes, independently executed:

| Command / check | Result |
|---|---|
| `git diff --check` | Exit 0; no whitespace errors |
| `python3` inline Markdown validator (required documents, relative links, fences, milestone ordering and absence of detailed plans) | Exit 0; 7 Markdown files, 24 relative links, balanced fences, milestones 01–11 in order, no detailed plans |
| `python3` inline Git provenance/scope check using `git cat-file -e 23de4f4:<path>` for every deleted file | Exit 0; all 15 removed documents recoverable; changed/untracked files are documentation and the plans-directory marker only |

These checks validate the documentation consolidation, **not** any application
milestone. The application suite was not rerun after documentation-only edits;
its executed baseline above remains failing and explicitly revision-bound.

### Fresh milestone-01 planning rerun

At clean revision `7368782`, on the same Python 3.13.5 environment, the exact
no-admin pytest command above exited **1**: **10 failed, 106 passed, 115 skipped,
1 deselected, 4 warnings**, **61.76s**. All nine earlier failures remain. The
additional failure is
`tests/test_followup_regressions.py::test_r12_golden_image_calls_the_real_installer`:
the documentation consolidation removed the literal strings
`PREBUILT-TEMPLATE REQUIREMENT` / `VERIFIES readiness` asserted by that old test.
This is a documentation/test coupling regression introduced by the consolidation,
not evidence that the application provisioning code changed. Repair its assertion
without weakening the requirement for usable templates and enforced readiness.

The exact `web/` audit command above again exited **1**, four affected packages,
**three critical / one high**. Read-only prerequisite checks: `docker compose
version` exited 0 (5.6.0); `docker info --format '{{.ServerVersion}}'` exited 0
(29.8.2). DB admin variables remain unset; `psql`, `playwright-cli`, and `nft` are
not on PATH. No Docker resources, DB schema, browser service, live range or host
firewall were created/mutated by these checks. These results supersede assumptions
about Docker availability, not the outstanding acceptance gates.

## Milestone 01 implementation evidence (2026-10-08)

Executed at clean revision **`ac5a61b`** (branch `happy-chipmunk`) on this
developer host: Python **3.13.5** (uv-created pip-less `.venv` from
`requirements.lock`), Node **22.23.3**, npm **10.9.9**, Docker daemon 29.8.2 /
Compose 5.6.0, cgroup v2 with a writable delegated subtree. No Proxmox, live
range, host firewall or unrelated-VM access; all fixtures run-owned.

| Gate (exact command) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **97 passed, 0 failed, 0 skipped, 139 deselected**, 4 warnings, 14.4s — infrastructure-free default |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**: 236 tests = 97 fast + 139 integration (db 113, containment 25, packet 4, browser 1, live 0 until milestone 11); required modes verified to fail for absent prerequisite, skipped required test and empty selection |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS**: fresh run-owned venv, locked install without re-resolve, dependency check clean, 4 entrypoint imports on Python 3.13.5 (CI matrix covers 3.11–3.13) |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**: disposable `postgres:16` (unique container/volume, loopback port, synthetic creds) — **113 passed, 0 skipped**, 123 deselected in required mode; fresh chain, populated pre-0010 forward upgrade, grants and append-only regressions; no `srtest_*`/`sr_*` leftovers; container+volume removed |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**: 21 namespace/recursive-membership/cancellation regressions in required mode, 0 skipped; no run-owned cgroups leaked (4 db∩containment compound tests run inside the db gate) |
| `.venv/bin/python infra/dev/acceptance.py packet` | **FAIL here (prerequisite)**: missing root + `nft` — this host is not the approved privileged fixture; CI packet job (standard Linux VM, nftables, rules only in disposable netns) is the gate |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**: `npm ci`, production `next build` (Next **16.4.0**, Pages Router, React **18.3.1**), `npm audit --omit=dev` → **0 vulnerabilities** (baseline was 3 critical/1 high across Next/PostCSS/Seroval/Solid; all were Next-14 transitive and are gone; no lower-severity findings remain to triage) |
| `.venv/bin/python infra/dev/acceptance.py compose` | **PASS**: real image build, fresh bootstrap + idempotent rerun (run-owned project, loopback ports, synthetic passwords/keys) — alembic at `0010`, app-role-only API readiness, app-role schema access, bastion running behind the seed-keys gate; only run-owned resources removed |
| `.venv/bin/python infra/dev/acceptance.py browser` | **FAIL here (prerequisite)**: pinned CLI present but Chromium cannot launch (missing system libraries such as `libglib-2.0.so.0`; no root to install them) — CI browser job (`playwright install --with-deps`) is the gate; E2E now isolated (free/configurable ports, `.next-e2e` dist, run-owned session) and covers replay seek |

Genuine production defects found by the first real DB-layer execution and
repaired with their regressions kept: SQLAlchemy 2.1 `Row` attribute access in
token recovery (`.scalars()`), phase-only JSON trusted by the deploy/idempotent
resume paths (now requires current capability evidence, F3), and migration
0010's helper rejecting an Engine. The supervisor additionally treats a
concurrently-removed operation cgroup tree as confirmed cessation (kernel only
removes empty cgroups). No safety regression was deleted or weakened.

**Review fixes (2026-10-08, post-`ac5a61b` review — VERDICT: FIX, all 8 items):**
Python 3.11 rejected a backslash inside an f-string expression in
`srplatform/coach/aar.py` — rewritten compatibly; the full 3.11/3.12/3.13
matrix now passes `acceptance.py python`. The CI db job now also delegates a
cgroup v2 subtree (the layer includes four DB+containment worker-chain tests),
and delegation is proven by a migration positive control both in the CI step
and inside `acceptance.py containment` (a real process is migrated in and
observed there — ownership alone is not permission). The compose override now
uses `!override` to REPLACE base port mappings (verified via `compose config`),
and the gate holds the default ports 5432/8000/2222 for its whole run. The PG
fixture claims ownership before each create/start, surfaces cleanup failures,
is idempotent, and `acceptance.py db` now runs a failure-path probe (occupied
port → fails and strands nothing). The frontend audit gate fails closed on
error responses/unparsable/missing metadata, and the skip gate read the wrong
count key (`skip` vs pytest's `skipped`) — both fixed with harness unit
regressions (`tests/test_acceptance_harness.py`, 4 tests). Replay coverage now
proves a REAL seek: the player's own polled position (`data-now`) must reach
the clicked event's offset and the rendered frame content must change to match
(bracketing frames at 1s/3600s). Compose verification now checks the exact
alembic head, DB-backed `/readyz`, the API's app-role-only credential env, and
authenticated account operations with idempotent rerun behavior (bootstrap
closed 403, duplicate member 409, login survives rerun).

Post-fix gate results at this revision: fast default **101 passed, 0 failed,
0 skipped, 139 deselected**; `selection` PASS (240 total); `python` PASS on
3.11.17/3.12.15/3.13.5; `db` PASS (failure-path probe + **113 passed,
0 skipped**); `containment` PASS (migration probe + 21 passed); `frontend`
PASS; `compose` PASS with default ports held (exact-head migrations,
credential split, `/readyz`, account ops, idempotent rerun, clean teardown).

**Round-3 review fixes (2026-10-08, post-`13daa88` review — VERDICT: FIX,
all 6 items):** the invalid top-level `x-delegate-cgroup` workflow key was
removed — the anchor now lives on a real step reused via alias, and a
structural workflow-schema test (`test_ci_workflow_is_schema_valid`) rejects
unknown top-level/job/step keys and nested step lists. CI now runs the db and
containment gates **inside** the delegated subtree via
`infra/dev/run_in_cgroup.sh`: root performs the single privileged migration
into the subtree, verifies it took effect, then drops to the unprivileged
user — so source and destination of every test migration are user-owned
(the old step only chowned the destination, which the kernel refuses to
migrate out of). The PG fixture now REFUSES pre-existing container/volume
names (collision = not ours, never removed), claims ownership only after a
name is verified free, and wraps the entire startup in exception-safe
cleanup so timeouts (`TimeoutExpired`) as well as nonzero exits strand
nothing; covered by fault-injected unit tests and a real-docker collision
probe in `acceptance.py db`. The audit evaluator additionally requires the
complete nonnegative-integer severity map and a consistent exit status
(0↔zero findings, 1↔findings; anything else fails). The compose gate now
provisions the stack's bastion token into `service_tokens` and verifies a
scoped target-resolution call authenticates with it (404 authenticated vs
401/403 refused) before AND after the idempotent rerun.

Round-3 gate results: fast default **106 passed, 0 failed, 0 skipped,
139 deselected** (245 total); `selection`, `frontend`, `containment` PASS;
`db` PASS with failure-path + collision probes; `compose` PASS with bastion
capability verified on both attempts.

**Round-4 review fixes (2026-10-08, post-`8ba0764` review — VERDICT: FIX,
all 3 items):** CI delegation now chowns the subtree's **control files**
(`cgroup.procs`), not just the directory — the kernel requires the delegatee
to write `cgroup.procs` for any migration — and `run_in_cgroup.sh` is
self-verifying end to end: after dropping privileges it runs an
**unprivileged migration probe** (create child cgroup, migrate a real
process in, observe, kill+wait, rmdir with retry) and fails before the gate
if any permission in the chain is wrong; the containment gate now runs that
same dropped-phase probe against the real subtree (full wrapper path, not
just `bash -n`), plus fast failure-path tests. The PG fixture distinguishes
inspection **errors** from absence (a daemon error is never a free name),
creates every resource with a run-unique `sr-range-run` **ownership nonce**,
and re-verifies that nonce before any deletion — a raced collision is left
in place and surfaced, never deleted; covered by fault-injected race/error
tests. The collision probe now tracks exactly which resources it created,
verifies its own nonce before removing them, and fails acceptance when its
teardown does not complete.

Round-4 gate results: fast default **111 passed, 0 failed, 0 skipped,
139 deselected** (250 total); `selection`, `containment` (incl. wrapper
dropped-phase probe) PASS; `db` PASS with failure-path + collision probes
(nonce-verified teardown).

**Round-5 review fixes (2026-10-08, post-`b97cfa9` review — VERDICT: FIX,
both items):** `docker volume create` succeeds for an already-existing
volume and keeps its FOREIGN label (re-verified against real Docker here),
so the fixture now verifies its ownership nonce landed **immediately after
creation and before the volume is mounted** into postgres — a raced foreign
volume is refused, never mounted, never removed. `cleanup()` no longer
clears its tracking flags on failure: identity-inspection errors, failed
removals, and foreign-nonce resources RETAIN the claim so every subsequent
`cleanup()` retries and re-reports until the resource is confirmed removed
or absent (only then is the obligation cleared). Regressions: raced-volume
(never mounted, never removed, obligation retained), retained-retry for
foreign containers and unconfirmable identity, and resolution-clears-claim
transitions.

Round-5 gate results: fast default **112 passed, 0 failed, 0 skipped,
139 deselected**; `db` PASS against real Docker (post-create nonce check on
the happy path, failure-path + collision probes, 113 passed required mode).

**Round-6 review fix (2026-10-08, post-`cf98a67` review — VERDICT: FIX,
the item):** the t03 discovery test replaced global `pathlib.Path` with a
lambda, which crashes Python 3.11 (`Path._flavour` INTERNALERROR, reproduced
on 3.11.17 before the fix). The direct `/sys` bridge-port read is now a named
module seam (`_local_bridge_ports` in `srplatform/safety/firewall.py`), and
the test doubles THAT — same trap semantics (a same-named local bridge must
never be consulted while an execution prefix is configured), no global class
replacement. Round-6 gate results: fast suite **112 passed** on 3.11.17,
3.12.15 and 3.13.5 (fresh locked venvs, mirroring the CI matrix); `python`
matrix gate PASS on all three; `selection` PASS; `containment` PASS (21
passed, wrapper probe included).

**First CI run (run 37832124220 at `beae969`) — failures and fixes
(2026-10-08):** selection/frontend/compose green; five distinct causes
behind the rest.
1. `python` matrix (all 3): the gate demanded a `uv` or bare `3.12` binary;
   GH runners have neither. `_interpreter_for` now accepts the RUNNING
   interpreter when it matches the spec — the matrix job's venv already IS
   the fresh run-owned locked install on that version.
2. `containment` (15 failures) + 2 `db` worker-chain failures: the
   supervisor's trusted boundary needs `unshare --user`, which Ubuntu
   24.04+ (GitHub runner images) restricts via AppArmor
   (`apparmor_restrict_unprivileged_userns`); the supervisor correctly
   refused every start (exit 4). The workflow now loads Ubuntu's documented
   SCOPED profile granting `userns` to exactly `/usr/bin/unshare` on the
   disposable runner (never the global sysctl switch), and the containment
   gate gained a boundary pre-probe that names this prerequisite instead of
   failing 15 tests on "command never started".
3. `browser`: Next 16 resolves `distDir` RELATIVE to the project and
   silently treats an absolute path as relative (built into
   `web/home/dev/...`, rc 0), so the baked-URL marker had no directory.
   The fixture now hands next a relative distDir (verified locally: build +
   `next start` serve from `.next-e2e`).
4. `db` hint-jump test: its cross-process client stripped the environment
   to `PATH=/usr/bin:/bin`, dropping `LD_LIBRARY_PATH`, which GitHub's
   hostedtoolcache python needs (its own workflow env exports it) — the
   child died before posting. `_minimal_python_env()` keeps the minimal
   surface but forwards loader variables.
5. Harness diagnostics: the first CI run showed failing test NAMES with no
   reasons (tracebacks above the 1500-char failure tail). Layer runs use
   `--tb=line` and the failure tail grew to 6000 chars.
Still open for the next CI run (tracebacks were invisible): the m2 bastion
and r06 packet failures — both green locally, but neither has ever passed
in CI, so treat them as unresolved until the one-line tracebacks name the
cause.
Round of fixes verified locally: fast default **113 passed** (new
interpreter-resolution regression), `selection`, `db` (113), `containment`
(boundary probe + 21), `python` gate in CI-matrix shape (current-interpreter
match) all PASS.

**Second CI run (run 37835631215 at `7de03cb`) — failures and fixes
(2026-10-08):** python matrix/selection/frontend/compose green and the m2
bastion test passed; four jobs red, three distinct causes — the new
`--tb=line` tails named them.
1. `containment` (12 failures) + `db` (2, "the remote job never started"):
   the scoped profile was `flags=(unconfined)` + `userns,`. That permits
   userns creation (the pre-probe passed), but Ubuntu's kernel treats a
   profile in the *unconfined state* as an unconfined creator and
   transitions it into the restrictive `unprivileged_userns` profile,
   whose `deny capability` then fails the boundary's two inner mounts
   (cgroup2 remount, tmpfs state mask) — exit 96. The workflow now loads a
   REAL confined profile (upstream apparmor's `bwrap-userns-restrict`
   pattern: explicit `allow capability/file/mount/umount/userns/...`;
   exec'd children inherit it), and both the workflow probe and the
   containment gate pre-probe exercise the FULL boundary including those
   mounts. A harness regression pins the profile shape.
2. `packet` (r06, "emergency must sever intra-range traffic"): R1↔R2
   traffic is BRIDGED, and the inet forward hook only sees bridged frames
   when `br_netfilter` is loaded — true on the dev host, false on the
   runner. The test declared `range_bridge_ports=""`, so the bridge-family
   emergency drop matched only the master, which the bridge forward hook
   never shows (the render's own audit-R05 comment says so). The test now
   declares the real veth ports, exercising the production L2-sever
   mechanism independent of any host module.
3. `browser`: the distDir fix worked — built, served and driven by
   Chromium; login failed with "Failed to fetch": `app.py` snapshotted
   `get_settings()` at IMPORT for CORS, while the test sets
   `API_ALLOWED_ORIGINS` after import (and pytest collection imports the
   app module even earlier), so the run's ephemeral web origin was never
   allowed. The CORS middleware now resolves origins when the middleware
   stack is BUILT (app startup) — production behaviour unchanged (read
   once, at boot); verified: a preflight from the configured origin gets
   ACAO, any other origin does not.
Verified locally after the fixes: fast default **114 passed** (new
confined-profile regression), `db` gate PASS (113, real Docker),
`containment` gate PASS (mount-inclusive probe + 21). Packet and browser
remain CI-only gates.

**Third CI run (run 37841594922 at `2bc926a`) — packet GREEN; two causes
left (2026-10-08):**
1. `containment` + `db` died in the workflow probe itself: `unshare:
   failed to execute sh: Permission denied` (exit 126). The confined
   profile had NO execute grant: under `abi <abi/4.0>` (policy v6) the
   file `m` bit is mmap-exec, not execute — exec requires an `x` rule
   with a transition mode. Added `/** rix,` (exec, inherit profile), so
   unshare can exec sh/bash/mount/the command and every child stays in
   the profile (capability/mount remain available inside the namespace).
   The harness regression now pins the exec grant too.
2. `browser`: login worked (CORS fix confirmed); replay failed "player
   never mounted" — asciinema-player 3.17 is the Solid rewrite: it mounts
   as `.ap-player` with the text mirror in `<pre class="ap-term-text">`;
   the legacy `.asciinema-player` class no longer exists, so the test's
   selector could never match. Verified against the installed package:
   `create(src, elem, opts)` API matches the page, unknown opts are
   filtered (not rejected), the vt WASM is base64-inlined (no external
   asset). Test selectors updated to the real DOM.
Fast default after fixes: **114 passed**.

**Fourth CI run (run 37843120582 at `4ace51e`) — exec fixed; boundary
mount + replay seek fixed (2026-10-08):** the confined profile now loads
and execs (the round-3 EACCES is gone). Two causes remained.
1. `containment` + `db` (probe exit 32): `mount: /sys/fs/cgroup: cgroup2
   already mounted on /sys/fs/cgroup` — the mount(2) SYSCALL returned
   EBUSY. On 6.8-era kernels (Ubuntu 24.04) the kernfs superblock layer
   refuses to create/reuse a cgroup2 superblock from a non-init user
   namespace ("reusing existing filesystem in another namespace not
   allowed"); the per-userns kernfs rework that permits it landed later
   (works on this dev host's 7.0 kernel, which is why the boundary always
   passed locally). The supervisor's boundary therefore re-roots
   /sys/fs/cgroup by **BINDING the operation's own cgroup directory**
   (the standard container mechanism — no superblock creation, works on
   every kernel; verified locally that the bind hides the hierarchy above
   and keeps the op subtree writable). The workflow's full-boundary probe
   moved into the delegated-cgroup step (it needs a real bindable cgroup
   dir) and the containment gate's pre-probe binds a run-owned probe
   child under the delegated root.
2. `browser`: the player mounted (selectors fixed) but the timeline click
   never moved `data-now`. Root cause: the 3.17 driver SILENTLY DROPS a
   seek issued while still loading, and the page swallowed load errors.
   The page now surfaces player errors (`data-player-error`) and the
   loaded duration (`data-duration`); the test waits for load, fails
   loudly on player errors, and REISSUES the seek click until the
   player's own reported position moves.
Verified locally after the fixes: fast default **114 passed**, `db` gate
PASS (113), `containment` gate PASS (bind-based probe + 21), web build
OK.

**Fifth CI run (run 37845728116 at `271e6f6`) — replay never loaded
(2026-10-08):** only `browser-e2e` red: "asciinema-player never loaded
the recording (duration stayed empty)", no player error. Instrumented
the page (unhandled-rejection trap, lifecycle-event trace
`data-player-events`, both surfaced as attributes + in the test's
failure message) and root-caused the rest against the REAL library
driver in Node: asciinema-player 3.17 made loading LAZY — `INIT_REQUESTED`
in COLD does nothing unless `preload` (or an npt poster) is set, so a
paused player never fetches the cast and `getDuration()` stays undefined.
The original single-click failure matches too: a seek issued before the
driver exists is queued behind the startup promise and silently
swallowed. Fix: `preload: true` in the page's create options (verified
in `CORE_OPTS`; Node repro: duration 3600 arrives post-init, seek lands,
metadata+seeked fire). With preload the duration wait also proves the
WASM vt came up (the driver only exists after terminalReady).

**Sixth CI run (run 37850316805 at `6841ace`) — browser-e2e GREEN;
two flakes (2026-10-08):** selection, python 3.11/3.12/3.13, frontend,
packet, containment and — for the first time — **`browser-e2e` all
passed**: the preload fix is confirmed in the runner's Chromium. Two
previously-green jobs turned red on a frontend-only diff:
1. `db`: m2 bastion "no input frames" — the two `conn.run` exec sessions
   each write their OWN output-only cast, and the test read `casts[0]`
   from `glob()`: filesystem order decided which cast was checked. Now
   every cast must have an opaque name + v2 header and the BOTH-
   directions assertion searches for the interactive cast (exec casts
   can never carry `i` frames, so this is equivalent, not weaker).
   Verified: `db` gate PASS locally (113).
2. `compose`: "member account creation through app-role API — 401"
   immediately after a successful login. No code path deletes or revokes
   WebToken rows between requests, FastAPI ≥0.106 commits dependency
   teardown before the response is sent, and the gate passes locally
   (both attempts, full stack). Unreproducible; the check discarded the
   response body, which would name the branch ("authentication required"
   vs "token expired or revoked" vs "bad token"). Bootstrap/users/login
   failures now include the body so a recurrence is classifiable.

**Milestone 01 implementation acceptance recorded (2026-10-08), superseded by
independent review below.** All locally
executable gates pass; packet and browser gates fail closed here for
missing prerequisites by design and were accepted through their required
CI jobs: run 37852029894 at `3539667` — selection, python 3.11/3.12/3.13,
frontend, compose, packet, db, containment and browser-e2e all green.

### Independent merged-work review (2026-10-08, `27e2624`)

**VERDICT: FIX.** Safe local results were rerun independently; hosted-only
results were read from GitHub job logs, not independently rerun on a privileged
machine. `3539667..27e2624` changes documentation only, so the hosted application
revision matches the reviewed application. No application code edited by review.

Findings (both P2; acceptance reopened rather than requirements weakened):

- **M01-R1 — browser build is shared, not run-owned.**
  `tests/test_stage5_browser_e2e.py:144–161` defaults to `web/.next-e2e`, reuses
  a build when its marker matches, and never removes the build. Two simultaneous
  runs use the same directory while baking different API URLs; one can overwrite
  the other run's build. `SR_E2E_DIST_DIR=.next` also permits overwriting a developer
  build. An inline mocked fixture probe invoked `web_app.__wrapped__` twice and
  observed `SR_NEXT_DIST_DIR=['.next-e2e', '.next-e2e']` (exit 0; no filesystem or
  real subprocess changes). Use a fresh run-owned build directory, reject unsafe
  path overrides, clean it on failure/success, and test preservation/concurrent
  isolation. This is approved step 8 / criterion 9, not new product scope.
- **M01-R2 — historical migration edited for a test-only calling convention.**
  `srplatform/db/migrations/versions/0010_fifth_followup_enrollment.py:79–91`
  adds Engine handling. `git diff da13e72..27e2624 --` that path confirms the edit;
  `upgrade()` still passes a Connection and the SQL is unchanged. Approved step 4
  and the architecture explicitly prohibit editing applied migrations. Restore
  the historical migration and pass a transaction-bound Connection from the
  helper test at `tests/test_fifth_followup_acceptance.py:978,999`. If production
  migration behavior needs changing, use a new forward revision instead.

Review environment: Linux, existing Python 3.13.5 `.venv`, Node 22.23.3;
Docker fixtures synthetic/run-owned, existing delegated cgroup only, no sudo,
host firewall, Proxmox or unrelated-VM changes. Commands from checkout root:

| Exact command | Independent result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0; 114 passed, 0 failed/skipped, 139 deselected, 4 warnings; 16.63s |
| `.venv/bin/python infra/dev/acceptance.py selection` | Exit 0; 253 classified, 114 fast/139 integration; negative prerequisite/skip/empty controls passed; 35.4s |
| `env SR_ACCEPTANCE_PYTHONS=3.11,3.12,3.13 .venv/bin/python infra/dev/acceptance.py python` | Exit 0; fresh locked installs, dependency checks and four imports each on 3.11.17/3.12.15/3.13.5; 13.1s |
| `.venv/bin/python infra/dev/acceptance.py db` | Exit 0; 113 passed, 0 skipped, 140 deselected; failure/collision probes and owned cleanup passed; 102.4s |
| `.venv/bin/python infra/dev/acceptance.py containment` | Exit 0; full boundary/migration/wrapper probes, 21 passed, 0 skipped, 232 deselected; cleanup passed; 11.2s |
| `.venv/bin/python infra/dev/acceptance.py frontend` | Exit 0; npm ci/build and production audit passed, zero findings; 11.0s |
| `.venv/bin/python infra/dev/acceptance.py compose` | Exit 0; fresh build, two bootstrap attempts, exact 0010 head, DB-backed readiness, app-role account/bastion checks, owned cleanup; 41.1s |
| `.venv/bin/python infra/dev/acceptance.py packet` | Exit 1; required prerequisites root/nft missing, no packet test executed locally |
| `.venv/bin/python infra/dev/acceptance.py browser` | Exit 1; initial attempt overlapped npm ci and saw CLI missing; rerun after install: Chromium launch prerequisite unavailable, 1 setup error, no browser test passed locally; owned DB cleaned |
| `gh run view 37852029894 --json conclusion,headSha,jobs,url,headBranch` | Exit 0; success, happy-chipmunk at 3539667, all ten jobs succeeded |
| `gh run view 37852029894 --log \| grep -E 'counts \|passed\|skipped\|acceptance:\|: PASS\|\[PASS\]\|\[FAIL\]'` | Exit 0; logs confirm packet 4 passed/249 deselected, browser 1 passed/0 skipped, Python matrix fast suite 114 passed each, and all acceptance commands executed |

Hosted evidence: [run 37852029894](https://github.com/DrSchnitzel57/sparring-range/actions/runs/37852029894).
Green command results remain valid, but do not prove run-owned build isolation or
waive migration immutability. Close M01-R1/R2 and rerun affected gates before
marking milestone 01 accepted. Billing protection remains an operator manual check.

**CI follow-up after user reported another failure (2026-10-08):**
`gh run list --workflow ci --limit 12 --json databaseId,headSha,headBranch,conclusion,status,createdAt,url,displayTitle`
and `gh run view 37852794770 --log-failed` (both exit 0) confirm
[happy-chipmunk run 37852794770](https://github.com/DrSchnitzel57/sparring-range/actions/runs/37852794770)
failed browser E2E at `27e2624`: `tests/test_stage5_browser_e2e.py:296`,
`assert 'command' in recent`, **1 failed**, 2 warnings, 50.05s.
`gh run view 37852833914 --json conclusion,jobs,url,headSha` (exit 0) confirms
[master run 37852833914](https://github.com/DrSchnitzel57/sparring-range/actions/runs/37852833914)
passed all ten jobs at the SAME commit. These are mixed results, not proof the
intermittent failure is repaired. They supersede any impression of consistently
green acceptance; the user's abbreviated email reference was not identified.

- **M01-R3 / P2 — command assertion does not wait for the command.**
  `tests/test_stage5_browser_e2e.py:293–296` waits for `web01`, already present
  in connection instructions, then immediately asserts `command` before the
  two-second dashboard poll is guaranteed to complete. This is consistent with
  the observed pass/fail at the same revision. Wait with a bounded deadline for
  the newly ingested command event itself, retaining the UI-rendering assertion;
  investigate further if it never appears. Rerun affected browser acceptance and
  check repeat-run stability; do not merely rerun until green or suppress failure.
  This repair falls within the existing browser-fixture step/criterion, not a
  new milestone or permission to change application behavior without evidence.

### M01-R1/R2/R3 repair round (2026-10-08)

- **R2 repaired:** migration `0010_fifth_followup_enrollment.py` restored
  byte-identical to `da13e72` (`git diff da13e72 -- <path>` empty); the helper
  test now passes the transaction-bound Connection (`s.connection()`) at both
  call sites instead of the Engine. `db` gate PASS (113 passed, 0 skipped,
  owned cleanup). No applied migration is edited.
- **R1 repaired:** the `web_app` fixture builds into a FRESH unique directory
  per call under `web/.e2e-builds/` (marker reuse removed), rejects unsafe
  `SR_E2E_DIST_DIR` targets (absolute, `..`, `.next`, `.next-e2e`,
  `node_modules`, project dirs), and removes the run dir on success AND on
  build/serve failure. 14 new fast isolation regressions
  (`tests/test_browser_fixture_isolation.py`): per-call uniqueness, override
  rejection, fresh relative build + teardown cleanup, concurrent-run
  isolation, failure cleanup — mocked npm/next/httpx against a temp WEB, so
  they run in the fast default (now **128 passed**, selection gate PASS).
- **R3 repaired:** the dashboard assertion waits with a bounded deadline for
  the ingested event itself (`_body_has(pw, "command", timeout=20)`);
  verified `command` appears on the session page ONLY as an event
  `action_type` cell (no static text can satisfy the wait early).

Re-accepted 2026-10-08: CI run 37855269245 at `62939f7` passed all ten jobs on
the initial attempt and again on the repeat-run stability check (attempt 2,
browser-e2e included); db/selection/fast gates rerun locally at the repair
revision (113 / PASS / 128 passed).

- **M01-R4 / P2 — intermittent db-layer auth-handoff failure (RESOLVED
  2026-10-09 — root cause and repair under "Milestone 02 implementation
  evidence").**
  Docs-only commit `9a12374` turned CI `db` red:
  `test_stage5_acceptance.py::test_hint_jumps_queued_red_turns_across_processes`
  line 144 `KeyError: 'session_id'` — the POST /sessions response carried no
  session_id, i.e. an error body the test discarded. Same signature as the
  earlier compose "member creation — 401" one-off: the request immediately
  after a successful login intermittently fails, and neither failure
  captured the response. Repairs at this revision: the stage-5 handoff calls
  now go through `_api_json` (status+body in the failure message), and every
  uvicorn readiness loop that silently proceeded on `server.started == False`
  now asserts (a failed port bind names itself instead of poisoning
  downstream requests). Local fast (128) and db gate (113) PASS. Unclassified
  until the next occurrence names the branch (401 vs 5xx vs wrong-server);
  milestone 01 acceptance rests on the twice-green `62939f7` runs, and this
  finding stays open until classified.

### Milestone-02 planning baseline and prerequisite (2026-10-09)

Clean `master` at **`9393a36`**, equal to locally recorded `origin/master` before
documentation edits. Executed:

- `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider`
  — exit 0, **128 passed, 0 failed/skipped, 139 deselected, 4 warnings**, 15.09s.
  This is infrastructure-free, not DB or live authority acceptance.
- `gh run list --limit 4 --json databaseId,headSha,status,conclusion,url`
  — exit 0; run **37858626650** succeeded at `9393a36`, but the later
  **37860676959** failed at the same revision.
- `gh run view 37860676959 --json jobs --jq '.jobs[] | {name,conclusion}'`
  — exit 0; DB failed, all other nine jobs succeeded.
- `gh run view 37860676959 --log-failed` — exit 0; hosted DB suite:
  **2 failed, 111 passed, 154 deselected, 3 warnings**, 104.83s; owned fixture
  container/volume cleanup passed. Failure gate exited 1.

Failures inspected, not yet diagnosed:
`tests/test_followup_regressions.py:1373` assumes login JSON contains `token`
without checking status/body (`KeyError: 'token'`);
`tests/test_stage5_acceptance.py:162` receives HTTP 404 launching a session just
created successfully. Shared state/server/DB lifetime is an investigation target,
not an established cause. Neither a green rerun nor added diagnostics fixes this.
M01-R4 remains open; the approved milestone-02 plan requires repair/regression and
repeat affected acceptance before authority implementation. No software/live
deployment acceptance is claimed by saving that plan.

## Milestone 02 implementation evidence (2026-10-09)

Executed at code revision **`71507bb`** (branch `quick-dingo`; the follow-up
docs commit **`bab084f`** touches only the four `docs/` files — `git diff
71507bb..bab084f --name-only` lists nothing else — so the exercised code is
identical). Full sweep environment: Python **3.13.5** (uv-created pip-less
`.venv` from `requirements.lock`), Node **22.23.3**, npm **10.9.9**, Docker
daemon 29.8.2 / Compose 5.6.0, cgroup v2 with a writable delegated subtree.
Re-anchored at **`bab084f`** on 2026-10-12: fast default **131 passed,
0 skipped, 164 deselected**, `selection` PASS, `authority` PASS (22 passed).
No Proxmox, live
range, host firewall, NAS or unrelated-VM access; every fixture is run-owned.

**M01-R4 prerequisite resolved (`a87e83b`).** Root cause classified: FastAPI
≥ 0.142 finalizes default-scope (`"request"`) generator dependencies **after**
the response is sent, so each request's `DbSession` commit could land after
the client's next request had already begun — exactly the intermittent
r02/stage5/M01-R4/compose signatures (login succeeded, the immediately
following request saw uncommitted state). Repair: one shared `DbSession`
dependency pinned to `scope="function"`, so commit/close complete before the
response; plus `_api_json`/`api_json` helpers that surface status+body on
unexpected responses, and commit-visibility regressions. No test was weakened,
no retry-until-green, no applied migration edited.

| Gate (exact command) | Result |
|---|---|
| `.venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **131 passed, 0 failed, 0 skipped, 164 deselected** — infrastructure-free default |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**: 295 tests = 131 fast + 164 integration (db 117, containment 25, packet 4, **authority 22**, browser 1, live 0 until milestone 11); required modes verified to fail for absent prerequisite, skipped required test and empty selection |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS**: fresh run-owned venv, locked install without re-resolve, `uv pip check` clean, 4 entrypoint imports on Python 3.13.5 (CI matrix covers 3.11–3.13) |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**: disposable `postgres:16` (unique container/volume, loopback port, synthetic creds) — **116 passed, 0 skipped, 179 deselected** in required mode; includes the 0011 upgrade-latch pair (non-torn-down deployments latch `safety_state`; downgrade never unlatches) and writer/terminal-row races; failure-path probe passes; no `srtest_*`/`sr_*` leftovers; container+volume removed |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**: 21 namespace/recursive-membership/signal-identity/cancellation regressions in required mode, 0 skipped; no run-owned cgroups leaked (4 db∩containment compound tests run inside the db gate) |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS** (new required gate): **22 passed, 0 skipped** — real operator policy validation, durable SQLite intent-before-effect, restart-with-active-claims latch+stop, lease expiry, cross-session/generation fencing, hard-stop read-back and SPARE-on-foreign-VMID, obligations retention across broker/PVE faults, and mutual-TLS/auth negatives against a live broker over loopback (TLS 1.3 refusal, no client cert, wrong CA all refused) |
| `.venv/bin/python infra/dev/acceptance.py packet` | **FAIL here (prerequisite)**: missing root + `nft` — CI packet job (standard Linux VM, rules only in disposable netns) is the gate |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**: `npm ci`, production `next build`, `npm audit --omit=dev` → **0 vulnerabilities** |
| `.venv/bin/python infra/dev/acceptance.py compose` | **PASS**: real image build + fresh bootstrap + idempotent rerun (run-owned project, loopback ports, synthetic creds) — alembic at head **0011**, API holds app-role credentials only, `/readyz` at schema head, account ops idempotent, bastion behind the seed-keys gate; fixture mode is explicit env (`ALLOW_LOCAL_DEV_FIXTURE` + `SR_BROKER_FIXTURE`), no production bypass; only run-owned resources removed |
| `.venv/bin/python infra/dev/acceptance.py browser` | **FAIL here (prerequisite)**: no launchable Chromium on this host (per operator instruction nothing was installed) — CI browser job (`playwright install --with-deps`) is the gate |

Boundary actually exercised: the authority gate runs the real broker service
(policy, ledger, mTLS server, cessation supervisor) in-process over loopback
against synthetic PVE fixtures — private deterministic boundary, fail-closed
cessation and durability semantics, not live Proxmox. Live ACL/isolation/stop
proofs remain explicit operator gates (Manual checks in the plan).

**Required CI at the implementation revision:** GREEN —
[run 38264738484](https://github.com/DrSchnitzel57/sparring-range/actions/runs/38264738484)
at `e6a1d4d` (branch `quick-dingo`, 2026-10-12), conclusion `success`. All
eleven jobs `success`: selection, authority, frontend, packet, containment,
python (3.11), db, python (3.13), compose, python (3.12), browser-e2e. The
CI-only packet and browser gates pass on the hosted runners, covering the two
prerequisites this host cannot provide. Operator/live gates (real PVE ACL
denials, VLAN/isolation proofs, identity/stop evidence, $0 budget check) remain
explicitly open — software acceptance only.

## Release blockers and missing work

### Paired milestone-03/04 planning baseline (2026-10-12)

Clean `master` at `cbaa3a0`, equal to locally recorded `origin/master`; no
unpushed commits. Approved paired scope and separate acceptance gates:
`.openchamber/plans/03-04-linux-guests-capture.md`.

Executed from checkout root:

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Exit **0**: **131 passed, 0 failed/skipped, 164 deselected, 4 warnings**,
**14.80s**, existing Python 3.13 venv. This is only the infrastructure-free
planning baseline. No new image, installed capture, database integration,
QEMU/CI or live PVE acceptance was executed during planning.

Inspected: `infra/images/golden-linux.pkr.hcl` remains invalid/incomplete;
the golden script installs capture but no scenario services; DB YAML has
placeholder user/hash baselines; deployment requests linked clones and weakly
checks bridge placement; broker clone path does not enforce declared resource
budgets; installed shipper uses `tail -n 0`, losing unread input on restart.
These are paired-plan work, not accepted behaviors or proof of live exploits.
The current published PVE API describes `/agent/file-read` and scoped
`VM.GuestAgent.FileRead`; actual installed-version/ACL support stays unverified.
User explicitly deferred storage selection and all live-lab testing.

| ID / priority | Current finding and evidence boundary | Milestone |
|---|---|---|
| B01 / P1 | **Repaired at `ac5a61b`, CI-accepted (see milestone-01 evidence):** baseline failures fixed on real host identities; DB marker leakage structurally prevented (fixture-closure derivation) | 01 |
| B02 / P1 | **Repaired at `ac5a61b`:** Next 16.4.0 + patched transitive deps; `npm audit --omit=dev` reports 0 vulnerabilities; build/replay/browser validated | 01 |
| B03 / P0 | Inspected API still constructs direct PVE adapter; current safety controller invokes privileged nft machinery. Incompatible with agreed private limited-token/no-runtime-host-root boundary | 02 |
| B04 / P0 | Current namespace/cgroup regression gate passes locally and in CI; full production authority, missing/unreadable control, bookkeeping, start/cancel fencing and every signal identity still require milestone-02 boundary/race acceptance | 02 |
| B05 / P0 | Run-row locking, guarded writers and any-run obligations exist. DB races and every writer/caller (spawn, callback, stop, watchdog, startup, emergency) remain unverified here; never rely on helper docstrings saying every writer is covered | 02 |
| B06 / P0 | Exact effective PVE permissions, static bridged/routed isolation, resource budgets and independent owned-VM emergency stop are not accepted. No attacks before real gates; no permission widening to pass | 02, 11 |
| B07 / P1 | Current image artifacts do not establish usable web/database templates. Service-present checks are not actual transactions; YAML has placeholder integrity/user baselines and seed contracts need completion | 03 |
| B08 / P1 | Enrollment now carries exact capability/generation evidence and migration 0010 invalidation logic. Fresh/legacy upgrades, stale-token rejection, recovery and concurrent confirms require disposable DB acceptance | 04 |
| B09 / P1 | **Missing software:** `tests/test_fifth_followup_installed_capture.py` and required installed-systemd/auditd acceptance. Subprocess synthetic stdin cannot prove `srshipper` reads real audit input or captures a real command | 04 |
| B10 / P1 | **CI passed at `3539667`:** dedicated required layers via `infra/dev/acceptance.py` fail closed for missing prerequisites/empty selections/skips. Review M01-R1 reopens browser-build isolation; installed-capture fixture still missing (milestone 04) | 01, 04 |
| B11 / P1 | SSH/recording/spool code exists; real pinned SSH, installed identity, input/API/token negatives, shared durable storage, delivery gaps and transport-loss recovery remain unverified | 04, 11 |
| B12 / P1 | **Missing release behavior:** configuration snapshots for new controls, explicit timed Begin, ready-idle expiry, server clock, restart interruption and automatic post-evidence cleanup. Existing end keeps owned VMs/reservation pending separate teardown | 05 |
| B13 / P1 | **Missing release behavior:** continuous independent HTTP/MySQL probes, availability samples/rubric, distinct live component scores, scorer-health detector and outage interruption | 06 |
| B14 / P1 | **Missing release behavior:** timed inject catalogue/deadlines/submissions, deterministic task results and separate written feedback | 07–08 |
| B15 / P1 | Inspected red loop terminates at step budget/objective completion; sustained pacing, both explicit start modes and bounded retry-then-interrupt policy still needed | 08 |
| B16 / P1 | Shared API model gateway exists; actual Qwen alias/context/structured responses, capacity, outage recovery and coaching usefulness remain unverified. No embeddings needed | 08, 11 |
| B17 / P1 | Inspected live UI exposes red phase/objective progress. Competition spoiler policy must be enforced across all API/CLI/event/report/replay reads, not just hidden controls | 09 |
| B18 / P1 | Browser pages exist but not agreed session builder/service scoreboard/inject flow/recovery states. Same-origin LAN HTTPS/IP-SAN trust and visiting-client localhost assumptions need work | 09–10 |
| B19 / P1 | Production packaging, owner/runtime credential separation, storage-pressure readiness, indefinite evidence/explicit offline purge and consistent DB+recording backup/restore are not accepted | 10 |
| B20 / P1 | Real R740 clone/storage/ACL/isolation/stop, installed telemetry, model, restart/restore and unaided operator/member usefulness gates have not run | 11 |

Windows/Sysmon/WEC remains unfinished later work (milestone 12), not a disguised
first-release blocker or claimed implemented pipeline. More storage can be added;
capacity must be discovered, not used to silently remove agreed scope.

### Paired milestone-03/04 rework evidence (2026-10-13, in progress)

> **Reopened 2026-10-12 (review finding, no code changed by review):** the
> images/capture QEMU gates boot a synthetic boot sector, not the Ubuntu
> guests with installed services/auditd the paired plan requires. That is a
> software-validation gap, not deferred live testing: 03/04 software
> acceptance is redone here under a strengthened gate (real Ubuntu boots);
> CI run 38316796599 no longer counts for 03/04. Milestone-05 planning waits
> for the re-acceptance decision.

Plan adjustment (step 7, recorded here; the paired plan lives in OpenChamber
UI): "boot actual artifacts in isolated QEMU" now explicitly means booting
assembled Ubuntu guest disks — pinned, checksum-verified noble base plus a
run-owned qcow2 overlay carrying the actually installed packages
(nginx/MySQL/auditd/shipper), payload, seeds, flaws and units — with a
NoCloud seed ISO, asserting live services/seeds/flaws/fixes/readiness
(images) and installed-capture negatives plus end-to-end delivery (capture)
over the serial console. The synthetic boot-sector helper is removed. Build-
phase package fetching uses pinned NAMES with guest-reported resolved
versions; verification boots run `-net none`. The overlay is a documented
superset build (role differences are config-level) so the 60-minute TCG job
budget holds. Also repaired en route: the installed shipper input is now a
durable persisted cursor (`--audit-log`), retiring the `tail -F -n 0`
restart loss the planning baseline flagged; the unit ExecStarts the artifact
directly.

> Superseded runs (kept for provenance; do NOT count as 03/04 acceptance
> after the reopening above): the first-round implementation ran on branch
> `warm-narwhal` from clean `master` `cbaa3a0`. No Proxmox, live
> range, host firewall, NAS or unrelated-VM access; every fixture was run-owned
> (synthetic keys/tokens, disposable Postgres, isolated QEMU run dirs).

Scope decisions (ambiguous points judged per plan intent, visible on review):
- Packer retired in place (`RETIRED` header; history preserved); the supported
  path is `python infra/images/build.py` from `infra/images/manifest.json`.
- Base-image SHA256 in the manifest is a pinned placeholder the builder treats
  as operator-verified at build time (refuses mismatch/absence); the builder
  itself never fetches (no network at build/test time).
- QEMU "boot" is a real isolated boot of a deterministically generated
  boot-sector artifact carrying the run's payload identity (SeaBIOS → COM1 →
  run-owned serial log), with full guest-payload verification via builder +
  service checks. A full Ubuntu-cloud boot stays an operator live gate (11).
- New tests that need Postgres are `images`/`capture` + `db` compound layers;
  the new gates start their own disposable `postgres:16` (like the db gate).
  Two FileRead/budget tests are additionally `authority`-marked (infra-free).

| Gate (exact command) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **131 passed, 0 failed/skipped, 187 deselected**, 4 warnings — infrastructure-free default unchanged |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**: 318 tests = 131 fast + 187 integration (db 122, containment 25, packet 4, authority 24, images 14, capture 9, browser 1, live 0); required-mode fail-closed controls pass |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS** (Python 3.13.5 fresh locked install; CI matrix covers 3.11–3.13) |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**: **121 passed, 0 skipped, 197 deselected** in required mode (`db and not browser`); owned cleanup verified |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS**: **24 passed** (22 prior + FileRead/budget identity), 0 skipped |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**: 21 passed, 0 skipped; no run-owned cgroups leaked |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**: `npm ci` + production build + `npm audit --omit=dev` 0 findings |
| `.venv/bin/python infra/dev/acceptance.py images` | **PASS here (2026-10-12, operator-installed QEMU 10.0.13)**: **14 passed, 0 skipped, 304 deselected** incl. the real isolated QEMU boot (TCG, `-net none`, run-owned disk/serial, owned cleanup); disposable-DB subset included; gate time 5.5s |
| `.venv/bin/python infra/dev/acceptance.py capture` | **PASS here (2026-10-12, QEMU 10.0.13)**: **9 passed, 0 skipped, 309 deselected** incl. the real isolated QEMU boot; disposable-DB subset included; gate time 6.8s |
| `.venv/bin/python infra/dev/acceptance.py packet` | **FAIL here (prerequisite)**: missing root + `nft` — CI packet job is the gate (unchanged) |
| `.venv/bin/python infra/dev/acceptance.py browser` | **FAIL here (prerequisite)**: no launchable Chromium — CI browser job is the gate (unchanged) |
| `.venv/bin/python infra/dev/acceptance.py compose` | Not rerun here (no application change to the compose path); last green per milestone-02 evidence |

Delivered (addresses B07–B11 as software, acceptance pending):
- `infra/images/manifest.json` + `packages-24.04.txt` + `README.md` (pinned
  noble URL/SHA256, packages incl. PyMySQL/auditd, 2vCPU/2GiB + 16/12/16GiB
  budgets, 64MiB spool / 32MiB cast); `infra/images/build.py` (deterministic,
  public-keys-only, scrubbed, manifest-hashed); `infra/images/specs.py`
  (canonical budgets/roles/aggregates/allowlisted host-key path).
- `infra/cloud-init/{attacker,mojang-web-local,mojang-web-db}.yaml`
  (defender+sudo, ufw/auditd/shipper/app services, empty pubkey slots).
- Guest payloads: local/MySQL catalogue app (`app.py`), diagnostic flaw +
  maintenance helper + `FIXES.md`, nginx unit, MySQL schema (SELECT-only
  reader) + 12-row seed SQL generated from `scenarios/mojang-seeds.json`
  (3 games, `buy-001`–`buy-012`, fictional).
- `scenarios/mojang-web-01.yaml` / `mojang-web-db-01.yaml` (fresh attacker at
  fixed 10.66.0.9, templates 9005/9011/9012, versioned seed/image baselines,
  `http_content`/`mysql_rows` logical checks, documented flaws/fixes);
  `verifiers/library/mojang.py` (`http_content`, `mysql_rows` SELECT-only);
  `SUPPORTED_SERVICES` += `mojang-web`; legacy scenarios preserved.
- Typed guest-agent FileRead: `ProxmoxClient.read_guest_file` (fixed path
  only) + `BrokerService.read_host_key` (owned VM/session/generation before
  AND after, bounded key parse, same-generation change refused with
  obligation, fresh-generation re-pin) + `CONTROL_OPS`/client surface; fake
  models `/agent/file-read` with fresh per-clone keys; no exec/host-shell
  surface (asserted).
- Orchestrator: explicit `deploy_clone_mode` setting (broker-validated, no
  fallback), aggregate budget reservation before side effects, host-key pins
  after each start, clone-mode recorded in deploy events; intents/conflicts/
  resume/reset/foreign-VM protection preserved.
- Capture: installed-unit/rules/installer assertions, spool replay/dedup/
  order/limits/gaps + crash/overflow/reboot, ENRICHED marker grouping,
  wrong-API/token/input negatives with recovery, stale/foreign/phase-only
  refusal + `/run` gate, concurrent-confirm idempotency + revocation binding,
  cast opaque-ID/symlink/size/missing/replay + TRUNCATED marker, no-logged-
  secrets + forgeable-telemetry contract note.
- `infra/dev/qemu_guest.py` (real isolated QEMU boot helper, bounds
  enforced, owned cleanup) + `images`/`capture` gates in
  `infra/dev/acceptance.py` (disposable PG + QEMU prereq + leftover checks) +
  `images`/`capture` CI jobs (QEMU install, userns profile, delegated cgroup,
  60-minute timeout) + `images`/`capture` markers (fast default excludes them).

**Required CI: GREEN** —
[run 38316796599](https://github.com/DrSchnitzel57/sparring-range/actions/runs/38316796599)
at `1fd74b4` (branch `warm-narwhal`, 2026-10-12), conclusion `success`. All
thirteen jobs `success` on the initial attempt: selection, python (3.11),
python (3.12), python (3.13), db, containment, authority, packet, frontend,
compose, browser-e2e, **images**, **capture**. The CI-only packet and browser
gates pass on the hosted runners, and the two new QEMU gates pass there with
apt-installed QEMU (TCG), the scoped userns profile, and the delegated cgroup
— matching the local QEMU-10.0.13 results above. Software acceptance is
complete; tick 03/04 in the roadmap. Live/operator gates (real PVE FileRead
ACL, clone/storage/NIC, isolation/stop, installed-capture on R740, $0 budget
check) remain explicitly open. The base-image SHA256 placeholder must be
replaced with the published noble SHA256SUMS value at operator build time.

## Historical finding coverage retained

The removed reports were at older revisions. The table preserves every finding
family and its requirement/test anchor without reusing its checkmarks. All rows
are **retest/preserve**, not newly accepted. Paths below are current code/test
anchors; detailed historical repros/results remain in Git and `audit/`.

| Historical IDs | Requirement to preserve / test anchor | Release work |
|---|---|---|
| F01, R01, N04 | Remote-only production execution; actual worker auth, minimal resolved env, no controller dotenv/secrets; `tests/test_stage3_telemetry.py`, `tests/test_followup_regressions.py` | 01–02 |
| F02, R03, N05, T01 | Durable operation IDs; local+remote acknowledged cessation, transport loss/crash/restart; `tests/test_stage2_safety.py`, `tests/test_third_followup_lifecycle.py` | 02 |
| F03, R05, N06, T03 | Actual range-scoped bridge/routed/IPv6/established denial, atomic safety, effective topology/policy, management preservation; firewall/netns regressions | 02, 11 |
| R04, N07 | Fail-closed latch/file+DB merge, persistence errors, no stale proof reuse; config identity/freshness/killswitch proof; safety regressions | 02 |
| F04 | Password auth, ownership, producer scopes, actor assignment, revocation; no forged verifier/score events | 02, 04, 09 |
| F05, R06, N01 | Correct PVE verbs/`newid`/UPID waiting, TLS; typed absence vs outage; no mutation without ownership; `tests/test_stage1_safety.py` | 02–03 |
| F06, R07–R08, N02–N03, T02 | Single reservation, intent-before-side-effect, idempotency, generation/ownership, fenced lifecycle/concurrency, uncertain cleanup retains lease | 02–05 |
| F07, R12 | Actual fresh Compose bootstrap, build secret exclusions, no runtime owner URL, real seed/volume wiring; `tests/test_stage5_bootstrap.py` | 01, 10 |
| F08, R02 | Real token→owner key binding, owned inventory and live SSH instructions, access revocation | 04, 09 |
| F09, R11, N08–N09, T05, T08 | Real audit assembly/source time/boot IDs, bounded synchronized crash-safe spool, installed identity/delivery/capture, automatic enrollment; telemetry/spool tests | 04 |
| F10, R09, N10 | Typed/quoted baseline-aware checks, expected polarity, unknown on errors, flag provenance, current owned pinned inventory, historical scores not live SSH to reused IPs | 03, 06 |
| F11 | API-only trusted scoring and finalize, immutable score snapshots; no CLI-submitted facts | 06 |
| F12, F18, R10 | Supported coach labels/citations, unscored ≠ failure, prioritized study; one actual cross-process scheduler, timeout/queue recovery | 08 |
| F13 | Ready/run/end outcomes distinguished from attacker achievement; production-role grants, idempotence, failure reporting | 05 |
| F14 | Ingest/event-ID cursor pagination, prior-summary carry-forward, logged action intent, no blind replay | 05, 08 |
| F15 | Strict nested tool schema, all objective truth independently verified, scenario phase/inventory; no model DONE awarded points | 08 |
| F16–F17 | Opaque UUID exclusive recordings, read/register path and symlink bounds, exec+resize capture; replay epoch/seek/multiple casts | 04, 09 |
| F19, N11, T04 | One strict immutable scenario snapshot drives deploy/reset/worker/score; versioned usable templates, no live YAML divergence | 03, 05 |
| F20 | Chronological per-domain/component history from trusted score snapshots, zero/unknown handling and actual browser workflow | 09 |
| F21 | Supported reproducible Linux image build, real seeded services/key installation; Windows deferred explicitly | 03, 12 |
| F22–F23, T07 | Safe explicit unique disposable DB fixtures, markers/CI/locks/readiness/packaging; bounded nonblocking byte reads and honest layers | 01, 02, 10 |
| Fifth F1 / P0 | Protected non-escapable bookkeeping/recursive authority, no failed reads treated empty; PID-namespace test premises must be repaired | 01–02 |
| Fifth F2 / P0 | Lock before fresh inventory after commits; registration vs every terminal writer; corrupt terminal row cannot hide obligations | 02 |
| Fifth F3–F4 / P1 | Legacy phase-only ready/run invalidated; exact capability+nonce+session+host+generation; idempotent concurrent confirmation | 04 |
| Fifth F5 / P1 | Kernel/stable-identity scoped signals; environment marker diagnostic only, scan-to-signal races/unrelated processes protected | 02 |
| Fifth F6 / P1 | Real installed systemd/auditd capture under `srshipper`; active-service bad API/token/unreadable-input negatives | 04 |
| Fifth F7 / P2 | Local-dev background children/operation rows resolved truthfully; runner health rejects unknown; never enable local-dev in production | 01–02 |
| Fifth F8 / P1 | Executable delegation and required containment/capture CI flags; missing prerequisites fail mandatory jobs | 01, 04 |

The fourth review's two blockers were authoritative completion/cessation and real
delivery/capture enrollment. The fifth review showed its completion report did not
prove them. The new namespace/migration repairs in `23de4f4` must be evaluated on
their merits; neither the prior failures nor report claims are blindly carried
forward as current defects/successes.

## Historical provenance and documentation consolidation

Recover removed tracked documents at the pre-cleanup application revision, e.g.:

```bash
git show 23de4f4:docs/plans/fifth-followup.md
git show 23de4f4:IMPLEMENTATION_AUDIT.md
```

| Historical source (removed from current tree) | Evidence revision / retained meaning |
|---|---|
| `plan.markdown` | Original M0–M7 contract; safety/API/evidence/replay/usefulness retained, new explicit release decisions supersede old GPU/LXC/grade assumptions |
| `IMPLEMENTATION_AUDIT.md`, `LOCAL_AGENT_HANDOFF.md` | `a5b19ab`, F01–F23 |
| `docs/FOLLOWUP_REVIEW.md`, `docs/FOLLOWUP_REMEDIATION.md` | `bd93f0d`, R01–R12 and subsequently corrected completion claims |
| `docs/SECOND_FOLLOWUP_{REVIEW,HANDOFF,COMPLETION_REPORT}.md` | `18377c6`, N01–N11; later addendum acknowledges incomplete original claims |
| `docs/THIRD_FOLLOWUP_{REVIEW,HANDOFF,COMPLETION_REPORT}.md` | `0b0d726`, T01–T08; later repairs/test anchors retained |
| `docs/FOURTH_FOLLOWUP_{REVIEW,COMPLETION_REPORT}.md` | `213246e` / `2357730`, two blockers and seven focused repair requirements |
| `docs/plans/fifth-followup.md` | Review at `2357730`, committed in `7c29c45`; F1–F8, production probes and stronger acceptance boundaries |
| `docs/ARCHITECTURE_NOTES.md` and old checklist/runbook/README | Consolidated into current architecture/roadmap/evidence/runbook; no old “all built” claim remains authoritative |

Prior fifth-review totals (including 206 passes with PostgreSQL 16) belong to
`2357730` and its environment, **not** this revision. Do not copy them as today's
result. Historical probe files/results in `audit/` are preserved, not deleted or
promoted to acceptance. Source/test comments and package metadata still naming
old docs are legacy references to reconcile in milestone 01 without changing
regression intentions; they cannot override `AGENTS.md` or the release design.

## Tomorrow-pilot implementation evidence (2026-10-13, plan 12-tomorrow-pilot)

Cross-cutting authorized exception plan (see `docs/ROADMAP.md` "Planning and
acceptance discipline"). It accepts NO milestone; everything below is pilot
evidence only. Branch `openchamber/tomorrow-pilot`, baseline `edb8df3`
(fast suite at baseline: 135 passed / 192 deselected). Implementation
commits `e789a8d..24f84ef` (8 commits). Environment: Python 3.13.5 venv;
Docker daemon 29.8.2 / Compose 5.6.0; QEMU 10.0.13 (TCG, 4-CPU/16G host,
one guest at a time); Node v22.23.3 + Playwright chromium-headless-shell
155.0.8059.12 (installed this session — the browser binary was the only
missing prerequisite); disposable PostgreSQL = run-owned container
`sr-acc-pg-52b3cf2b` on loopback `127.0.0.1:49003` (acceptance-harness
fixture image; superuser password reset in-container, no host DB touched).

### Fast suite (criterion 1) — PASS

`env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m pytest -q -ra -p no:cacheprovider` at `24f84ef`:
exit 0, **152 passed, 0 failed, 0 skipped, 206 deselected**, 17.2 s.

### DB layer + browser (criteria 3, 5, 6) — PASS

`env SR_PG_ADMIN_URL=<disposable> SR_REQUIRE_DB=1 PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m pytest -q -p no:cacheprovider -m db
--ignore=tests/test_stage5_browser_e2e.py`: exit 0, **135 passed, 0 failed,
222 deselected**, 144.8 s. The browser e2e (also db-classified) ran
separately with `SR_REQUIRE_BROWSER=1 -m browser`: **1 passed**, 43.2 s —
real chromium drives login → launch → API-served connections → ingest →
Begin (server clock + deadline) → sustained run stopped via UI → end
(destroy + release) → AAR. New pilot db tests: `tests/test_pilot_lifecycle.py`
(10: snapshot at creation, Begin idempotence/never-extends, idle expiry with
safe cleanup, deadline end, end destroys + frees range, failed destroy keeps
lease and retries, restart interrupts and never resumes, connections served
by API, worker-env snapshot values) and `tests/test_pilot_uptime.py` (2 db:
identity-bound samples through the real prober, append-only grants — app-role
UPDATE/DELETE raise `InsufficientPrivilege` — dashboard/end reporting).
Plan-authorized semantics change: END now destroys owned VMs and releases the
lease; the R07 invariant (a machine that still exists keeps the reservation)
is preserved and newly covered (`test_end_with_failed_destroy_keeps_lease_and_retries`,
updated `test_r07_*`).

### Sustained attacker + uptime (criteria 4, 5) — PASS (fast layer)

`tests/test_pilot_sustained_attacker.py` (9) and `tests/test_pilot_uptime.py`
(8 fast) pass within the suite above: loop runs to the SERVER deadline (not
20 steps / objective completion), per-action throttle is deadline-aware and
non-overlapping, DONE never ends a match, gateway retry policy 3 attempts
(5 s/15 s, 60 s timeout) then truthful interrupt; uptime math scores only
valid checks, zero-valid is unscored, staleness/coverage surfaced, and a
confirmed probe-infrastructure failure interrupts instead of fabricating
downtime.

### Attack chain on real boots (criterion 2) — PASS

`env SR_PG_ADMIN_URL=<disposable> PYTHONDONTWRITEBYTECODE=1
SR_REQUIRE_IMAGES=1 .venv/bin/python -m pytest -q -p no:cacheprovider
-m "images or db" tests/test_mojang_images_deploy.py` at the final
revision: **10 passed, 0 failed**, 393.8 s (warm overlay cache). Markers
proven on real Ubuntu 24.04 boots: `DIAG-FLAW` (genuine
`subprocess.run(shell=True)` as the web user over HTTP), `ROOT-FLAW`
(HTTP-driven plant → `sudo -n` helper → uid-0 proof file), `MAINT-HELPER`,
`MAINT-FIX` (revoke sudoers rule → chain dead, services active),
`DIAG-FIX-PASS` (endpoint disabled → 403, catalogue still serves), plus
MYSQL-READY/COUNT/ROW on the DB variant.

**Two real gate bugs found and fixed while chasing a "flaky MYSQL-COUNT":**
(1) `boot_full_guest` judged a NEW boot on the PREVIOUS boot's serial file:
two verify tests share one overlay + run dir, so both wrote
`guest.serial.log`; the poll loop saw the stale `DONE rc=0` before QEMU
opened the file and returned the old markers instantly (web-local's serial
has no MYSQL checks — hence "MYSQL-COUNT missing, no FAIL, DONE rc=0").
Fix: unique `serial_name` per boot + unlink before start. This is very
likely the pre-existing images-CI failure at `fe940fc`.
(2) The chain battery is state-mutating BY DESIGN (MAINT-FIX removes the
sudoers rule, DIAG-FIX disables the endpoint) and writes persist in the
overlay booted; a module-scoped shared overlay made the second verify boot
start already-fixed (flaw checks then correctly failed). Fix: fresh
overlay copy per verify test (cache copy+rebase, no extra boots).
Serial hardening (marker double-emit, `dmesg -n 1`, getty stop, always
preserve serials) is retained as defense in depth, but the initial
corruption theory was wrong — evidence over theory.

### Gates (criteria 7, 8) — PASS

`python infra/dev/acceptance.py frontend`: PASS 7.1 s (lockfile-faithful
`npm ci`, `next build`, `npm audit --omit=dev` zero findings — moderate=0
low=0). `python infra/dev/acceptance.py compose`: PASS 63.2 s — fresh
bootstrap + idempotent rerun, migrations at head **0013**, API runtime holds
app-role credentials only, bastion capability + running, run-owned project
fully cleaned.

### Template build (criterion 9) — PASS

`PYTHONDONTWRITEBYTECODE=1 .venv/bin/python infra/images/pve_template_build.py
--out /tmp/sr-templates --pubkey <ed25519.pub> --cache-dir /tmp/sr-guest-cache
--roles attacker,mojang-web-local`: exit 0. Base `noble-20261012`
(sha256 `6a81c375…5bb4d2`, verified against the published
cloud-images SHA256SUMS). Flattened standalone qcow2s verified (format qcow2,
no backing file, budgeted 16 GiB virtual, `qemu-img check` clean — the
initial `-r no` invocation was invalid and is fixed). FINAL artifacts —
rebuilt at the final revision with the OPERATOR's bastion public key
(`charl@lenovo`, SHA256 `fM6V/cZLUQny3u159PnxRowPIlM1Y6S94cJ7aXe9tOE`,
fingerprint confirmed against the operator's own keygen output) baked in:
attacker VMID 9005 sha256
`a8c78964f1d6629df37176a188dc143a73b1867d44f651232b5f0f9d43a4032a`,
mojang-web-local VMID 9011 sha256
`653259af19c1b6b0ea617830a16f2cfbb31796dd363a5948021652a94b87e17c`;
`sha256sum -c SHA256SUMS` OK; `IMPORT-STEPS.md` + `TEMPLATE-INFO.json`
emitted. The finalize boot bakes the ONE operator/bastion PUBLIC key into
root/defender/attacker (chk BAKE passed) and scrubs per-clone identity.
Earlier test-key builds (attacker `77add10c…`, web-local `aedfae4d…`) are
superseded; key rotation = rebuild + reimport per generation.

### Still open after the pilot (honest ledger)

Milestones 03–11 acceptance states unchanged. Live/operator gates (VLAN
default-deny positive controls, emergency-stop drill, PVE token/ACL, template
import, full two-teammate rehearsal, model smoke through the gateway) are
Manual checks for the operator — attacks stay latched until they pass.
Installed-capture acceptance stays open (pilot command truth is events/casts).
CI images/capture jobs at `fe940fc` remain failing (pre-existing; the stale
serial bug fixed here is the likely images-gate cause — CI re-greening on
push stays open, not a pilot gate). The web-db verify's intermittent
missing-`MYSQL-COUNT` was root-caused to two real gate bugs (above) and
fixed; contradictory single-boot outcomes must be reproduced before being
believed. Browser/packet gates remain CI-required for acceptance; local
chromium passing does not replace them.

## Plan 13 implementation evidence (2026-10-14, plan 13-live-deploy-hardening)

Cross-cutting authorized exception plan (see `docs/ROADMAP.md`). It accepts
NO milestone; phase checkboxes in the plan track implementation only.
Branch `plan-13-implementation`, base revision `44a712a`. Environment:
fresh uv `.venv`, Python **3.13.5**; Docker daemon 29.8.2 / Compose 5.6.0;
QEMU 10.0.13; Node 22.23.3. No Proxmox, live range, host firewall, NAS or
unrelated-VM access; every fixture run-owned and synthetic.

### Phase 1 — contract, fresh baseline, deployment manifest

Fresh baseline reproduced at `44a712a` before any change (also recorded in
`AGENTS.md`):

| Exact command | Fresh result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **176 passed, 0 failed, 0 skipped, 206 deselected**, 4 warnings, 19.43s — fast layer only |
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python infra/dev/acceptance.py authority` | Exit 1: **16 failed, 8 passed, 358 deselected**, 3 warnings. Classification: every failure is `tests/test_authority_boundary.py` fixture name `web01-deadbeef` rejected by the current `sr-` name policy (`infra/broker/policy.py check_name`); production naming (`sr-<scenario>-<host>-<32hex>`) already satisfies the policy. Fixture repair is phase-2 work; the policy stays. |
| `SR_MATCH_SCHEDULER_ENABLED=1 SR_MATCH_DEFAULT_DURATION_MINUTES=60` probe of `Settings(_env_file=None)` | `match_scheduler_enabled=False`, `match_default_duration_minutes=30` — documented `SR_*` names ignored (phase-4 repair target) |

Delivered (fast tests `tests/test_release_manifest.py`, 22 passed):

- User amendments recorded authoritatively: `docs/ARCHITECTURE.md`
  "Plan 13 release amendments", `docs/ROADMAP.md` 2026-10-14 exception.
- Versioned release manifest: `infra/release_manifest.py` (schema v1,
  fail-closed validation: secret-material rejection, placeholder refusal,
  VMID/address overlap refusal, mandatory template checksums, bounded clone
  window, measured-capacity headroom, three distinct HTTPS/internal/ingest
  listeners, absolute state paths, explicit backup status) +
  `deploy/manifest.example.json` (candidate values clearly marked as
  verify-first, per the plan).
- Installer inventory classification: `classify_resource` (absent/matching/
  conflicting/**unreadable — an error is never absence**),
  `assess_capacity` (measured free capacity vs payload+headroom; unreadable
  is unsafe; a storage label is never proof), `inventory_report` (refuses
  before side effects on any conflict/unreadable/version/capacity problem).
- Source-of-truth map (`SOURCE_OF_TRUTH_MAP` + `render_broker_policy` +
  `render_env(role)`): manifest → broker policy (re-validated by the real
  `BrokerPolicy.from_dict`), per-role env fragments (worker minimal, no PVE
  credentials anywhere, absolute state paths), service/template consumers.

No live installation was inferred or performed. DB/packet/browser/live gates
were not rerun in phase 1; old totals are not claimed.

### Phase 2 — Proxmox/broker boundary and recovery contracts

Fresh results at this revision (same environment; every gate run with
`env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD`):

| Exact command | Fresh result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **223 passed, 0 failed, 0 skipped, 208 deselected**, 4 warnings, 40.27s (adds 22 pve-contract + 3 lease + 1 capacity tests to the 198) |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS**: 25 passed, 0 failed, 0 skipped (was 16 failed/8 passed at `44a712a`) — fixtures repaired to the `sr-` policy; the policy itself unchanged |
| `.venv/bin/python infra/dev/acceptance.py pve-contract` (new gate) | **PASS**: 22 passed, 0 skipped — REAL pinned proxmoxer 2.3.0 over loopback HTTPS |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS** |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS** (fresh locked install, Python 3.13.5) |

Delivered:

- **Authority fixtures repaired, policy untouched**: `web01-deadbeef` →
  `sr-web01-deadbeef` (foreign-resource fixtures deliberately keep non-`sr-`
  names); all latch/race/intent/uncertain-cleanup assertions preserved.
- **`pve-contract` gate** (`tests/test_pve_real_client_contract.py`,
  `adapter` marker — runs in the fast default AND required mode): real
  `ProxmoxAPI`/requests stack against a synthetic PVE dialect server —
  `/api2/json` prefix survival, `PVEAPIToken` header, query/form encoding,
  nextid assertion→scan, clone/start/stop/delete UPID polling, task
  exitstatus ERROR, malformed replies uncertain, 404 vs the exact
  config-absent 500 dialect (confirmed absence) vs the router
  `no such file` 500 (NEVER absence), 401/403/timeout/refused uncertain,
  TLS trust enforced (no-CA/foreign-CA fail closed), agent file-read query
  encoding + comment stripping + allowlist refusal before any HTTP.
  `_Recorder` is never substituted for this boundary.
- **Deadlines checked together**: `HttpTransport.OP_TIMEOUTS` per op exceed
  the documented server bounds (static contract test); a task longer than
  the old flat 30 s completes; a lost mutation response stays
  `BrokerUnavailable` and is **never** transport-retried; lost reads get
  exactly one safe retry; `proxmox_http_timeout_s` is an explicit setting.
- **Reservation accounting fixed**: `clone_and_wait` no longer double-charges
  the target VMID's own `reserved` claim against `max_vms`
  (`test_reserved_claim_is_not_double_counted` — old code refused the third
  guest of a three-VM range).
- **Bounded DB/control-failure lease policy**: `control_is_active()` is
  tri-state (active/provably-idle/**unverified**); renewals continue only
  within `max_unverified_s` (default 60 s = 2× broker TTL), then go silent
  so the broker watchdog latches and stops the range; unverified is never
  provable idle; recovery resets the window (4 heartbeat tests).
- **`deploy/pve_broker_acl.sh`**: dry-run default, `--apply` (idempotent,
  only "already exists" tolerated), `--verify` probes EFFECTIVE token
  permissions (allowed ops + denials on unrelated VM, ACL read/write,
  foreign file-read/stop) — role names alone are never proof; no
  broad-privilege fallback; token secret never on argv, never printed.
- **Audit A6 repaired**: resume re-pins when `state == created` but
  `host_key_ref` is missing; regression
  `tests/test_deploy_resume_repins_missing_host_key.py` is **db-layer —
  pending the db gate** (no disposable PostgreSQL in this environment; not
  claimed as run). A12/A13 comment fixes landed; every audit finding now has
  a code/test anchor in `docs/audits/pve92-alignment.md` "Fix anchors";
  remaining live probes stay explicit operator work.

### Phases 3–8 — guests, configuration, lifecycle, match contract, tooling

#### Review rounds 3–4 evidence (2026-10-15, final — HEAD `496ec7d` + round 10)
- Images rebuild (mgmt→root key policy + USER markers + native-password
  seed): 19 passed, 0 skipped — recorded 36-user sets identical across
  roles, conformance test green against built fixtures.
- Capture: 11 passed, 0 skipped (incl. live docker-MySQL protocol test
  with fixture-scoped volume tracking, no leaks).
- Fast 334/0; db layer 168/0; matrix, frontend, compose, browser,
  containment, authority, pve-contract all PASS; install sandbox proofs
  PASS (VM job pending by design). (2026-10-15, branch `plan-13-implementation`)
- Fast suite 330/0; db layer 167/0 (incl. claim-takeover supersede,
  cross-session interrupt stickiness, atomic expiry, race-decide,
  competition matrix, breach proof + no-worker-on-refusal, pin-error
  readiness + republication, assumed-breach snapshot/disclosure tests).
- Matrix (selection/python/authority/pve-contract) PASS; frontend,
  compose, browser PASS; install sandbox proofs PASS (render, preserve,
  rotate, partial recovery, CA-less refusal, 44GiB ceiling).
- Images rebuild running (role_keys mgmt→root + USER markers change all
  cache keys); recorded 36-user sets already confirmed identical across
  roles and match the expanded baselines exactly. Capture queued behind.
- Declined with documented reasons: PVE range-grants without per-VMID
  enumeration (implemented instead per audit A7); loopback-only MySQL
  observation (triangulated instead); replay/scenario-objective filtering
  (first-party / published-threat-model).

Fresh results at the phase-8 revisions (same environment; every command run
with `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD`):

| Exact command | Fresh result |
|---|---|
| `…python -m pytest -q -p no:cacheprovider` (fast default) | Exit 0: **330 passed, 0 failed, 0 skipped, 230 deselected**, 4 warnings, 50.1s |
| `bash -e …selection python authority pve-contract…` | **PASS** on the final revision — 87.5s / 4.1s / 16.2s / 26.4s, all four gates exit 0 |
| `…acceptance.py db` | **PASS** after 183.9s — disposable fixture, fresh + forward migrations (incl. 0014/0015), **151 passed, 0 failed** incl. the 202 executor, deadline, network-plane and inject tests |
| `…acceptance.py images` | **PASS** after 284.1s on the final revision (cache-warm; overlay inputs unchanged) — **18 passed, 0 skipped**, no leaks |
| `…acceptance.py capture` | **PASS** after 206.8s on the final revision — **10 passed, 0 skipped**, no leaks |
| `…acceptance.py frontend` | **PASS** — npm ci, production build, audit zero high/critical (re-run PASS on the final UI revision) |
| `…acceptance.py compose` | **PASS** — full stack + seed-bastion-keys success gate, cleaned |
| `…acceptance.py browser` | **PASS** — isolated real-browser workflow + replay incl. control builder, inject inbox, safety page (re-PASS after the session-tick fix) |
| `…acceptance.py db` | **PASS** after 155.7s — disposable fixture, fresh + forward migrations (incl. 0014/0015), **150 passed, 0 failed** (phase-3/6 regressions repaired; deploy-operation, network-plane and inject tests included) |
| `…acceptance.py containment` | **PASS** after 11.6s — real namespace/cgroup fixtures created, positive-control process migration, 21 required-mode regressions 0 skipped, no leaked run cgroups |
| `…acceptance.py packet` | **FAIL (prerequisite)** — needs root + nft (missing here); runs only in the approved disposable-netns CI packet job; never accepted from this host |
| `…acceptance.py images` | **PASS** after 1784.8s — all three role overlays rebuilt from the fixed recipe (web-local `f1b5777d`, web-db `7ae761c9`, attacker `7552a591`), **18 passed, 0 skipped**: real Ubuntu builds, boot tests, services/seeds/flaws/fixes, readiness + clone-mode + host-key contracts, attacker records its 5 resolved packages (the PKG-before-SETUP-OK fix), no QEMU or DB leaks |
| `…acceptance.py capture` | **PASS** after 202.4s — 10 passed, 0 skipped: installed auditd+shipper on the real DB overlay guest, EXECVE capture proven locally with NO delivery on the negative boot, end-to-end delivery to the synthetic API, cursor durability; two pre-existing test-expectation bugs fixed (the harness emits bare `BOOT` liveness, never `BOOT-PASS`; the DB payload check now asserts tier separation) |
| `…acceptance.py install` | Sandbox contract **PASS** (dry-run, idempotent rerun, key preservation, invalid manifest refused before effects); **FAILS** on the managed-service VM half until the disposable-VM job sets `SR_INSTALL_VM_EVIDENCE` — deliberately not accepted from a sandbox |

Delivered:

- **Phase 3 (guest/template contract)**: `infra/images/role_keys.py` role
  key policy (runner→attacker only, bastion→defender guests only, mgmt and
  separate explicit emergency; private/placeholder/unknown refused; dedup);
  attacker template now carries auditd + shipper (canonical inputs), the
  reboot-persistent cgroup delegation unit and the scoped AppArmor profile
  (`infra/runner/`), with verify checks; web/DB tiers separated (DB payload
  ships no web app; role-conditional units, firewall and verify checks;
  per-role overlay cache keys); base image pinned to the DATED retained
  directory `noble/20260926` (byte-identical to the `current` alias as
  re-verified 2026-10-14; checksum+size enforced); resolved packages
  recorded from every build including the attacker; deploy-time DB wiring
  (`srplatform/scenario_engine/guest_config.py` + orchestrator pass):
  fresh per-deployment reader credential, grants/listener/firewall narrowed
  to owned web sources + loopback probe, atomic web config to the owned DB
  IP with read-back, resume-idempotent, visible skip (event) without a
  channel; verifier reads the credential inside the guest; template build
  takes per-principal public keys and defaults to all three roles.
  17 fast contract tests (`tests/test_guest_contract.py`).
- **Phase 4 (configuration/trust/readiness)**: settings now honor the
  documented `SR_*` env names (the plan-13 baseline probe
  `SR_MATCH_SCHEDULER_ENABLED=1`/`SR_MATCH_DEFAULT_DURATION_MINUTES=60`
  resolves True/60; bare names unchanged); 55 compatibility tests prove
  EVERY key of EVERY shipped example reaches the model with non-default
  values; shipper HTTPS uses an explicit verified SSL context
  (`SR_TLS_CA_FILE`), enrollment provisions the public CA into guests,
  production refuses http/localhost/missing-anchor APIs; readiness refuses
  created clones without pinned host keys; confirmed teardown unpublishes
  pins; boot-race 255 retry now distinguishes definitive auth/pin failures;
  private keys parse-checked at startup with ssh-keygen-format fingerprints
  recorded in `TEMPLATE-INFO.json` for rotation drift detection; typed
  broker policy REFUSES `gw=` — range guests are on-link only, no default
  route by construction. The guest-facing range listener answers with
  nothing but the authenticated enrollment/ingest routes
  (`SR_API_INGEST_ONLY`; 404 elsewhere, bounded bodies); `GET /stages`
  distinguishes install-ready / lab-ready / attack-authorized with the
  explicit `SR_ATTACK_AUTHORIZED` operator gate, and the three-plane
  separation is documented in `deploy/README` §2a.
- **Phase 5 (durable lifecycle operations)**: `deploy_operations` table
  (migration 0014) + orchestrator helpers; launch/reset commit identity,
  fence, phase and deadline BEFORE effects; redacted
  `GET /sessions/{id}/operation` polling; startup reconcile marks dead
  executors `interrupted` before clearing claims (live fences survive;
  stale requests cannot finalize replacements); 4 db-layer tests pass in the
  db gate. **202 refinement (2026-10-15):** launch/reset/deploy return 202
  after synchronous durable acceptance; the supervised executor completes
  the attempt in the background and the redacted result (connections,
  readiness, deployment summary — never plaintext enrollments) is polled
  from the operation row. The deviation is closed.
- **Phase 6 (match contract)**: snapshot v2 freezes bounded
  choices (mode practice|competition, start condition manual|auto-on-ready,
  intensity pace ∈ {0,15,30,60}, injects toggle) plus scenario/rubric/seed/
  image versions, the scenario digest and effective settings with 422 before
  storage; `uptime.coverage` computes the EXPECTED schedule from the match
  clock — gaps are visible `missed`, unknown ≠ downtime, zero valid
  unscored; the prober additionally runs an authenticated read-only MySQL
  BUSINESS TRANSACTION every cycle for provisioned DB tiers (three truths
  separate: wrong seeded count = down, unestablished session = unknown,
  broken probe credential = probe-infrastructure interrupt). Versioned
  injects (`srplatform/injects.py`, migration 0015): trusted server
  schedule from the frozen duration at Begin, four versioned injects
  (restricted-account, web-restoration, DB-data-recovery technical;
  incident-report written/advisory-only), identity-bound submissions where
  the FIRST answer decides (pending|correct|incorrect|late|duplicate|
  advisory), deterministic verification through the shared verifier
  registry, disabled set releases nothing, and a SEPARATE inject score —
  no combined grade. **Open requirement:** the full control-matrix live
  tests and browser inject inbox (phase 7 UI) remain; the release gate
  exists but refuses to run without a deployed lab.
- **Phase 7 (browser/visibility/reports, partial)**: the live session page
  now carries the inject inbox (release windows, submissions, separate
  score); Begin, uptime panel, detections, AAR/replay links, per-user
  history and server-served SSH instructions already exist; competition
  visibility is enforced at the API (own sessions only for members;
  inject/readiness data per-session). Frontend gate PASS (npm ci,
  production build, zero high/critical). **Open requirement:** the
  operator safety-panel refinements and the attacker control builder
  remain unbuilt UI scope.
- **Phase 8 (installer/gates)**: `deploy/install.sh` (idempotent,
  key-preserving, verify-before-enable, explicit migrations, optional
  backups) + `install`/`release` acceptance gates with honest
  prerequisite refusal.

## Recording new acceptance evidence

For every gate record: date, evidence Git revision and dirty status, exact command
and non-secret environment, runtime/fixture versions, exit code and all
pass/fail/skip/deselect totals, boundary actually exercised, prerequisite blockers,
and observable live outcomes where applicable. Never record plaintext credentials,
real admin terminal casts or mutable generated files as proof in Git.

Only close a blocker after independently executing its agreed milestone criteria.
No implementation milestone is closed by this documentation pass.

## First production install (2026-10-15, operator-executed, agent-guided)

Host `pve` (PVE 9.2.21), bridge `srrange` (vid 66 only), storage `data`,
service VMs 201/202/203 (Ubuntu 24.04, `onboot: 1`), templates
9005/9011/9012 (16/12/16 GiB, never booted), range `10.66.0.0/24`,
mgmt `10.10.10.0/24`. Release revision `795faf4` on all three service
VMs. No secrets are recorded here; passwords/capabilities were generated
locally and transferred staged, never pasted.

| Exact command/probe | Result / meaning |
|---|---|
| `python infra/images/pve_template_build.py --out /tmp/sr-templates --cache-dir /data/sr-guest-cache --runner-key ... --bastion-key ... --mgmt-key ... --emergency-key ... --roles attacker,mojang-web-local,mojang-web-db` (KVM, `SR_QEMU_KVM=1`) + `sha256sum -c SHA256SUMS` | Build clean, checksums verify; SHAs `31f3842e…` (9005), `81c15306…` (9011), `141ac244…` (9012) written into `/etc/sparring-range/manifest.json` (no placeholders left) |
| `deploy/pve_broker_acl.sh` dry-run → `--apply` → `--verify` (node `pve`, bridge `srrange`, templates `9005,9011,9012`, window `9100-9199`, storage `data`, foreign probe `107`) | Applied clean; `pveum user token permissions` shows exactly 106 grants (node audit, bridge SDN, 3× template Clone+Audit, 100× window Base, storage); effective probes pass after the PUT/metadata probe fix (`795faf4`): template/foreign-VM denials `403`, escalation `PUT /access/acl` `403` |
| Narrow PVE firewall rule (pos 0: in/ACCEPT/vmbr0, `10.10.10.200/32` → TCP 8006) + OPNsense inter-VLAN allowance for the same tuple | `curl -sk https://192.168.86.83:8006/api2/json/version` from 202 answers `401` (transport proven; auth needs the token). Management IPSet untouched (still LAN-only) |
| `deploy/install.sh --manifest ... --no-backup` on 201 (`HTTPS_IP=10.10.10.150`) | `install[done]`; TLS identities issued; broker policy rendered (templates + window + `10.66.0.0/24` vlan 66); defect found+fixed: installer shadowed generation keys under `tls/` (now removed; bootstrap owns `ssh/`) and the `ssh/` dir blocked traversal (now `0750`) |
| PostgreSQL 16 install, `sr_owner`/`sr_app` roles, `sparring_range` DB, `alembic upgrade head` | `0001 → 0015` clean; defect found+fixed: app role had CONNECT only (fixtures never exercise the split) — standing DML + default privileges in migration `0016` |
| `GET /readyz` on 201 | `{"ready":true,"migration_version":"0015","issues":[]}` (runner host-key + recordings pending first deploy, as designed) |
| `rangectl bootstrap` on 201 | Operator account created; bastion capability minted once into the operator secret store |
| `sr-brokerd` on 202 (policy + mTLS + token via staged transfer) | `active`, `listening ('0.0.0.0', 8443)`, reconciliation empty, unlatched |
| `GET /stages` (operator auth) on 201 | `install_ready:true, lab_ready:true` (broker `ok`, latch unlatched), `attack_authorized:false` (gate holds until Manual checks) |
| `sr-bastion` on 203 (`:2222`, host key pinned by fingerprint `SHA256:uamaB/…`) | `active`, `LISTEN 0.0.0.0:2222`, clean publickey refusal; defect found+fixed: unit missed the derived env (now loads it like `sr-api`) |

Open (operator Manual checks, plan §Manual checks): teammate LAN paths
(`:8443`/`:2222` allowances), isolation denials with positive controls,
emergency-stop drill + read-back + release, rehearsal launch→end→cleanup
→second launch with a second member, then `SR_ATTACK_AUTHORIZED=1`.
Backup destination/restore remain explicitly unverified (not release-blocking).
The inference endpoint `http://10.10.10.197:8096/v1` answers
`qwen3.8-flash-next` `loaded`.

## Live deployment hardening — the pin-serving failure (2026-10-16, `a6fd49c`)

Live find (operator session on the first production install above): every
bastion guest dial failed `HostKeyNotVerifiable` after auth and token resolve
succeeded, on a deployment that reported `ready`. Deterministic, not a race.
Independent repro (standalone script, not committed): a known_hosts line
built from the truncated `host_key_ref` display form yields ZERO trusted
keys — asyncssh silently drops unparseable lines — while the full key
verifies and connects. The token endpoint served that ref as
`target_host_key` (introduced by `e6f380f`, "api-served pins"), so no
deployment pin was ever dialable. The boot-completion/stability gates
(`5fc6bb7`, `29d1471`) were sound and unrelated.

Repairs (commits `6cef3cc`, `0d33723`, `a6fd49c`):

- `_pin_host_key` stores the FULL public key as `host_key_pin` next to the
  display-only ref; resume repins when ref, full pin, or publication is
  missing — legacy ref-only rows backfill without a re-clone.
- `GET /tokens/{token}` serves only the full pin (`dial_pin_for`); a
  ref-only row serves `None` so the bastion fails closed.
- The bastion validates the pin before any dial (`PinRefused`, no pin
  material in member output or the recording).
- Readiness requires the full pin; a ref-only row stays red until resume
  repairs it.
- `read_host_key` client bound 150 → 300 → 360 s (server worst case:
  (120 s boot-marker window + one in-flight request of ≤30 s) + (120 s
  SHARED stability window + one in-flight request of ≤30 s) = 300 s; once
  a window is exhausted NO further probe is issued, so the bound is real);
  the duplicated unreachable except was removed and the stage's own
  retained obligation is no longer re-recorded.

| Exact command/probe | Result / meaning |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` (clean tree at `a6fd49c`) | Exit 0: **361 passed, 0 failed, 0 skipped, 250 deselected**, 4 warnings, 50.29s. Fast layer; seven new tests over the previous 354. |
| `pytest -q tests/test_bastion_dial_path.py` (real asyncssh server: real host-key verification + public-key auth end-to-end through `_handle_session`) | 10 passed; the full pin reaches the guest (`echo hi`, exit 0); the display-ref shape is refused before any dial (`PinRefused`, no material echoed). |
| `pytest -q tests/test_dial_pin_serving.py` (new fast contract) | Serves `host_key_pin` only; ref-only rows serve `None`; `asyncssh.import_public_key(ref)` raises `KeyImportError` (documents the mechanism). |
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python infra/dev/acceptance.py authority` | Exit 0: **25 passed, 586 deselected, 0 skipped** (broker boundary/durability/cessation, required mode). |
| `.venv/bin/python infra/dev/acceptance.py db` (gate-owned disposable `postgres:16` fixture; the manual `SR_PG_ADMIN_URL` export was overridden by the gate) | Exit 0: **170 passed, 441 deselected, 0 skipped**, 464.8s; includes the new resume-backfill db tests; owned `srtest_*` resources and the fixture container/volume removed. |

Review round (2026-10-16, `e00ed70`): an independent review confirmed the
pin work and raised one blocker — the stability re-reads each received a
FRESH 120 s window, so a slow-but-working sequence (reviewer's virtual
clock: 118 s marker + 110 s read + 2 s pause + 110 s confirmation)
succeeded at ~340 s server-side while the 300 s client bound had already
failed the deployment. Fixed in `e00ed70`: the re-read phase shares ONE
window (each read gets only the time left; an exhausted window allows a
single non-blocking attempt, so `agent_ready_timeout_s=0` fixtures still
pin instantly-answered keys). Evidence: virtual-clock regression tests in
`tests/test_broker_grant_recovery.py` — the 340 s sequence now fails
bounded with `host-key-read-uncertain` retained, and a 118 s marker + 10 s
read still pins; the negative test fails `DID NOT RAISE` when run against
the previous code (regression proven genuine). Fast suite **363 passed**,
authority gate **25 passed** at `e00ed70`.

Review round 2 (2026-10-16, after `e819d95`): the shared window fixed the
polling-sleep case, but `timeout_s=0` bounds retry SLEEPS, not the HTTP
request — each post-exhaustion probe still cost up to the 30 s HTTP
timeout and a success response bypassed the deadline check, so extra
probes could stabilize at **327 s** on the reviewer's virtual clock while
the 300 s client bound had already failed. Fixed: once the shared window
is exhausted the read loop issues NO further probe, the documented server
worst case counts one in-flight request per window (120+30+120+30 = 300 s),
and the client bound is 360 s (20 % margin). Evidence in
`tests/test_broker_grant_recovery.py`: with 29 s requests the pre-fix code
RETURNS a key at t=327 s after 7 key requests; the fixed code raises
`never stabilized` at t=240 s after 4 (`host-key-unstable` retained), and a
slow-but-legitimate 29 s sequence still pins inside the window. The
zero-window fixture `test_pin_waits_for_boot_completion` moved to the
virtual clock because exhausted/zero windows may no longer probe.
Evidence at `00571e9`: fast suite exit 0, **365 passed, 0 failed,
0 skipped, 250 deselected**, 4 warnings, 53.10s; authority gate exit 0,
**25 passed, 0 skipped**; `tests/test_pve_real_client_contract.py`
**22 passed** (static `read_host_key > 300` bound).

Open (operator Manual check): deploy `00571e9` to the service VMs (201
API / 202 broker / 203 bastion), relaunch/resume the existing deployment once
so `host_key_pin` backfills, then re-test the recorded SSH login.
