# Reviewer handoff — milestone 15 (appliance software)

Branch `15`. The milestone's first commit is `96082f9`; **HEAD is `e587a07`**
(34 commits, nothing pushed). The objective was
`.openchamber/plans/15-complete-practice-product.md`; plans **14** (nested
appliance foundation), **16** (installable release) and **17** (hand-off) were
executed in the same series because plan 15 depends on 14 and 16, and the
operator asked for a deployable product. Plan 17 is drafted and partially
built — see "What is not done" below.

Read in this order:

1. `.openchamber/plans/14-nested-appliance-foundation.md`,
   `15-complete-practice-product.md`, `16-appliance-release.md`,
   `17-appliance-handoff.md` — what was promised.
2. `docs/ARCHITECTURE.md` → "Ubuntu/KVM appliance" and the new subsection
   **I. Milestone 15 implementation decisions** (the decisions and why).
3. `docs/FINDINGS_CHECKLIST.md` → the **top** section: every gate result with
   the exact environment, plus the list of defects this milestone found.
4. `AGENTS.md` → "Milestone 15 implementation baseline" (reproduced counts).
5. `docs/OPERATOR_RUNBOOK.md` → "Installing the appliance in your own virtual
   machine" and "Appliance installation and the new acceptance layers".

## The commit map

| Commits | What they do |
|---|---|
| `96082f9` | Controller MySQL reads through locked PyMySQL (replaces hand-written wire code) |
| `4363d72`, `797328d` | Separate-UID worker dispatch: durable claim/assign/heartbeat/failure, migration `0018`, the broker-socket setting — and the fix that keeps the queued-run credential inside the durable INSERT (a lock-holding window had turned an unconfirmed queued stop into a confirmed kill) |
| `a932f63`, `8cd5f75` | The appliance installer: manifest-derived policy, a sandboxable system root, the digest-only install receipt, the `verify` command, and the real service steps (native packages, locked venv, DB roles + owner migrations, TLS, key onboarding, the web/NGINX front door) |
| `a6cbc27`, `df87849`, `26bf77b`, `205e107` | The guest contract: static addressing in every mode, an overlay never smaller than its base, the guest-agent protocol, and the member contract proven end to end (readiness marker, host key, SSH, `.cast`, `sudo`, interactive PTY + resize, reconnect, denial) |
| `d1095c0`, `870f624`, `ff8c3b6` | The recording bastion: one production pin source (no stale local fallback), the remote stdin EOF that killed every interactive session, and the terminal resize that arrived as an exception |
| `f2c4af1` | The backend's own domain identity (libvirt UUID) recorded per deployment |
| `1b7e41b`, `ed8b49d` | The new acceptance layers and the `appliance` aggregate |
| `5f018ad`, `e6771d3`, `e587a07` | The release bundle, the one-command hand-off, the model gateway/alias |
| `aa50a52` | One controller per database (PostgreSQL advisory lock) and visible startup failures |
| `7600722` | The live broker-authority gate: the real broker over the real Unix socket against real libvirt |
| `24c56ad` | The journey's match-option matrix |
| `review round` (this branch, after `e587a07`) | The independent review's findings: fenced supervisor callbacks (migration `0019`), cross-UID cancellation through the supervisor, controller-lock loss detection, the Unix-socket control heartbeat, the separate schema-owner credential, the TLS SANs, the credential accessibility contract, the frontend build/routing, the manifest's role images, the journey's SSH/browser/incident workflows and the managed-service installation contract |

## Verify it yourself

```bash
# fast, infrastructure-free (≈60 s)
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider

# the whole software matrix in one pass (≈34 min); writes a receipt when
# SR_APPLIANCE_RECEIPT is set
SR_APPLIANCE_BASE_IMAGE=$PWD/.cache/appliance/appliance-base.qcow2 \
  .venv/bin/python infra/dev/acceptance.py appliance
```

Individual gates: `selection python db authority install hypervisor
containment images capture access frontend browser compose bundle journey
packet`. Two of them need preparation:

- `hypervisor` needs libvirt. Here it is an **unprivileged** libvirt extracted
  under `.cache/libvirt-debs` with a path-redirect shim for its data files:
  `sh -c '. .cache/libvirt-debs/env.sh && .venv/bin/python infra/dev/acceptance.py hypervisor'`.
  There is **no `/dev/kvm` in this environment**, so every guest boot is
  software emulation (TCG) and the gate labels it as such. The `images` gate
  additionally needs a **warm build cache** — a cold build exceeds the
  1500 s serial-marker timeout under emulation.
- `journey` needs the **installed** appliance and two bearer tokens; it fails
  closed with the exact missing prerequisites.
- `packet` needs root and `nft`; it fails closed and was not simulated.

The base image and the release bundle are **not in git** (`.cache/` is
ignored). Rebuild them with:

```bash
.venv/bin/python infra/images/appliance_base.py --cache-dir .cache/appliance
.venv/bin/python deploy/bundle.py build \
    --output .cache/bundle/sparring-range-appliance \
    --base-image .cache/appliance/appliance-base.qcow2
.venv/bin/python deploy/bundle.py verify .cache/bundle/sparring-range-appliance
```

## What is claimed

Everything in the table at the top of `docs/FINDINGS_CHECKLIST.md` was
reproduced on this branch: the fast suite (402 passed, 0 skipped) and the
`selection`, `python`, `db`, `authority`, `install`, `hypervisor`,
`containment`, `images`, `capture`, `access`, `frontend`, `browser`, `compose`
and `bundle` gates, plus the `appliance` aggregate (14 gates, one run,
1931 s, receipt with the revision and the base-image digest).

## What is NOT claimed

- **The privileged install path has never run end to end.** `apply` needs root
  and a real VM. The sandbox proves the *sequences* (clean, rerun, reboot,
  populated upgrade, drift + repair), not the systemd, TLS, PostgreSQL or
  network effects.
- **`journey`** — needs the installed appliance.
- **`packet`** — needs root + `nft`.
- **Nested-KVM promotion, isolation denials, emergency stop, the member-SSH
  rehearsal, the real-model run and the second-member acceptance** are the
  operator's manual gates. Nothing in this branch claims them.
- Every guest boot here was **TCG**, never KVM.

## The independent review round (after `e587a07`)

A reviewer read the milestone and returned **VERDICT: FIX** with 17 findings.
Every finding that reproduced was fixed; the fixes are in the commits after
`e587a07` on this branch. What changed, and where:

| Area | What was wrong | The fix |
|---|---|---|
| Supervisor callbacks | The claim credential was not compared: an obsolete claimant could assign, heartbeat and overwrite a terminal state | A second credential (`runs.worker_claim_token`, migration `0019`) fences every callback; `worker_failed` only transitions a run that is still `running`/`stopping` |
| Cross-UID cancellation | The API signalled worker groups it does not own; a stopped run stayed `stopping` forever | The API never signals a foreign-UID child: it marks the run, the supervisor learns it on the heartbeat, terminates the child and reports the cessation; a run that never started resolves immediately |
| Controller lock | Ownership survived the death of the lock's session | `ControllerLock.held` is a live fact, a monitor drops the ownership, the readiness report shows it and the control heartbeat stops renewing |
| Control heartbeat | A Unix-socket deployment never armed the broker lease | The heartbeat starts for `broker_socket` **or** `broker_url` |
| Match scheduler | The generated environment left it disabled | `SR_MATCH_SCHEDULER_ENABLED=1` in the derived environment |
| Owner credential | `ensure_database` recommended putting the schema owner in the environment every service loads | The owner URL lives in its own root-only file and reaches Alembic through the environment only |
| Database bootstrap | The URL was split on `/`, the owner role was never created, `SR_POSTGRES_URL_OWNER` was passed to Alembic (which reads `POSTGRES_URL_OWNER`) | A proper URL parse, both roles created, `POSTGRES_URL_OWNER` in the environment, the DSN never on a command line |
| TLS artifacts | `INGEST_SANS` was missing (no ingest certificate) and the telemetry trust anchor named a file the bootstrap never creates | The SANs are derived from the manifest; the anchor is the API CA |
| Member onboarding | Bare public keys were written; the bastion read the username as `ssh-ed25519` | `<username> <public-key>` lines |
| Credential accessibility | The capability sat under a `0700` directory; the API and the supervisor could not read it, and the runner/verifier/bastion keys were never provisioned | A `sr-secrets` group (`srrange`, `srworker` only), one 0600 copy per service, and the machine keys provisioned with the ownership of their reader |
| Frontend | The build passed `cwd` to a `Runner` that rejects it, baked no API URL, and nginx kept a prefix the API does not serve | `cwd` support, `NEXT_PUBLIC_API_URL=<public>/api`, nginx strips `/api` |
| Guest NIC | The controller asked for `virtio,bridge=srlab0,tag=66`; the policy accepts only the untagged form | The tag is omitted when the range has no VLAN; the derived environment says so |
| Bundle | `verifiers/` and `telemetry/` were missing; every role got the bare base image; the manifest's image paths could be relative | The allowlist carries the missing packages (with a hermetic import test), a manifest without the role artifacts is refused, the paths are absolute |
| Hand-off | `--range-bridge` did not exist, and `apply` demanded the venv it creates | `--bridge`, and the venv check removed from the path that creates it |
| Acceptance | The aggregate omitted `packet`/`journey`; `install` checked files, not the services; the journey could pass without SSH, browser, submissions or failures | The aggregate attempts the operator gates and reports them pending with the exact prerequisite; the install gate checks the managed-service contract; the journey requires SSH, drives a real browser and walks the incident and refusal paths |

The contract checks that would have caught several of these at install time
are now a gate of their own: `infra/dev/service_contract.py` (checked by the
`install` gate and by `tests/test_appliance_service_contract.py`).

### The second review round

A second review of the first round's fixes returned **VERDICT: FIX** with 13
findings; all of them are fixed (`dd88707`, `d36264a`, `45064d0` and the
bundle/image commits). The evidence and the exact commands are in
`docs/FINDINGS_CHECKLIST.md` ("Second review round"). Two things a reviewer
should look at hardest in that round:

* the cross-UID stop path (`srplatform/api/runs.py` +
  `srplatform/worker_supervisor.py`): every callback carries the claim
  credential, every final UPDATE is fenced by the claim hash, and the state
  of one assignment is immutable — a late heartbeat cannot touch the next
  one;
* the shipped images (`deploy/bundle.py`): the bundle flattens an image that
  depends on a backing file, verifies that what it ships stands alone, and
  the bundle gate boots a shipped image from the bundle.

### The third review round

A third review (VERDICT: FIX, seven findings) is fixed in `51f4166`,
`fec3f53`, `0a6638e` and `818d99e`: the bastion's service credential (a
0600 file of its own), the password redaction, the journey's real
break/repair proof, the fail-closed key derivation, the disposable tamper
fixture, the bundle's binding to the candidate and the mandatory
shipped-image boot. The evidence is in `docs/FINDINGS_CHECKLIST.md`
("Third review round").

## Where I would look hardest

1. `srplatform/bastion/proxy.py` — the interactive path changed three times
   (`send_eof=False`, `TerminalSizeChanged`, the pin policy). Ask: does a
   member's session still behave when the guest is slow, does the resize
   reach the guest correctly, and does removing the local-pin fallback break
   any non-production path?
2. `deploy/appliance.py` + `deploy/appliance_services.py` — the installer
   *claims* real steps. The privileged ones are untested here. `apt-get`,
   `pip`, `alembic`, `bootstrap_tls.sh`, `systemctl` — each is a real effect
   with a real failure mode.
3. `infra/images/appliance_base.py` — the base builder runs `apt` in a guest
   and flattens the result. Host keys and the machine-id are scrubbed, but
   the **journal and the apt lists are not**: a guest's `journalctl` still
   shows the *build's* boot. Decide whether that must go before a release.
4. `srplatform/controller_lock.py` and the API startup — the lock is a
   *session-level* PostgreSQL advisory lock, so with several API workers only
   one of them is the controller and the others report it. Is that the
   intended behaviour, and is the readiness report the right signal?
5. `deploy/bundle.py` — the secret scan exempts application source (the
   repository's own policy covers it) and scans configuration. A reviewer
   should decide whether that exemption is the right line.
6. `infra/appliance/seed.py` — the guest contract: static addressing (the
   production range is on-link, no default route), the NOPASSWD sudo rule
   for the management identities only, the MOTD/machine-id decisions and the
   role→key mapping. These are security-relevant choices, not plumbing.
7. The new gates' independence: `access` drives the product's own bastion
   (good), while `hypervisor` and the broker-live test drive the backend and
   the broker service directly — is that enough separation from the code
   under test?
8. `docs/FINDINGS_CHECKLIST.md` — the counts and results are per revision
   and per environment; please re-run rather than trust them.
9. The cross-UID stop path (`srplatform/api/runs.py` +
   `srplatform/worker_supervisor.py`) — the API now waits for the
   supervisor's report instead of killing a process group it does not own.
   Ask whether a supervisor that dies mid-run still leaves the obligation
   visible and recoverable, and whether the 45 s wait is the right shape.
10. The capability's two copies — the API and the supervisor hold the same
    value in two 0600 files. Ask what happens on a partial restore (one
    copy present, one missing): the installer refuses, which is the safe
    direction, but the operator has to know that is what happened.
