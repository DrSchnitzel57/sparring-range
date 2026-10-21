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
