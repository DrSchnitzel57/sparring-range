# Operator runbook and live acceptance gates

## Current direction — Ubuntu/KVM appliance (2026-10-20)

The user selected one Ubuntu appliance VM with nested full practice VMs. Read
[the appliance architecture](ARCHITECTURE.md#ubuntu-kvm-appliance--2026-10-20)
and [plans 14–16](ROADMAP.md#current-completion-sequence--draft-2026-10-20).
This section began as planning guidance. The installer now exists and the
operator completed commissioning for the supervised AI run on the patched
appliance. See the [current findings and open blockers](FINDINGS_CHECKLIST.md).
The appliance instructions below are current; the **historical direct-PVE**
section is a Git-history pointer, not appliance installation. No new live
action is requested by this doc update.

Operator checkpoints for the new release:

1. Before milestone 14's host rehearsal, approve a disposable Ubuntu 24.04 VM,
   resource/storage budget, LAN address and nested CPU exposure. Confirm KVM by
   an actual inner boot; do not unload modules on a running Proxmox host.
2. Run the milestone-14 installer/preflight inside that VM. Review its fixed
   inner-network rules. It must never require an outer-PVE token or host SSH.
3. With attacks disabled, prove guest denial of appliance administration, LAN,
   model, NAS, WAN/DNS/IPv6 and outer management, with working authorized flows;
   prove broker stop/read-back/control-loss and manual outer-VM power-off.
4. Fresh launch, actual member SSH, sudo, exec/interactive/resize/reconnect,
   synthetic recording replay, cleanup, second fresh launch. Record the exact
   revision/config/images and user-visible outcomes. A ready flag cannot pass it.
   Actual deployed member SSH/sudo/replay subsequently passed (2026-10-23).
   Retain scoped evidence; do not repeat completed commissioning merely to
   compensate for stale documentation. Complete milestone acceptance is broader.
5. After milestone 15, validate the real model and complete both presets/modes/
   start conditions with truthful service/inject changes. Milestone 16 requires
   an operator and another member to complete the workflow unaided and reuse it.
6. Inventory the old installation before cutover; preserve closed history,
   recordings and trust material. Resolve old resources with the old operator
   authority; never import old PVE claims/tokens as appliance runtime state.
   Retire old VMs/bridge only by a separate explicit operator decision.

Backing up to a real destination/restoring there remains optional; absence is
visible. Normal restore must be disconnected/quiesced and never resume attacks.
Each live action still requires operator approval; implementation agents deliver
the fixtures and instructions and skip these manual checks.

## Appliance installation and the new acceptance layers (2026-10-20, branch `15`)

These are the commands that actually exist in the tree today. They replace the
historical direct-PVE procedure (see the pointer at the end of this file).

### Build the guest base image once (no root, no host changes)

```bash
# Pinned Ubuntu 24.04 cloud image is verified against the repository manifest.
# The build boots it once, installs the guest agent, scrubs host keys and the
# machine-id, cleans the cloud-init state and flattens the result.
.venv/bin/python infra/images/appliance_base.py --cache-dir .cache/appliance
```

The output is `.cache/appliance/appliance-base.qcow2`. It is the ONLY guest
image the appliance clones from; per-instance keys and addressing come from
each clone's seed, never from the image. The base carries one netplan entry
(`00-sr-base-dhcp.yaml`, interface key `range-nic`) so a guest has an address
within seconds of boot; the per-instance seed writes the same interface key,
so its static production configuration merges over the build-time fallback
instead of colliding with it.

### Validate, plan and apply the appliance

```bash
.venv/bin/python deploy/appliance.py validate --manifest /etc/sparring-range/appliance-manifest.json
.venv/bin/python deploy/appliance.py plan     --manifest /etc/sparring-range/appliance-manifest.json
.venv/bin/python deploy/appliance.py apply    --manifest /etc/sparring-range/appliance-manifest.json --dry-run
.venv/bin/python deploy/appliance.py apply    --manifest /etc/sparring-range/appliance-manifest.json
.venv/bin/python deploy/appliance.py status   --manifest /etc/sparring-range/appliance-manifest.json --json
.venv/bin/python deploy/appliance.py doctor   --manifest /etc/sparring-range/appliance-manifest.json
```

Start from `deploy/appliance.manifest.example.json` (schema-checked in CI).
For an Underpressure install declare `network.segments` plus `max_nics`;
one segment MUST be the range network itself (`range`/`range_bridge`/
`range_cidr`) so flat-lane guests stay inside the approved address lane.

`apply` needs root and creates the service identities (`srbroker`, `sringest`,
`srworker`, plus `srrange`/`srbastion`), the fixed systemd units, the derived
broker policy and the control-plane environment. It never regenerates an
existing private key or capability: a rerun is idempotent, and a suspiciously
short existing token is an error, not something to overwrite.

### Recovery is local, explicit and evidence-bound

**2026-10-23 field limitation:** normal End after killswitch can retain the
reservation because typed destroy is refused under the broker cessation latch
(HTTP 423), even when guests are stopped. `status:complete` alone is not cleanup
success. The successful scoped workaround kept the API safety latch, stopped
broker to avoid concurrent ledger writers, verified exact session/claims and zero
obligations/intents, used broker-service identity and libvirt/KVM groups for typed
stop/readback, audited broker release, typed destroy/independent absence and lease
disarm; then restarted broker and retried authenticated API End for that session.
This is a receipt, not a generic executable recipe: obtain fresh inventory and
approval, never reuse old session IDs or edit SQL/ledger files. Open obligations
need supported resolution tooling, not this zero-obligation workaround. Permanent
teardown/recovery UX remains open; do not broadly remove latch checks or Begin
to extend idle expiry. Local SSH waiting after verified VM shutdown is not proof
of surviving guest work. Retain independent appliance power-off fallback.

```bash
.venv/bin/python deploy/appliance.py recovery status    --manifest M
.venv/bin/python deploy/appliance.py recovery reconcile --manifest M
.venv/bin/python deploy/appliance.py recovery resolve   --manifest M \
    --obligation 12 --evidence /root/evidence/oblig-12.json
```

`resolve` refuses unless the evidence file names that obligation and the
backend is read AGAIN and no longer owns the resource. A timestamp or an
operator assertion alone never releases a reservation.

### The new acceptance layers

```bash
gate() { .venv/bin/python infra/dev/acceptance.py "$@"; }
gate hypervisor   # real libvirt clone/start/QGA host key/ownership/destroy
gate access       # real guest SSH, pinned target key, recorded .cast replay
gate journey      # the INSTALLED appliance, both presets, real services
```

`hypervisor` and `access` need a base image
(`SR_APPLIANCE_BASE_IMAGE`) and, for `hypervisor`, libvirt plus a working
`/dev/kvm`; without nested KVM the gate fails closed unless the operator
explicitly sets `SR_HYPERVISOR_ALLOW_TCG=1` for a clearly labeled
software-emulation run. `journey` needs the installed appliance and two
bearer tokens:

```bash
export SR_JOURNEY_BASE_URL=https://appliance.example.edu
export SR_JOURNEY_OPERATOR_TOKEN=...      # operator bearer token
export SR_JOURNEY_MEMBER_TOKEN=...        # the member who owns the sessions
export SR_JOURNEY_SSH_KEY=/root/keys/member_ed25519
export SR_JOURNEY_BASTION_KNOWN_HOSTS=/root/keys/known_hosts
gate journey
```

The journey launches both Mojang presets, begins a match, reads the live view,
replays the recorded session, scores, ends, and launches a second session to
prove the range is reusable. It mutates only the sessions it creates.

## Installing the appliance in your own virtual machine (bundle hand-off)

This is the operator-facing path for milestone 16/17: one bundle, one
manifest, one installer, one health check. Everything below is read-only
until the `apply` step, and `apply` is the only step that changes the VM.

### 0. What the appliance needs from the VM

* Ubuntu 24.04 LTS, x86-64, a fixed LAN address, and **nested virtualization**
  actually exposed (an inner guest must boot with KVM — TCG is not accepted
  for a real match).
* The bundle's base image must be copied to the appliance's image directory
  and its digest must match the bundle's `MANIFEST.json`.
* Your own public keys: one for the attack identity, one for the bastion
  (member) identity, one for management. The bundle never carries them.

### 1. Build the bundle (on a machine with the repository)

```bash
.venv/bin/python infra/images/appliance_base.py --cache-dir .cache/appliance
.venv/bin/python deploy/bundle.py build \
    --output .cache/bundle/sparring-range-appliance \
    --base-image .cache/appliance/appliance-base.qcow2 \
    --role-image attacker=$HOME/.cache/sr-guest-cache/attacker.qcow2 \
    --role-image mojang-web-local=$HOME/.cache/sr-guest-cache/mojang-web-local.qcow2 \
    --role-image mojang-web-db=$HOME/.cache/sr-guest-cache/mojang-web-db.qcow2
.venv/bin/python deploy/bundle.py verify .cache/bundle/sparring-range-appliance
```

`verify` re-computes every digest in `MANIFEST.json` and refuses drift, an
unlisted file, or credential material. A bundle that does not verify is
never installed.

**The ROLE images are not optional.** The base image is a bare Ubuntu; the
practice product (the web/DB services, the shipped payload, the baked role
keys) lives in the role images. `deploy/bundle.py manifest` therefore
**refuses** to render an operator manifest from a bundle that lacks a role
artifact — a bundle that silently assigned the base image to every role
would ship guests that cannot run the scenario. The build prints
`roles_missing` when a role is absent.

### 2. On the appliance VM: verify, then render the manifest

The one-command path does all of this (and stops at the first failure):

```bash
sudo ./deploy/hand_off.sh \
    --bundle /opt/sparring-range \
    --installation-id "$(uuidgen)" \
    --lan-address 10.10.10.50 --range-cidr 10.66.0.0/24 \
    --public-url https://sr.example.edu \
    --bridge srlab0 \
    --model-base-url http://127.0.0.1:8001/v1 --model-alias my-model
```

The script carries the sealed-tree hygiene itself: every bundle-Python
call runs with `-B` and `PYTHONDONTWRITEBYTECODE=1` exported for its
children, so the hand-off never writes bytecode into the sealed bundle
(`bundle.py verify` refuses any unlisted file, and it holds without the
operator exporting anything).

The steps it performs, if you prefer to run them by hand:

```bash
cd /opt/sparring-range            # the unpacked bundle
python3 -B deploy/bundle.py verify .         # the bundle root (-B: never write
                                         # bytecode into the sealed tree)
mkdir -p /etc/sparring-range/keys
ssh-keygen -t ed25519 -N '' -f /etc/sparring-range/keys/runner
ssh-keygen -t ed25519 -N '' -f /etc/sparring-range/keys/bastion
ssh-keygen -t ed25519 -N '' -f /etc/sparring-range/keys/mgmt
install -m 0600 /dev/null /etc/sparring-range/secrets/model.key   # then put the model key in it

python3 -B deploy/bundle.py manifest . --out /etc/sparring-range/appliance-manifest.json \
    --installation-id "$(uuidgen)" \
    --lan-address 10.10.10.50 --range-cidr 10.66.0.0/24 \
    --public-url https://sr.example.edu \
    --internal-url http://127.0.0.1:8000 \
    --ingest-url https://10.66.0.1:8443 \
    --bridge srlab0 \
    --access-key runner=/etc/sparring-range/keys/runner.pub \
    --access-key bastion=/etc/sparring-range/keys/bastion.pub \
    --access-key mgmt=/etc/sparring-range/keys/mgmt.pub \
    --model-api-key-file /etc/sparring-range/secrets/model.key
```

The manifest is **rendered**, never hand-written: it satisfies the strict
appliance schema (image digests, budgets, subnets) or the command fails.

#### The two database credentials are separate files

The **schema owner** credential is used ONLY to run the forward migrations.
It lives in its own root-only file and is never written into an environment
that a service loads:

```bash
# /etc/sparring-range/secrets/db-owner.env   (0600, root only)
SR_POSTGRES_URL_OWNER=postgresql+psycopg2://sr_owner:<pw>@127.0.0.1:5432/sparring_range
```

The **runtime** credential (the app role) goes into the environment the API,
the ingest listener and the bastion load:

```bash
# /etc/sparring-range/control-plane.env      (0640, root:srrange)
SR_POSTGRES_URL=postgresql+psycopg2://sr_app:<pw>@127.0.0.1:5432/sparring_range
```

`apply` creates both roles, runs `alembic upgrade head` with
`POSTGRES_URL_OWNER` **in the environment** (never on a command line, never
in a log) and refuses to continue if the owner URL is missing. `hand_off.sh`
writes both files for you. If the owner URL ever appears in
`control-plane.env`, every service holds the schema owner — move it back.

### 3. Plan, then apply

```bash
python3 -B deploy/appliance.py plan  --manifest /etc/sparring-range/appliance-manifest.json
python3 -B deploy/appliance.py apply --manifest /etc/sparring-range/appliance-manifest.json --dry-run
python3 -B deploy/appliance.py apply --manifest /etc/sparring-range/appliance-manifest.json
```

`apply` installs the pinned native packages, builds the locked venv, creates
the database roles and runs the forward migrations **as the owner role**,
provisions the TLS material (including the guest-facing ingest certificate
with its SANs), onboards the member's public keys in the bastion's
`<username> <public-key>` format, provisions the appliance's own machine keys
(runner/verifier/bastion-client, each owned by the identity that uses it),
builds the frontend with the public API URL baked in, renders the fixed
systemd units and the network artifacts, and enables the services. It never
regenerates an existing key or capability, so a rerun is safe.

**Routing:** the API's routes are unprefixed (`/auth/login`, `/sessions`).
The clients use the `/api` prefix, and nginx **strips** it. The frontend is
built with `NEXT_PUBLIC_API_URL=<public url>/api`, so the browser reaches
the API through the same origin. Do not "fix" a routing problem by changing
the prefix in one place only.

**The worker-supervisor capability** is a secret, and the production
settings refuse a group-readable token file, so it exists as TWO 0600
copies of the same value: the API's (`worker-supervisor.token`, owned by
`srrange`) and the supervisor's (`worker-supervisor.token.srworker`, owned
by `srworker`). The secrets directory is `0750 root:sr-secrets`; the
`sr-secrets` group holds exactly `srrange` and `srworker` — the ingest
listener, the bastion and the frontend must never read it.

### 4. Apply the isolated range's network, then start the services

`apply` renders the inner bridge and the fixed nftables rules but does NOT
change the host's live networking: those artifacts are a one-time, reviewable
change to the machine, and the operator applies them in a maintenance window.

```bash
# REVIEW the rules first. They drop management/WAN/IPv6/model/NAS traffic
# from the range and keep the authorized flows.
less /etc/nftables.d/sr-appliance.nft
less /etc/systemd/network/10-srlab.netdev /etc/systemd/network/20-srlab.network

# apply them
networkctl reload
nft -f /etc/nftables.d/sr-appliance.nft
systemctl enable --now sr-appliance-broker sr-api sr-appliance-ingest \
  sr-worker-supervisor sr-bastion sr-web
```

If the rules do not fit your host, change them in the manifest and re-render
(`appliance.py plan` shows the exact artifacts) - never hand-edit the rendered
files, and never widen them to make a test pass.

### 4b. Give the recording bastion its service token

The bastion authenticates its callbacks to the API with a **service
token**; the API issues it and shows it once. It is a secret, so it lives
in the bastion's own 0600 file — not in an environment the API also loads.

```bash
# 1. the API issues a bastion-scoped service token (operator only)
curl -sS -X POST https://sr.example.edu/api/admin/service_tokens \
     -H "Authorization: Bearer $OPERATOR_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"scope": "bastion"}'
# -> {"token": "svc-bastion-...", ...}

# 2. it goes into the bastion's own file (the bastion's directory is
#    0750 root:srbastion; the file is 0640 root:srbastion, so the service
#    can read it and nobody else can)
install -m 0640 -o root -g srbastion /dev/null \
     /etc/sparring-range/ssh/bastion.token
printf '%s' 'svc-bastion-...' > /etc/sparring-range/ssh/bastion.token
chown root:srbastion /etc/sparring-range/ssh/bastion.token
chmod 0640 /etc/sparring-range/ssh/bastion.token
systemctl restart sr-bastion
```

The bastion **refuses to start without a token** (its callbacks would be
refused and no member could authenticate), so an empty file fails loudly.

### 5. Check the appliance came up

```bash
python3 -B deploy/appliance.py firstboot --manifest /etc/sparring-range/appliance-manifest.json
```

Every check is named and reported; the command exits non-zero if any of them
fails. It is read-only and prints no secret. In the staged first boot the
manual-window checks are reported `pending` and the command exits **3** with
the remediation hint — that is "not your window yet", not a failure; exit
**1** means something is genuinely broken. The JSON report never claims
`ok` while anything is pending, and names genuine breakage separately in
`failed`.

### 6. Prove it, and keep the evidence

* `python3 -B deploy/appliance.py status` — units, the broker's inventory.
* `python3 -B deploy/appliance.py doctor` — prerequisites and the KVM state.
* `python3 -B deploy/appliance.py recovery status` — the broker's obligations;
  an unresolved obligation keeps the range reserved and is released only
  with fresh evidence (`recovery resolve --obligation N --evidence FILE`).
* The rehearsal itself (fresh launch → member SSH → sudo → reconnect →
  replay → cleanup → second fresh launch) is the **manual** check of
  milestone 14/17: record the exact commands and outcomes. It cannot be
  automated away, and a green script is not a substitute for it.
* `python3 infra/dev/acceptance.py journey` — the automated member journey
  against the installed appliance. It now requires **all** of:

  | Variable | What it is |
  |---|---|
  | `SR_JOURNEY_BASE_URL` | the installed API (https) |
  | `SR_JOURNEY_OPERATOR_TOKEN`, `SR_JOURNEY_MEMBER_TOKEN` | the two bearer tokens |
  | `SR_JOURNEY_SSH_KEY`, `SR_JOURNEY_BASTION_KNOWN_HOSTS` | the member's key and the pinned bastion host key — the SSH rehearsal is **not** optional |
  | `SR_JOURNEY_BROWSER_URL`, `SR_JOURNEY_BROWSER_USER`, `SR_JOURNEY_BROWSER_PASSWORD` | the browser journey (a real Chromium login into the appliance) |
  | `SR_JOURNEY_CA_FILE` | the appliance's CA, when the URL is private-CA https |

  The journey also walks the **incident workflow**: a submission before the
  release opens is refused (409), an open incident accepts an answer and the
  verifier decides it, and the second answer never re-decides. The failure
  paths (unknown session → 404, unknown incident → 404, an operator-only
  view as a member → 403) are checked in every session.

### 7. Replacing the appliance: fresh reinstall, no preserving upgrade

The appliance is fresh-replacement (operator decision 2026-11-01): a new
release is installed by a **fresh install from the new bundle** (§§0-3) on
a clean VM — configuration, database, recordings and history of the old
installation are **not** carried across. There is no in-place upgrade
engine, admission fence, journal or fence-token to carry, resume or clear.
Quiesce, snapshot/export anything you personally need, then reinstall;
`/etc/sparring-range/release-version.json` no longer exists — the release
identity is the bundle's own `MANIFEST.json` revision.

Post-install checks before admitting members (all operator-side):

```bash
/opt/sparring-range/.venv/bin/python -B /opt/sparring-range/deploy/appliance.py doctor --manifest /etc/sparring-range/appliance-manifest.json
/opt/sparring-range/.venv/bin/python -B /opt/sparring-range/deploy/appliance.py verify --manifest /etc/sparring-range/appliance-manifest.json
curl -fsS https://<appliance>/readyz
# Every unit must ACTUALLY be active — journalctl exits clean for missing
# units, so a bare grep below it can print "clean boot" as a false clean.
for u in sr-appliance-broker.service sr-api.service sr-appliance-ingest.service \
         sr-worker-supervisor.service sr-bastion.service sr-web.service; do
  systemctl is-active --quiet "$u" || { echo "NOT ACTIVE: $u"; exit 1; }
done
# Retrieval is separate from interpretation: if journalctl itself fails,
# that is NOT a clean boot. Output goes to a private file (removed after)
# so the pipeline's exit status is trustworthy.
jlog=$(mktemp) || { echo "cannot create private log file"; exit 1; }
trap 'rm -f "$jlog"' EXIT
if journalctl -u sr-api.service -u sr-web.service \
     -u sr-appliance-broker.service -b --since "-15 min" \
     >"$jlog" 2>/dev/null; then
  if grep -iqE "error|refus" "$jlog"; then
    echo "error/refusal lines found — investigate before admitting members"
  else
    echo "clean boot"
  fi
else
  echo "JOURNAL RETRIEVAL FAILED — status unknown, this is NOT a clean boot"
  exit 1
fi
```

## Historical direct-PVE runbook

The direct-Proxmox operator runbook (discovery, PVE tokens/ACLs, service VMs,
R740 gates and the 2026-10-15 field notes) is preserved in Git history:
`git log -- docs/OPERATOR_RUNBOOK.md`. The Ubuntu/KVM appliance sections
above replace it; the retired PVE adapter is not a production fallback.

## Underpressure replica: operator prerequisites before any build (2026-10-21)

The `underpressure-range` environment (10 real-service Windows guests behind
OPNsense) cannot be built until the operator supplies the media and entitlements
its fidelity ledger names as *not held*. Nothing here is destructive to the
outer host; all steps happen on the appliance or on the operator's workstation.

1. **Licensing path**: Microsoft licensing for this scenario is the operator's
   explicit responsibility. Confirm the agreement covers evaluation-enterprise
   Windows runs and per-seat Windows 11 use for the participating teams, or
   record the operator's accepted basis, before provisioning guests.
2. **Windows 11 SECDISARM ISO**: download from the vendor's evaluation centre,
   record the SHA-256 next to the file, and verify the CPU supports
   Nested Virtualization and AVX-512 on the exact appliance node *before* the
   first install attempt — AMD EPYC Rome and newer meet both; Intel client CPUs
   before Sapphire Rapids do not meet AVX-512, and no hypervisor setting fixes
   that. On an unsupported CPU the workstation guest stays unprovisioned and
   the blueprint records it honestly rather than substituting.
3. **Windows Server 2022 evaluation ISO**: vendor evaluation centre; same
   hash-then-record step. Guest keys are lab-generated (the blueprint refuses
   `owner_key: *` values); activation stays on evaluation keys.
4. **SQL Server 2022 Developer**: vendor download (free for the developer
   use-case, not for competition prize money or production). This is the
   declared *reconstruction* install from the original configuration guide,
   not a re-imaged original.
5. **OPNsense 25.x**: live installer image from the project site; verify the
   published checksum. It substitutes the original's third-party firewall
   distribution: capture the original's exported configuration, translate it
   into OPNsense aliases and rules, and keep the export with the run records.
6. **Winamp**: the original is third-party proprietary media and is *not*
   redistributed or re-downloaded by this project. The replica provisions the
   Windows 11 substitute; if the operator holds a licensed copy, its installer
   can be staged like any other guest software after the guest exists.
7. **Guest images**: builds happen only as the appliance's isolated build VMs
   (no shares to the outer host, no domain join during build). The DC holds the
   only domain-controller role; the domain is the lab's own, generated at
   build time from the blueprint — the original organization's names and
   credentials never enter the appliance.

Until items 1-5 are on the appliance, `sr` environment commands and the broker's
environment deploy path stay correctly blocked (no template VMs exist); fixture
tests remain the only proof of the control plane.
