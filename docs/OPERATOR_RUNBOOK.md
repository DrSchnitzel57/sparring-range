# Operator runbook and live acceptance gates

## Current direction — Ubuntu/KVM appliance (2026-10-20)

The user selected one Ubuntu appliance VM with nested full practice VMs. Read
[the appliance architecture](ARCHITECTURE.md#ubuntu-kvm-appliance--2026-10-20)
and [plans 14–16](ROADMAP.md#current-completion-sequence--draft-2026-10-20).
This section began as planning guidance. The installer now exists and the
operator completed commissioning for the supervised AI run on the patched
appliance. See [current receipts and unresolved repairs](FINDINGS_CHECKLIST.md#consolidated-deployment-and-product-status--2026-10-23)
and [the installed patch handoff](HANDOFF-LIVE-PRACTICE.md). The appliance
instructions below are current; later **historical direct-PVE** instructions are
not appliance installation. No new live action is requested by this doc update.

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

These are the commands that actually exist in the tree today. They are the
appliance counterpart of the historical direct-PVE section below, which stays
historical.

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

The steps it performs, if you prefer to run them by hand:

```bash
cd /opt/sparring-range            # the unpacked bundle
python3 deploy/bundle.py verify .            # the bundle root
mkdir -p /etc/sparring-range/keys
ssh-keygen -t ed25519 -N '' -f /etc/sparring-range/keys/runner
ssh-keygen -t ed25519 -N '' -f /etc/sparring-range/keys/bastion
ssh-keygen -t ed25519 -N '' -f /etc/sparring-range/keys/mgmt
install -m 0600 /dev/null /etc/sparring-range/secrets/model.key   # then put the model key in it

python3 deploy/bundle.py manifest . --out /etc/sparring-range/appliance-manifest.json \
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
python3 deploy/appliance.py plan  --manifest /etc/sparring-range/appliance-manifest.json
python3 deploy/appliance.py apply --manifest /etc/sparring-range/appliance-manifest.json --dry-run
python3 deploy/appliance.py apply --manifest /etc/sparring-range/appliance-manifest.json
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
python3 deploy/appliance.py firstboot --manifest /etc/sparring-range/appliance-manifest.json
```

Every check is named and reported; the command exits non-zero if any of them
fails. It is read-only and prints no secret. In the staged first boot the
manual-window checks are reported `pending` and the command exits **3** with
the remediation hint — that is "not your window yet", not a failure; exit
**1** means something is genuinely broken. The JSON report never claims
`ok` while anything is pending, and names genuine breakage separately in
`failed`.

### 6. Prove it, and keep the evidence

* `python3 deploy/appliance.py status` — units, the broker's inventory.
* `python3 deploy/appliance.py doctor` — prerequisites and the KVM state.
* `python3 deploy/appliance.py recovery status` — the broker's obligations;
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

### 7. Preserving in-place upgrade (milestone 21, review-corrected)

The upgrade is driven by a built release bundle — the same artifact you
installed from, at a newer revision.

**Before anything else: a whole-VM snapshot.** The engine keeps config +
database backups, but the honest rollback of a hypervisor-VM appliance is
a powered-off snapshot (or full copy) taken while no engagement runs.
That snapshot, not the engine, is your last resort; keep it until you
have completed the post-upgrade checks below.

Quiesce first: finish or stop engagements, drain model work, and confirm
nothing is in `cessation_unknown` (the CLI now BLOCKS on it — that state
means provider-side cessation is unconfirmed and needs your bounded
resolution, never a restart-over). The credential for the owner dump
travels by ENVIRONMENT ONLY — never a CLI argument, because argv is
world-readable in the process table for the whole upgrade:

```bash
# Run the release bundle's OWN CLI tree with the INSTALLED release venv:
# /opt/sparring-range/.venv/bin/python is the interpreter the services and
# the engine's migrations use, provisioned from the locked requirements and
# re-verified at every provision stage — a bare `python3` or an old
# checkout carries no dependency guarantee for deploy/appliance.py's
# imports (sqlalchemy, alembic). This is the exact tested contract:
# locked python + payload-tree deploy/appliance.py + cwd = payload tree.
cd /srv/sr-release
/opt/sparring-range/.venv/bin/python -c \
  'import deploy.appliance, deploy.upgrade, sqlalchemy, alembic'  # bootstrap check
/opt/sparring-range/.venv/bin/python deploy/bundle.py verify /srv/sr-release  # must pass
# Inline environment assignment: invisible to ps, never in journal or logs.
# Both URL forms are accepted — the installer's SQLAlchemy format
# (postgresql+psycopg2://…) and plain postgresql:// — and the credential
# transport is validated during --dry-run, before any mutation.
SR_PG_UPGRADE_URL='postgresql+psycopg2://sr_owner:…@127.0.0.1:5432/spranging' \
  /opt/sparring-range/.venv/bin/python deploy/appliance.py upgrade \
  --manifest /etc/sparring-range/appliance-manifest.json \
  --payload /srv/sr-release --dry-run
```

If the bootstrap check ever fails on an older venv, that is the venv being
told you it does not match this payload's lockfile — the real run's
provision stage (re)builds it from the payload's own `requirements.lock`
before anything serves; do not hand-install packages to make the check
pass.

The dry-run verifies the COMPLETE payload (bytes, upgrade contract,
inventory, migration graph) and every durable-work authority BEFORE it
answers anything, with zero side effects; a refusal naming a queued or
cessation-unknown job is the quiescence telling you the truth. Only then
remove `--dry-run`. On a provably never-claimed appliance you may add
`--allow-fresh-install`; a missing broker ledger otherwise refuses, on
purpose. Never add it to work around a refusal.

What the real run does, journaled under `/etc/sparring-range/upgrade/`
(the journal tree is never part of the config backup and a restore never
rewrites any journal): it raises the **admission fence**
(`/var/lib/sparring-range/maintenance` — the API then answers 503 to NEW
work — including NEW internal generations like model-turn callbacks —
while terminality callbacks for existing work, login and health keep
flowing, so nothing can race the upgrade and in-flight runs still
terminalize), then **stops the admitting services** (`sr-api`,
`sr-worker-supervisor`) and PROVES them inactive before re-checking every
durable authority: that stop is the barrier an old, not-yet-fence-aware
process cannot bypass, and unconfirmed cessation is refused, never
"ceased" by killing a process. Then the private config backup (original
modes/ownership recorded; journal tree excluded) and a `pg_dump` whose
password arrives ONLY through a private 0600 `PGPASSFILE` — no credential
is in any argv, log or child environment; digest-verified staging;
per-file atomic activation (only payload-owned files — a bundle's ROLE
IMAGES are fresh-install material; an upgrade never replaces your running
guest images); **provisioning of the activated release** (locked
`requirements.lock` install into the service venv, an entrypoint import
check with that venv's own interpreter, the locked frontend build); the
API-only credential-store bootstrap for the 0021 schema contract (creates
the `sr_secret`-style role and its 0600 `secrets/db-secret.env` ONLY when
missing — old 0019-era appliances need no manual SQL); proven FORWARD-only
migrations with the installed venv; config re-render; `systemctl
daemon-reload`; a **checked restart** (every unit restarted AND verified
active); and a **bounded real readiness gate** — the parsed `/readyz`
contract must hold: HTTP 200 AND `ready: true` with NO issues AND
`migration_version` equal to the payload's schema head (a 200 reporting
`ready: false`, or `ready: true` from a stale process at an old head, is
NOT ready; malformed reports fail closed), and the frontend must answer
200. Only then is the version stamp written and the fence dropped — and
the fence is only ever dropped by its OWNING attempt completing; a
config restore of another attempt never releases it. Users, password hashes,
keys/pins, closed sessions, audit rows, casts and historical reports are
never deleted or rewritten; a rerun at the same revision answers `no_op`
— but an UNFINISHED attempt always outranks that answer.

Failure and interruption discipline:

* A failed stage (provisioning, migration, restart) leaves the attempt
  **in progress**, keeps the fence UP (new work stays refused; nothing
  silently resumes on half-verified bytes) and writes NO version stamp —
  the appliance never claims a release that never ran. Fix the cause,
  then resume exactly that attempt: `... upgrade ... --resume
  <ATTEMPT>`; only unfinished stages re-run. A new upgrade is refused
  while any attempt is in progress; never delete a journal to unstick it.
* Migration state after an interruption is PROVEN from the database
  before continuing; an unrecognizable position stops with the attempt
  retained rather than guessing a schema.
* Config-only rollback: `... upgrade --manifest ... --restore-config
  <ATTEMPT>` validates the COMPLETE backup BEFORE writing (a corrupt
  late file changes ZERO files), restores original modes/ownership and
  issues NO service action — you start services yourself, so a restore
  can never resume an engagement. While the attempt is UNFINISHED the
  restore KEEPS the admission fence up (the output says so explicitly):
  restoring config does not roll back the activated runtime or the
  forward-only schema, so admission stays refused until you complete the
  attempt with `--resume` or resolve it deliberately. Only a restore of
  an already-COMPLETED attempt clears a fence — and only when NO other
  attempt is unresolved and the fence provably belongs to the restored
  attempt; a fence owned by another identity, or whose identity cannot
  be read, is kept and reported (releasing it is an explicit recovery
  decision, never a side effect of a config rollback). Database rollback
  is deliberately not offered: schema is forward-only; the attempt
  journal holds your `pg_dump` for an explicit, quiesced `pg_restore`
  if you ever truly need it.
* Supported 0025-era databases with duplicate truncation markers take a
  RECORDED prerequisite (0026's index is un-creatable over legacy rows;
  forward 0027 installs the legacy-safe guard). This is automatic,
  journalled, and deletes nothing. Pre-21 bundles are refused as
  payloads by construction (no `upgrade` contract).

Post-upgrade checks before admitting members again (all operator-side,
on the installed appliance — none of this runs from the upgrade):

```bash
/opt/sparring-range/.venv/bin/python /opt/sparring-range/deploy/appliance.py doctor --manifest /etc/sparring-range/appliance-manifest.json
/opt/sparring-range/.venv/bin/python /opt/sparring-range/deploy/appliance.py verify --manifest /etc/sparring-range/appliance-manifest.json
ls /var/lib/sparring-range/maintenance            # must NOT exist
cat /etc/sparring-range/release-version.json      # the new revision
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

Then log in with a real member account (existing password, not a reset)
and open an old session: member-visible threads must show ONLY
member-audience coach content — sealed legacy coach history is
operator-only by policy (the upgrade fail-closed relabels historical
rows to `legacy`), so a member seeing none of it is the CORRECT result,
not a data-loss symptom; verify the relabel itself as operator, e.g.
`SELECT audience, count(*) FROM coach_messages GROUP BY 1`. Then start
one supervised practice engagement, end it, and replay a pre-upgrade
recording byte-for-byte. Only after all of that remove the pre-upgrade
VM snapshot.

## Historical direct-PVE runbook

Status: **planning runbook, not an accepted production installation guide**.
Updated 2026-10-08; current application baseline `23de4f4` is failing.
See [ARCHITECTURE.md](ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md), and
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md). Old instructions requiring runtime
host-root/nft execution or claiming final acceptance are superseded.

The operator owns Proxmox/network setup and approves disposable live fixtures.
Agents prepare artifacts and execute authorized safe automated tests, not mutate
your R740 or unrelated workloads. No model-driven attacks until actual isolation
and emergency-stop gates pass. Windows/AD gates belong to the later milestone.

## 1. Discovery before production configuration

Record these non-secret inputs when their milestone is planned:

- Installed Proxmox version/node, VMID allocations, approved templates, range
  bridge/VLAN and actual routed/bridged paths; management/model/NAS destinations.
- VM disk storage, free capacity, supported full/linked-clone mode, measured
  clone/reset performance and budget for simultaneous lab disks/recordings.
  Approximately 100 GB free on the boot disk is not an accepted VM/evidence store.
  Add SSD storage if needed; do not cut release features silently.
- CPU/RAM/disk/network budgets protecting other R740 workloads and inference.
- Control-plane VM/bastion placement, private web IP/port, ingest/probe/control
  flow allowlist, PVE CA and trusted guest SSH host-key acquisition method.
- Qwen endpoint URL/API model alias, llama.cpp build, quantization/context limits,
  authentication and measured structured-response/latency compatibility. Existing
  inference LXC stays outside the range and is not an attack host.
- Protected persistent storage and backup destination (NAS can be chosen),
  credential storage/rotation, and disposable restore/test environments.

Do not put real values containing credentials in the repository or recordings.
Unresolved version/storage/ACL inputs block deployment, not authorize guesses.

## 2. Identity, secrets and trust

The operator creates/disables member accounts and provisions member SSH **public**
keys. Never request or upload member private keys. Current bastion key format is
one `<username> <algorithm> <base64-public-key>` entry per authorized key; a live
session token binds the SSH login to its owning member. Production onboarding/
disable/rotation steps will be accepted in milestone 10, not assumed from format.

Keep secret files outside Git/image contexts; `.gitignore` alone does not protect
Docker layers or every generated filename. The old `deploy/bastion/` suggestion
is not an assurance that arbitrary files there are ignored. Keep PVE tokens solely
in the private deployment boundary, owner-DB credentials solely in explicit
offline migration/admin tooling, verifier keys in trusted services, and NAS
credentials solely in protected backup tooling. No such secret enters workers,
model prompts, member/browser responses, telemetry, normal logs or casts.

Pin guest SSH identities through a trusted provisioning channel. An unauthenticated
`ssh-keyscan` alone is not verification; fake development pins/TOFU never satisfy
production readiness. Validate PVE HTTPS with its CA. LAN access still requires
password authentication, ownership checks and scoped/revocable producer tokens.

Production member access will be same-origin `https://<private-ip>:<port>` using
a self-signed certificate with the chosen IP SAN. Distribute/verify its fingerprint
out of band and document client trust installation; do not normalize ignoring all
certificate errors. Do not expose the public API, broker, DB or model to the WAN.

## 3. Network setup and restricted automation

Install static default-deny isolation using operator-owned Proxmox administration
tools. Attacker and targets are full VMs with no host filesystem, NAS, GPU or device
mounts/passthrough. The running platform must not SSH to Proxmox as root or execute
host-shell/firewall commands. The existing nft adapter/renderers are legacy code
to preserve/test while redesigning the boundary, not the accepted deployment path.

Deny range access to WAN (including DNS, IPv4/IPv6 and arbitrary TCP/UDP), Proxmox
management, model LXC, NAS, control administration and unrelated workloads.
Allow only exact necessary bastion replies, scoped telemetry ingestion, trusted
probe and guest-management flows. Telemetry ingestion is a narrow endpoint, not
general API administration. Test bridged and routed traffic, established flows,
and new clone NIC placement. No update proxy exception is enabled during matches;
image provisioning occurs outside the active attack environment.

Provision a dedicated non-root automation identity and restricted PVE token for
approved lab resources only. Validate **effective** ACLs, including denials against
unrelated VMs/LXCs, host administration, forbidden config/mount/storage operations
and privilege changes. An assigned resource pool does not prove isolation. The
token is installed ONLY on the broker VM (`SR_PROCESS_ROLE=broker` with
`PROXMOX_TOKEN_*`); the controller/API holds only its mutual-TLS client
certificate (`BROKER_URL`, `BROKER_CLIENT_CERT/KEY`, `BROKER_TLS_CA_FILE`), and
production validation refuses a controller that carries PVE credentials. The
broker additionally validates typed requests against its operator policy file
(`BROKER_POLICY_FILE`: node, templates, bounded VMID range, storage, clone mode,
exact NIC/VLAN, provisioning fields, aggregate CPU/RAM/disk limits) plus exact
ownership/generation in its protected SQLite ledger. If safe ACLs cannot support
required operations on your PVE version, block deployment and revise the design
explicitly; never widen permissions to make a test green.

Broker startup and operations (broker VM only):

```bash
SR_PROCESS_ROLE=broker python -m infra.broker          # daemon: reconciles, then serves
python -m infra.broker.tools status                    # claims/obligations/lease/audit
python -m infra.broker.tools enroll --vmid N --name X --tag srsess-<hex> --operator drew
python -m infra.broker.tools reconcile-legacy --db-url <app-db> [--adopt]
python -m infra.broker.tools stop --yes --reason "incident"
python -m infra.broker.tools release --operator drew   # refused while obligations open
```

Enrollment and legacy adoption require an EXACT PVE identity match (clone name +
session ownership tag); names/tags never auto-adopt. A broker restart with active
claims and an unverified control lease latches and hard-stops BEFORE serving.

## 4. Images, access and installed capture

Approved paired software plan (2026-10-12):
[03+04 Linux guests and capture](../.openchamber/plans/03-04-linux-guests-capture.md).
This is not an installation acceptance claim. Automated work uses isolated
disposable QEMU fixtures, not the R740. All live testing and storage selection
are deferred; each live gate still requires operator approval. Before deployment,
verify the installed PVE supports scoped `VM.GuestAgent.FileRead` for approved
lab VMs and denies other guest-agent/host operations; never substitute broad
`VM.Monitor` or unrestricted-agent privileges. The proposed broker reads only a
fresh owned clone's public SSH host key; network keyscan/TOFU is not enrollment.
Resource profiles and capacity prerequisites are recorded in the architecture;
templates, control services, recordings and free-space reserve are additional.

Milestone 03 must deliver reproducible Linux web and web+MySQL templates with
synthetic seeded business data, usable services, declared vulnerabilities/limited
footholds, defender guest administration, trusted verification channels and stable
baselines. Existing scripts/YAML are not proof those guests exist. Image versions,
template IDs, service/data baselines and host keys are part of accepted inventory.

Install the trusted operation supervisor **inside the disposable attacker VM**,
not on Proxmox. It requires correctly delegated cgroup v2/kernel facilities and
supported namespace protection; a top-level mkdir/chown example is insufficient.
Milestone 02 must specify/prove launcher identities, migration permissions,
bookkeeping protection and safe cancellation. Missing prerequisites refuse work
before command execution. Development `local-dev` is never a production fallback.

Linux capture requires the actual installed `sparring-shipper` systemd unit as
`srshipper`, its declared input/group/sandbox permissions and writable bounded
spool. The deployment provisions a session/host/generation-scoped capability plus
fresh nonce, never a live token baked into an image. Readiness separately proves:

1. Provisioning and service startup.
2. Authenticated delivery from the exact current capability/nonce/generation.
3. A harmless marker command executed on the guest, captured by real auditd, and
   observed through that installed service at the authenticated API/DB boundary.

`systemctl is-active`, fabricated audit stdin or controller-posted callbacks cannot
substitute for capture. With the unit still active, wrong API/path, invalid token
and unreadable audit input must each block readiness visibly and recover after
repair. Migration 0010/current enrollment code exists, but safe legacy-ready/run
upgrade and exact binding remain unverified here. No installing/reconfiguring
auditd or user accounts on this review host; use an explicitly disposable fixture.

Recording bastion and API need an accepted durable same-path storage or transfer
contract; dev Compose uses a shared volume. Replay exposes opaque IDs, never
filesystem paths/tokens. Missing files, truncation and capture/delivery gaps are
visible. Record only synthetic lab activity, never real admin operations.

## 5. Production startup and match behavior — target, not shipped

**Plan 13 status note (2026-10-14):** the release-stage ladder is now an
API fact — `GET /stages` (operator) reports install-ready (config, schema
at head, state writable; no clone/pin required), lab-ready (+ broker latch
answers) and attack-authorized (+ explicit `SR_ATTACK_AUTHORIZED=1`, set
only after §3 isolation and §6 emergency-stop verification). The guest-
facing range listener serves ONLY the authenticated enrollment/ingest
routes (`deploy/env.telemetry-listener.example`; deploy/README §2a). The
member flow below is exercised end-to-end by the browser acceptance gate
against the Compose stack; live-infrastructure claims remain operator
gates (§9).

Milestone 10 will supply executable managed guest-service packaging, same-origin
HTTPS and exact startup/upgrade/recovery commands. Production is not simply dev
Compose pointed at your real infrastructure. Preserve PostgreSQL 16+ UTF8,
separate owner/app roles, forward Alembic migrations, app-role denial of event
UPDATE/DELETE/TRUNCATE and DB trigger enforcement. Current explicit migration
entrypoint is `rangectl db migrate`; inspect/configure it before authorized use.

Accepted startup order must establish storage/DB, role bootstrap and migrations,
private deployment boundary, API readiness/reconciliation, bastion and frontend,
then dependent jobs. HTTP liveness alone is insufficient. No owner DB URL in
runtime services; no attacks automatically resumed after API restart.

The agreed member flow is: login → approved preset/options → Start practice →
provisioning/readiness → per-host SSH instructions → connect → **Begin competition**
→ defend/watch scores/injects → final evidence/report inputs → automatic cleanup
→ reusable range and retained history. Current code does **not** implement all of
this. Current end leaves resources/reservation until separate teardown; do not
tell members the new automatic cleanup exists yet.

- Options: guided/competition; 30/60/120 minutes; low/normal/high intensity;
  injects on/off; explicit network-entry/assumed-breach starts.
- Ready/unstarted expiry: 15 minutes. Running server clock continues on browser
  closure. API restart interrupts/reconciles; it never silently restarts attacks.
- Service checks: every 10s, 5s timeout. Dashboard refresh: 2s. Attack dispatch
  ceilings: 60/30/15s, no overlaps; not guaranteed achieved attack throughput.
- Model timeout: 60s; at most three attempts with 5/15s delays; exhausted recovery
  interrupts. No hidden scripted attacker or foothold fallback.
- Confirmed scorer-infrastructure outage interrupts and preserves partial results;
  actual target failure counts as downtime when scoring infrastructure is healthy.
- Unknown stop/ownership/cleanup retains durable obligations and lease. New users
  see a blocked/recovery state, not an available environment with residual guests.

Effective operator settings are snapshotted per session. Endpoint testing may
require agreeing revised defaults; do not silently alter an in-progress match.

## 6. Emergency stop, recovery and release

**Implemented (milestone 02):** the killswitch persists the latch first, then
attempts three INDEPENDENT layers and reports each truthfully: (a) worker process
groups, (b) the static isolation layer (operator-managed; the runtime executes no
host commands), and (c) the broker's `hard_stop_all` — hard-stopping every owned
lab VM including pending creations, confirming PVE task exit AND stopped/absent
read-back, continuing across failures, and retaining an obligation plus `unknown`
claim for anything unconfirmed. A claim whose VM reads back with a foreign name
(VMID recycled) is NOT stopped; it becomes an operator obligation. API timeout or
worker death is never treated as confirmation. Independently, the broker's
control lease (5 s heartbeat / 30 s expiry) latches and stops the range by itself
when the control plane dies; renewal can never resume a stopped range.

If the platform/broker is unavailable, the operator uses trusted Proxmox UI/API
to stop only the exact identified owned lab guests. If ownership is uncertain,
inspect the approved reservation/creation ledger and actual identities before
mutating anything—no name-prefix sweep. Do not reset disks or change unrelated VMs.

Retain the lease and unresolved operation/resource inventory until verified
cessation and cleanup. Do not edit evidence, mark obligations done by hand, delete
a corrupt latch, or release merely because the attacker worker disappeared.
Record interruption and reconciliation outcomes without secrets. Safe retry is
idempotent; old callbacks/late starts cannot revive the match.

Release is TWO explicit operator actions in order: (1) on the broker, resolve
every obligation (`status`, `stop_and_confirm` reality, `reconcile-legacy`) and
run `python -m infra.broker.tools release --operator <name>` — refused while any
obligation is open;
(2) release the application latch via the operator API and record fresh
isolation/stop evidence bound to the current configuration. It never restores
WAN access or resumes interrupted attacks. A forward upgrade that finds legacy
pre-broker deployments starts LATCHED (migration 0011) until
`python -m infra.broker.tools reconcile-legacy` verifies and adopts or clears
each residual resource.

## 7. Evidence storage, backup and purge

Reports, score evidence, immutable specs/settings and SSH recordings remain until
explicit operator purge. No automatic eviction. Show usage and block new starts
when evidence cannot be stored safely; an active storage failure is surfaced and
handled conservatively, not silently ignored. Finalization must preserve required
inputs before normal VM cleanup; report model work may finish afterward.

Back up PostgreSQL, casts and reference/template/rubric manifests consistently to
operator-selected protected storage. Keep NAS credentials/mounts out of the range.
Test restores in a disposable isolated stack: identity/history, component scores,
recording references/replay and immutable report versions must survive. Restored
operational state must be reconciled, not restart attacks or mutate old VMIDs.

Milestone 10 specifies backup scheduling/consistency, recovery objectives and an
offline scoped archive/purge procedure with confirmation and export/backup first.
Runtime app roles do not gain event-delete/truncate privileges. Missing/removed
recordings are shown honestly. Do not improvise recursive evidence deletion or
volume resets as a recovery action. Indefinite retention requires capacity
monitoring and an operator decision when storage fills.

## 8. Safe validation commands and prerequisites

### Current optional developer baseline

From the repository root (no DB admin selected):

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

This default selection is infrastructure-free (milestone 01): DB/containment/
packet/browser/live are explicit layers, DB and containment membership derives
from the fixture closure, and the default run has zero prerequisite skips.
Per-gate acceptance runs through `python infra/dev/acceptance.py <check>`
(`selection|python|db|containment|authority|pve-contract|packet|frontend|
compose|browser|images|capture|install|release`),
which executes the real commands and fails on absent prerequisites, empty
selections or cleanup problems. The `authority` gate (milestone 02) needs no
external service: it exercises the real broker policy, SQLite ledger, mutual-TLS
server and cessation read-back over loopback. `packet` and `browser` remain
CI-only on hosts without root/nft or a launchable pinned chromium.
`images`/`capture` build real Ubuntu artifacts under QEMU — set
`SR_GUEST_CACHE` to a DISK-backed directory when `/tmp` is tmpfs (RAM), or
the builds will be OOM-killed. `install` proves the installer contract in a
sandbox and additionally requires the disposable service-VM job
(`SR_INSTALL_VM_EVIDENCE=1`); `release` drives the deployed lab
(`SR_LIVE_BASE_URL`). Both refuse to pass from a sandbox by design.

### Disposable database integration

`python infra/dev/acceptance.py db` starts its own run-owned `postgres:16`
container (unique names/storage, loopback port, synthetic credentials, scoped
cleanup). To point tests at an already-approved disposable cluster instead,
set `SR_PG_ADMIN_URL` or `SR_PG_ADMIN_CMD`; fixtures create/drop unique
`srtest_*` DBs and roles derived from that endpoint and must never target
production. Then run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -m "db and not browser" \
  -q -ra -p no:cacheprovider
```

With `SR_REQUIRE_DB=1` a skipped DB test is a failure. The absence of DB test
failures due to skipped fixtures is not DB acceptance.

### Containment, installed capture and packet jobs

Containment jobs require correctly delegated cgroup v2, user/mount/cgroup/PID
namespace support and actual harmless containment proof; run them with
`python infra/dev/acceptance.py containment` (sets `SR_REQUIRE_CONTAINMENT=1`,
verifies no run-owned cgroups leak). CI now runs required layers as dedicated
jobs (`SR_REQUIRE_*` per job) — a missing prerequisite, empty selection or
skipped required test fails the job; optional developer skips remain.

The required installed-capture fixture/flag/job is **missing**, to be implemented
in milestone 04. Do not run a nonexistent file and call it a hardware-only gate.
Packet tests (`python infra/dev/acceptance.py packet`) need root + nftables +
iproute2 and apply rules ONLY inside disposable network namespaces the tests
create and remove; never install host firewall rules here or on the R740 merely
to get green tests. The CI packet job runs on a standard GitHub Linux VM for
exactly this reason. Required jobs must execute, not skip/deselect.

### Frontend and browser

From `web/`:

```bash
npm ci
npm run build
npm audit --omit=dev --json    # release gate: zero high/critical
```

Browser acceptance (`python infra/dev/acceptance.py browser`) uses a disposable
DB fixture, the pinned local Playwright CLI (`@playwright/cli` web
devDependency), a run-owned named session, FREE-or-configurable ports
(`SR_E2E_API_PORT`/`SR_E2E_WEB_PORT`) and an isolated `.next-e2e` build — a
developer's `.next`, ports 3000/8010 and other services are never displaced.
The E2E (`tests/test_stage5_browser_e2e.py`, `-m browser`) covers the member
workflow plus replay seek with controlled PVE/model/runner/verifier/datapath
boundaries and synthetic capture. It is not real installed telemetry or R740
acceptance.

### Dev Compose

`python infra/dev/acceptance.py compose` validates the real path: image build,
fresh bootstrap and an idempotent rerun with a run-owned project name, loopback
ports, synthetic `SR_DEV_OWNER_PASSWORD`/`SR_DEV_APP_PASSWORD`/bastion token
and synthetic operator keys, asserting alembic-at-head, app-role-only API
readiness and bastion startup behind the key-seeding gate, then removing only
its own resources. `infra/db/bootstrap.sql` takes the app-role password from
`SR_DEV_APP_PASSWORD` (no committed default dependency). Do not point
unaccepted dev defaults at live infrastructure or delete an existing volume.
Fake pins/dev local runner/datapath relaxations are not production safety
evidence.

## 9. Actual R740 release gates — all open

Each gate needs operator approval, exact evidence revision/environment/commands,
non-secret outcomes and positive controls. Early discovery is useful; attack gates
do not become optional because development tests pass.

- [ ] Effective limited PVE ACLs allow only approved operations/resources and deny
  unrelated VM/LXC, host-administration and privilege-expansion access.
- [ ] Real booted lab VM cannot reach WAN/DNS/IPv6, management, inference, NAS or
  unrelated workloads; authorized bastion/probe/ingest flows work. Cover bridge,
  routing and established flows; management stays usable.
- [ ] Emergency stop stops all owned attacker/target VM traffic and work, including
  background/transport-loss/control-outage cases; latch/release/new-start rules are
  honest and manual PVE stop works independently of the application.
- [ ] Supported template clone/read-back/start/reset/teardown and concurrent launch
  conflict work; failures/unknowns retain ownership/lease; unrelated VMs unaffected.
- [ ] Pinned member SSH, interactive/exec/resize/reconnect casts and durable API
  replay work; revoked/foreign keys/tokens fail.
- [ ] Installed Linux auditd/systemd capture under `srshipper` binds current
  session/host/generation, plus active-service API/token/input negatives recover.
- [ ] Qwen endpoint works through bounded shared gateway: valid tool output,
  measured prompt/context/latency, guided hint priority, paced attacks, retry then
  interruption, honest objective verification and no secret/tool authority.
- [ ] Production HTTPS/IP trust, services/role grants/migrations, boot/restart
  interruption, capacity/quota handling and consistent disposable backup restore.
- [ ] Real service break/restore affects separate scores; technical inject timing/
  verification and written advisory feedback work, including partial results.
- [ ] Both presets/start conditions and guided/competition policies work; operator
  and another member complete unaided browser+SSH sessions, view replay/history
  across sessions, and accept the usefulness/truthfulness of the AAR.

Windows licensing/templates, Sysmon/WEC installed capture, Windows verification
and access are later milestone-12 gates, not marked complete by Linux acceptance.

## 10. Operator shell pitfalls (field notes 2026-10-15)

Learned the hard way during the first production install. All of these
look like something else when they bite.

### Scope file edits to the stanza you mean

A `sed` pattern matching line content (e.g. `bridge-vids 2-4094`) matches
every stanza with that line — including `vmbr0`. Narrowing the wrong
bridge to vid 66 drops untagged LAN/management traffic and kills your
own SSH mid-session. Always `diff` against a backup before `ifreload -a`,
and keep the backup until the change is verified:

```bash
cp -a /etc/network/interfaces /root/interfaces.bak-$(date +%F)
# ... edit ...
diff /root/interfaces.bak-* /etc/network/interfaces   # must show ONLY your stanza
```

### `set -e` in pasted blocks ends your session, not your network

A pasted block starting with `set -e` aborts the shell on the first
failed command — and an exited login shell prints `Connection ... closed`,
which reads exactly like a network drop. If SSH "drops" right after a
command fails, check whether the shell simply exited before blaming the
transport. Prefer blocks without `set -e` for interactive pastes so
failures print errors instead of ejecting you.

### Wildcards expand before `sudo` runs

An unprivileged shell expands `*` before `sudo` ever executes. Against a
`0700 root:<group>` directory the glob fails and the literal `*` reaches
the command, which then reports files "not found" that plainly exist.
Let root's shell do the expanding:

```bash
# wrong (your shell expands, fails, sudo sees a literal '*'):
sudo cp /etc/sparring-range/ssh/*_ed25519.pub /tmp/
# right:
sudo bash -c 'cp /etc/sparring-range/ssh/*_ed25519.pub /tmp/'
```

Same rule over SSH — quote so the *remote root* shell expands:

```bash
ssh -t host "sudo bash -c 'cp /src/*_ed25519.pub /tmp/'"
```

(`ssh host "sudo cmd ..."` without a TTY also cannot prompt for a
password; `ssh -t` fixes that half.)

### Service identities before keys, always

Key generation assumes the service user/group already exists
(`install.sh` step 2 runs before step 3 for exactly this reason). Any
manual key flow must preserve that order: create `srrange`/`srbastion`/
`srbroker` first, then generate, then `chown root:<group>` + `chmod`.
Stray keys generated in `$HOME` by a failed run must be deleted, never
left beside the real ones.

### `urls.ingest` is the controller's real range address

The shipped example uses a candidate ingest address. In production
`urls.ingest` (and therefore `trust.san_ips`, and the guests'
`SR_API_URL`) must name the address the control-plane ingest listener
actually binds — the range NIC of the control-plane VM. A wrong value
here fails closed everywhere at once (shipper TLS, enrollment, probes),
which is the intended behavior, not a bug to work around.

### Diagnosing dropped SSH sessions

In order: (1) rule out shell-exit masquerading as a drop (above);
(2) `journalctl -b -p err` for OOM kills — under critical memory
pressure, `fork()` on Enter is exactly when the killer strikes, so
sessions die on keystroke while idling fine; (3) link flaps
(`dmesg | grep -iE 'link|down|up'`, cable/switch); (4) fail2ban or
throttled auth; (5) client-side sleep, Wi-Fi roam, or VPN flap —
correlate with continuous pings to each path before concluding
anything about the host.
### Inter-VLAN transport is firewall-shaped, not broken cabling (2026-10-15)

Service VMs on the management VLAN reach each other over L2, but anything
routed (own gateway, LAN, PVE API) dies unless explicitly allowlisted —
OPNsense denies inter-VLAN by default and the PVE host firewall enforces
its own layer. Symptom pattern: PVE→guest works while guest→PVE times
out. Localize with packet counters (`iptables -L PVEFW-HOST-IN -n -v`)
before changing anything: SYNs arriving means the host rule works and the
return/forward path is the problem; no arrivals means the forward path.

Narrow-allowlist pattern (used for the broker's PVE API path): one
`ACCEPT,in,vmbr0,TCP/8006` rule for source `10.10.10.200/32` at pos 0 —
never widen the `management` IPSet, which also gates host SSH, VNC and
SPICE (five ports). The same shape applies to teammate paths
(LAN → control-plane `:8443`, LAN → bastion `:2222`). Prove each rule
with an authenticated exchange (`401` from the API counts as transport
proof for an unauthenticated probe), not just ping.

### Names must match certificates, not just route

`PROXMOX_HOST` must be a name in the node certificate's SAN
(`pve`/`pve.internal` here — the SAN's stale `.84` IP no longer matches
the host after DHCP drift, so IP-based verification would fail while
hostname verification passes). Resolve it via `/etc/hosts` on the broker
VM; verify the chain against `/etc/pve/pve-root-ca.pem` (the cluster CA,
not the node cert). Same treatment on the control plane: `BROKER_URL`
uses `broker.range.internal` with a hosts entry, keeping the broker
server certificate's DNS SAN valid with no regeneration.

### API-wide 500s mean settings validation failed — read the journal

Production settings validate when the middleware stack builds (first
request), so one bad value 500s every route including `/healthz`. The
unit log names every problem in a `RuntimeError: production config
invalid` list (missing/unreadable SSH keys, wrong key paths). Check that
list before suspecting the network, the database, or the build.

### Generation keys live in one place; env paths must agree with the build

The `.pub` halves baked into templates at build time came from
`/etc/sparring-range/ssh/` — the verifier and runner key paths in
`control-plane.env` must name those same private halves, never fresh
keys generated beside them (fresh keys authenticate nowhere). The
installer no longer creates same-named shadow copies under `tls/`
(`bootstrap_tls.sh` owns generation, generate-if-missing). The ssh dir
itself must stay traversable (`0750 root:<service-group>`); a `0700`
dir denies entitled services while every file inside looks correct.

### Move secrets staged, never pasted; compare host keys by fingerprint

Remote `sudo` over non-interactive SSH cannot prompt (no TTY): stage
files to a readable directory on the source with a real terminal, then
plain `scp` them, fix ownership/permissions at the destination, and
delete the staging. `ssh -p 2222 -o BatchMode=yes` reporting `Host key
verification failed` on a first contact is unknown-key refusal, not
evidence of compromise — `ssh-keyscan` the presented key, compare its
fingerprint against the host's public half out-of-band, and only then
pin it with `UserKnownHostsFile` (no TOFU).
