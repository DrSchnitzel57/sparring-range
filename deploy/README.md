# Pilot deployment — operator runbook (pilot plan step 7)

The agent builds the artifacts; the OPERATOR executes them. Nothing here
contacts Proxmox or configures host networking automatically — isolation is
operator-owned (project boundary), and attacks stay latched until the
plan's Manual checks pass.

Topology (three machines + one VLAN):

```
 teammates ──HTTPS──▶ control-plane VM ──mTLS──▶ broker VM ──token──▶ PVE host
     │                     │                                            │
     └──SSH :2222──▶ bastion (same VM) ──defender key──▶ range guests ◀─┘
   range VLAN (default-deny) ◀── attacker 9005 ↔ web target 9011 only
   inference LXC 10.10.10.197:8096 — model calls only, outside the range
```

## 0. Release manifest (single non-secret deployment input)

One versioned manifest describes the intended release; every consumer
(env files, broker policy, systemd services, template import verification,
the installer) is derived from it. Validate before use:

```bash
.venv/bin/python -c 'from infra.release_manifest import load_manifest; \
    m = load_manifest("deploy/manifest.example.json"); print(m.release_revision)'
```

`deploy/manifest.example.json` carries **candidate** values (node `pve`,
bridge `srrange`, VLAN 66, storage `local-zfs`, VMIDs 9005/9011/9012,
9100–9199) that fresh operator discovery must confirm — the installer never
assumes them. Secrets never enter the manifest: `secret_inputs` maps each
required secret to a locally protected file the operator installer reads.
The source-of-truth map and per-role renderings live in
`infra/release_manifest.py` (`SOURCE_OF_TRUTH_MAP`, `render_broker_policy`,
`render_env`).

## 1. Build the templates (any machine with QEMU + network)

```bash
python infra/images/pve_template_build.py \
    --out /tmp/sr-templates \
    --pubkey /etc/sparring-range/ssh/bastion_ed25519.pub \
    --roles attacker,mojang-web-local
```

`--pubkey` is the bastion's PUBLIC dial key (see §4) — baked into
root/defender/attacker at the finalize boot; the private half never leaves
the bastion. Output: flattened qcow2 + `SHA256SUMS` + `TEMPLATE-INFO.json`
+ `IMPORT-STEPS.md` (the `qm importdisk` → `qm template` procedure, VMIDs
9005 attacker / 9011 mojang-web-local). Verify `sha256sum -c SHA256SUMS`
before import. Rotating the bastion key = rebuild + reimport (per
generation).

## 2. Control-plane VM (fresh Ubuntu 24.04)

PostgreSQL 16 (owner/app roles — the app role is DML-only, migrations run
as owner):

```sql
CREATE ROLE sr_owner LOGIN PASSWORD '...';
CREATE ROLE sr_app  LOGIN PASSWORD '...';
CREATE DATABASE sparring_range OWNER sr_owner;
```

```bash
git clone <repo> /opt/sparring-range && cd /opt/sparring-range
python3.13 -m venv .venv && .venv/bin/pip install -r requirements.lock .
install -d -o srrange -g srrange /var/lib/sparring-range /etc/sparring-range
cp deploy/env.control-plane.example /etc/sparring-range/control-plane.env
$EDITOR /etc/sparring-range/control-plane.env        # CHANGE the marked values
# migrate + bootstrap (operator account), then systemd:
POSTGRES_URL_OWNER=... .venv/bin/alembic upgrade head
.venv/bin/rangectl bootstrap
install -m 640 deploy/systemd/sr-*.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now sr-api sr-bastion
```

Frontend (built, then served behind self-signed IP-SAN HTTPS):

```bash
cd web && npm ci && NEXT_PUBLIC_API_URL=https://<LAN-IP> npm run build && cd ..
# serve `web/out` (static export) or `npm start` behind nginx:
#   listen 443 ssl; ssl_certificate     /etc/sparring-range/tls/https.crt;
#   ssl_certificate_key /etc/sparring-range/tls/https.key;
#   location / { proxy_pass http://127.0.0.1:3000; }   # or root web/out
#   proxy_read_timeout 900s; proxy_send_timeout 900s;  # REQUIRED: launch is
#     a synchronous deploy (clones + boot + guest-agent key waits) and can
#     legitimately run for minutes; nginx's 60s default 504s the browser
#     while the deploy keeps running server-side (live find 2026-10-14).
```

Trust instructions for teammates: the web cert is self-signed with the LAN
IP in the SAN; `deploy/bootstrap_tls.sh` prints its SHA256 fingerprint —
verify it out-of-band once, then import `https.crt` into the browser/OS or
accept the pin on first visit. The bastion banner shows the session token
login; SSH instructions come from the web UI (server-served, re-fetchable).

## 3. Broker VM (fresh Ubuntu 24.04)

```bash
git clone <repo> /opt/sparring-range && cd /opt/sparring-range
python3.13 -m venv .venv && .venv/bin/pip install -r requirements.lock .
install -d -o srbroker -g srbroker /var/lib/sparring-range /etc/sparring-range
.venv/bin/python deploy/gen_broker_policy.py \
    --node <node> --bridge <range-bridge> --vlan <vlan> \
    --cidr 10.66.0.0/24 --gateway 10.66.0.1 \
    --templates 9005,9011 --vmid-range 9100-9199 --storage <storage> \
    --out /etc/sparring-range/broker-policy.json
cp deploy/env.broker.example /etc/sparring-range/broker.env   # fill in token
install -m 640 deploy/systemd/sr-brokerd.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now sr-brokerd
```

PVE side (operator, on the host UI or `pveum`): create realm user
`sr-broker@pve` with API token `range` — the user name in
`PROXMOX_TOKEN_ID` must match the realm user EXACTLY (a stray hyphen
answers 401 "Authentication failed!", not 403) — ACLs ONLY for the
policy's node,
template VMIDs, VMID range and storages (`VM.Audit, VM.Clone, VM.Allocate,
VM.Config.Network, VM.Config.Cloudinit, VM.Config.Options, VM.PowerMgmt,
VM.GuestAgent.FileRead, Datastore.Allocate, Datastore.AllocateSpace` — on
PVE 9 the guest-agent privileges are `VM.GuestAgent.*` (PVE 8:
`VM.AgentFileRead`) and spawning new VMIDs needs `VM.Allocate` (PVE 8
called it `VM.Create`); `VM.Config.Cloudinit` covers the per-clone
`ipconfig0`, `VM.Config.Options` the ownership `tags`. `VM.Clone`
only on the two template VMIDs; plus `Sys.Audit` on `/nodes/<node>` —
without it PVE hides the whole `/nodes/<node>/...` API subtree from the
token ("no such file" on every call despite full `/vms` rights); plus
`SDN.Use` on the range bridge object `/sdn/zones/localnetwork/<bridge>`
(PVE 8+ treats every bridge as an SDN object — without it the clone
task itself starts and then dies with `403 Permission check failed
(/sdn/zones/localnetwork/<bridge>, SDN.Use)`; live find 2026-10-14:
`pveum role add SRBrokerSdn --privs "SDN.Use" && pveum acl modify
/sdn/zones/localnetwork/srrange --users srbroker@pve --roles SRBrokerSdn`).
`VM.GuestAgent.FileRead` is what lets the broker pin each fresh clone's
SSH host key (no TOFU). Never `Admin.*`. The broker refuses any operation
the policy file does not fully determine (fail closed).

## 4. TLS + keys

```bash
BROKER_HOST=broker.range.internal HTTPS_IP=<LAN-IP> SR_TLS_DIR=/etc/sparring-range/tls \
    deploy/bootstrap_tls.sh
```

Distribute per the script's closing note: CA + `api-client.*` → control
plane; CA + `broker-server.*` → broker VM; `bastion_ed25519` stays on the
bastion (its `.pub` goes into §1). The bastion dials guests as **defender**
with that key (`BASTION_TARGET_USER=defender`, `BASTION_CLIENT_KEY_PATH`) —
the root default is replaced; guest root SSH stays reserved for the
verifier/management key.

## 5. Member onboarding (take-turns accounts)

On the control plane (offline administration exception):

```bash
.venv/bin/rangectl user-add teammate01 --role member
```

Passwords are scrypt-hashed; per-session bastion capabilities are
server-issued login tokens (single-use, revoked at end/expiry) — member
accounts carry no standing range access. Operator-provisioned public keys
are baked at template build (§1) for emergency console access only.

## 6. Match lifecycle the operator will see

* **Launch** → lab `ready`; a ready, un-begun lab **expires after 15
  minutes** and is cleaned up automatically (VMs destroyed, lease freed).
* **Begin** (web button) starts the SERVER 30-minute clock + the sustained
  attacker together (pace 30 s/action default; 0 = no intentional delay —
  snapshotted at session creation).
* The attacker runs **until the deadline** — objective completion does not
  end the match (maintain/deepen). Stop the attacker any time (stop red).
* **End** (button, deadline, or idle expiry) stops and confirms the worker,
  captures final evidence, revokes capabilities, **destroys the owned VMs**
  and frees the range for the next teammate. A blocked stop or failed
  destroy shows `recovery required` and RETAINS the reservation — retry
  `end session`; never work around it.
* An API restart **interrupts** running matches (never resumes them) and
  reconciles cleanup on boot. `SR_MATCH_SCHEDULER_ENABLED=1` runs this
  automatically.

## 7. Operator access matrix (operator configures; agent documents)

| Source → Destination | Purpose | Verdict |
|---|---|---|
| Teammate laptops → control plane HTTPS | Web UI/API | allow |
| Teammate laptops → bastion TCP 2222 | Recorded SSH | allow |
| Control plane → PVE API | Broker operations (via broker only) | allow |
| Control plane → broker | Mutually authenticated TLS | allow |
| Control plane → inference LXC `10.10.10.197:8096` | Model calls | allow |
| Control plane → range guests | Bastion 22 (defender), management SSH (verifier), telemetry ingest, HTTP probe | allow |
| Range guests ↔ each other | Attacker ↔ target only | allow |
| Range guests → telemetry ingest | Installed shipper | allow (narrow) |
| Range → WAN/DNS/IPv6, Proxmox mgmt, NAS, VLAN 30, inference LXC | — | **deny** |

## 8. Before any attack (Manual checks, plan §Manual checks)

VLAN default-deny verified with positive controls; emergency-stop drill
(`hard_stop_all` + read-back + latch release); model smoke test through the
gateway; one full rehearsal (launch → connect → Begin → end → cleanup →
second teammate launches); PVE token/ACL created; templates imported and
`SHA256SUMS` verified. The pilot is not "safe by test suite" — attacks stay
latched until these pass.
