# sparring-range

A Linux-first, browser-led CCDC defense practice range: disposable lab VMs,
AI attacks, service scoring, timed injects, SSH replay and after-action feedback.

**Status: incomplete and not accepted for live model-driven practice.** Existing
backend, CLI, frontend and safety/evidence repairs are foundations—not proof that
the agreed competition workflow or deployment is finished.

**Current direction (2026-10-20):** one Ubuntu/KVM appliance on Proxmox, with
disposable nested full VMs and the existing external inference endpoint. The
appliance holds no outer-Proxmox credentials. See the
[current architecture](docs/ARCHITECTURE.md#ubuntukvm-appliance--2026-10-20) and
[three-milestone completion sequence](docs/ROADMAP.md#current-completion-sequence--draft-2026-10-20).
Subsequent scoped SSH/isolation commissioning is recorded in the findings ledger;
approved upgrade plans 18–21 and whole-release acceptance remain outstanding.
Older deployment/baseline prose below is historical, not the new installation path.

## Current project contract

- [Project guidance and safety boundaries](AGENTS.md)
- [Release architecture and decisions](docs/ARCHITECTURE.md)
- [Ordered milestones](docs/ROADMAP.md)
- [Current findings and exact validation evidence](docs/FINDINGS_CHECKLIST.md)
- [Operator prerequisites and live gates](docs/OPERATOR_RUNBOOK.md)

The original master plan and accumulated audit/handoff/completion documents are
superseded. Their useful requirements/findings are consolidated above; detailed
historical records remain in Git. No implementation milestone is accepted yet.
OpenChamber Todos hold actionable work; `.openchamber/plans/` contains saved
implementation agreements. Existing numbered plans and roadmap entries remain
traceable history, not a required milestone process. Planning/implementation/review
use native OpenChamber flows and task-selected models, without a custom global
rulebook. [Historical agent receipts](docs/AGENT_HISTORY.md) are not current policy.

## Agreed first release

LAN-only HTTPS at a private IP/port; operator-managed accounts and SSH public keys;
one active environment. Users select web or web+database, guided or competition,
30/60/120 minutes, attack intensity, injects on/off, and explicit network-entry or
assumed-breach starts. Deployment/readiness produces SSH instructions; **Begin
competition** starts the server clock, attacks, service scoring and injects.

Display service-availability, technical-inject and security-state scores
separately. Written reports receive advisory AI feedback, never verified points.
Preserve evidence/reports/replay inputs before automatic VM cleanup; keep history
until explicit operator purge. These are target behaviors, not claims about the
current UI. Windows/AD follows the first Linux release.

Attacker and targets are full VMs, not LXCs. The existing inference LXC on the
same R740 serves the operator's Qwen 3.8 Flash Next endpoint outside the attack
network. AI commands never receive Proxmox/host-root, DB-owner, verifier or NAS
authority. A private deterministic deployment service with restricted PVE access
and permanent operator-configured isolation is planned; current privileged nft
wiring is **not** the accepted production design.

## Repository layout

| Path | Purpose |
|---|---|
| `srplatform/` | FastAPI, DB/migrations, scenario engine, bastion, supervised worker, coach and safety |
| `rangectl/` | HTTP CLI client; explicit offline DB migration/admin exceptions |
| `infra/` | Existing PVE adapter, image/cloud-init, runner and dev deployment artifacts |
| `scenarios/` | Validated YAML snapshots; usable release presets still need completion |
| `verifiers/` | Trusted deterministic state checks, not model self-reported success |
| `telemetry/` | Linux audit shipper/spool/unit and later Windows artifacts |
| `web/` | Next.js Pages Router client of the same API |
| `tests/`, `audit/` | Regression/integration tests and preserved historical probes |
| `.openchamber/plans/` | Agreed milestone plans only |

The Python package is `srplatform`, not `platform`, to avoid shadowing the Python
standard library. Preserve the existing stack; do not rewrite around a new framework.

## Safe development baseline

Python 3.11–3.13 are current CI targets; locked requirements are in
`requirements.lock`. On a new developer environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps -e .
```

Do not replace an existing environment or use live credentials implicitly. Current
optional baseline without DB administration:

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Historical baseline at application revision `23de4f4`, Python 3.13.5:
**exit 1, 9 failed, 107 passed,
115 skipped, 1 deselected, 4 warnings**. Eight process-test failures need
namespace/identity investigation; one unmarked test requires unavailable DB.
Do not weaken containment to satisfy old premises. DB tests need explicitly
approved disposable PostgreSQL administration; skipped tests are not acceptance.

From `web/`, frontend commands are `npm ci` and `npm run build`; browser acceptance
is separate. Fresh lockfile audit: **3 critical / 1 high**, four affected packages;
applicability/patch validation remains open. Do not displace OpenChamber or another
service to free browser-test ports. The audit totals above are historical, not
current findings; consult the dated findings ledger for later repairs and evidence.

Read the runbook before Compose, migration, privileged packet/systemd or live
testing. No production quick-start is claimed yet; deployment, containment,
installed capture, browser workflow and R740 safety still need the ordered gates.
