# sparring-range

Linux-first CCDC practice appliance: FastAPI/SQLAlchemy/Alembic, Typer CLI,
Next.js, PostgreSQL, and a private deterministic libvirt broker. Keep business
logic behind the API; CLI/web are clients. Preserve `srplatform` rather than
shadowing Python's `platform` module.

## Project references

- [README](README.md): orientation and safe development commands.
- [Architecture](docs/ARCHITECTURE.md): current Ubuntu/KVM design and decisions.
- [Findings](docs/FINDINGS_CHECKLIST.md): current receipts, blockers and evidence.
- [Operator runbook](docs/OPERATOR_RUNBOOK.md): prerequisites and live gates.
- [Roadmap](docs/ROADMAP.md): retained product scope and historical status.
- `.openchamber/plans/`: saved implementation agreements; existing numbers are
  historical identifiers, not a required format for future work.

## Domain and safety boundaries

- Attacker/vulnerable targets are full VMs, not host-kernel-sharing LXCs. The
  existing inference LXC is inference-only and outside the attack network.
- Model-selected commands receive no Proxmox/host-root, controller/owner-DB,
  verifier/NAS credentials or GPU devices. No outer-Proxmox credentials enter
  the appliance. API/model/bastion/ingest cannot access libvirt or `/dev/kvm`.
- Only the separate deterministic private broker uses local libvirt for approved
  inner VMs. Legacy PVE tooling is not a production fallback. Never broaden
  privileges, disable containment or execute arbitrary host-shell/firewall work
  to get green tests. Operator-installed rules belong to the dedicated appliance,
  never the outer host or unrelated workloads.
- Range isolation denies management/WAN/Proxmox/model/NAS/unrelated workload
  access except narrow approved control paths. Attacks require real isolation
  and emergency-stop gates, not software doubles or a readiness flag.
- Unknown ownership, containment, readiness, cessation or cleanup is not success.
  Preserve reservations and durable obligations until actually resolved.
- Events are append-only; reports/specifications are versioned. Use forward
  migrations, not edits to applied migrations. Mutable operational metadata is
  an explicit exception, not permission to rewrite evidence.
- The appliance is fully fresh-replacement: no data, upgrade path or
  byte-compatibility from an older installation is preserved (operator
  decision 2026-11-01, widened same day) — drop old contracts when the change
  serves current goals. Preserving-upgrade and legacy-compatibility machinery
  stays green until retired, never extended. This relaxes compatibility only:
  authority, isolation, append-only evidence and fail-closed obligations stay
  fully binding.
- Verified scores require deterministic authenticated evidence; subjective
  feedback cannot award verified points. Enforce competition visibility in APIs.
  Compromised-host telemetry is not independent truth.
- Keep secrets out of Git/images/prompts/logs/recordings. Use synthetic disposable
  fixtures. No destructive live tests, unrelated VM mutations, host firewall
  changes, auditd installation or volume resets without separate authorization.
- Preserve completed commissioning receipts without claiming whole-release
  acceptance. Installed/model/adversarial gates remain distinct from fixture tests.

## Development commands

Infrastructure-free Python checks from the repository root:

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Other gates use `.venv/bin/python infra/dev/acceptance.py <check>`; inspect their
prerequisites first. DB fixtures require disposable `srtest_*` databases via
`SR_PG_ADMIN_URL` or `SR_PG_ADMIN_CMD`, never production. Frontend commands are
`npm ci` and `npm run build` in `web/`; browser acceptance is separate. Do not
displace OpenChamber or another service to free a port.

## Working agreement

Feature work proceeds as small contract-bounded slices; each slice gets ONE
fresh-session review against its contract, with at most one fix round. Receipts
are recorded in the findings ledger only for live-appliance gates. The
per-review-round bundle re-seal and receipt-bundle ceremony is retired; dated
process history lives in Git, not in fresh documents.
