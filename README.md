# sparring-range

AI Red-Team Sparring Range — built to `plan.markdown` (Parts 1–7 are the contract).

The one-line mental model: this repo is the *factory* (code, config, scripts); the
R740 + range VLAN + GPU box are the *kitchen*. Nothing here runs until it's pointed
at real infrastructure via `.env` (see `.env.example`).

## Layout

Per plan Part 3, with **one deviation**: the plan's `platform/` directory is named
**`srplatform/`** here, because `platform` is a Python stdlib module that SQLAlchemy,
the OpenAI SDK, and proxmoxer all import — a top-level importable package named
`platform` shadows the stdlib and breaks the stack whenever the repo root is on
`sys.path`. Contents are identical to the plan's intent.

```
rangectl/          Typer CLI — the human's main interface; pure API client
                   (only sanctioned exception: `db migrate` runs Alembic as owner)
infra/             proxmoxer wrapper, cloud-init, firewall egress-deny + killswitch,
                   golden-image scripts, dev Dockerfile, db bootstrap roles
srplatform/        the platform (plan's `platform/`): api, db (models+alembic),
                   bastion, red_agent, coach, scenario_engine
verifiers/         deterministic checks — the ONLY thing allowed to declare red success
scenarios/         YAML scenario specs (the product's contract)
telemetry/         auditd rules + Sysmon config + the ~100-line tail-and-POST shipper
web/               M7 Next.js app — thin client of the same FastAPI service
tests/             one test per acceptance criterion (gates between milestones)
```

## Hard constraints (Part 1) — where they live in code

1. **Range VLAN has no WAN egress** → `infra/firewall/range-egress-deny.nft.conf.tmpl` (default-DENY). Datapath proof is Drew's (`rangectl safety verify`).
2. **Killswitch stops the red agent AND drops the datapath, tested first** → `srplatform/safety.py` + `infra/firewall/killswitch.sh`; `tests/test_m0_acceptance.py`.
3. **No self-reported success** → `verifiers/` only; grades/objectives derive from verifier-result events.
4. **Event log is append-only** → Alembic migration `0001` (RAISE trigger + role revocations); test attempts an UPDATE and expects failure.
5. **Secrets never enter the repo** → `.env` (gitignored); only `.env.example` committed.
6. **Home-LAN trust boundary** → no internet-facing exposure, simple LAN auth.

## Design rules honored

- **API is the only front door** — CLI and web are both HTTP clients; nothing else
  touches Postgres.
- **New capability = new scenario YAML field + a verifier**, not new machinery.
- **The log is the product** — AAR, timeline, scorecard, /hint, replay are all
  queries over `events`.

## Dev loop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
cp .env.example .env        # fill in your infra
.venv/bin/pytest            # one test per acceptance criterion
docker compose up           # dev postgres+api+agents (real deploy = LXCs)
```

## Milestones

M0 skeleton+safety ✅ (automated gates pass locally; datapath proof pending Drew's VLAN)
M1..M7 — see `plan.markdown` Part 5; tests named `test_m<N>_acceptance_*.py`.
