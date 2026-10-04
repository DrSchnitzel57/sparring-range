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

## Milestones — all built, one commit per milestone

| Milestone | Automated acceptance (tests/) | Drew's live-infra gate (Part 0.4) |
|---|---|---|
| M0 skeleton+safety | ✅ append-only UPDATE raises (real PG), killswitch kills+datapath-drops, default-deny ruleset | prove ping/DNS die from a real range VM |
| M1 templates+deploy | ✅ linked clones, cloud-init IP pin, reset=destroy+reclone, teardown no orphans | golden images (esp. Win DC/Win10+Sysmon) |
| M2 bastion+event bus | ✅ real asyncssh round-trip: `.cast` v2 both directions + auditd ingest tied to live session | bastion LXC at the boundary |
| M3 red harness | ✅ verifier-gated objectives, phase-tagged steps, anti-self-report gate, kill/resume from agent_state | model endpoint `curl` proof (Part 6.1) + prompt tuning |
| M4 scenarios+verifiers | ✅ validator (unknown verifier/points/host rejected), pure-YAML scenario runs+scores, YAML-only objective addition | author 1–2 more scenarios |
| M5 coach | ✅ AAR cites event timestamps/ids; hint context-aware; hint jumps the queue ahead of batches | judge AAR usefulness |
| M6 practice loop | ✅ CLI-over-real-HTTP end-to-end: scenarios→deploy→run→hint→status→report→teardown | run it unaided, list rough edges |
| M7 web gym | ✅ login/library/live/AAR/replay/progress endpoints (progress = SQL VIEW over the log); Next.js app builds; browser-checked login→library→progress | member accounts, LXC deploy, judge AAR before polishing |

`rangectl` story (Part 0.5) — every command implemented:
`db migrate` · `safety verify/killswitch` · `deploy` · `run` · `status` · `hint` · `score` · `report` · `reset` · `teardown` · `scenarios` · `sessions`

## Deviations & environment notes (honest list)

1. **`platform/` → `srplatform/`** (above).
2. **Driver: psycopg2**, not psycopg3 — psycopg3 returns bytes for text on
   SQL_ASCII databases (this box's cluster default) and SQLAlchemy's dialect
   chokes. Drew's production DB must be **UTF8** (see `infra/db/bootstrap.sql`
   comment; the test fixture enforces `ENCODING 'UTF8' TEMPLATE template0`).
3. The local asyncssh build required `public_key_auth_supported() -> True` and
   `line_editor=False` on the bastion server (transparent pipe — no double echo).
4. Killswitch is provably effective in-process/API-level in tests; **the
   "from inside a range VM" proof is Drew's** — that is by design (Part 0.4)
   and `rangectl safety verify` prints the exact commands to run.
5. Web app is dev-only-cors (localhost origins), LAN trust — matches
   constraint #6; do not expose to the internet.

## Dev loop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
cp .env.example .env        # fill in your infra
.venv/bin/pytest            # 23 tests — one per acceptance criterion
docker compose up           # dev postgres+api+agents (real deploy = LXCs)
cd web && npm install && npm run build && npm start   # the gym front door
```
