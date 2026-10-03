# AI Red-Team Sparring Range — Master Build Plan (v1)

**Audience:** this document is written to be read by two different readers.

- **A coding agent** will treat Parts 1–7 as its contract: constraints it may not break, a stack it should not reinvent, a repo layout to follow, and milestones with concrete "accept when…" tests it must pass before moving on.
- **You (Drew)** should read **Part 0** first. It explains what the agent is actually producing, where your hardware and your hands come into it, and how a pile of generated code turns into a running system on your R740. Every milestone then repeats that split under **"You (human) do"** so you always know what is yours to do and what is the agent's.

> **One-line mental model:** the coding agent builds a *factory* (a repository of code, config, and scripts). You pour the *foundation* (Proxmox, networking, GPU serving, golden images) and flip the *power* on (deploy, run, verify). The code is inert until it runs against real infrastructure that only you can stand up.

---

## Part 0 — What you're actually building (read this first)

### 0.1 What the coding agent produces

The agent does not "build a system." It writes **files into a git repository**: Python modules, SQL migrations, YAML, config templates, shell scripts, tests. That's it. When the agent says "I built the red agent," what exists is `platform/red_agent/*.py` — a program that does nothing until something runs it and points it at a real model endpoint and a real target network.

So the question "how do I go from what the agent creates to something real?" has a precise answer: **you clone that repo onto your R740, install its dependencies, give it secrets and addresses for your real infrastructure (via `.env`), run its database migrations, and then run its commands.** The repo is the recipe; your hardware is the kitchen.

### 0.2 The architecture is just processes on networks

Every box in your diagram is a normal program ("service") running somewhere and listening on a port. Demystified:

| Box in the diagram | What it really is | Where it runs |
|---|---|---|
| Web UI | a Next.js process | platform LXC (M7) |
| API | a FastAPI/uvicorn process on a port | platform LXC |
| Event DB | a PostgreSQL server | platform LXC |
| Scenario Engine | a Python library the API imports | in-process |
| Red Agent Svc | a Python process running a loop, calling the GPU box over HTTP | platform LXC |
| Coach Svc | a Python process, same idea, bigger prompts | platform LXC |
| SSH Bastion | an `asyncssh` proxy process | boundary LXC |
| Kali attacker | a container with attack tools the red agent shells into | range VLAN |
| Win DC / Win10 / Linux / web app | cloned VMs | range VLAN |
| vLLM / model endpoint | a model server exposing an OpenAI-style HTTP API | your GPU box |

Nothing here is magic. "The agent attacks the DC" means: the Red Agent process asks the model what to do, gets back a command, runs that command inside the Kali container, and the command's packets travel over the range VLAN to the DC. Then it writes a row to Postgres describing what it did.

### 0.3 The three planes (this is the part people get wrong)

Keep three networks clearly separate in your head and on the host:

1. **Control plane (management network).** Where the platform services talk to each other and where *you* operate from your laptop (`rangectl`, the API, the DB, SSH to the bastion). Has normal LAN access.
2. **Range VLAN.** Where the attack happens: Kali + the target VMs. **No WAN egress, ever.** The red agent reaches *into* this network to attack; you reach into it *only* through the bastion. If an uncensored model running attack tools can reach the internet, you have built a liability, not a lab. This is why safety is milestone zero.
3. **GPU serving.** Your 3×V620 box exposing an OpenAI-compatible endpoint. The platform talks to it from the control plane. It is *not* on the range VLAN.

Blue (you) → SSH → **bastion** → into the range. Red (agent) → Kali container → into the range. Both land their events on the **one event log** in the control plane.

### 0.4 What only YOU can do (the agent cannot)

A coding agent working in a repo cannot touch physical or host-level reality. These are yours:

- Install/confirm **Proxmox** on the R740.
- Create the **Linux bridge + VLAN** for the range and **verify at the datapath** that it has no route to the WAN (the agent can write the firewall config; only you can confirm packets actually die).
- Create a **Proxmox API token** so `rangectl` can drive the host without your root password.
- Build the **golden images** once — especially the **Windows DC and Win10** (licensing, interactive OOBE, Sysmon install). This is hands-on-keyboard work the agent can script around but cannot perform.
- Stand up the **model serving stack** on the GPU box and prove it answers (see the ROCm warning in Part 6 — this is your single biggest unknown).
- **Run the acceptance tests** at each milestone and refuse to let the agent advance until they pass.

The milestones below are explicit about this at every step.

### 0.5 How the repo becomes a running system (deployment flow)

This is the literal path from "agent finished a milestone" to "it runs on my box":

```
1. git clone <repo>  onto the R740 (or a management LXC)
2. install deps        (uv/pip for Python; the agent provides exact versions)
3. cp .env.example .env ; fill in:
     - POSTGRES_URL
     - PROXMOX_HOST + PROXMOX_TOKEN_ID + PROXMOX_TOKEN_SECRET
     - LLM_BASE_URL (your GPU box OpenAI endpoint) + LLM_API_KEY (dummy ok locally)
     - RANGE_VLAN / bridge names, template VMIDs, bastion address
4. rangectl db migrate         # create the event schema
5. rangectl safety verify      # prove the range can't reach WAN  <-- gate
6. rangectl deploy <scenario>  # clone target VMs for a scenario
7. rangectl run <scenario>     # start the red agent loop
8. ssh drew@bastion -l tok_web01   # you defend, from your own terminal
9. rangectl report <session>   # get the graded after-action review
```

If you understand those nine lines, you understand the whole product. Everything the agent builds is in service of making one of those commands work.

---

## Part 1 — Hard constraints (non-negotiable; the agent may not skip these)

These override convenience, speed, and any milestone pressure. If a milestone can't be done without violating one, stop and ask.

1. **Range VLAN has no WAN egress.** The only permitted outbound path is an explicit, whitelisted update proxy (if any), and even that is off by default. Default-deny, not default-allow.
2. **A killswitch exists and is tested before any model-driven attack runs.** `rangectl safety killswitch` must (a) stop the red agent service and (b) drop the range datapath, both. It must be provably effective from *inside* a range VM, not just "the rule is configured."
3. **No self-reported success anywhere in grading.** The red agent may *claim* compromise; only a **deterministic verifier** that checks real state (a flag file, an AD account, a registry key) makes it true. Grades and objectives depend only on verifiers.
4. **The event log is append-only.** No `UPDATE`/`DELETE` on the events table by the application role; enforce with a DB trigger *and* role permissions. The log is evidence; evidence that can be edited is worthless.
5. **Secrets never enter the repo.** `.env`, API tokens, model keys live outside git. Commit `.env.example` only.
6. **This is a home-LAN trust boundary.** No internet-facing exposure, no multi-tenant hardening, no real destructive malware/ransomware. Out of scope is out of scope (see the WON'T list in the source spec).

---

## Part 2 — Tech stack (decided — do not re-litigate)

Chosen for a solo student who needs to *understand and debug* the system, so: one primary language, minimal framework magic, transparent loops over heavy orchestration libraries.

- **Primary language:** Python 3.11+. One language for CLI, API, agents, verifiers.
- **CLI:** `rangectl`, built with **Typer** — the primary *human* interface for v1, and itself a client of the API (it never touches Postgres directly; see Part 3).
- **API:** **FastAPI** + **uvicorn**. This is the **single source of truth**: every client — the `rangectl` CLI now, the web app in M7 — goes through it, and nothing else touches Postgres directly (see the front-door rule in Part 3).
- **Database:** **PostgreSQL 16**, accessed via **SQLAlchemy 2.x**, migrations via **Alembic**.
- **Proxmox automation:** the **`proxmoxer`** Python library, driven from inside `rangectl`, using a Proxmox **API token** (not root). *(Terraform with the `bpg/proxmox` provider is an acceptable alternative for the deploy layer if you prefer declarative infra, but keep it optional — one unified Python tool is easier for you to reason about.)*
- **SSH recording proxy:** **`asyncssh`**. Session recordings written as **asciinema cast v2** (`.cast`) files for replay.
- **Command source of truth:** **auditd** (`execve`) on Linux targets and **Sysmon** on Windows targets, shipped into the event log. (See Part 6 for *why the bastion alone can't give you clean commands.*)
- **LLM client:** the official **`openai`** Python SDK, pointed at your local OpenAI-compatible endpoint via `LLM_BASE_URL`. **The harness is model-server-agnostic** — it only needs an OpenAI-shaped HTTP API, so the serving stack is swappable (critical; see Part 6).
- **Red agent orchestration:** a **hand-rolled loop**, not LangChain/LangGraph for v1. You learn more and debug faster seeing the raw `load state → prompt → call → parse → execute → log → verify` cycle. Revisit frameworks only if the loop gets unwieldy.
- **Telemetry shipping:** **Vector** (or a ~100-line custom Python tail-and-POST shipper) from auditd/Sysmon into an API ingest endpoint. Custom shipper is fine for v1.
- **Dev vs. prod containers:** **docker-compose** for local development of the platform services; **LXC** containers on Proxmox for the real deployment. The agent builds the compose file for dev; you place services into LXCs for the range.

---

## Part 3 — Repository structure (the agent creates this skeleton in M0)

```
sparring-range/
├── README.md
├── pyproject.toml                 # deps pinned here
├── .env.example                   # every required var, documented, no secrets
├── docker-compose.yml             # dev: postgres + api + agents
│
├── rangectl/                      # the CLI — the human's main interface
│   ├── cli.py                     # Typer app
│   └── commands/                  # deploy, run, report, hint, safety, db
│
├── infra/                         # Proxmox + network automation
│   ├── proxmox_client.py          # proxmoxer wrapper
│   ├── cloud-init/                # per-template cloud-init configs
│   ├── firewall/                  # range egress-deny rules + killswitch
│   └── images/                    # golden-image build/provision scripts
│
├── platform/
│   ├── api/                       # FastAPI app (event ingest, sessions)
│   ├── db/                        # SQLAlchemy models + alembic migrations
│   ├── bastion/                   # asyncssh recording proxy
│   ├── red_agent/                 # the harness: loop, memory, tools, phases
│   ├── coach/                     # AAR generation + /hint
│   └── scenario_engine/           # YAML load/validate + orchestration
│
├── verifiers/                     # deterministic checks (red objectives + blue scoring)
├── scenarios/                     # YAML scenario specs (the product's contract)
├── telemetry/                     # auditd/Sysmon configs + shipper
└── tests/                         # one test per acceptance criterion
```

**Design rule the agent must honor:** new capability = **new scenario YAML field + a verifier**, not new machinery. If adding a feature means editing the core loop or the schema, pause and justify it. This is what keeps the project to one semester instead of forever.

**Second design rule — the API is the only front door.** All reads and writes go through the FastAPI service. `rangectl` (today) and the web app (M7) are both just *clients* of that API — neither talks to Postgres directly, and no logic lives in the CLI that the web app can't reach. Honor this and the web front end becomes a thin layer of views instead of a second, divergent system; break it and you will end up maintaining two half-products. This is the single decision that makes the "cyber gym" web experience cheap to add later.

---

## Part 4 — Data model (the backbone; build this in M0)

### 4.1 Core tables

```sql
-- A gym member. Added in M0 even though v1 has one user, because
-- retrofitting identity into an append-only log later is miserable.
users (
  user_id      uuid primary key,
  username     text unique not null,
  display_name text,
  created_at   timestamptz not null default now()
);

-- A play-through of one scenario by one member.
sessions (
  session_id   uuid primary key,
  scenario_id  text not null,
  user_id      uuid references users(user_id),  -- the primary defender
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  status       text not null,          -- 'running' | 'stopped' | 'complete'
  players      jsonb                   -- reserved for future team mode
);

-- THE event log. Append-only. Source of truth for everything.
events (
  event_id        bigserial primary key,
  session_id      uuid references sessions(session_id),
  ts              timestamptz not null,   -- when it actually happened
  ingested_at     timestamptz not null default now(),
  actor           text not null,          -- 'red' | 'blue:<user>' | 'system' | 'telemetry'
  host            text,                   -- target host, or 'bastion'
  action_type     text not null,          -- 'tool_call'|'command'|'detection'|'verifier'|'hint'|'aar'
  phase           text,                   -- red kill-chain phase, nullable
  mitre_technique text,                   -- nullable
  payload         jsonb not null,         -- structured details
  raw_ref         text,                   -- pointer to .cast offset / raw blob
  raw_output_hash text                    -- integrity of raw output
);

-- Rolling agent memory, so context lives in the DB, not a chat window.
agent_state (
  session_id   uuid references sessions(session_id),
  summary      text,                      -- LLM-compressed "situation report"
  summary_upto bigint,                    -- last event_id folded into summary
  current_phase text,
  updated_at   timestamptz default now()
);
```

### 4.2 Append-only enforcement (constraint #4, made real)

- Revoke `UPDATE`/`DELETE` on `events` from the application DB role.
- Add a trigger that `RAISE`s on any `UPDATE`/`DELETE` of `events`.
- The acceptance test for M0 explicitly tries to update a row and expects failure.

### 4.3 Why this is "the product"

The AAR, the live timeline, the scorecard, `/hint`, and replay are **all just queries over `events`**. Build the log first and correctly and the rest is views; get it wrong and you rebuild everything. This table is also your answer to the "the agent forgets" fear: the agent reconstructs its situation from `agent_state` + recent `events` after any restart or context overflow — it never relies on the model remembering.

The same philosophy covers the gym's progress tracking: a member's scores by domain over time (M7) are a **view** that joins verifier-result events to `sessions` and `users` — not a new table. "Add a feature" almost always means "write a new query," not "change the backbone."

---

## Part 5 — Milestones (dependency order; gate on acceptance tests)

Each milestone: **Goal**, **Agent builds**, **You (human) do**, **Accept when**. The agent must not start a milestone until the previous one's acceptance test passes.

### M0 — Skeleton & safety *(nothing ships until this passes)*

- **Goal:** repo exists, DB schema exists, and the range provably cannot reach the internet.
- **Agent builds:** repo skeleton (Part 3); Postgres models + Alembic migration (Part 4) including append-only enforcement; `docker-compose.yml` for dev; `.env.example`; `infra/proxmox_client.py`; `infra/firewall/` egress-deny rule templates; `rangectl safety killswitch` and `rangectl safety verify`; `rangectl db migrate`.
- **You (human) do:** install/confirm Proxmox on the R740; create the range Linux bridge + VLAN; create a Proxmox API token for `rangectl`; place the GPU box on the control-plane side (not the range); apply the egress-deny config; then **prove it** from a throwaway VM on the range VLAN.
- **Accept when:**
  1. From a VM on the range VLAN, `ping 1.1.1.1` **fails** and DNS resolution **fails**.
  2. `rangectl safety killswitch` stops the red agent service **and** drops range traffic, confirmed from inside a range VM.
  3. `rangectl db migrate` creates the schema; an attempted `UPDATE events SET ...` **raises** an error.

### M1 — Templates & deploy

- **Goal:** one command stands up and resets a scenario's VMs.
- **Agent builds:** `rangectl deploy|reset|teardown` using `proxmoxer` + **linked clones**; per-template cloud-init; Linux golden-image provisioning scripts; (optional) Packer config for repeatable image builds.
- **You (human) do:** build and boot the golden images **once** — Ubuntu server/web, and the fiddly ones: **Windows DC** and **Win10** (licensing/OOBE, install **Sysmon** with a sane config, install auditd on Linux); snapshot each as a Proxmox template; put the template VMIDs in `.env`.
- **Accept when:** `rangectl deploy web-foothold-01` creates the scenario hosts from templates; `rangectl reset` returns them to a clean baseline; `rangectl teardown` removes every clone with no orphans left behind.

### M2 — Event bus + bastion recording (blue capture)

- **Goal:** you SSH in normally, with copy-paste, and everything you do is logged and replayable — **with zero vision/screenshot cost**.
- **Agent builds:** the `asyncssh` recording proxy that (a) lets you pick a target via a token login (`-l tok_web01`), (b) dials the real VM, (c) tees the byte stream to an asciinema `.cast`, (d) writes session events to `events`; auditd config + an API ingest endpoint that records `execve` events as `action_type='command'` tied to the live `session_id`.
- **You (human) do:** deploy the bastion LXC on the boundary between your management access and the range; confirm you can `ssh` through it into a range host and that scrollback/copy-paste work like a normal terminal; confirm auditd events arrive.
- **Accept when:** you SSH through the bastion into `web01`, run several commands, and afterward (1) a replayable `.cast` of the session exists and (2) the corresponding auditd command events appear in `events` with the correct `session_id`.

### M3 — Red agent harness *(the risky, iterate-heavy milestone)*

- **Goal:** a scenario-seeded red agent achieves a real, verifier-confirmed objective end-to-end, with every action logged.
- **Agent builds:** a tool-execution sandbox that runs commands **inside the Kali container, constrained to the range VLAN**; the LLM client (`openai` SDK → `LLM_BASE_URL`); the **hand-rolled loop** (`load agent_state + recent events → build prompt → one model call → parse JSON tool call → execute → log event → run relevant verifiers → compress old history into agent_state → advance phase`); a kill-chain **phase state machine** (recon → initial-access → priv-esc → lateral → persistence → objectives); a strict JSON tool-call schema; one trivial scenario wired to a flag verifier.
- **You (human) do:** stand up the model server on the GPU box and **prove the endpoint works with a plain `curl`** before the agent relies on it (see Part 6 — this is where your real risk lives); choose the model; set `LLM_BASE_URL`; babysit the first runs and tune the prompts/compression with the agent.
- **Accept when:** `rangectl run web-foothold-01` drives the agent to the `foothold` objective; the **flag verifier** (not the model's own claim) confirms compromise; every red step is in `events` with a `phase` tag; killing and restarting the agent process mid-run resumes correctly from `agent_state`.

### M4 — Scenario engine + verifier library

- **Goal:** scenarios are pure data; verifiers are reusable; the same verifiers that confirm red objectives also score blue.
- **Agent builds:** the YAML loader + schema validator (including the scenario-library metadata — `focus`, `est_minutes`, `techniques` — that the M7 launcher filters on); a `Verifier` interface and a library covering CCDC staples — rogue account, persistence (run key / scheduled task / service / cron), disabled AV/firewall, exfil flag, unpatched service, data-integrity, flag-file; wiring so each verifier can serve as a red objective check **and** a blue scorecard item.
- **You (human) do:** author 1–2 more scenarios in YAML; sanity-check a few verifiers against real host state to confirm they report truth.
- **Accept when:** a scenario defined **entirely in YAML (no code changes)** deploys, runs, and produces a score; adding a new objective is a YAML edit reusing an existing verifier.

**Verifier interface (the agent should implement to this shape):**
```python
class Verifier:
    id: str
    description: str
    mitre: list[str]
    def check(self, ctx) -> VerifierResult:   # -> {passed: bool, evidence, ts}
        ...
```

**Scenario YAML (target shape):**
```yaml
id: web-foothold-01
name: "Vulnerable web app foothold"
difficulty: 1
focus: [web, initial-access]        # library filter: domain / skill area
est_minutes: 30                     # shown in the scenario library
techniques: [T1190, T1505.003]      # MITRE, for library browse + AAR tagging
topology:
  hosts:
    - name: web01
      template_vmid: 9001
      ip: 10.66.0.10
      services: [http]
red:
  start_phase: recon
  objectives:
    - id: foothold
      verifier: flag_file_present
      args: { host: web01, path: /root/flag_foothold.txt }
    - id: persistence
      verifier: cron_persistence_present
      args: { host: web01 }
scoring:
  blue_checks:
    - { verifier: no_rogue_admin, host: web01, points: 10 }
    - { verifier: firewall_enabled, host: web01, points: 5 }
```

### M5 — Coach (AAR + hints)

- **Goal:** the payoff — a graded after-action review that cites your actual log, and Socratic hints on demand.
- **Agent builds:** a timeline compressor; the AAR generator (coach model → graded report with **MITRE ATT&CK + NIST CSF** mapping, "what you missed and when," "what you did well," a prioritized study list); a `/hint` endpoint that queries `events` for where you currently are and answers Socratically; a **priority request queue** in the API so interactive hints never starve behind the red agent's 200th recon call.
- **You (human) do:** play a full session; read the AAR; judge whether it's actually useful; iterate on the rubric prompt with the agent.
- **Accept when:** `rangectl report <session>` emits a graded AAR that **cites specific logged events with timestamps** (e.g., "Sysmon flagged the new service at 14:02 — you never investigated it"); `rangectl hint` returns a context-aware Socratic hint mid-session without stalling the red loop.

### M6 — First real practice session

- **Goal:** prove the loop closes for a real user (you).
- **Agent builds:** glue and CLI ergonomics surfaced by real use.
- **You (human) do:** run `deploy → defend → report` end-to-end as blue, unaided; write down every rough edge.
- **Accept when:** you complete a full scenario without touching the coding agent, and the AAR teaches you something true about your own play.

### M7 — The web app (the gym front door)

This is the phase that turns the engine into a *gym*: a place multiple teammates log into, practice in, and track progress over time. Nothing here re-architects anything — **every screen is a view over the event log, and the web app is just another client of the API** (Part 3's front-door rule). The Next.js app lives in a new top-level `web/` directory and talks only to FastAPI.

- **Goal:** a teammate who has never touched the CLI can log in, pick a scenario, practice, and get graded feedback and progress — all from the browser.
- **Agent builds:**
  - **Accounts & login:** `users`-backed auth with simple session tokens (LAN-appropriate — *not* SSO/OAuth), plus per-member history.
  - **API endpoints** backing every view below (scenario listing, live session state, AAR, replay data, progress) — added to the same FastAPI service, not a new one.
  - **Scenario library / launcher:** browse exercises by `difficulty`, `focus`, `est_minutes`, and `techniques`; one click launches a session (same code path as `rangectl deploy|run`).
  - **Live session dashboard:** current red phase, detections as they fire, a session clock, and a "request hint" button — your situational scoreboard while you defend in the terminal.
  - **After-action review page:** the payoff — overall grade, per-CCDC-domain scorecard, a red-vs-blue timeline that flags exactly what you missed and when ("Sysmon caught the new service at 14:02 — you never looked"), MITRE/NIST mapping, and a prioritized study plan.
  - **Replay:** asciinema `.cast` playback scrubbed in sync with the event timeline, so you can rewatch yourself against what red was doing at each moment.
  - **Progress dashboard:** per-domain scores across sessions, trends, and which skills lag — a **view** derived from events (no new tables).
- **You (human) do:** create member accounts for the team; deploy the web app and API as LXCs on the control plane; play several sessions; judge honestly whether the AAR *content* is good enough to hand a teammate before polishing the chrome.
- **Accept when:** a teammate (not you) logs in, browses the library, launches and defends a scenario using only the browser plus their terminal, and then reads a graded AAR and a progress dashboard that reflects more than one session.
- **Do NOT build here (scope traps that turn a semester into a decade):** live head-to-head PvP; real-time multi-watcher collaboration (websocket presence, shared cursors); enterprise auth / SSO / RBAC (simple LAN accounts are enough); and above all, **don't gold-plate the UI until the after-action reviews are genuinely useful** — a beautiful dashboard around a mediocre AAR is lipstick.

> **Beyond M7 (only if the semester allows):** difficulty adaptation (red gets more patient or aggressive based on your detection rate), a spaced-repetition study graph built from your AARs, C2 integration (e.g. Sliver) for beacon-hunting practice, custom scenario import, and true team mode (multiple defenders on one scenario). Each of these should still be *a new scenario field + a verifier + a new query*, not new machinery.

---

## Part 6 — Known integration risks (where YOU must stay in the loop)

These are the things most likely to burn you, roughly in order. The agent can't de-risk them for you because they live in hardware and model behavior, not in code.

### 6.1 ⚠️ GPU serving on AMD V620 is your biggest unknown — validate it *before* M3

Your 3×V620 are **AMD RDNA2 (gfx1030)** cards, not Nvidia and not AMD's data-center CDNA (MI-series) line. vLLM's ROCm support is strongest on CDNA; on RDNA2 it can range from "needs careful build flags" to "painful," and quantized models (GPTQ/AWQ) on ROCm are hit-or-miss. **Do not assume `vLLM on V620` just works.**

Because the harness only needs an **OpenAI-compatible endpoint**, the serving stack is a swappable component. Realistic options, in order of likely reliability on these cards:
1. **llama.cpp server** (ROCm or Vulkan backend) with its OpenAI-compatible API.
2. **Ollama** (also exposes an OpenAI-compatible endpoint).
3. **vLLM on ROCm** — best throughput *if* you can get your model/quant running on gfx1030.

**Action:** treat "a local OpenAI endpoint answers a `curl` with your chosen model" as a literal prerequisite for M3. Prove it standalone first. If vLLM fights you, switch backends — the architecture doesn't care which one answers.

### 6.2 You can't cleanly parse interactive commands from the bastion byte stream

The clever bastion is real, but be honest about what it captures. An **interactive shell** runs over a PTY channel — you get a raw byte stream full of terminal escape codes and line editing, **not** clean command strings. Reliable command-level events therefore come from **auditd (`execve`) on Linux and Sysmon on Windows**, which are the source of truth; the bastion `.cast` is for **replay**. (You *can* also parse the non-interactive `exec` channel for `ssh host "cmd"` invocations, but don't build grading on scraping an interactive PTY.) This is why M2 pairs the recording proxy with auditd rather than relying on the proxy alone.

### 6.3 Windows template engineering is fiddly

Licensing aside, the DC and Win10 images need interactive setup, a sane Sysmon config, and patch-level control so planted vulns stay planted. Budget real hands-on time in M1; this is the least-automatable step.

### 6.4 Local-model agent reliability needs tuning time

A mid-size local model is made effective by the **harness** (phase state machine, strict tool schema, deterministic verifiers filtering hallucinated "success"), not by being a big model. Expect M3 to be iteration-heavy: prompt shape, the rolling-summary compression, and tool-call parsing are where local behavior gets finicky. The verifiers are what make it *trustworthy* even when the model is mediocre — lean on them.

### 6.5 GPU contention between the three call types

Red-loop calls (frequent, short), coach AARs (rare, huge context), and hints (interactive, latency-sensitive) will collide on one box. Either run two model instances (small-fast for red, big for coach) if VRAM allows, or run one model behind the **priority queue** from M5 so `/hint` never waits behind a long red batch.

---

## Part 7 — How the coding agent should work

- **Gate on acceptance tests.** Do not start milestone N+1 until milestone N's "Accept when" passes. Write an automated test per acceptance criterion in `tests/`.
- **Small, reviewable changes.** One concern per commit; keep diffs readable so Drew can follow what changed.
- **Respect the hard constraints (Part 1) above all.** If a task seems to require WAN access from the range, an editable event log, or self-reported red success — **stop and flag it**, don't work around it.
- **Minimal dependencies.** Prefer the stdlib and the chosen stack; justify any new library. Favor transparent code over framework magic so Drew can debug it.
- **Secrets stay out of git.** Read everything environment-specific from `.env`; commit only `.env.example`, fully documented.
- **Log verbosely and structurally.** When in doubt, write an event. The log is the product.
- **Assume Drew owns the infrastructure.** When a task needs Proxmox/network/GPU/image work, produce the script or config and a short "Drew: run this / verify this" note — do not pretend to have performed host-level actions.

---

## Appendix — Glossary (for Drew)

- **Control plane / management network:** where the platform services and your laptop operate; has normal LAN access.
- **Range VLAN:** the isolated attack network; **no WAN egress**; reachable only via the bastion (you) or the Kali container (red agent).
- **Bastion / jump host:** the recording SSH proxy you connect through; gives you normal copy-paste while teeing the session to a recording and logging commands.
- **Linked clone:** a Proxmox VM cloned cheaply off a template, sharing the base disk — fast deploy/reset, which is what makes per-scenario spin-up practical.
- **cloud-init:** first-boot configuration (hostname, users, packages) baked into a VM so clones come up configured.
- **LXC vs. VM:** LXC = lightweight Linux container (platform services); VM = full virtual machine (the Windows/Linux targets).
- **OpenAI-compatible endpoint:** an HTTP API shaped like OpenAI's; any server speaking it (vLLM, llama.cpp, Ollama) is a drop-in for the harness.
- **Verifier:** deterministic code that checks real system state to confirm a fact — the only thing allowed to declare red success or score blue.
- **AAR (after-action review):** the graded report the coach produces from the event log after a session.
- **Kill-chain phases:** recon → initial access → privilege escalation → lateral movement → persistence → objectives; the states the red agent moves through.
- **asciinema cast:** a text format recording of a terminal session, replayable later.
- **auditd / Sysmon:** host logging on Linux / Windows; your authoritative source for "what command ran" and "what the host detected."
- **Killswitch:** the command that immediately halts all red activity and severs the range datapath — tested before any model-driven attack runs.
