"""rangectl — the human's primary interface (v1). A Typer app and a PURE
client of the API (front-door rule): no Postgres, no SSH to targets, no local
verifier execution (F11). One sanctioned exception: `db migrate` runs Alembic
as the schema-owner role.

Fresh stack:
  docker compose up -d   (seed-bastion-keys populates the key volume) ;
  rangectl bootstrap ; set SR_BASTION_TOKEN ; docker compose up -d bastion ;
  rangectl login

Practice loop:
  rangectl login ; rangectl launch <scenario> ; ssh <instr> ;
  rangectl run <session> ; rangectl status <session> ; rangectl hint <session> ;
  rangectl end <session> ; rangectl report <session>
"""
import getpass
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import typer

from rangectl import client as c
from rangectl.commands import db as db_cmds
from rangectl.commands import safety as safety_cmds

app = typer.Typer(name="rangectl", help="AI Red-Team Sparring Range control CLI.", no_args_is_help=True)
app.add_typer(db_cmds.app, name="db")
app.add_typer(safety_cmds.app, name="safety")


# --- fresh-stack bootstrap (Stage 5 item 3) -------------------------------------
# Idempotent provisioning path: operator account + service capabilities +
# key-material/recording checks. Key material itself is operator-supplied and
# consumed by the compose seed step (infra/dev/seed_bastion_keys.sh); the CLI
# only validates it — live tokens and keys are never committed or echoed twice.

def _bootstrap_http_call(method: str, path: str, *, json_body=None, headers=None):
    """Like c.call but RETURNS 4xx responses: bootstrap treats 'already
    provisioned' as success, so SystemExit-on-403 would break idempotency."""
    import httpx

    return httpx.request(method, f"{c.base()}{path}", json=json_body,
                         headers=headers or {}, timeout=30)


def run_bootstrap(call, *, username: str, password: str, telemetry_hosts=(),
                  state_path, recordings_dir=None, keys_dir=None) -> dict:
    """Core of `rangectl bootstrap`, against a running API. `call(method,
    path, *, json_body=None, headers=None)` returns an httpx.Response-like
    (production: real HTTP; tests: TestClient). Re-running is safe: a closed
    bootstrap and already-minted capabilities are reported, never re-minted
    (minting is recorded in a 0600 state file). Returns a report dict with
    'steps', 'tokens' and 'problems' (non-empty problems => caller exits 1)."""
    state_path = Path(state_path)
    report = {"operator": username, "steps": [], "tokens": {}, "problems": []}

    def step(msg):
        report["steps"].append(msg)

    # 1. recordings dir (compose mounts the named volume at the same path)
    if recordings_dir:
        rd = Path(recordings_dir)
        rd.mkdir(parents=True, exist_ok=True)
        if not os.access(rd, os.W_OK):
            report["problems"].append(f"recordings dir {rd} exists but is not writable")
        else:
            step(f"recordings dir ready: {rd}")

    # 1b. bastion key material (operator-supplied; the compose seed step
    #     copies it into the bastion-keys volume — checked here, never committed)
    if keys_dir:
        kd = Path(keys_dir)
        for f, why in ((kd / "authorized_keys", "'<username> <algo> <base64>' member lines"),
                       (kd / "target_known_hosts", "pinned range host keys (ssh-keyscan output)")):
            if not f.is_file():
                report["problems"].append(
                    f"missing {f} — the compose seed step (seed-bastion-keys) will fail; "
                    f"provide it per docs/OPERATOR_RUNBOOK.md §0 ({why})")
            elif not f.read_text().strip():
                report["problems"].append(f"{f} is empty — the bastion would authenticate nobody")
            else:
                step(f"key material present: {f}")

    # 2. operator account — 403 'closed' means already provisioned (idempotent)
    r = call("POST", "/auth/bootstrap", json_body={"username": username, "password": password})
    if r.status_code == 201:
        step(f"operator '{username}' created")
    elif r.status_code == 403 and "closed" in r.text:
        step(f"operator '{username}': bootstrap already closed (account exists) — ok")
    elif r.status_code == 403:
        report["problems"].append(
            f"bootstrap refused: {r.text[:200]} (username must equal "
            "BOOTSTRAP_OPERATOR_USERNAME, password needs 10+ chars)")
        return report
    else:
        report["problems"].append(f"bootstrap failed {r.status_code}: {r.text[:200]}")
        return report

    r = call("POST", "/auth/login", json_body={"username": username, "password": password})
    if r.status_code != 200:
        report["problems"].append(
            f"operator login failed {r.status_code}: {r.text[:200]} — on re-run the "
            "password must be the EXISTING operator password")
        return report
    auth = {"Authorization": f"Bearer {r.json()['token']}"}

    # 3. service capabilities — recorded in the state file; never re-minted
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except ValueError:
            report["problems"].append(
                f"state file {state_path} unreadable — repair or remove it (it records "
                "which capabilities were already minted; removing it re-mints)")
            return report
    minted = state.setdefault("minted", {})

    def mint(key, body):
        if key in minted:
            report["tokens"][key] = minted[key]["token"]
            step(f"capability '{key}': already minted {minted[key]['minted_at']} — not re-minted")
            return
        r = call("POST", "/admin/service_tokens", json_body=body, headers=auth)
        if r.status_code != 201:
            report["problems"].append(f"mint '{key}' failed {r.status_code}: {r.text[:200]}")
            return
        tok = r.json()["token"]
        minted[key] = {"token": tok,
                       "minted_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        report["tokens"][key] = tok
        step(f"capability '{key}' minted (shown ONCE — store in your secret store): {tok}")

    mint("bastion", {"scope": "bastion"})
    for host in telemetry_hosts:
        mint(f"telemetry:{host}", {"scope": "telemetry", "host": host})

    # 4. state file (0600 — contains live tokens; same store as the login token)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state["operator"] = username
    state_path.write_text(json.dumps(state, indent=2))
    os.chmod(state_path, 0o600)
    step(f"state recorded: {state_path} (0600, contains live tokens — treat as secret)")
    return report


@app.command("bootstrap")
def bootstrap_cmd(
    username: str = typer.Option(None, help="must equal BOOTSTRAP_OPERATOR_USERNAME"),
    password: str = typer.Option(None, help="else $BOOTSTRAP_OPERATOR_PASSWORD, else prompt"),
    telemetry_host: list[str] = typer.Option(
        [], "--telemetry-host", help="mint a host-bound telemetry capability (repeat per host)"),
    keys_dir: str = typer.Option(
        None, help="operator-supplied authorized_keys/target_known_hosts dir that the compose "
        "seed step consumes (validated only — never committed)"),
    state_file: str = typer.Option(
        None, help="idempotency record (default ~/.rangectl/bootstrap.json, 0600)"),
    recordings_dir: str = typer.Option(None, help="default: settings RECORDINGS_DIR"),
):
    """Fresh-stack bootstrap: operator account + service capabilities + key
    material check + recordings dir. Idempotent — safe to re-run."""
    s = get_settings()
    username = username or s.bootstrap_operator_username
    password = (password or os.environ.get("BOOTSTRAP_OPERATOR_PASSWORD")
                or getpass.getpass("operator password (10+ chars; on re-run the existing one): "))
    state = Path(state_file) if state_file else Path.home() / ".rangectl" / "bootstrap.json"
    rep = run_bootstrap(_bootstrap_http_call, username=username, password=password,
                        telemetry_hosts=telemetry_host, state_path=state,
                        recordings_dir=recordings_dir if recordings_dir is not None
                        else (s.recordings_dir or None),
                        keys_dir=keys_dir)
    for m in rep["steps"]:
        typer.echo(f"  ok  {m}")
    for p in rep["problems"]:
        typer.echo(f"  ERR {p}", err=True)
    if rep["problems"]:
        raise typer.Exit(1)
    if "bastion" in rep["tokens"]:
        typer.echo("next: set SR_BASTION_TOKEN (compose: SR_DEV_BASTION_TOKEN in .env) and "
                   "recreate the bastion — docker compose up -d bastion")


@app.command("user-add")
def user_add_cmd(
    username: str,
    role: str = typer.Option("member", help="member|operator"),
    password: str = typer.Option(None, help="else prompt (10+ chars)"),
):
    """Operator OFFLINE onboarding (control-plane only — the documented CLI
    administration exception): create a take-turns member (or operator)
    account with a scrypt-hashed password. Teammates log in with these;
    per-session bastion capabilities stay server-issued."""
    from sqlalchemy import select
    from srplatform.api.auth import hash_password
    from srplatform.db.models import User
    from srplatform.db.session import db as db_ctx
    if role not in ("member", "operator"):
        typer.echo("role must be member|operator", err=True)
        raise typer.Exit(2)
    password = password or getpass.getpass(f"password for {username} (10+ chars): ")
    if len(password) < 10:
        typer.echo("password too short (10+ chars)", err=True)
        raise typer.Exit(2)
    with db_ctx() as s:
        if s.execute(select(User).where(User.username == username)).first():
            typer.echo(f"user {username!r} already exists", err=True)
            raise typer.Exit(1)
        s.add(User(username=username, role=role,
                   password_hash=hash_password(password)))
        s.commit()
    typer.echo(f"ok: {role} account {username!r} created")


# --- auth ------------------------------------------------------------------------
@app.command("login")
def login(username: str | None = None):
    """Authenticate (operator-provisioned account) and store the session token."""
    username = username or input("username: ")
    password = getpass.getpass()
    r = c.call("POST", "/auth/login", json={"username": username, "password": password})
    c.save_token(r.json()["token"])
    typer.echo(f"welcome {r.json()['username']} ({r.json()['role']}); token stored (expires "
               f"{r.json()['expires_in_h']}h)")


@app.command("logout")
def logout():
    c.call("POST", "/auth/logout")
    f = c.token_file()
    if f.exists():
        f.unlink()
    typer.echo("logged out")


@app.command("whoami")
def whoami():
    typer.echo(c.call("GET", "/users/me").json())


# --- the practice loop --------------------------------------------------------------
@app.command("launch")
def launch(scenario_id: str, run: bool = typer.Option(False, help="start red immediately after deploy")):
    """One command: create session → reserve range → deploy → per-host SSH
    instructions (same backend workflow the browser uses, F08)."""
    sess = c.call("POST", "/sessions", json={"scenario_id": scenario_id}).json()
    sid = sess["session_id"]
    typer.echo(f"session {sid} (scenario snapshot {sess['scenario_sha256'][:12]})")
    out = c.call("POST", f"/sessions/{sid}/launch").json()
    for i in out["connections"]:
        typer.echo(f"  {i['host']}: {i['ssh']}")
    if run:
        r = c.call("POST", f"/run/{scenario_id}", json={"session_id": sid})
        typer.echo(f"  red run {r.json()['run_id']} started")
    return sid


@app.command("run")
def run_cmd(scenario_id: str, session: str = typer.Option(..., "--session", "-s"),
            no_start: bool = typer.Option(False, help="create-if-missing + deploy, don't start red")):
    """Start the verifier-gated red loop for a session (HTTP only)."""
    if no_start:
        typer.echo(f"session {session} ready — start with: rangectl run {scenario_id} --session {session}")
        return
    r = c.call("POST", f"/run/{scenario_id}", json={"session_id": session})
    typer.echo(f"run {r.json()['run_id']} started (verifiers decide everything; "
               f"watch: rangectl status {session})")


@app.command("end")
def end(session_id: str):
    """Idempotent finalize: stop red, TRUSTED final score, evidence, revoke,
    release the range (F11/F13)."""
    r = c.call("POST", f"/sessions/{session_id}/end").json()
    typer.echo(f"session {session_id} → {r['status']} ({r.get('outcome')}); "
               f"score: {r.get('earned')}/{r.get('total')} [{r.get('scorecard_status')}]")


@app.command("score")
def score(session_id: str):
    """Ask the BACKEND to run the trusted scorecard (CLI never runs verifiers, F11)."""
    card = c.call("POST", f"/sessions/{session_id}/score").json()
    if card.get("status") == "unscored":
        typer.echo("unscored — no checks available or hosts unreachable")
        return
    for item in card.get("items", []):
        typer.echo(f"  [{(item.get('status') or '?').upper():<7}] {item['verifier']}@"
                   f"{item.get('host')} {item.get('awarded')}/{item['points']} "
                   f"({item.get('domain')})")
    typer.echo(f"score: {card['earned']}/{card['total']} [{card.get('status')}]")


@app.command("report")
def report(session_id: str, regenerate: bool = False):
    """Graded AAR from the append-only log (persisted; GET never regenerates)."""
    r = c.call("POST", f"/sessions/{session_id}/aar",
               json={"regenerate": regenerate, "narrative": True})
    typer.echo(r.json()["markdown"])


@app.command("hint")
def hint(session_id: str, question: str = typer.Argument("",
      help="Optional; empty = 'where am I / what did I miss so far?'")):
    """Socratic hint (interactive priority on the model gateway)."""
    r = c.call("POST", f"/sessions/{session_id}/hint", json={"question": question}, timeout=200)
    typer.echo(r.json()["hint"])


# --- resources ----------------------------------------------------------------------
@app.command("reset")
def reset(session: str):
    out = c.call("POST", f"/sessions/{session}/reset").json()
    for n in out.get("removed", []):
        typer.echo(f"  destroyed {n}")
    for h in out["hosts"]:
        typer.echo(f"  re-cloned {h['name']} (vmid {h['vmid']}, {h['ip']})")


@app.command("teardown")
def teardown(session: str):
    out = c.call("POST", f"/sessions/{session}/teardown").json()
    for n in out.get("removed", []):
        typer.echo(f"  destroyed {n}")


@app.command("stop")
def stop(run_id: str):
    out = c.call("POST", f"/runs/{run_id}/stop").json()
    typer.echo(f"run {run_id}: {out.get('status')}")


# --- views ------------------------------------------------------------------------------
@app.command("scenarios")
def scenarios():
    """Browse the validated scenario library."""
    for s in c.call("GET", "/scenarios").json():
        if s.get("_valid") is False:
            typer.echo(f"  {s['id']:<24} INVALID: {s.get('_issues')}")
            continue
        typer.echo(f"  {s['id']:<24} d{s.get('difficulty', '?')}  {s.get('est_minutes', '?')}m  "
                   f"focus={','.join(s.get('focus', []))}  techniques={','.join(s.get('techniques', []))}")


@app.command("sessions")
def sessions_cmd(all: bool = False):
    for s in c.call("GET", "/sessions", params={"mine": "false" if all else "true"}).json():
        typer.echo(f"  {s['session_id']}  {s['scenario_id']:<20} {s['status']:<10} "
                   f"{s.get('outcome') or ''}  started={s['started_at']}")


@app.command("status")
def status(session_id: str, tail: int = 15):
    """Live view: LATEST events (server-side tail — F14)."""
    events = c.call("GET", "/events", params={"session_id": session_id, "tail": tail}).json()
    for e in events:
        p = e["payload"]
        what = p.get("command") or p.get("objective") or p.get("argv") or p.get("note") or ""
        typer.echo(f"  [{e['ts'][:19]}] {e['actor']:<12} {e['action_type']:<14} "
                   f"{(e.get('phase') or '-'):<14} {str(what)[:70]}")


@app.command("readyz")
def readyz():
    typer.echo(c.call("GET", "/readyz").json())


if __name__ == "__main__":
    app()
