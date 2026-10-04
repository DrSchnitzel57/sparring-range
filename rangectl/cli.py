"""rangectl — the human's primary interface (v1). A Typer app and a PURE
client of the API (front-door rule): no Postgres, no SSH to targets, no local
verifier execution (F11). One sanctioned exception: `db migrate` runs Alembic
as the schema-owner role.

Practice loop:
  rangectl login ; rangectl launch <scenario> ; ssh <instr> ;
  rangectl run <session> ; rangectl status <session> ; rangectl hint <session> ;
  rangectl end <session> ; rangectl report <session>
"""
import getpass

import typer

from rangectl import client as c
from rangectl.commands import db as db_cmds
from rangectl.commands import safety as safety_cmds

app = typer.Typer(name="rangectl", help="AI Red-Team Sparring Range control CLI.", no_args_is_help=True)
app.add_typer(db_cmds.app, name="db")
app.add_typer(safety_cmds.app, name="safety")


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
