"""rangectl — the human's primary interface (v1). A Typer app and a pure client
of the API; it never touches Postgres directly (Part 3 front-door rule), with one
sanctioned exception: `db migrate` runs Alembic as the schema-owner role.

Nine-line story (Part 0.5), one command each:
  rangectl db migrate ; safety verify ; deploy <s> ; run <s> ;
  ssh -l tok_web01 drew@bastion ; hint <s> ; score <s> ; report <s> ; teardown <s>
"""
import httpx
import typer

from rangectl.commands import db as db_cmds
from rangectl.commands import safety as safety_cmds

app = typer.Typer(name="rangectl", help="AI Red-Team Sparring Range control CLI.", no_args_is_help=True)
app.add_typer(db_cmds.app, name="db")
app.add_typer(safety_cmds.app, name="safety")


# --- scenario lifecycle ---------------------------------------------------------
@app.command("deploy")
def deploy(scenario_id: str):
    """Clone the scenario's hosts from their golden templates and boot them (M1)."""
    from rangectl.commands.deploy import deploy as _deploy
    typer.echo(_deploy(scenario_id))


@app.command("reset")
def reset(scenario_id: str):
    """Return a deployed scenario's hosts to their golden baseline (M1)."""
    from rangectl.commands.deploy import reset as _reset
    typer.echo(_reset(scenario_id))


@app.command("teardown")
def teardown(scenario_id: str):
    """Remove every clone belonging to a scenario; no orphans left behind (M1)."""
    from rangectl.commands.deploy import teardown as _teardown
    out, code = _teardown(scenario_id)
    typer.echo(out)
    raise typer.Exit(code)


@app.command("run")
def run(scenario_id: str, username: str = typer.Option("drew", help="defending member"),
        no_start: bool = typer.Option(False, help="create the session but don't start the red loop")):
    """Create a session and start the verifier-gated red agent loop (M3)."""
    from rangectl.commands.run import run as _run
    typer.echo(_run(scenario_id, username=username, no_start=no_start))


# --- library / live views ---------------------------------------------------------
@app.command("scenarios")
def scenarios():
    """Browse the scenario library (fields the web launcher filters on, M7)."""
    rows = httpx.get(f"{_base()}/scenarios", timeout=30).json()
    for s in rows:
        typer.echo(f"  {s['id']:<24} d{s.get('difficulty', '?')}  {s.get('est_minutes', '?')}m  "
                   f"focus={','.join(s.get('focus', []))}  techniques={','.join(s.get('techniques', []))}")


@app.command("sessions")
def sessions():
    """List sessions."""
    for s in httpx.get(f"{_base()}/sessions", timeout=30).json():
        typer.echo(f"  {s['session_id']}  {s['scenario_id']:<20} {s['status']}  started={s['started_at']}")


@app.command("status")
def status(session_id: str, tail: int = 15):
    """Live session view: the tail of the append-only log."""
    events = httpx.get(f"{_base()}/events", params={"session_id": session_id}, timeout=30).json()
    for e in events[-tail:]:
        p = e["payload"]
        what = p.get("command") or p.get("objective") or p.get("argv") or p.get("note") or ""
        typer.echo(f"  [{e['ts'][:19]}] {e['actor']:<12} {e['action_type']:<14} "
                   f"{(e.get('phase') or '-'):<14} {str(what)[:70]}")


# --- referee & coach ----------------------------------------------------------------
@app.command("score")
def score(session_id: str):
    """Run the blue scorecard (same verifiers that judge red, against real state, M4)."""
    from rangectl.commands.scoring import score as _score
    typer.echo(_score(session_id))


@app.command("report")
def report(session_id: str):
    """Graded after-action review citing your actual event log (M5)."""
    from rangectl.commands.report import report as _report
    typer.echo(_report(session_id))


@app.command("hint")
def hint(session_id: str, question: str = typer.Argument("",
      help="Optional; empty = 'where am I / what did I miss so far?'")):
    """Ask the coach for a context-aware Socratic hint mid-session (M5)."""
    from rangectl.commands.report import hint as _hint
    typer.echo(_hint(session_id, question))


def _base() -> str:
    from srplatform.settings import get_settings
    return get_settings().api_base_url


if __name__ == "__main__":
    app()
