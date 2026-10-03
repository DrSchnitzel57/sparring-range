"""rangectl — the human's primary interface (v1). A Typer app and a pure client
of the API; it never touches Postgres directly (Part 3 front-door rule), with one
sanctioned exception: `db migrate` runs Alembic as the schema-owner role.
"""
import typer

from rangectl.commands import db as db_cmds
from rangectl.commands import deploy as deploy_cmds
from rangectl.commands import report as report_cmds
from rangectl.commands import run as run_cmds
from rangectl.commands import safety as safety_cmds

app = typer.Typer(name="rangectl", help="AI Red-Team Sparring Range control CLI.", no_args_is_help=True)
app.add_typer(db_cmds.app, name="db")
app.add_typer(deploy_cmds.app, name="deploy")
app.add_typer(run_cmds.app, name="run")
app.add_typer(report_cmds.app, name="report")
app.add_typer(safety_cmds.app, name="safety")


@app.command("hint")
def hint(session_id: str, question: str = typer.Argument("", help="Optional; empty = 'where am I / what did I miss so far?'")):
    """Ask the coach for a Socratic hint mid-session (M5)."""
    from rangectl.commands.report import do_hint

    typer.echo(do_hint(session_id, question))


@app.command("reset")
def reset(scenario_id: str):
    """Return a deployed scenario's hosts to their golden baseline (M1)."""
    from rangectl.commands.deploy import do_reset

    typer.echo(do_reset(scenario_id))


@app.command("teardown")
def teardown(scenario_id: str):
    """Remove every clone belonging to a scenario; no orphans left behind (M1)."""
    from rangectl.commands.deploy import do_teardown

    typer.echo(do_teardown(scenario_id))


if __name__ == "__main__":
    app()
