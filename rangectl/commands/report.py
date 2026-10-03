"""rangectl report / hint — implemented in M5 (coach)."""
import typer

app = typer.Typer(no_args_is_help=True)


@app.command("report")
def report(session_id: str):
    typer.echo("coach AAR lands in M5")
    raise typer.Exit(2)


def do_hint(session_id: str, question: str) -> str:
    return "coach hints land in M5"
