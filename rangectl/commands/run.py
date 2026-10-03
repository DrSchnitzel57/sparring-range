"""rangectl run — implemented in M3 (red agent harness)."""
import typer

app = typer.Typer(no_args_is_help=True)


@app.command("run")
def run(scenario_id: str):
    typer.echo("red agent harness lands in M3")
    raise typer.Exit(2)
