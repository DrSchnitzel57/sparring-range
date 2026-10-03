"""rangectl deploy — implemented in M1 (linked clones from golden templates)."""
import typer

app = typer.Typer(no_args_is_help=True)


@app.command("deploy")
def deploy(scenario_id: str):
    raise typer.Exit(_pending("M1"))


@app.command("reset")
def reset(scenario_id: str):
    raise typer.Exit(_pending("M1"))


@app.command("teardown")
def teardown(scenario_id: str):
    raise typer.Exit(_pending("M1"))


def _pending(m: str) -> int:
    typer.echo(f"deploy layer lands in {m}")
    return 2
