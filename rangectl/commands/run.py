"""rangectl run — start the red agent loop for a scenario (M3)."""
import httpx
import typer

from srplatform.settings import get_settings

app = typer.Typer(no_args_is_help=True)


@app.command("run")
def run(scenario_id: str, username: str = typer.Option("drew", help="defending member"),
         no_start: bool = typer.Option(False, help="create the session but don't start the loop")):
    """Deployed scenario -> create session -> start the verifier-gated red loop."""
    base = get_settings().api_base_url
    sid = httpx.post(f"{base}/sessions", json={"scenario_id": scenario_id, "username": username},
                     timeout=30).json()["session_id"]
    typer.echo(f"session {sid}")
    if no_start:
        return
    r = httpx.post(f"{base}/run/{scenario_id}", json={"session_id": sid}, timeout=30)
    r.raise_for_status()
    typer.echo("red agent loop started (verifiers decide everything; watch with: "
               f"curl '{base}/events?session_id={sid}')")
