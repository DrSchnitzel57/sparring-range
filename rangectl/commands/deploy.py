"""rangectl deploy — one command stands up and resets a scenario's VMs (M1).
Pure API client (front-door rule): the orchestrator inside the API does the
proxmoxer work; the CLI just calls it and prints."""
import httpx
import typer

from srplatform.settings import get_settings

app = typer.Typer(no_args_is_help=True)


@app.command("deploy")
def deploy(scenario_id: str):
    """Clone the scenario's hosts from their golden templates and boot them."""
    r = httpx.post(f"{get_settings().api_base_url}/deploy/{scenario_id}", timeout=300)
    r.raise_for_status()
    out = r.json()
    for h in out["hosts"]:
        typer.echo(f"  cloned {h['name']} (vmid {h['vmid']}, {h['ip']})")


@app.command("reset")
def reset(scenario_id: str):
    """Return the scenario's hosts to their golden baseline (destroy + re-clone)."""
    r = httpx.post(f"{get_settings().api_base_url}/deploy/{scenario_id}/reset", timeout=300)
    r.raise_for_status()
    out = r.json()
    for name in out.get("removed", []):
        typer.echo(f"  destroyed {name}")
    for h in out["hosts"]:
        typer.echo(f"  re-cloned {h['name']} (vmid {h['vmid']}, {h['ip']})")


@app.command("teardown")
def teardown(scenario_id: str):
    """Remove every clone belonging to the scenario. No orphans."""
    r = httpx.post(f"{get_settings().api_base_url}/deploy/{scenario_id}/teardown", timeout=300)
    r.raise_for_status()
    out = r.json()
    for name in out.get("removed", []):
        typer.echo(f"  destroyed {name}")
    if out["orphans"]:
        typer.echo(f"  ORPHANS: {out['orphans']}")
        raise typer.Exit(1)


# Top-level aliases so `rangectl reset X` / `rangectl teardown X` work too
# (wired in cli.py to these implementations).
do_reset = reset
do_teardown = teardown
