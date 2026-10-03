"""rangectl safety — killswitch and egress verification (hard constraints #1/#2)."""
import httpx
import typer

from srplatform.settings import get_settings

app = typer.Typer(no_args_is_help=True)


@app.command("killswitch")
def killswitch():
    """Stop the red agent service AND drop the range datapath. Both, provably."""
    r = httpx.post(f"{get_settings().api_base_url}/safety/killswitch", timeout=30)
    r.raise_for_status()
    for line in r.json().get("actions", []):
        typer.echo(line)
    typer.echo(f"killswitch: {r.json()['killswitch']}")


@app.command("killswitch-release")
def killswitch_release():
    """Release the killswitch (baseline egress-deny must remain active)."""
    r = httpx.post(f"{get_settings().api_base_url}/safety/killswitch-release", timeout=30)
    r.raise_for_status()
    typer.echo(r.json()["note"])


@app.command("verify")
def verify():
    """Report safety config state and the live datapath proof Drew must run."""
    r = httpx.get(f"{get_settings().api_base_url}/safety/verify", timeout=30)
    r.raise_for_status()
    for k, v in r.json().items():
        typer.echo(f"{k}: {v}")
