"""rangectl report / hint (M5) — the payoff, as a pure API client."""
import httpx
import typer

from srplatform.settings import get_settings

app = typer.Typer(no_args_is_help=True)


@app.command("report")
def report(session_id: str):
    """Graded after-action review that cites your actual event log."""
    r = httpx.post(f"{get_settings().api_base_url}/sessions/{session_id}/aar",
                   json={"narrative": True}, timeout=300)
    r.raise_for_status()
    typer.echo(r.json()["markdown"])


def do_hint(session_id: str, question: str) -> str:
    r = httpx.post(f"{get_settings().api_base_url}/sessions/{session_id}/hint",
                   json={"question": question}, timeout=120)
    r.raise_for_status()
    return r.json()["hint"]
