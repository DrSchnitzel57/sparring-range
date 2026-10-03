"""rangectl score — referee-side blue scoring (M4). Runs the same verifiers that
judge red objectives against REAL host state via the management exec channel,
so blue and red are judged by identical code. Writes results as verifier events."""
import httpx
import typer

from srplatform.settings import get_settings

app = typer.Typer(no_args_is_help=True)


@app.command("score")
def score(session_id: str):
    base = get_settings().api_base_url
    sess = next((s for s in httpx.get(f"{base}/sessions", timeout=30).json()
                 if s["session_id"] == session_id), None)
    if not sess:
        typer.echo("session not found")
        raise typer.Exit(1)

    from srplatform.red_agent.sandbox import KaliSandbox
    from srplatform.scenario_engine.scoring import compute_blue_score
    from verifiers.base import Context

    result = compute_blue_score(sess["scenario_id"], Context(exec=KaliSandbox().verifier_exec))
    for item in result["items"]:
        mark = "PASS" if item["awarded"] else "FAIL"
        typer.echo(f"  [{mark}] {item['verifier']}@{item['host']} +{item['awarded']}/{item['points']}")
    typer.echo(f"score: {result['earned']}/{result['total']}")

    # record the scorecard in the append-only log (evidence for the AAR)
    httpx.post(f"{base}/events", json={
        "session_id": session_id, "actor": "system", "action_type": "verifier",
        "payload": {"scorecard": result},
    }, timeout=30)
