"""rangectl safety — operator-side safety operations (F02). All calls carry the
authenticated token; these endpoints are operator-only."""
import json

import typer

from rangectl import client as c

app = typer.Typer(no_args_is_help=True)


@app.command("killswitch")
def killswitch():
    """Engage: stop workers AND drop the range datapath — independently, truthfully."""
    r = c.call("POST", "/safety/killswitch").json()
    for line in r.get("actions", []):
        typer.echo(f"  {line}")
    typer.echo(f"killswitch: {r['killswitch']}")
    if r.get("warning"):
        typer.echo(f"WARNING: {r['warning']}", err=True)


@app.command("release")
def release():
    """Remove the emergency ruleset (baseline deny preserved); invalidates evidence."""
    r = c.call("POST", "/safety/killswitch-release").json()
    typer.echo(json.dumps(r, indent=2))


@app.command("status")
def status():
    typer.echo(json.dumps(c.call("GET", "/safety/status").json(), indent=2))


@app.command("baseline-check")
def baseline_check():
    """Run backend baseline verification and RECORD the outcome."""
    r = c.call("POST", "/safety/baseline-check", json={}).json()
    typer.echo(json.dumps(r, indent=2))


@app.command("datapath-proof")
def datapath_proof(vm_hostname: str, ping: str, dns: str, ipv6: str | None = None):
    """Record the operator's live proof from a range VM (probes as OBSERVED —
    your attestation; the API stores what you state you saw)."""
    probes = {"ping": ping, "dns": dns}
    if ipv6:
        probes["ipv6"] = ipv6
    r = c.call("POST", "/safety/datapath-proof", json={"probes": probes, "vm_hostname": vm_hostname}).json()
    typer.echo(json.dumps(r, indent=2))


@app.command("reclassify")
def reclassify(kind: str, reason: str = typer.Option(..., "--reason"),
               expect_recorded_at: float | None = typer.Option(
                   None, "--expect-recorded-at",
                   help="recorded_at of the record being classified; refuses "
                        "if the newest record has since changed")):
    """ONE-TIME classification of a legacy pre-contract qualification record
    (the recovery the safety surfaces name). This does NOT mint a fresh test:
    it records that YOU verified the existing record's provenance, bound to
    today's configuration, original kept. A failed/already-contracted/absent
    or changed record is refused."""
    body = {"kind": kind, "reason": reason}
    if expect_recorded_at is not None:
        body["expect_recorded_at"] = expect_recorded_at
    r = c.call("POST", "/safety/reclassify-qualification", json=body).json()
    typer.echo(json.dumps(r, indent=2))
