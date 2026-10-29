"""rangectl bastion — account-bound public-key enrollment (plan 22 LIVE-06).

The defender bastion refused a desktop key because the CURRENT account had
no enrolled public key, and nothing could answer "which accounts can
authenticate?" without digging through the operator file. These commands
talk to the API enrollment routes: PUBLIC keys go in, SHA256 fingerprints
come out, and the operator-provisioned commissioning file is never
rewritten. Enrollments take effect on the next authentication (the bastion
hot-reloads the store) — no restart.
"""
import json
from pathlib import Path

import typer

from rangectl import client as c

app = typer.Typer(no_args_is_help=True)


@app.command("status")
def status():
    """Every account with enrolled public keys (operator view)."""
    typer.echo(json.dumps(c.call("GET", "/admin/bastion/enrollment").json(),
                          indent=2))


@app.command("me")
def me():
    """Self-diagnosis: is a public key enrolled for MY account?"""
    r = c.call("GET", "/bastion/enrollment/me").json()
    if r["enrolled"]:
        typer.echo(f"account {r['username']}: a public key can authenticate "
                   f"at the bastion")
        for fp in r["fingerprints"]:
            typer.echo(f"  {fp}")
    else:
        typer.echo(f"account {r['username']}: NO public key enrolled — SSH "
                   f"will refuse even with a valid login token")
        raise typer.Exit(1)


@app.command("enroll")
def enroll(username: str, public_key_file: str = typer.Argument(
        ..., help="file containing ONE OpenSSH public-key line")):
    """Enroll a PUBLIC key for an account (idempotent; re-adding the same
    key changes nothing). Pass the .pub file or '-' to paste."""
    if public_key_file == "-":
        key = typer.prompt("public key", prompt_suffix="")
    else:
        key = Path(public_key_file).read_text()
    r = c.call("POST", "/admin/bastion/enrollment",
               json={"username": username, "public_key": key}).json()
    verb = "enrolled" if r["created"] else "already enrolled"
    typer.echo(f"{verb} for {username}:")
    for fp in r["fingerprints"]:
        typer.echo(f"  {fp}")


@app.command("revoke")
def revoke(username: str, fingerprint: str):
    """Remove one enrolled fingerprint from one account."""
    c.call("DELETE", "/admin/bastion/enrollment",
           params={"username": username, "fingerprint": fingerprint})
    typer.echo(f"revoked {fingerprint} from {username}")
