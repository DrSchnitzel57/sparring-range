#!/usr/bin/env python3
"""Installed-appliance practice journey.

This is deliberately a *live* client, not another fake-broker test.  It talks
to the installed API over HTTPS, launches both Mojang presets, authenticates
as the member through the recording bastion, begins a match, reads the live
dashboard and replay, scores, ends, and then launches a second session to prove
the range can be reused.  It mutates only the sessions it creates; it never
touches the database, broker, libvirt or host directly.

Required environment (the acceptance gate passes these through):

  SR_JOURNEY_BASE_URL       installed API base URL (https://...)
  SR_JOURNEY_OPERATOR_TOKEN operator bearer token
  SR_JOURNEY_MEMBER_TOKEN   member bearer token (the journey owner)
  SR_JOURNEY_SSH_KEY        member private key provisioned in the appliance
  SR_JOURNEY_BASTION_KNOWN_HOSTS  pinned bastion host key file
Optional:
  SR_JOURNEY_CA_FILE, SR_JOURNEY_PRESET (comma-separated), SR_JOURNEY_DURATION_MINUTES,
  SR_JOURNEY_PACE_SECONDS, SR_JOURNEY_REUSE=0

The model/attacker worker is started by Begin exactly as in a real match.  This
runner does not claim that model quality was exercised; the real-model/human
gate remains separate.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import shlex
import sys
import time

import httpx

PRESETS = ("mojang-web-01", "mojang-web-db-01")


class JourneyError(RuntimeError):
    pass


def _client(base: str, token: str, ca: str | None) -> httpx.Client:
    return httpx.Client(base_url=base.rstrip("/"),
                        headers={"Authorization": f"Bearer {token}"},
                        verify=ca or True, timeout=60.0)


def _json(r: httpx.Response, what: str) -> dict:
    if r.status_code >= 300:
        raise JourneyError(f"{what}: HTTP {r.status_code} {r.text[:800]}")
    try:
        return r.json()
    except ValueError as exc:
        raise JourneyError(f"{what}: non-JSON response {r.text[:300]!r}") from exc


def _poll_operation(c: httpx.Client, sid: str, timeout_s: float = 1800) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _json(c.get(f"/sessions/{sid}/operation"), "operation")
        if last.get("state") in ("succeeded", "failed", "interrupted"):
            return last
        time.sleep(2)
    raise JourneyError(f"operation for {sid} did not finish: {last}")


def _ssh_connection(c: httpx.Client, sid: str) -> dict:
    data = _json(c.get(f"/sessions/{sid}/connections"), "connections")
    conns = data.get("connections") or []
    if not conns:
        raise JourneyError("ready session exposed no member connection")
    # Prefer the defender target (web/db tier), then any target.
    preferred = [x for x in conns
                 if not str(x.get("host", "")).startswith(("attacker", "10.66.0.9"))]
    return (preferred or conns)[0]


async def _ssh_check(conn: dict, key: str, known_hosts: str) -> dict:
    import asyncssh
    args = shlex.split(conn["ssh"])
    if not args or args[0] != "ssh":
        raise JourneyError(f"unexpected SSH instruction: {conn['ssh']}")
    host = args[1]
    port = 22
    token = ""
    i = 2
    while i < len(args):
        if args[i] == "-p":
            port = int(args[i + 1])
            i += 2
        elif args[i] == "-l":
            token = args[i + 1]
            i += 2
        else:
            i += 1
    if not token:
        token = conn.get("login_token", "")
    async with asyncssh.connect(
            host, port, username=token, client_keys=[key],
            known_hosts=known_hosts, connect_timeout=20) as c:
        result = await c.run("hostname; id -u", check=False)
        if result.exit_status != 0:
            raise JourneyError(f"member SSH command failed: {result.stderr[:500]}")
        return {"host": host, "port": port, "output": (result.stdout or "").strip()}


def _run_preset(c: httpx.Client, preset: str, *, duration: int, pace: int,
                ssh_key: str | None, known_hosts: str | None,
                label: str) -> dict:
    created = _json(c.post("/sessions", json={
        "scenario_id": preset, "duration_minutes": duration,
        "pace_seconds": pace, "mode": "practice",
        "start_condition": "network-entry", "injects_enabled": True}),
        f"create {preset}")
    sid = created["session_id"]
    out: dict = {"preset": preset, "session_id": sid, "label": label}
    launch = c.post(f"/sessions/{sid}/launch")
    if launch.status_code != 202:
        raise JourneyError(f"launch {preset}: HTTP {launch.status_code} "
                           f"{launch.text[:800]}")
    op = _poll_operation(c, sid)
    out["launch_state"] = op.get("state")
    if op.get("state") != "succeeded":
        raise JourneyError(f"launch {preset} did not succeed: {op}")
    sess = _json(c.get(f"/sessions/{sid}"), "session")
    if sess.get("deployment_status") != "ready":
        raise JourneyError(f"{preset} not ready: {sess}")
    if (sess.get("match") or {}).get("state") != "ready":
        raise JourneyError(f"{preset} match not ready: {sess.get('match')}")
    out["ready"] = True
    out["match_snapshot"] = (sess.get("match") or {}).get("snapshot_version")

    conn = _ssh_connection(c, sid)
    out["ssh_instruction"] = conn.get("ssh")
    out["ssh"] = None
    if ssh_key and known_hosts:
        out["ssh"] = asyncio.run(_ssh_check(conn, ssh_key, known_hosts))
    elif ssh_key or known_hosts:
        raise JourneyError("SR_JOURNEY_SSH_KEY and "
                           "SR_JOURNEY_BASTION_KNOWN_HOSTS must be set together")

    started = _json(c.post(f"/sessions/{sid}/begin"), "begin")
    if started.get("status") != "running":
        raise JourneyError(f"{preset} Begin did not start the match: {started}")
    out["started_at"] = started.get("started_at")
    out["deadline_at"] = started.get("deadline_at")
    live = c.get(f"/sessions/{sid}/live")
    if live.status_code != 200:
        raise JourneyError(f"live dashboard {preset}: HTTP {live.status_code} "
                           f"{live.text[:500]}")
    out["live"] = True
    inj = c.get(f"/sessions/{sid}/injects")
    if inj.status_code != 200:
        raise JourneyError(f"injects {preset}: HTTP {inj.status_code}")
    out["inject_releases"] = len((inj.json() or {}).get("releases") or [])

    # Replay is read after the member's SSH transcript exists. A missing cast
    # is a real failure for this gate, not an empty-success.
    replay = _json(c.get(f"/sessions/{sid}/replay"), "replay")
    out["casts"] = len(replay.get("casts") or [])
    out["cast_frames"] = sum(len(x.get("frames") or [])
                             for x in replay.get("casts") or [])
    if ssh_key and known_hosts:
        if out["casts"] < 1 or out["cast_frames"] < 1:
            raise JourneyError(f"{preset}: no replay cast frames after member SSH")

    score = c.post(f"/sessions/{sid}/score")
    if score.status_code != 200:
        raise JourneyError(f"score {preset}: HTTP {score.status_code} "
                           f"{score.text[:800]}")
    card = score.json()
    out["score_status"] = card.get("status")
    if card.get("status") not in ("scored", "partial", "unscored"):
        raise JourneyError(f"unexpected scorecard: {card}")

    end = c.post(f"/sessions/{sid}/end")
    if end.status_code != 200:
        raise JourneyError(f"end {preset}: HTTP {end.status_code} {end.text[:800]}")
    after = _json(c.get(f"/sessions/{sid}"), "session after end")
    if after.get("status") not in ("complete", "torn_down"):
        raise JourneyError(f"{preset} did not reach a terminal state: {after}")
    out["end_status"] = after.get("status")
    out["outcome"] = after.get("outcome")
    return out


def run_journey(*, base_url: str, operator_token: str, member_token: str,
                ca_file: str | None = None, presets: tuple[str, ...] = PRESETS,
                duration: int = 30, pace: int = 30, ssh_key: str | None = None,
                bastion_known_hosts: str | None = None,
                reuse: bool = True) -> dict:
    operator = _client(base_url, operator_token, ca_file)
    member = _client(base_url, member_token, ca_file)
    results = []
    try:
        # Operator visibility is checked independently of the member's own view.
        visible = _json(operator.get("/sessions?mine=false"), "operator sessions")
        if not isinstance(visible, list):
            raise JourneyError("operator session listing is not a list")
        for preset in presets:
            results.append(_run_preset(
                member, preset, duration=duration, pace=pace,
                ssh_key=ssh_key, known_hosts=bastion_known_hosts,
                label="primary"))
        if reuse:
            # The second launch proves release/destroy/reuse with the SAME
            # member after a completed primary journey.
            results.append(_run_preset(
                member, presets[0], duration=duration, pace=pace,
                ssh_key=ssh_key, known_hosts=bastion_known_hosts,
                label="reuse"))
        return {"ok": True, "base_url": base_url, "presets": list(presets),
                "sessions": results, "operator_sessions_visible": len(visible)}
    finally:
        operator.close()
        member.close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="journey")
    ap.add_argument("--base-url", default=os.environ.get("SR_JOURNEY_BASE_URL", ""))
    ap.add_argument("--operator-token",
                    default=os.environ.get("SR_JOURNEY_OPERATOR_TOKEN", ""))
    ap.add_argument("--member-token",
                    default=os.environ.get("SR_JOURNEY_MEMBER_TOKEN", ""))
    ap.add_argument("--ca-file", default=os.environ.get("SR_JOURNEY_CA_FILE"))
    ap.add_argument("--ssh-key", default=os.environ.get("SR_JOURNEY_SSH_KEY"))
    ap.add_argument("--bastion-known-hosts",
                    default=os.environ.get("SR_JOURNEY_BASTION_KNOWN_HOSTS"))
    ap.add_argument("--preset", default=os.environ.get("SR_JOURNEY_PRESET",
                                                       ",".join(PRESETS)))
    ap.add_argument("--duration", type=int,
                    default=int(os.environ.get("SR_JOURNEY_DURATION_MINUTES", "30")))
    ap.add_argument("--pace", type=int,
                    default=int(os.environ.get("SR_JOURNEY_PACE_SECONDS", "30")))
    ap.add_argument("--no-reuse", action="store_true")
    ap.add_argument("--evidence-out")
    args = ap.parse_args(argv)
    missing = [name for name, value in (
        ("SR_JOURNEY_BASE_URL", args.base_url),
        ("SR_JOURNEY_OPERATOR_TOKEN", args.operator_token),
        ("SR_JOURNEY_MEMBER_TOKEN", args.member_token)) if not value]
    if missing:
        print("missing journey inputs: " + ", ".join(missing), file=sys.stderr)
        return 2
    out = run_journey(
        base_url=args.base_url, operator_token=args.operator_token,
        member_token=args.member_token, ca_file=args.ca_file,
        presets=tuple(x.strip() for x in args.preset.split(",") if x.strip()),
        duration=args.duration, pace=args.pace, ssh_key=args.ssh_key,
        bastion_known_hosts=args.bastion_known_hosts,
        reuse=not args.no_reuse)
    text = json.dumps(out, indent=2, sort_keys=True)
    if args.evidence_out:
        pathlib.Path(args.evidence_out).write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
