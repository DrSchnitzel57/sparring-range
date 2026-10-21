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
import subprocess
import sys
import time
import uuid

import httpx

REPO = pathlib.Path(__file__).resolve().parents[2]

PRESETS = ("mojang-web-01", "mojang-web-db-01")

# The match options the product must cover (plan 15): both presets, the three
# durations, the two modes, both start conditions and the inject toggle.  The
# journey walks this matrix so a missing option is a failed journey, not a
# silently untested one.
SESSION_OPTIONS = (
    {"duration_minutes": 30, "mode": "practice",
     "start_condition": "network-entry", "injects_enabled": True},
    {"duration_minutes": 60, "mode": "practice",
     "start_condition": "network-entry", "injects_enabled": True},
    {"duration_minutes": 120, "mode": "practice",
     "start_condition": "network-entry", "injects_enabled": True},
    {"duration_minutes": 30, "mode": "practice",
     "start_condition": "assumed-breach", "injects_enabled": True},
    {"duration_minutes": 30, "mode": "practice",
     "start_condition": "network-entry", "injects_enabled": False},
    {"duration_minutes": 30, "mode": "evaluation",
     "start_condition": "network-entry", "injects_enabled": True},
)


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


def _playwright_cli() -> str | None:
    """The PINNED local Playwright CLI (the web devDependency)."""
    local = REPO / "web" / "node_modules" / ".bin" / "playwright-cli"
    if local.exists():
        return str(local)
    import shutil

    return shutil.which("playwright-cli")


def _browser_check(base_url: str, username: str, password: str, *,
                   cli: str | None = None, timeout: int = 180) -> dict:
    """Drive a REAL browser against the installed appliance.

    The member's browser journey (login -> library) is part of the product:
    an API-only journey would not notice a frontend that cannot log in, and
    the review of the release must not accept one.
    """
    cli = cli or _playwright_cli()
    if not cli:
        raise JourneyError("the browser step needs the pinned playwright CLI "
                           "(run `npm ci` in web/ first)")
    session = f"sr-journey-{uuid.uuid4().hex[:8]}"

    def pw(*args, check=True, timeout=timeout):
        r = subprocess.run([cli, f"-s={session}", *args], capture_output=True,
                           text=True, timeout=timeout, cwd=str(REPO))
        if check and r.returncode != 0:
            raise JourneyError(f"playwright-cli {' '.join(args)} -> "
                               f"{r.returncode}: {(r.stdout or r.stderr)[-400:]}")
        return r

    out: dict = {"base_url": base_url}
    try:
        pw("open", base_url, "--browser=chromium")
        pw("fill", 'input[placeholder="username"]', username)
        pw("fill", 'input[placeholder="password"]', password)
        pw("click", 'button[type="submit"]')
        deadline = time.time() + 60
        body = ""
        while time.time() < deadline:
            body = pw("--raw", "eval", "document.body.innerText",
                      check=False).stdout
            if "scenario library" in body or "sparring-range" in body:
                break
            if "expired" in body.lower() or "invalid" in body.lower():
                raise JourneyError(f"the browser login was refused: {body[:300]}")
            time.sleep(1)
        if "scenario library" not in body:
            raise JourneyError("the browser never reached the scenario library "
                               f"after the login: {body[:300]}")
        out["logged_in"] = True
        out["library"] = True
    finally:
        pw("close", check=False)
    return out


def _inject_workflow(c: httpx.Client, sid: str, *, wait_s: float) -> dict:
    """The incident (break) -> submission -> decision workflow.

    The release inbox is the product's incident plan: each entry breaks
    something in the practice environment and the verifier decides whether
    it was repaired.  This step proves the whole path:

    * a submission BEFORE the release opens is REFUSED (never queued);
    * an open release accepts a submission and the verifier decides it;
    * the first answer decides: a second submission never re-decides.
    """
    out: dict = {}
    inbox = _json(c.get(f"/sessions/{sid}/injects"), "inject inbox")
    releases = inbox.get("releases") or []
    out["releases"] = len(releases)
    if not releases:
        raise JourneyError("the session has no incident releases — the break/"
                           "repair workflow cannot be exercised")
    # 1. the refusal path
    early = [r for r in releases if r.get("status") == "pending"]
    if early:
        refused = c.post(f"/sessions/{sid}/injects/{early[0]['release_id']}",
                         json={"content": "answer before the incident opened"})
        out["early_submission"] = refused.status_code
        if refused.status_code != 409:
            raise JourneyError(
                f"a submission before the release opened was not refused: "
                f"HTTP {refused.status_code} {refused.text[:200]}")
    # 2. wait for the incident to open, then answer it
    opened = None
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        inbox = _json(c.get(f"/sessions/{sid}/injects"), "inject inbox")
        for r in inbox.get("releases") or []:
            if r.get("status") == "pending":
                opened = r
                break
        if opened is not None:
            break
        time.sleep(5)
    if opened is None:
        raise JourneyError(f"no incident release opened within {wait_s:.0f}s — "
                           "the break/repair workflow was not exercised")
    first = c.post(f"/sessions/{sid}/injects/{opened['release_id']}",
                   json={"content": "the answer that decides the incident"})
    if first.status_code != 200:
        raise JourneyError(f"the submission to an open incident was refused: "
                           f"HTTP {first.status_code} {first.text[:300]}")
    out["submission_status"] = (first.json() or {}).get("status")
    out["inject_id"] = opened.get("inject_id")
    # 3. the first answer decides
    second = c.post(f"/sessions/{sid}/injects/{opened['release_id']}",
                    json={"content": "a second answer"})
    if second.status_code != 200:
        raise JourneyError(f"the duplicate submission was refused: "
                           f"HTTP {second.status_code}")
    payload = second.json() or {}
    out["duplicate_note"] = payload.get("note")
    if "duplicate" not in str(payload.get("note") or ""):
        raise JourneyError(f"the second submission re-decided the incident: "
                           f"{payload}")
    out["duplicate_status"] = payload.get("status")
    return out


def _refusal_paths(c: httpx.Client, sid: str) -> dict:
    """The failure workflows: the API must REFUSE, not fake a success."""
    out: dict = {}
    unknown = c.get("/sessions/00000000-0000-0000-0000-000000000000")
    out["unknown_session"] = unknown.status_code
    if unknown.status_code != 404:
        raise JourneyError(f"an unknown session was not refused: "
                           f"HTTP {unknown.status_code}")
    unknown_release = c.post(
        f"/sessions/{sid}/injects/00000000-0000-0000-0000-000000000000",
        json={"content": "x"})
    out["unknown_release"] = unknown_release.status_code
    if unknown_release.status_code != 404:
        raise JourneyError(f"an unknown incident release was not refused: "
                           f"HTTP {unknown_release.status_code}")
    # an operator-only view must stay closed to a member
    member_only = c.get("/safety/status")
    out["operator_only_view"] = member_only.status_code
    if member_only.status_code != 403:
        raise JourneyError(f"a member reached an operator-only view: "
                           f"HTTP {member_only.status_code}")
    return out


def _run_preset(c: httpx.Client, preset: str, *, duration: int, pace: int,
                ssh_key: str | None, known_hosts: str | None,
                label: str, options: dict | None = None,
                incident: bool = False, inject_wait_s: float = 420.0) -> dict:
    opts = dict(options or SESSION_OPTIONS[0])
    created = _json(c.post("/sessions", json={
        "scenario_id": preset, "duration_minutes": opts["duration_minutes"],
        "pace_seconds": pace, "mode": opts["mode"],
        "start_condition": opts["start_condition"],
        "injects_enabled": opts["injects_enabled"]}),
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
    out["options"] = opts
    out["match_snapshot"] = (sess.get("match") or {}).get("snapshot_version")
    snapshot = (sess.get("match") or {}).get("snapshot") or {}
    # the session must record the options it was created with: a journey
    # that silently ignored an option is not a journey.
    for key, value in (("duration_minutes", opts["duration_minutes"]),
                       ("mode", opts["mode"]),
                       ("start_condition", opts["start_condition"]),
                       ("injects_enabled", opts["injects_enabled"])):
        if snapshot and snapshot.get(key) not in (None, value):
            raise JourneyError(
                f"{preset}: the session did not record {key}={value!r} "
                f"(snapshot: {snapshot.get(key)!r})")

    # The member SSH rehearsal is part of the journey: a journey that skipped
    # it would pass without ever proving that the member can reach the
    # practice environment.
    if not ssh_key or not known_hosts:
        raise JourneyError(
            "the member SSH rehearsal is part of the journey: "
            "SR_JOURNEY_SSH_KEY and SR_JOURNEY_BASTION_KNOWN_HOSTS are "
            "required (the bastion's pinned host key and the member's key)")
    conn = _ssh_connection(c, sid)
    out["ssh_instruction"] = conn.get("ssh")
    out["ssh"] = asyncio.run(_ssh_check(conn, ssh_key, known_hosts))

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

    # The failure workflows: the API refuses what it cannot do.
    out["refusals"] = _refusal_paths(c, sid)

    # The incident (break) -> submission -> decision workflow, on the primary
    # session: the release schedule opens minutes into the match, so it is
    # exercised once rather than in every option-matrix session.
    if incident:
        out["incident"] = _inject_workflow(c, sid, wait_s=inject_wait_s)

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
                reuse: bool = True,
                browser_url: str = "", browser_user: str = "",
                browser_password: str = "", browser_cli: str | None = None,
                require_browser: bool = True,
                inject_wait_s: float | None = None) -> dict:
    operator = _client(base_url, operator_token, ca_file)
    member = _client(base_url, member_token, ca_file)
    if inject_wait_s is None:
        # the first incident opens at 20% of the match duration
        inject_wait_s = max(120.0, duration * 60 * 0.25 + 60)
    results = []
    try:
        # The browser journey: the product is used through the browser, so the
        # release may not be accepted on the API's word alone.
        browser: dict = {"skipped": True}
        if browser_url and browser_user and browser_password:
            browser = _browser_check(browser_url, browser_user, browser_password,
                                     cli=browser_cli)
        elif require_browser:
            raise JourneyError(
                "the browser journey is part of the acceptance: provide the "
                "appliance's browser URL and the member's login "
                "(SR_JOURNEY_BROWSER_URL / _USER / _PASSWORD)")
        # Operator visibility is checked independently of the member's own view.
        visible = _json(operator.get("/sessions?mine=false"), "operator sessions")
        if not isinstance(visible, list):
            raise JourneyError("operator session listing is not a list")
        for index, preset in enumerate(presets):
            results.append(_run_preset(
                member, preset, duration=duration, pace=pace,
                ssh_key=ssh_key, known_hosts=bastion_known_hosts,
                label="primary", incident=(index == 0),
                inject_wait_s=inject_wait_s))
        # the option matrix: every documented match option is exercised
        for index, options in enumerate(SESSION_OPTIONS):
            results.append(_run_preset(
                member, presets[0], duration=duration, pace=pace,
                ssh_key=ssh_key, known_hosts=bastion_known_hosts,
                label=f"options-{index}", options=options))
        if reuse:
            # The second launch proves release/destroy/reuse with the SAME
            # member after a completed primary journey.
            results.append(_run_preset(
                member, presets[0], duration=duration, pace=pace,
                ssh_key=ssh_key, known_hosts=bastion_known_hosts,
                label="reuse"))
        return {"ok": True, "base_url": base_url, "presets": list(presets),
                "sessions": results, "operator_sessions_visible": len(visible),
                "browser": browser}
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
    ap.add_argument("--browser-url",
                    default=os.environ.get("SR_JOURNEY_BROWSER_URL", ""))
    ap.add_argument("--browser-user",
                    default=os.environ.get("SR_JOURNEY_BROWSER_USER", ""))
    ap.add_argument("--browser-password",
                    default=os.environ.get("SR_JOURNEY_BROWSER_PASSWORD", ""))
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
        reuse=not args.no_reuse,
        browser_url=args.browser_url, browser_user=args.browser_user,
        browser_password=args.browser_password)
    text = json.dumps(out, indent=2, sort_keys=True)
    if args.evidence_out:
        pathlib.Path(args.evidence_out).write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
