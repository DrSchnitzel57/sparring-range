"""Timeline compressor (M5 — F12 rewrite): compact, CITABLE, and honest about
what the evidence does and does NOT show.

Old failure modes fixed here:
  * A bastion DISCONNECT (or any later blue event) no longer counts as "having
    investigated" every earlier red success. Response must be correlated:
    telemetry commands or explicit defender actions, on the SAME host, AFTER
    the objective — within a window.
  * Not every blue event is a "win". Wins are explicit remediations.
  * Detection events are RENDERED (source times included).
  * Where evidence is missing we say "no correlated response observed" or
    "telemetry gap" — never "you never investigated" as fact.
"""
from __future__ import annotations

from datetime import datetime, timedelta

RESPONSE_WINDOW = timedelta(minutes=30)
RESPONSE_KINDS = {"command", "remediation"}          # correlated responses
WIN_KINDS = {"remediation"}                          # explicit defender wins
CONNECTION_NOISE = {"bastion_session_start", "bastion_session_end"}


def _t(e: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(e["ts"]).replace("Z", "+00:00"))
    except (ValueError, KeyError, TypeError):
        return None


def compress_timeline(events: list[dict], max_lines: int = 80) -> tuple[str, dict]:
    """Returns (timeline text, index):
      misses     – passed red objectives with no correlated response (with reason)
      telemetry_gaps – hosts whose objectives lack telemetry entirely
      wins       – explicit remediation events
      detections – verifier/detection events (rendered, source time)
      shown_ids  – CANONICAL citable ids: the events this render actually
                   shows (plan 20 F5 — never ids a payload merely mentions;
                   plan 22 review — also never ids the max_lines trim cut)
    """
    events = sorted(events, key=lambda e: (e.get("event_id") or 0))
    lines, misses, gaps, wins, detections = [], [], [], [], []
    line_ids: list[int | None] = []     # citable id PARALLEL to each line
    responses: list[tuple[datetime, str | None, dict]] = []
    telemetry_hosts: set[str] = set()

    def emit(e: dict, text: str) -> None:
        """Citations are canonical (plan 20 F5, sharpened by plan 22
        review): the citable id is bound to the RENDER LINE at emit time
        (paired, never re-parsed out of the text — a payload containing
        `#99999999` must not forge a citation), and only lines the FINAL
        render keeps become citable: events the max_lines TRIM cut leave
        the allowed set too."""
        lines.append(text)
        try:
            line_ids.append(int(e.get("event_id")))
        except (TypeError, ValueError):
            line_ids.append(None)

    for e in events:
        ts, kind = _t(e), e.get("action_type", "?")
        actor, host = e.get("actor", ""), e.get("host")
        p = e.get("payload") or {}
        stamp = ts.strftime("%H:%M:%S") if ts else "??:??:??"
        if kind == "tool_call" and actor == "red":
            emit(e, f"[{stamp}#{e.get('event_id')}] RED (agent) "
                    f"{e.get('phase') or '?'}: {p.get('command', '')[:90]}")
        elif kind == "action_result" and actor == "red":
            emit(e, f"[{stamp}#{e.get('event_id')}] RED (agent) "
                    f"exit={p.get('exit_code')}: {p.get('output', '')!r:.70}")
        elif kind == "verifier":
            label = "PASS" if p.get("passed") else (p.get("status") or "fail")
            emit(e, f"[{stamp}#{e.get('event_id')}] VERIFY {p.get('objective')}={label}"
                    + (f" @{host}" if host else ""))
            detections.append(e)
        elif kind == "command" and actor == "telemetry":
            # UNATTRIBUTED ACTIVITY (audit Stage 5): auditd shows that A
            # process ran on the host — not WHO ran it. A compromised host's
            # telemetry (or the attacker's own commands) must never count as
            # a defender response; it is rendered as activity on record only.
            telemetry_hosts.add(host or "?")
            emit(e, f"[{stamp}#{e.get('event_id')}] AUDITD {host}: "
                    f"{str(p.get('argv') or p.get('comm'))[:70]} "
                    f"[unattributed activity — not defender-attributed]")
        elif kind == "detection" and actor == "telemetry":
            # detection events are RENDERED explicitly (audit Stage 5)
            telemetry_hosts.add(host or "?")
            emit(e, f"[{stamp}#{e.get('event_id')}] DETECT {host}: "
                    f"watch {p.get('audit_key') or '?'} "
                    f"{str(p.get('argv') or p.get('comm') or '')[:50]} "
                    f"[watch hit — unattributed until correlated]")
        elif kind in CONNECTION_NOISE:
            continue  # connection lifecycle is NOT investigation (F12)
        elif kind == "remediation":
            responses.append((ts, host, e))
            wins.append(e)
            # a member's remediation STATEMENT is a CLAIM until the scorecard
            # verifies host state (audit Stage 5)
            who = actor.split(":", 1)[1] if actor.startswith("blue:") else "defender"
            emit(e, f"[{stamp}#{e.get('event_id')}] MEMBER {who} REMEDIATION "
                    f"{host or ''}: "
                    f"{str(p.get('action') or p.get('command') or '')[:70]} "
                    f"[claim — verified only via scorecard state]")
        elif actor.startswith("blue:") and kind in RESPONSE_KINDS:
            responses.append((ts, host, e))
            # PROVENANCE (plan 22 LIVE-10): an authenticated member's recorded
            # bastion activity is neither attacker reconnaissance nor agent
            # output — name the actor class so coaching cannot misattribute it.
            who = actor.split(":", 1)[1] or "member"
            emit(e, f"[{stamp}#{e.get('event_id')}] MEMBER {who}"
                    + (f" @{host}" if host else "")
                    + f" via bastion: {p.get('command') or kind} "
                      f"[authenticated member activity — not the red agent]")

    for e in detections:
        p = e.get("payload") or {}
        if not (p.get("objective") and p.get("passed")):
            continue
        ts = _t(e)
        host = e.get("host")
        correlated = [r for r in responses
                      if ts and r[0] and r[0] > ts and r[0] - ts <= RESPONSE_WINDOW
                      and (r[1] in (None, host) or host is None)]
        if not correlated:
            if host and host not in telemetry_hosts:
                reason = ("no telemetry received from this host — cannot distinguish "
                          "'no response' from 'no visibility'")
                gaps.append({"event": e, "reason": reason})
            else:
                misses.append({"event": e,
                               "reason": "no correlated defender action on this host within "
                                         f"{int(RESPONSE_WINDOW.total_seconds()//60)} min"})

    # The allowed citation set comes from the EXACT final render window
    # (plan 22 review): pairing ids with lines at emit time, then taking
    # the same [-max_lines:] slice, is what makes "validated but never
    # shown" citations impossible — without re-parsing payload text.
    kept_ids = {i for i in line_ids[-max_lines:] if i is not None}
    return ("\n".join(lines[-max_lines:]),
            {"misses": misses, "telemetry_gaps": gaps,
             "wins": wins, "detections": detections,
             "shown_ids": sorted(kept_ids)})


def session_context_note(context: dict | None) -> str:
    """One header line for coaching prompts (plan 22 LIVE-10): phase/run
    state as OBSERVED by the platform, plus what each actor class means.
    A READY session with no red run has never had attacker activity —
    operator identity/sudo/connectivity checks and background telemetry
    are setup noise, not reconnaissance. Attribution beyond these classes
    stays unknown; host telemetry alone proves neither identity nor
    intent."""
    if not context:
        return ""
    status = context.get("session_status") or "?"
    if run := (context.get("red_run_state") or None):
        phase = context.get("phase")
        run_line = (f"red run state: {run}"
                    + (f" (phase {phase})" if phase else ""))
    else:
        run_line = ("NO red run has started — anything before the first RED "
                    "entry is setup, defender work or background telemetry, "
                    "not attacker reconnaissance")
    return (f"Session context: status={status}; {run_line}. "
            "Line classes: RED (agent) = platform red agent only; "
            "MEMBER <user> = that member's recorded bastion login; "
            "AUDITD/DETECT = unattributed host telemetry; VERIFY = platform "
            "verifier. Telemetry alone proves neither identity nor intent — "
            "keep attribution UNKNOWN when it is unknown.")


def format_citation(e: dict) -> str:
    ts = _t(e)
    p = e.get("payload") or {}
    what = p.get("objective") or p.get("command") or p.get("action") or e.get("action_type")
    return (f"event #{e.get('event_id')} at {ts.strftime('%H:%M') if ts else '??'} — "
            f"{e.get('actor')}/{e.get('action_type')} {what}")
