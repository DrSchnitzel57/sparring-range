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
    """
    events = sorted(events, key=lambda e: (e.get("event_id") or 0))
    lines, misses, gaps, wins, detections = [], [], [], [], []
    responses: list[tuple[datetime, str | None, dict]] = []
    telemetry_hosts: set[str] = set()

    for e in events:
        ts, kind = _t(e), e.get("action_type", "?")
        actor, host = e.get("actor", ""), e.get("host")
        p = e.get("payload") or {}
        stamp = ts.strftime("%H:%M:%S") if ts else "??:??:??"
        if kind == "tool_call" and actor == "red":
            lines.append(f"[{stamp}#{e.get('event_id')}] RED {e.get('phase') or '?'}: "
                         f"{p.get('command', '')[:90]}")
        elif kind == "action_result" and actor == "red":
            lines.append(f"[{stamp}#{e.get('event_id')}] RED exit={p.get('exit_code')}: "
                         f"{p.get('output', '')!r:.70}")
        elif kind == "verifier":
            label = "PASS" if p.get("passed") else (p.get("status") or "fail")
            lines.append(f"[{stamp}#{e.get('event_id')}] VERIFY {p.get('objective')}={label}"
                         + (f" @{host}" if host else ""))
            detections.append(e)
        elif kind == "command" and actor == "telemetry":
            # UNATTRIBUTED ACTIVITY (audit Stage 5): auditd shows that A
            # process ran on the host — not WHO ran it. A compromised host's
            # telemetry (or the attacker's own commands) must never count as
            # a defender response; it is rendered as activity on record only.
            telemetry_hosts.add(host or "?")
            lines.append(f"[{stamp}#{e.get('event_id')}] AUDITD {host}: "
                         f"{str(p.get('argv') or p.get('comm'))[:70]} "
                         f"[unattributed activity — not defender-attributed]")
        elif kind == "detection" and actor == "telemetry":
            # detection events are RENDERED explicitly (audit Stage 5)
            telemetry_hosts.add(host or "?")
            lines.append(f"[{stamp}#{e.get('event_id')}] DETECT {host}: "
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
            lines.append(f"[{stamp}#{e.get('event_id')}] BLUE REMEDIATION {host or ''}: "
                         f"{str(p.get('action') or p.get('command') or '')[:70]} "
                         f"[claim — verified only via scorecard state]")
        elif actor.startswith("blue:") and kind in RESPONSE_KINDS:
            responses.append((ts, host, e))
            lines.append(f"[{stamp}#{e.get('event_id')}] BLUE {p.get('command') or kind}")

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

    return "\n".join(lines[-max_lines:]), {"misses": misses, "telemetry_gaps": gaps,
                                           "wins": wins, "detections": detections}


def format_citation(e: dict) -> str:
    ts = _t(e)
    p = e.get("payload") or {}
    what = p.get("objective") or p.get("command") or p.get("action") or e.get("action_type")
    return (f"event #{e.get('event_id')} at {ts.strftime('%H:%M') if ts else '??'} — "
            f"{e.get('actor')}/{e.get('action_type')} {what}")
