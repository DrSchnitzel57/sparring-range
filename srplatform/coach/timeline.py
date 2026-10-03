"""Timeline compressor (M5): turns the event log into a compact, CITABLE
timeline. Citations are deterministic — every line references real event ids
and timestamps from the log — so the AAR can't hallucinate things that
happened at "14:02" unless the log says 14:02.
"""
from __future__ import annotations

from datetime import datetime


def _t(e: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(e["ts"]).replace("Z", "+00:00"))
    except (ValueError, TypeError, KeyError):
        return None


def compress_timeline(events: list[dict], max_lines: int = 80) -> tuple[str, dict]:
    """Returns (compact timeline text, index) where index has:
      misses  = red actions the defender never investigated afterwards
      wins    = blue actions that preceded/beat red steps
      detections = verifier/detection events
    """
    events = sorted(events, key=lambda e: (str(e.get("ts") or ""), e.get("event_id", 0)))
    blue_ts = [_t(e) for e in events if e.get("actor", "").startswith("blue:")]
    lines, misses, wins, detections = [], [], [], []

    for e in events:
        ts = _t(e)
        stamp = ts.strftime("%H:%M:%S") if ts else "??:??:??"
        actor, kind = e.get("actor", "?"), e.get("action_type", "?")
        p = e.get("payload") or {}
        if kind == "tool_call" and actor == "red":
            lines.append(f"[{stamp}#{e['event_id']}] RED {e.get('phase') or '?'}: {p.get('command', '')[:90]}")
        elif kind == "verifier":
            obj = p.get("objective")
            passed = p.get("passed")
            lines.append(f"[{stamp}#{e['event_id']}] VERIFY {obj}={'PASS' if passed else 'fail'}")
            detections.append(e)
            if passed:
                # a confirmed red objective that no blue action followed = a miss
                later_blue = [b for b in blue_ts if b and ts and b > ts]
                if not later_blue:
                    misses.append(e)
        elif kind == "command" and actor == "telemetry":
            lines.append(f"[{stamp}#{e['event_id']}] AUDITD {e.get('host')}: {str(p.get('argv') or p.get('comm'))[:70]}")
        elif actor.startswith("blue:"):
            lines.append(f"[{stamp}#{e['event_id']}] BLUE {p.get('command') or p.get('token') or kind}")
            wins.append(e)

    return "\n".join(lines[-max_lines:]), {"misses": misses, "wins": wins, "detections": detections}


def format_citation(e: dict) -> str:
    ts = _t(e)
    p = e.get("payload") or {}
    what = p.get("objective") or p.get("command") or e.get("action_type")
    return (f"event #{e.get('event_id')} at {ts.strftime('%H:%M') if ts else '??'} — "
            f"{e.get('actor')}/{e.get('action_type')} {what}")
