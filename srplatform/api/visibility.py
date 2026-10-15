"""Competition visibility (plan 13 phase 7): centralize competition
filtering across every member-visible read, so hiding a button is never
the control.

Rule: in competition mode, member principals must not see red internals
(tool calls, agent memory, detection/verifier detail, live telemetry
command content) before the match reaches a terminal state. Operators and
service principals always see everything; practice mode is fully visible;
completed/interrupted/failed matches are full history (the AAR needs
truth). Members always keep permitted service/inject data: session state,
uptime totals, inject inbox, their own capabilities, lifecycle events.
"""
from __future__ import annotations

#: payloads that reveal red internals
SPOILER_ACTORS = frozenset({"red", "telemetry"})
SPOILER_KINDS = frozenset({"tool_call", "detection", "verifier"})

TERMINAL_MATCH_STATES = frozenset({"completed", "interrupted", "failed"})

SEALED_NOTE = "competition — sealed until the match completes"


def competition_sealed(db, sess, p) -> bool:
    if p.is_operator or getattr(p, "kind", None) == "service":
        return False
    from srplatform import lifecycle
    m = lifecycle.get_match(db, sess.session_id)
    if m is None:
        return False
    if (m.snapshot or {}).get("mode") != "competition":
        return False
    return m.state not in TERMINAL_MATCH_STATES


def filter_event(db, sess, p, ev: dict) -> dict:
    """Redact one serialized event for a sealed principal. Metadata
    (presence, timing, host, kind) stays — only spoiler CONTENT goes."""
    if sess is None or not competition_sealed(db, sess, p):
        return ev
    if ev.get("actor") in SPOILER_ACTORS \
            or ev.get("action_type") in SPOILER_KINDS:
        ev = dict(ev)
        ev["payload"] = {"redacted": SEALED_NOTE}
        ev["raw_ref"] = None
    return ev


def filter_detection(item: dict) -> dict:
    """One live detection for a sealed principal: timing stays, the
    verdict (what fell) is sealed."""
    return {"event_id": item.get("event_id"), "ts": item.get("ts"),
            "sealed": SEALED_NOTE}


def filter_scorecard(card: dict) -> dict:
    """Scorecard for a sealed principal: totals and status stay (scores
    are visible), per-check pass/fail/evidence is sealed."""
    card = dict(card)
    card["items"] = [
        {"verifier": i.get("verifier"), "host": i.get("host"),
         "domain": i.get("domain", "general"), "points": i.get("points"),
         "sealed": SEALED_NOTE}
        for i in card.get("items", [])]
    return card
