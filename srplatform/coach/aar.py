"""The coach (M5): graded after-action review + Socratic hints.

Structure (grade, MITRE/CSF mapping, the misses with timestamps) is produced
DETERMINISTICALLY from the event log, so even a weak coach model can't invent
or omit facts; the model adds narrative polish on top. If the coach model is
unavailable, the deterministic report still ships — the payoff never depends
on the GPU box.
"""
from __future__ import annotations

from datetime import datetime, timezone

from srplatform.coach.timeline import compress_timeline, format_citation

# action/evidence kind -> NIST CSF 2.0 function (kept blunt and honest)
CSF_MAP = {
    "detection": "DE — Detect",
    "verifier": "ID/DE — Identify & Detect (verified state)",
    "command": "RS — Respond (defender actions on record)",
    "tool_call": "ID — unauthorized activity to detect/protect against",
    "hint": "PR — Protect (knowledge applied)",
}

STUDY_BY_TECHNIQUE = {
    "T1136": "Account monitoring: baseline /etc/passwd changes, alert on UID 0 additions (CCDC: account forensics).",
    "T1053": "Persistence hunting: cron/schtasks/systemd unit diffs vs golden image (CCDC: persistence sweeps).",
    "T1543": "Service auditing: compare unit files + running services against template baselines.",
    "T1547": "Autoruns triage on Windows: Run keys, startup folders, services.",
    "T1190": "Web app hardening + WAF/log review for exploitation attempts.",
    "T1041": "Egress monitoring: large/odd outbound flows from DB tiers (you have no egress — know why).",
    "T1562": "Defense evasion: watch for AV/firewall tampering, auditd stops.",
    "T1567": "Exfil channels: staging directories, unusual child processes on web servers.",
    "T1053.005": "schtasks creation events (Sysmon 4/13) hunting.",
    "T1021.004": "Lateral movement via SSH: anomalous authentications in auth logs.",
}


def build_aar(events: list[dict], scenario: dict, scorecard: dict | None,
              narrative: str | None = None) -> dict:
    timeline, idx = compress_timeline(events)
    techniques = set(scenario.get("techniques", []))
    for e in events:
        if e.get("mitre_technique"):
            techniques.add(e["mitre_technique"])

    misses = idx["misses"]
    wins = idx["wins"]
    earned = (scorecard or {}).get("earned", 0)
    total = (scorecard or {}).get("total", 0) or 1
    red_complete = any((e.get("payload") or {}).get("passed") for e in events
                       if e.get("action_type") == "verifier")
    # grade: how much you defended (scorecard) discounted for red finishing
    pct = round(100 * earned / total)
    if red_complete:
        pct = max(0, pct - 15)
    grade = ("A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60
             else "D" if pct >= 45 else "F")

    missed_section = "\n".join(
        f"- You never investigated: {format_citation(e)}"
        + (f" — techniques {', '.join(sorted(techniques))}" if techniques else "")
        for e in misses) or "- No uninvestigated confirmed red objectives (good)."
    won_section = "\n".join(f"- {format_citation(e)}" for e in wins[-10:]) or "- No defender actions were logged."

    csf_section = "\n".join(f"- {label}" for kind, label in sorted(CSF_MAP.items())
                            if any(e.get("action_type") == kind for e in events))
    study = sorted({STUDY_BY_TECHNIQUE.get(t, f"Study MITRE {t}.")
                    for t in techniques} | set())

    started = next((e for e in events if e.get("action_type") == "session_start"), None)
    end_note = datetime.now(timezone.utc).strftime("%H:%M UTC")

    md = f"""# After-Action Review — {scenario.get('name', scenario.get('id', '?'))}
Grade: **{grade}** ({earned}/{total} blue points{', −15 red completed objectives' if red_complete else ''})

## What you missed, and when
{missed_section}

## What you did well
{won_section}

## MITRE ATT&CK seen this session
{', '.join(f"`{t}`" for t in sorted(techniques)) or 'none recorded'}

## NIST CSF coverage of this session's evidence
{csf_section}

## Prioritized study list
{chr(10).join(f'1. {s}' for s in study) or '1. Nothing pressing — run it again on Hard.'}

## Timeline (compressed, citable)
{timeline}

{('## Coach narrative' + chr(10) + narrative) if narrative else ''}
_Report generated {end_note} from the append-only event log (started {started['event_id'] if started else '?'})."""

    cited = [e.get("event_id") for e in misses + wins]
    return {"markdown": md, "grade": grade, "earned": earned, "total": total,
            "misses": [format_citation(e) for e in misses], "cited_events": cited}


HINT_SYSTEM = """You are a Socratic CCDC coach. The defender is mid-session.
Do NOT give the answer command; ask the question that leads them there, using
the CONTEXT (timestamps are real; reference them). Keep it under 5 sentences."""


def build_hint(events: list[dict], question: str, llm) -> dict:
    """Socratic hint grounded in the live log: the model sees the compressed
    timeline and answers the defender's question against it."""
    timeline, idx = compress_timeline(events[-200:], max_lines=25)
    state_line = f"You have {len(idx['misses'])} confirmed red items with no follow-up from you."
    user = f"DEFENDER QUESTION: {question or '(none — tell me where to look next)'}\n\nCONTEXT (live log):\n{timeline}\n\n{state_line}"
    text = llm.complete(HINT_SYSTEM, user) if llm else f"Look at your unhandled detections: {state_line}"
    return {"hint": text, "context_events": [e["event_id"] for e in events[-5:]] if events else []}
