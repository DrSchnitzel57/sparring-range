"""The coach (M5): graded after-action review + Socratic hints (F12 rewrite).

Honesty contract:
  * The GRADE comes only from the declared deterministic rubric (the trusted
    scorecard). Unscored sessions are UNSCORED — never a fabricated F, never a
    synthetic denominator.
  * No implicit penalties. A red-complete session without a declared rubric
    penalty is reported as context, not arithmetic.
  * Scenario-DECLARED techniques are listed separately from techniques
    OBSERVED in evidence.
  * Behavioural claims are correlation-based and labelled as such
    ("no correlated response observed"), never "you never investigated".
  * LLM narrative is optional garnish: citations are VALIDATED against the
    event ids actually supplied; unsupported sentences are dropped.
  * Study priority is failure-weighted (points lost, misses), not alphabetical.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from srplatform.coach.timeline import compress_timeline, format_citation
from srplatform.red_agent.llm import CompletionRejected

CSF_MAP = {
    "detection": "DE — Detect",
    "verifier": "ID/DE — Identify & Detect (verified state)",
    "command": "telemetry/RS — activity on record",
    "remediation": "RS/RV — Respond & Recover (defender actions)",
    "action_result": "ID — unauthorized activity to detect/protect against",
    "hint": "PR — Protect (knowledge applied)",
}

STUDY_BY_TECHNIQUE = {
    "T1136": "Account monitoring: baseline /etc/passwd changes, alert on UID 0 additions (CCDC: account forensics).",
    "T1053": "Persistence hunting: cron/schtasks/systemd unit diffs vs golden image (CCDC: persistence sweeps).",
    "T1053.003": "Cron diffing against a documented baseline; alert on non-baseline entries.",
    "T1053.005": "schtasks creation events (Sysmon 4/13) hunting.",
    "T1543": "Service auditing: compare unit files + running services against template baselines.",
    "T1547": "Autoruns triage on Windows: Run keys, startup folders, services.",
    "T1190": "Web app hardening + WAF/log review for exploitation attempts.",
    "T1041": "Egress monitoring: large/odd outbound flows from DB tiers (you have no egress — know why).",
    "T1021.004": "Lateral movement via SSH: anomalous authentications in auth logs.",
    "T1505.003": "Web shell detection: file-integrity on webroots, request-pattern review.",
    "T1562": "Defense evasion: watch for AV/firewall tampering, auditd stops.",
    "T1565": "Data integrity: protect/verify critical files; know your golden hashes.",
    "T1567": "Exfil channels: staging directories, unusual child processes on web servers.",
}

_GRADE_TABLE = ((90, "A"), (75, "B"), (60, "C"), (45, "D"), (0, "F"))
CITE_RE = re.compile(r"#(\d+)")


def _grade_from_pct(pct: float | None) -> str | None:
    if pct is None:
        return None
    for floor, g in _GRADE_TABLE:
        if pct >= floor:
            return g
    return None


def build_aar(events: list[dict], scenario: dict, scorecard: dict | None,
              narrative: str | None = None) -> dict:
    timeline, idx = compress_timeline(events)

    declared = set(scenario.get("techniques", []))
    observed = {e["mitre_technique"] for e in events if e.get("mitre_technique")}
    # techniques observed via verifier events referencing them
    for d in idx["detections"]:
        pass  # verifier events carry objective, not technique ids; MITRE stays declared

    card = scorecard or {}
    status = card.get("status", "unscored")
    earned, total = card.get("earned"), card.get("total")
    pct = round(100 * earned / total) if (earned is not None and total) else None
    grade = _grade_from_pct(pct)

    # red completion is CONTEXT, not an implicit arithmetic penalty (F12)
    red_done = [d for d in idx["detections"]
                if (d.get("payload") or {}).get("objective")
                and (d.get("payload") or {}).get("passed")]
    red_note = ("Red objectives were verifier-confirmed this session; scoring follows "
                "the declared rubric only (no implicit penalty).") if red_done else ""

    score_line = (f"Grade: **{grade}** ({earned}/{total} rubric points)" if grade
                  else "Grade: **UNSCORED** — no trusted scorecard was produced; "
                       "no grade is fabricated.")

    def _miss_lines(entries, key):
        out = []
        for m in entries:
            e = m["event"] if isinstance(m, dict) else m
            reason = m.get("reason", "") if isinstance(m, dict) else ""
            out.append(f"- {format_citation(e)} — {reason}")
        return "\n".join(out)

    missed_section = _miss_lines(idx["misses"], "misses") or \
        "- No passed red objective lacked a correlated defender response."
    gap_section = _miss_lines(idx["telemetry_gaps"], "telemetry_gaps") or \
        "- Telemetry covered all hosts with confirmed red activity."
    won_section = "\n".join(f"- {format_citation(e)}" for e in idx["wins"][-10:]) or \
        "- No explicit remediation actions were recorded (absence of evidence — not a statement about your work)."
    if idx["wins"]:
        won_section += ("\n(Recorded remediations are defender-ATTRIBUTED CLAIMS; host-state "
                        "verification follows the scorecard items above — a claim alone "
                        "earns no state credit.)")

    # failure-weighted study priority: observed-in-evidence first, then declared,
    # tie-broken deterministically; misses/lost points raise everything equally
    lost_total = sum(int(i.get("points", 0)) - int(i.get("awarded", 0))
                     for i in card.get("items", []))
    study_pool = sorted(set(declared) | observed)
    weight = {s: (10 if s in observed else 0) + len(idx["misses"]) + (1 if lost_total else 0)
              for s in (STUDY_BY_TECHNIQUE.get(t, f"Study MITRE {t}.") for t in study_pool)}
    for tech in study_pool:
        s = STUDY_BY_TECHNIQUE.get(tech, f"Study MITRE {tech}.")
        weight[s] = weight.get(s, 0) + (10 if tech in observed else 0)
    study = sorted(set(STUDY_BY_TECHNIQUE.get(t, f"Study MITRE {t}.") for t in study_pool),
                   key=lambda s: (-weight.get(s, 0), s))

    csf_section = "\n".join(f"- {label}" for kind, label in sorted(CSF_MAP.items())
                            if any(e.get("action_type") == kind for e in events))

    started = next((e for e in events if e.get("action_type") == "session_start"), None)
    cutoff = max((e.get("event_id") or 0 for e in events), default=0)
    end_note = datetime.now(timezone.utc).strftime("%H:%M UTC")

    narrative_block = ""
    # Review finding 8: citations are valid only against the evidence the
    # report ACTUALLY shows (the rendered, compressed timeline) — never
    # against every id that existed in the window but was compressed away.
    # Plan 20 F5: the set is the compressor's CANONICAL accounting of the
    # events it rendered, not a regex over the text — a payload that says
    # ``echo reference #99999999`` adds nothing to what exists.
    visible_ids = set(idx["shown_ids"])
    if narrative:
        narrative = validate_narrative(narrative, visible_ids)
        if narrative.strip():
            narrative_block = "## Coach narrative (citations validated)\n" + narrative.strip() + "\n"

    # precomputed: a backslash inside an f-string EXPRESSION is a SyntaxError
    # before Python 3.12 (the supported matrix starts at 3.11)
    red_block = ("\n" + red_note) if red_note else ""

    md = f"""# After-Action Review — {scenario.get('name', scenario.get('id', '?'))}
{score_line}

## Correlational misses (passed red objectives without a correlated response)
{missed_section}

## Telemetry gaps (visibility limitations — NOT proof of inaction)
{gap_section}

## Defensive actions on record
{won_section}

## Declared scenario techniques
{', '.join(f"`{t}`" for t in sorted(declared)) or 'none declared'}

## Techniques observed in evidence
{', '.join(f"`{t}`" for t in sorted(observed)) or 'none directly observed'}
{red_block}

## NIST CSF coverage of this session's evidence
{csf_section}

## Prioritized study list (failure-weighted)
{chr(10).join(f'1. {s}' for s in study) or '1. Nothing pressing — run it again on Hard.'}

## Timeline (compressed, citable)
{timeline}

{narrative_block}_Report generated {end_note} from the append-only event log up to event #{cutoff}
(rubric version {card.get('rubric_version', scenario.get('rubric_version', '?'))}, score status: {status})."""

    cited = [m["event"].get("event_id") for m in idx["misses"] + idx["telemetry_gaps"]
             if isinstance(m, dict)] + [e.get("event_id") for e in idx["wins"]]
    # The UI may turn #id tokens into ACTIVE links only for this list:
    # events the report shows, key evidence it names, and the cutoff.
    # Anything else renders as an honest unverified label.
    approved_citations = sorted(
        visible_ids | {c for c in cited if c} | ({cutoff} if cutoff else set()))
    return {"markdown": md, "grade": grade, "score_status": status,
            "earned": earned, "total": total, "pct": pct,
            "misses": [f"{format_citation(m['event'])} — {m['reason']}" for m in idx["misses"]],
            "telemetry_gaps": [f"{format_citation(g['event'])} — {g['reason']}"
                               for g in idx["telemetry_gaps"]],
            "cited_events": sorted(set(filter(None, cited))),
            "approved_citation_ids": approved_citations,
            "evidence_cutoff_event_id": cutoff,
            "rubric_version": card.get("rubric_version", scenario.get("rubric_version", 1))}


def validate_narrative(text: str, valid_ids: set) -> str:
    """Drop sentences citing event ids that were not supplied (or don't exist).
    This is a guardrail, not a rewrite: kept sentences are verbatim."""
    kept = []
    for sent in re.split(r"(?<=[.!?])\s+", text):
        ids = [int(m) for m in CITE_RE.findall(sent)]
        if all(i in valid_ids for i in ids):
            kept.append(sent)
    return " ".join(kept)


HINT_SYSTEM = """You are a Socratic CCDC coach. The defender is mid-session.
Do NOT give the answer command; ask the question that leads them there, using
the CONTEXT (timestamps are real; reference them). Keep it under 5 sentences."""


def hint_prompt(events: list[dict], question: str) -> tuple[str, str, str]:
    """Build the hint request EXACTLY once (system, user, state_line).
    The synchronous path AND the durable-async enqueue share this
    builder — two prompt constructions would drift, and a member's
    async hint must be grounded in the same evidence view as the sync
    one."""
    timeline, idx = compress_timeline(events[-200:], max_lines=25)
    n_miss, n_gap = len(idx["misses"]), len(idx["telemetry_gaps"])
    state_line = (f"Status: {n_miss} confirmed red items without a correlated response; "
                  f"{n_gap} with telemetry gaps (visibility unknown).")
    user = (f"DEFENDER QUESTION: {question or '(none — tell me where to look next)'}\n\n"
            f"CONTEXT (live log):\n{timeline}\n\n{state_line}")
    return HINT_SYSTEM, user, state_line


def hint_fallback(reason: str, state_line: str) -> str:
    return (f"{reason} — deterministic guidance (not an AI-generated hint). "
            f"{state_line} Which recent event can you corroborate with a second "
            "log source, and where is visibility still missing? "
            "No diagnosis or successful remediation is inferred.")


def build_hint(events: list[dict], question: str, llm) -> dict:
    """Socratic hint grounded in the live log, with HONEST state (F12): we say
    'no correlated response observed', not 'you ignored it'."""
    system, user, state_line = hint_prompt(events, question)
    n_tail = [e["event_id"] for e in events[-5:]] if events else []
    fallback_reason = "No model available"
    text = None
    if llm:
        try:
            text = llm.complete(user=user, system=system)
        except CompletionRejected:
            fallback_reason = "Model response was empty, incomplete, or rejected"
        # Test doubles/alternative adapters may not enforce the shared client's
        # contract; never persist an empty hint from those either.
        if not isinstance(text, str) or not text.strip():
            fallback_reason = "Model response was empty, incomplete, or rejected"
            text = None
    if text is None:
        text = hint_fallback(fallback_reason, state_line)
    return {"hint": text, "context_events": n_tail}
