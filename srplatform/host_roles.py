"""Deterministic deployed-host role policy (plan 22 LIVE-09).

The connections view once advertised a member SSH login for EVERY host,
including the attacker machine — but the appliance seeds that guest with
runner-only principals (``infra/appliance/seed.py``: attacker admits
``runner``, never ``defender``), so following the advertised instruction
guaranteed ``Permission denied``. One classifier now answers the question
BOTH the launch response and the re-fetch route ask: what is this host,
and may a member SSH to it?

Classification is deliberately boring and total:

* the image spec's template->role mapping wins when the template VMID is
  known (authoritative, same table the deploy budget uses);
* otherwise the topology host name ``attacker`` is the fallback used by
  the scenario authoring convention;
* everything else is a target (defender-side machine) — SSH policy
  unchanged there.

Nothing here enforces authentication (the appliance image does); this
only decides what the platform ADVERTISES, so the UI can never offer a
capability the platform itself refuses to use.
"""
from __future__ import annotations

ATTACKER_NOTE = ("attacker host: driven by the red operator through platform "
                 "red operations (dispatched commands); it intentionally has "
                 "no member SSH login — the guest admits only the range "
                 "runner principal")


def host_role(host_name: str, template_vmid) -> str:
    try:
        from infra.images.specs import guest_for_template
        role = guest_for_template(int(template_vmid or 0))
    except Exception:  # noqa: BLE001 — infra import is best-effort fallback
        role = None
    if role:
        return role
    if str(host_name or "").strip().lower() == "attacker":
        return "attacker"
    return "target"


def member_ssh_allowed(role: str) -> bool:
    return role != "attacker"


def annotate(entry: dict) -> dict:
    """Add role policy to one connection/instruction entry IN PLACE.
    Attacker entries advertise NO member ssh string; the token that used
    to be shown there would only have failed authentication."""
    role = host_role(entry.get("host", ""), entry.get("template_vmid"))
    entry["role"] = role
    allowed = member_ssh_allowed(role)
    entry["member_ssh"] = allowed
    if not allowed:
        entry.pop("ssh", None)
        entry["note"] = ATTACKER_NOTE
    return entry
