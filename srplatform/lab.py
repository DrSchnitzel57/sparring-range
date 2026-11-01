"""Lab lifecycle contracts: dependency-aware reset planning (pure).

Resetting ONE guest of a running replica is only safe when the impact is
COMPUTED AND SHOWN FIRST: everything that depends on the selected guests
rebuilds too (no silent cascade onto unlisted work happens — the cascade is
IN THE PLAN, which the captain approves or cancels), some dependencies
cannot be safely decoupled at all (a lone domain-controller rollback, or a
member left behind after its domain is rebuilt), and fences always apply
before destructive effects: AI offense is fenced and canceled, scoring is
fenced, and unknown ownership/state BLOCKS the operation instead of
guessing.

Pure functions over the validated blueprint — no DB, no side effects. The
API layer persists plans (lab_reset_plans), records events, and executes
through the broker with per-guest generation bumps.
"""
from __future__ import annotations

from .environment_specs.blueprint import EnvironmentBlueprint, GuestRole

RESET_PLAN_VERSION = 2

# Inventory-state policy (fail-closed). ONLY these states are resettable on
# their own merits. Anything else — transitional, foreign, destroyed, or a
# string this build does not recognize — is a blocker; a `failed` guest is
# eligible only when the executing path positively reconciled ownership of
# the exact generation (reconciled_guests). Unknown-ownership rule: an
# unrecognized state is never evidence of eligibility.
RESET_ELIGIBLE_STATES = frozenset({"ready", "stopped"})
TRANSITIONAL_STATES = frozenset({"pending", "creating", "provisioning",
                                 "destroying"})
FOREIGN_STATES = frozenset({"foreign", "destroyed-foreign"})
DESTROYED_STATES = frozenset({"destroyed"})
RECONCILABLE_STATES = frozenset({"failed"})
_KNOWN_GUEST_STATES = (RESET_ELIGIBLE_STATES | TRANSITIONAL_STATES
                       | FOREIGN_STATES | DESTROYED_STATES
                       | RECONCILABLE_STATES | {"unknown"})

# Guests whose domain membership is established by AD join / SSSD realm.
# Rebuilding the DC invalidates their machine identity; rebuilding a member
# does not invalidate the domain.
DOMAIN_DEPENDENT_ROLES = {"windows-dc", "windows-sql", "windows-desktop",
                          "linux-server", "mail-server", "splunk-server",
                          "linux-desktop"}


def _dependents_index(bp: EnvironmentBlueprint) -> dict[str, set[str]]:
    """guest -> guests that (transitively) depend on it."""
    down: dict[str, set[str]] = {g.name: set() for g in bp.guests}
    for g in bp.guests:
        for dep in g.depends_on:
            down[dep].add(g.name)
    # transitive closure (graphs here are tiny)
    closure: dict[str, set[str]] = {}
    for name in down:
        seen: set[str] = set()
        stack = list(down[name])
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(down[n])
        closure[name] = seen
    return closure


def compute_reset_plan(bp: EnvironmentBlueprint, selected: list[str],
                       guest_states: dict[str, str] | None = None,
                       full: bool = False,
                       reconciled_guests: frozenset[str] = frozenset(),
                       ) -> dict:
    """Versioned dependency plan for a destructive reset.

    guest_states: current LabGuest states (from durable inventory). Only
    explicitly eligible states (ready/stopped) plan as resettable; missing,
    transitional, foreign, unrecognized or failed states become blockers
    with recovery instructions. `reconciled_guests` names guests whose
    OWNERSHIP of the current generation was positively reconciled by the
    executing path (broker-ledger read-back); only those failed guests may
    plan the supported recovery reset. The pure planner never invents
    ownership: string state alone is not proof, and the executor must
    re-check identity/generation/ownership before destroying anything.
    """
    issues: list[str] = []
    known = {g.name for g in bp.guests}
    selected = sorted(set(selected or []))
    states = guest_states or {}
    if full:
        selected = sorted(known)
    if not selected:
        issues.append("select at least one guest (or full=True); an empty "
                      "destructive plan is never executed")
    unknown = [g for g in selected if g not in known]
    if unknown:
        issues.append(f"unknown guests in selection: {unknown} — refusing to "
                      f"guess; refresh inventory and retry")
    if issues:
        return {"plan_version": RESET_PLAN_VERSION, "ok": False,
                "blockers": issues, "advisories": [], "rebuild": [],
                "preserved": [], "selected": selected, "full": full,
                "fences": _fences(selected)}

    down = _dependents_index(bp)
    rebuild: set[str] = set(selected)
    cascade_from: dict[str, list[str]] = {}
    for g in selected:
        for d in down.get(g, set()):
            if d not in rebuild:
                cascade_from.setdefault(g, []).append(d)
            rebuild.add(d)

    # DC/forest honesty: rebuilding the domain controller while a DOMAIN-
    # MEMBER guest is preserved leaves that member unable to trust its
    # domain — never offered as a safe isolated reset. Dependents that
    # declare `depends_on` already cascaded; this catches trust WITHOUT a
    # declared dependency (e.g. manual joins) so the plan must widen/cancel.
    dc_names = [g.name for g in bp.guests if g.role == GuestRole.WINDOWS_DC]
    preserved = sorted(known - rebuild)
    for dc in dc_names:
        if dc in rebuild:
            left = [g.name for g in bp.guests
                    if g.name not in rebuild
                    and g.name != dc
                    and g.role.value in DOMAIN_DEPENDENT_ROLES]
            if left:
                issues.append(
                    f"resetting {dc} preserves {sorted(left)}, whose domain "
                    f"membership/machine trust depends on it — isolated DC "
                    f"rollback is NOT offered as safe; widen the plan "
                    f"(or full=True), or cancel")
    # SQL honesty: the shared SQL guest backs MULTIPLE business databases;
    # a rebuild replaces both seeded datasets atomically (advisory below).
    blockers = issues

    advisories: list[str] = []
    for src, deps in sorted(cascade_from.items()):
        advisories.append(f"{src} rebuild cascades to {sorted(deps)} "
                          f"(declared dependencies; unapproved work on those "
                          f"guests is destroyed)")
    for g in bp.guests:
        if g.role == GuestRole.WINDOWS_SQL and g.name in rebuild:
            advisories.append(f"{g.name} hosts the store AND webmail databases; "
                              f"the rebuild replaces both seeded datasets")
    for dc in dc_names:
        if dc in rebuild:
            advisories.append(f"{dc} reset re-provisions the forest; domain "
                              f"member reboots cannot substitute for "
                              f"re-provisioned machine trust")
    if any(g.name in rebuild for g in bp.guests
           if g.role in (GuestRole.ROUTER, GuestRole.FIREWALL)):
        advisories.append("router/firewall rebuild interrupts ALL segments "
                          "(transit/NAT/DHCP) until read-back confirms")

    # durable inventory honesty: ONLY explicitly eligible states reset.
    # Fail-closed for unknown ownership, transitional and foreign states —
    # a string we do not recognize is not evidence of anything, and a
    # FAILED guest resets only with positive reconciled ownership supplied
    # by the executing path (see reconciled_guests).
    for g in sorted(rebuild):
        st = states.get(g)
        if st is None:
            blockers.append(f"no durable inventory for guest {g} — reset "
                            f"refused until ownership is reconciled "
                            f"(recovery: reconcile broker ledger, then retry)")
        elif st in RESET_ELIGIBLE_STATES:
            continue
        elif st == "failed":
            if g not in reconciled_guests:
                blockers.append(
                    f"guest {g} is failed; reset requires positive "
                    "reconciled ownership/read-back (reconcile the broker "
                    "ledger for this exact generation, then retry)")
        elif st in TRANSITIONAL_STATES:
            blockers.append(f"guest {g} is mid-provision (state {st!r}); "
                            f"finish or fail the provisioning attempt first")
        elif st in FOREIGN_STATES:
            blockers.append(f"guest {g} is state {st!r}: ownership is not "
                            f"ours (or not proven); never reset what we do "
                            f"not provably own")
        elif st not in _KNOWN_GUEST_STATES:
            blockers.append(f"guest {g} has unrecognized inventory state "
                            f"{st!r}; refusing to plan against a state we "
                            f"cannot interpret")
        # remaining known non-eligible states (e.g. destroyed) fall through
        # to the explicit blocker below
        else:
            blockers.append(f"guest {g} is state {st!r}, which is not a "
                            f"resettable state")

    return {
        "plan_version": RESET_PLAN_VERSION,
        "ok": not blockers,
        "blockers": sorted(set(blockers)),
        "advisories": advisories,
        "full": full,
        "selected": selected,
        "rebuild": sorted(rebuild),
        "preserved": preserved,
        # destructive-effects preview per rebuilt guest (generation bump +
        # key rotation are execution invariants, listed here for the UI)
        "effects": {g: ["destroy owned resources", "new generation (keys/"
                        "host pins/console/SSH capabilities revoked)",
                        "re-provision from pinned image + seed",
                        "stale verifier objectives for this guest expire"]
                    for g in sorted(rebuild)},
        "fences": _fences(selected),
    }


def _fences(selected: list[str]) -> dict:
    return {
        "ai_offence_fence": True,      # dispatch stops, managed commands cancel
        "scoring_fence": True,         # scheduled samples mark gap UNKNOWN
        "model_memory_invalidation": "affected-guests",
        "console_capabilities": "revoked-for-rebuilt",
    }
