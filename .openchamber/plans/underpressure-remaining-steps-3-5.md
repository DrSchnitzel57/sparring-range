# Underpressure — remaining slices (steps 3–5)

> Drafted 2026-11-03 during the appliance outage. Status facts as of commit
> `Findings: open appliance-incident entry; nine real goldens`. This is the
> implementation order for the REST of the Underpressure plan
> ([saved plan](../docs/ARCHITECTURE.md#underpressure-live-ai-defense-range--2026-11-01-implementation-in-progress),
> steps 3–5); step 1 (contract) and most of step 2 (images/topology) are done.

## Steps
- [ ] A. Console gateway (browser consoles over the bastion; capability-tokened, per-generation).
- [ ] B. Exercise sessions bound to a lab (visibility, `sessions.lab_id` reuse; no second clone).
- [ ] C. Availability vantage runner (executes the check registry from the scoring golden, dependency-aware evidence via `srplatform/availability.py`).
- [ ] D. Offense binding (red worker consumes the environment `attack_view`; environment verifiers for Linux + Windows guests).
- [ ] E. Integrated proof gate (two members, reset mid-exercise, replay AAR, next-user reuse) + findings entry.
- [ ] F. Release packaging & review of the above; roadmap/architecture status truth.

## Changed producer → consumer map (facts, not guesses)

| Slice | Producer | Consumer(s) | Contract that must not drift | Existing tests |
| --- | --- | --- | --- | --- |
| A | `srplatform/api/lab_routes.py` + new console WS | browser, bastion | capability tokens are session/generation bound and revoked on reset | `tests/test_lab_api.py`, `tests/test_plan19_browser_admin.py` |
| B | `lab_service` (exists) | session launch/verifier/visibility | a lab session REUSES deployed guests; `scenario_spec()` stays the frozen grading spec | `tests/test_lab_api.py`, `tests/test_visibility*.py` |
| C | new vantage executor | `verification_service`, scoring | `availability.evaluate_registry` is the ONLY decision table; unknown never awards | `tests/test_availability.py` |
| D | env `attack.yaml` + `scenario red.*` | `red_agent/loop.py` (`render_environment_context` exists) | objective verifiers run from the VANTAGE, never the attacker; no hidden credentials | `tests/test_red_*`, `tests/test_environment_underpressure.py` |
| E | all above | release evidence | real guests, real members, real reset; accelerated fixtures labeled | `infra/dev/acceptance.py` gates |

## Observed vs. assumed

- OBSERVED (2026-11-04): nine real goldens registered and verified; the 12-guest
  lab reaches `active` on the appliance; a bastion token logs a member into a
  Linux environment guest from the operator box (`ecomm`, `sr` uid 1001);
  selective reset + lab API + availability decision table pass db tests; red
  agent renders environment context.
- OBSERVED FIXES this session (root causes, not workarounds): broker restart
  deadlock (boot hashed 30 GB against a 30 s lease, and releases did not
  refresh the lease — the range could not come back up); image keys owned by
  the wrong uid (`sr` is 1001, `ubuntu` is 1000); `qemu-guest-agent` never
  enabled by a chroot `systemctl enable` and missing entirely from the desktop
  image.
- LANDED IN CODE, NOT YET LIVE-PROVEN: the availability VANTAGE executor
  (`srplatform/availability_runner.py`, plans -> exit-code -> evidence);
  lab-bound exercise sessions (`lab_service.attach_exercise`, no second clone)
  and their verifier host resolution; typed `guest_exec` (the Windows
  verifier lane, through the guest agent).
- ASSUMED (needs verification): the availability runner's plan templates treat
  a refused TCP connection as a SCORER error (exit != 0/3), i.e. `unknown`
  rather than `failed` — the semantics to settle before scoring on it.
- NOT STARTED: console gateway (A), Windows verifier dispatch onto `guest_exec`,
  offense binding for env guests (D), integrated proof gate (E), release
  review (F).

## Non-goals (kept honest)

- No public hosting, no concurrent ranges, no official competition weights.
- Windows 11 workstation is BIOS-only today; UEFI/vTPM stays declared-not-wired.
- Accelerated fixtures never prove AI effectiveness or live behavior.
- Do not erase the appliance or touch outer-host firewall without authorization.

## Order and gates (each slice = one commit, one fresh review)

1. A/B are independent of C/D but need the lab product; C/D need the live
   appliance (real vantage, real guests).
2. C before D: the AI must not grade itself; availability evidence comes first.
3. E runs only when A–D are green on the appliance; it uses the REAL 12 guests.
4. F updates FINDINGS/ARCHITECTURE status boundaries — never claims whole-
   release or real-model acceptance.

## Appliance-load rule learned 2026-11-03

The appliance VM disappeared while ~40 GiB of nested guests + a 6 GiB Windows
build ran. Serialize: 12-guest gates and Windows builds do NOT run together;
prefer ≤10 guests for verification gates until the outer host's budget is
measured.
