"""Scenario orchestrator (M1 — F06 rewrite): deployment with a global lease,
persisted intent, exact resource ownership, and reconciliation.

The old version named VMs by scenario prefix, reused static IPs, allocated
VMIDs with a read-then-use scan, and destroyed everything matching a prefix —
two launches could collide and destroy each other's machines. Now:

  * A durable SINGLE-ACTIVE-RANGE lease (`range_lease` row) is acquired BEFORE
    any external side effect; concurrent launches conflict cleanly.
  * A `deployments` row records intent; resources are appended EXACTLY as each
    side effect completes (vmid/node/name/ip), so recovery from a partial
    failure works from the recorded list — never from name prefixes.
  * Reset/teardown act only on positively-owned recorded resources (with an
    ownership tag double-check) and ignore prefix-similar foreign VMs.
  * Every external call goes through the task-aware ProxmoxClient (F05).
  * Database failures after side effects are LOUD (recorded + raised), never
    swallowed (F06 `_log()` fix).
"""
from __future__ import annotations

import time
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from infra.broker.errors import BrokerError, BrokerUnavailable
from srplatform.db.models import (Deployment, Event, OperationClaim, RangeLease,
                                  ServiceToken,
                                  Session as SessionModel)
from srplatform.scenario_engine.loader import load_scenario
from srplatform.settings import get_settings


class LeaseConflict(RuntimeError):
    def __init__(self, holder_session_id, acquired_at):
        self.holder_session_id = str(holder_session_id) if holder_session_id else None
        self.acquired_at = acquired_at.isoformat() if acquired_at else None
        super().__init__(f"range is already reserved by session {self.holder_session_id}")


class OperationInProgress(RuntimeError):
    """A durable operation claim for this session is held by another request."""

    def __init__(self, session_id, operation, claimed_at):
        self.session_id, self.operation = str(session_id), operation
        self.claimed_at = claimed_at.isoformat() if claimed_at else None
        super().__init__(f"operation '{operation}' already in progress for session "
                         f"{self.session_id}")


class ForeignResourceError(RuntimeError):
    """A VMID we intended to use is positively occupied by a foreign machine."""


# ------------------------------------------------------------------ claims ---
# DURABLE OPERATION CLAIMS (audit N02): a normal row lock does NOT survive the
# intent commits that deployment correctness REQUIRES (acquire_lease/deploy
# commit per side effect). The claim is a committed row: it serializes
# launch/deploy/reset/teardown/end for one session ACROSS those commits.
# Crash recovery: claims older than the stale window may be taken over (with
# loud evidence), and API startup clears claims (single-API architecture —
# see docs/ARCHITECTURE_NOTES.md).
CLAIM_STALE_AFTER = timedelta(minutes=30)


def claim_operation(db: Session, session_id, operation: str,
                    stale_after: timedelta = CLAIM_STALE_AFTER) -> str:
    """Acquire the durable operation claim and return the OWNER TOKEN
    (audit T02). Release is fenced on this token: a request whose claim was
    taken over (stale window) can never delete the replacement's row."""
    owner = uuidlib.uuid4().hex
    now = _now()
    row = db.get(OperationClaim, session_id)
    if row is not None:
        age = (now - row.claimed_at) if row.claimed_at else None
        if age is not None and age < stale_after:
            raise OperationInProgress(session_id, row.operation, row.claimed_at)
        _log(db, session_id, "operation_claim_takeover", None,
             {"stale_operation": row.operation, "stale_claimed_at":
              row.claimed_at.isoformat() if row.claimed_at else None,
              "new_operation": operation})
        row.operation, row.claimed_at, row.owner = operation, now, owner
        db.commit()   # the claim must survive any later rollback
        return owner
    db.add(OperationClaim(session_id=session_id, operation=operation,
                          claimed_at=now, owner=owner))
    try:
        db.commit()   # durable BEFORE any side effect
    except IntegrityError:
        # concurrent claimer won the race — they hold the operation
        db.rollback()
        row = db.get(OperationClaim, session_id)
        raise OperationInProgress(session_id, row.operation if row else "?",
                                  row.claimed_at if row else None)
    return owner


def release_operation(db: Session, session_id, owner: str | None = None) -> bool:
    """Release the claim. WITH an owner token the delete is FENCED (audit T02):
    it only removes the row this request still owns — a stale request whose
    claim was taken over returns False and erases nothing. Without a token
    (startup reconciliation only) the row is removed unconditionally."""
    row = db.get(OperationClaim, session_id)
    if row is None:
        return False
    if owner is not None and row.owner != owner:
        return False   # someone else holds it now — never erase their ownership
    db.delete(row)
    db.commit()
    return True


def clear_operation_claims(db: Session) -> int:
    """API startup reconciliation: claims only have meaning while the single
    API process is alive; anything left over belongs to a dead request.

    Deploy-operation rows are reconciled FIRST (plan 13 phase 5): an
    accepted/running operation whose executor died becomes `interrupted`
    with loud evidence, so clearing its claim can never make a dead
    attempt look like one that is still in flight."""
    reconcile_deploy_operations(db)
    n = 0
    for row in db.execute(select(OperationClaim)).scalars().all():
        db.delete(row)
        n += 1
    db.commit()
    return n


# ------------------------------------------------- durable deploy operations --
def begin_deploy_operation(db: Session, session_id, operation: str, *,
                           fence: str, deadline_s: int):
    """DURABLE ACCEPTANCE (plan 13 phase 5): identity, owner fence, phase and
    deadline are committed BEFORE the first side effect. A caller that loses
    the response can still find this row; a duplicate request finds the live
    claim and is refused, so no second deployment exists."""
    from srplatform.db.models import DeployOperation
    row = DeployOperation(session_id=session_id, operation=operation,
                          state="accepted", phase="queued", fence=fence,
                          deadline_at=_now() + timedelta(seconds=deadline_s))
    db.add(row)
    db.commit()
    return row


def advance_deploy_operation(db: Session, row, phase: str) -> None:
    """Phase/progress transitions commit immediately: a poller sees where the
    attempt really is, and a crash leaves the LAST phase it reached."""
    from srplatform.db.models import DeployOperation
    row = db.get(DeployOperation, row.operation_id)
    if row is None or row.state in ("succeeded", "failed", "interrupted"):
        return
    row.state = "running"
    row.phase = phase
    row.updated_at = _now()
    db.commit()


def finish_deploy_operation(db: Session, row, state: str, *,
                            error: str | None = None) -> None:
    """Terminal outcome, committed. `error` is redacted + bounded by the
    caller; full provisioning commands and secrets never reach this row."""
    from srplatform.db.models import DeployOperation
    row = db.get(DeployOperation, row.operation_id)
    if row is None:
        return
    row.state = state
    row.error = (error or None) and str(error)[:500]
    row.completed_at = _now()
    row.updated_at = row.completed_at
    db.commit()


def reconcile_deploy_operations(db: Session) -> int:
    """Startup: operations still accepted/running belong to an executor that
    died with the process. Mark them `interrupted` — never silently resumed,
    never deleted; the range stays owned and the next launch resumes through
    the durable deployment inventory."""
    from srplatform.db.models import DeployOperation
    rows = db.execute(select(DeployOperation).where(
        DeployOperation.state.in_(("accepted", "running")))).scalars().all()
    for row in rows:
        row.state = "interrupted"
        row.error = "executor lost (API restart) — range stays owned; " \
                    "next launch resumes"
        row.completed_at = _now()
        row.updated_at = row.completed_at
    db.commit()
    return len(rows)


def latest_deploy_operation(db: Session, session_id):
    from srplatform.db.models import DeployOperation
    return db.execute(
        select(DeployOperation)
        .where(DeployOperation.session_id == session_id)
        .order_by(DeployOperation.created_at.desc())
    ).scalars().first()


def _now():
    return datetime.now(timezone.utc)


def _log(db: Session, session_id, action, host, payload):
    """Deployment actions are recorded in the append-only log. A failure here
    RAISES — silent loss of deployment evidence was itself an audit finding."""
    db.add(Event(session_id=session_id, ts=_now(), actor="system", host=host,
                 action_type=action, payload=payload))
    db.flush()


def _enroll_telemetry(db: Session, session_id, host: str,
                      deployment_id=None) -> tuple[str, str]:
    """Per-deployment telemetry enrollment (audit N09/T-05): each clone gets
    a session-AND-host-bound telemetry capability AND a FRESH ENROLLMENT
    NONCE, issued at deploy time. The plaintext token+nonce are returned ONCE
    (provisioning); the inventory keeps only a reference. Revocation follows
    the session lifecycle — end, reset and teardown revoke every session
    capability including these (the same code path), so an old clone can
    never contribute events to a new session. Trust limit: events from a
    COMPROMISED host are evidence of what that host CLAIMED under a valid
    capability, not ground truth."""
    import uuid as _u
    token = f"svc-telemetry-{_u.uuid4().hex}"
    nonce = _u.uuid4().hex
    db.add(ServiceToken(token=token, scope="telemetry", session_id=session_id,
                        host=host, enroll_nonce=nonce,
                        enrollment_deployment_id=deployment_id))
    return token, nonce


def _token_ref(token: str) -> str:
    return f"...{token[-6:]}"


# ------------------------------------------------- telemetry enrollment (T05/T-05) --
# Token ISSUANCE is not enrollment, and a RUNNING SERVICE is not evidence.
# Each clone must be PROVISIONED with its session-bound capability through
# the management channel, and enrollment advances only on DISTINCT evidence:
#
#   provisioned          — env written + service enabled/restarted (channel rc 0)
#   service_running      — `systemctl is-active` answers active
#   delivery_confirmed   — an AUTHENTICATED callback bound to a fresh nonce
#                          arrived FROM THE PROVISIONED HOST (proves the API
#                          address, the token and the delivery path)
#   confirmed            — a harmless capture probe was OBSERVED AS AN AUDIT
#                          EVENT THROUGH THE INSTALLED SERVICE (proves the
#                          input path and command capture)
#
# Phases: (none) -> pending_token -> provisioned -> service_running ->
#         delivery_confirmed -> confirmed
#         failure states: provision_failed / confirm_failed / unconfigured
# The phase is persisted per resource so an interrupted or lost-response
# provisioning resumes safely instead of re-issuing blindly.
import time as _time

_enrollment_exec = None  # fn(addr, command) -> (code, out); test/operator hook


def set_enrollment_exec(fn):
    """Test/operator hook: replace the enrollment provisioning channel."""
    global _enrollment_exec
    _enrollment_exec = fn


def enrollment_channel_available() -> bool:
    """Enrollment is ENFORCED when a provisioning channel exists: the
    explicit hook, or the real pinned-key SSH management channel (key +
    EXISTING known-hosts file). A verifier-READ override does not count —
    reading host state is not the same capability as writing it."""
    if _enrollment_exec is not None:
        return True
    import os
    s = get_settings()
    return bool(s.verifier_ssh_key_path and s.verifier_ssh_known_hosts
                and os.path.exists(s.verifier_ssh_known_hosts))


# Poll interval for the first-boot management-channel retry (tests shorten it).
_MANAGEMENT_READY_POLL_S = 5.0


#: Signatures in ssh's 255 output that DEFINITIVELY explain the failure
#: (plan 13 phase 4): bad key/auth and pin mismatches can never be ridden
#: out by retrying, and must fail distinctly and immediately. A bare 255
#: without one of these stays the ambiguous "session never established"
#: boot race — the command provably never ran, so retry is safe.
_SSH_DEFINITIVE_FAILURES = (
    "Permission denied",               # bad key / auth method
    "Host key verification failed",    # pinned key mismatch
    "REMOTE HOST IDENTIFICATION HAS CHANGED",
    "no matching host key type",       # transport negotiation refused
)


def ssh_failure_is_definitive(tail) -> bool:
    t = str(tail)
    return any(sig in t for sig in _SSH_DEFINITIVE_FAILURES)


def _provision_with_boot_wait(chan, ip: str, command: str,
                              wait_s: float) -> tuple[int, str]:
    """Run a provisioning command, riding out ONLY the sshd boot race.

    Live find 2026-10-14: right after a clone starts, ssh exits 255
    ("session never established") until sshd finishes booting — the first
    live deploy failed enrollment exactly there. 255 means the command
    NEVER RAN, so retrying the same (idempotent) command is safe and is
    bounded by `wait_s`. Any other rc is a real answer from the guest and
    is returned immediately — broken channels still fail fast and visibly
    (audit: a wrong API address or rejected token must not hide).
    Definitive 255 causes (bad key/auth/pin, plan 13 phase 4) fail
    distinctly WITHOUT burning the boot window."""
    code, tail = chan(ip, command)
    if code == 255 and ssh_failure_is_definitive(tail):
        return code, tail
    if code == 255 and wait_s > 0:
        deadline = time.monotonic() + wait_s
        while code == 255 and time.monotonic() < deadline:
            time.sleep(_MANAGEMENT_READY_POLL_S)
            code, tail = chan(ip, command)
    return code, tail


def _enrollment_channel():
    if _enrollment_exec is not None:
        return _enrollment_exec
    if enrollment_channel_available():
        from srplatform import verification_service
        return verification_service.management_exec
    return None


def management_runner():
    """Public bounded management-channel runner (plan 13 phase 6): returns
    a callable ``(ip, command) -> (exit_code, output)`` or None when no
    channel is configured. The uptime MySQL business probe reads through
    the SAME authenticated path the verifier uses — one read-only command
    per call, no boot-race replay (the target is long booted)."""
    return _enrollment_channel()


def _recover_telemetry_token(db: Session, session_id, host: str,
                             deployment_id=None) -> tuple[str, str] | None:
    """Recover the issued plaintext + nonce after a lost deployment response:
    the ServiceToken row IS the durable record (plaintext primary key), so a
    retry resumes enrollment for the SAME capability and the SAME enrollment
    nonce instead of issuing a second one.

    AUDIT F4: recovery RESUMES the CURRENT deployment generation's token —
    not 'whichever matching host row happens to be newest'. A pre-existing
    capability being safely RE-ENROLLED (older generation, or unbound) is
    rebound to the current generation; it is never gratuitously replaced."""
    q = (select(ServiceToken)
         .where(ServiceToken.session_id == session_id,
                ServiceToken.host == host,
                ServiceToken.scope == "telemetry",
                ServiceToken.revoked_at.is_(None)))
    if deployment_id is not None:
        row = db.execute(q.where(
            ServiceToken.enrollment_deployment_id == deployment_id)
            .order_by(ServiceToken.created_at.desc())).scalars().first()
        if row:
            return (row.token, row.enroll_nonce)
    row = db.execute(q.order_by(ServiceToken.created_at.desc())).scalars().first()
    if row is None:
        return None
    if deployment_id is not None and row.enrollment_deployment_id != deployment_id:
        row.enrollment_deployment_id = deployment_id   # re-enroll: rebind
        db.commit()
    return (row.token, row.enroll_nonce)


def enrollment_evidence_current(db: Session, session_id, host: str,
                                deployment_id) -> bool:
    """AUDIT F3/F4: valid enrollment evidence for the CURRENT deployment
    generation means the EXACT capability bound to that generation carries
    BOTH distinct evidence timestamps (authenticated delivery callback +
    capture probe observed). A JSON phase alone is never evidence."""
    if deployment_id is None:
        return False
    row = db.execute(select(ServiceToken.token)
                     .where(ServiceToken.session_id == session_id,
                            ServiceToken.host == host,
                            ServiceToken.scope == "telemetry",
                            ServiceToken.revoked_at.is_(None),
                            ServiceToken.enrollment_deployment_id == deployment_id,
                            ServiceToken.enroll_confirmed_at.isnot(None),
                            ServiceToken.enroll_capture_at.isnot(None))
                     .limit(1)).first()
    return row is not None


def capture_marker(nonce: str) -> str:
    """The harmless capture-probe marker (audit T-05): a unique token carried
    in the argv of a harmless command executed on the host. Observing it as
    an audit event THROUGH the installed service is the only evidence that
    command capture works."""
    return f"SR-CAPTURE-{nonce[:12]}"


def _provision_command(host: str, token: str, nonce: str, s) -> str:
    """The per-clone provisioning command the golden image's installer
    contract expects: write the REAL env file (no placeholders, including the
    enrollment nonce), restrict it to the service identity, and enable+
    restart the enrolled service. For an https API the PUBLIC range CA is
    provisioned alongside (plan 13 phase 4) so the shipper verifies the
    listener with an explicit trust anchor — never a disabled check."""
    import shlex
    env = (f"SR_API_URL={s.api_base_url}\n"
           f"SR_TELEMETRY_TOKEN={token}\n"
           f"SR_HOST={host}\n"
           f"SR_ENROLL_NONCE={nonce}\n"
           f"SR_SPOOL_DIR=/var/lib/sparring-range/shipper\n")
    ca_pre, ca_env = "", ""
    if s.api_base_url.startswith("https://") and s.telemetry_ca_file:
        try:
            ca_pem = open(s.telemetry_ca_file).read()
        except OSError as e:
            raise RuntimeError(
                f"telemetry CA file {s.telemetry_ca_file!r} unreadable — "
                f"refusing to enroll {host} without its trust anchor: {e}") from e
        ca_pre = ("install -d -m 0755 /etc/sparring-range/tls && "
                  f"printf '%s' {shlex.quote(ca_pem)} > "
                  "/etc/sparring-range/tls/api-ca.crt && "
                  "chmod 0644 /etc/sparring-range/tls/api-ca.crt && ")
        env += "SR_TLS_CA_FILE=/etc/sparring-range/tls/api-ca.crt\n"
    return (ca_pre +
            "install -d -m 0750 /etc/sparring-range && "
            f"printf '%s' {shlex.quote(env)} > /etc/sparring-range/shipper.env && "
            "chown root:srshipper /etc/sparring-range/shipper.env && "
            "chmod 0640 /etc/sparring-range/shipper.env && "
            "systemctl enable --now sparring-shipper && "
            "systemctl restart sparring-shipper")


def _provision_guest_configs(db: Session, dep: Deployment, spec: dict,
                             resources: list, session_id) -> None:
    """Deploy-time DB-tier wiring (plan 13 phase 3): web hosts with a
    ``db_ref`` get config targeting the OWNED DB IP with a fresh scoped
    reader credential; the DB host binds, grants and firewalls ONLY the
    owned web sources plus the loopback probe. Idempotent (resume-safe);
    a missing channel is a VISIBLE skip (event + readiness gate), a
    channel that answers with failure fails the deployment loudly."""
    from srplatform.scenario_engine import guest_config
    plan = guest_config.plan_db_provisioning(spec)
    if not plan:
        return
    chan = _enrollment_channel()
    if chan is None:
        # Same contract as telemetry enrollment: skipping is a VISIBLE
        # dev-mode relaxation (event + resource flag), never silent —
        # enforced readiness refuses a db_ref deployment whose tier was
        # never configured (phase 4 gate).
        _log(db, session_id, "guest_config_skipped", None,
             {"reason": "management channel not configured — dev-mode "
                        "relaxation, visible in readiness"})
        db.commit()
        return
    s = get_settings()
    by_host = {r.get("host"): r for r in resources}
    for step in plan:
        res = by_host.get(step["host"])
        ip = (res or {}).get("ip")
        if not ip:
            raise RuntimeError(
                f"cannot provision {step['host']}: no owned IP in the "
                "deployment inventory")
        if step["kind"] == "db":
            pw = guest_config.reader_password(resources, step["host"])
            cmd = guest_config.db_provision_command(step, pw)
        else:
            pw = (by_host.get(step["db_ref"]) or {}).get("db_reader_password")
            if not pw:
                raise RuntimeError(
                    f"web host {step['host']} must be provisioned AFTER its "
                    f"DB tier {step['db_ref']}")
            cmd = guest_config.web_provision_command(step, pw)
        code, out = _provision_with_boot_wait(
            chan, ip, cmd, s.management_ready_wait_s)
        if code != 0:
            raise RuntimeError(
                f"guest config provisioning failed on {step['host']} "
                f"(exit {code}): {str(out)[:300]}")
        if step["kind"] == "db":
            res["db_reader_password"] = pw
        res["db_configured"] = True
        dep.resources = resources
        flag_modified(dep, "resources")
        _log(db, session_id, "guest_config_provisioned", step["host"],
             {"kind": step["kind"], "db_ref": step.get("db_ref")})
        db.commit()


def _enrollment_evidence(db: Session, session_id, host: str, attr: str,
                         deployment_id=None):
    """Evidence timestamp of the capability bound to the CURRENT deployment
    generation (audit F4) — or, when no generation is given, the newest
    un-revoked telemetry capability."""
    q = select(getattr(ServiceToken, attr)).where(
        ServiceToken.session_id == session_id,
        ServiceToken.host == host,
        ServiceToken.scope == "telemetry",
        ServiceToken.revoked_at.is_(None))
    if deployment_id is not None:
        q = q.where(ServiceToken.enrollment_deployment_id == deployment_id)
    return db.execute(q.order_by(ServiceToken.created_at.desc()).limit(1)
                      ).scalars().first()


def _wait_for_enrollment_evidence(db: Session, session_id, host: str, attr: str,
                                  timeout_s: float, poll_s: float = 0.25,
                                  deployment_id=None):
    """Bounded wait for the HOST-ORIGINATED evidence (the API routes set it
    when the provisioned host calls in). Returns the timestamp or None —
    a timeout is a VISIBLE enrollment failure, never an assumed pass."""
    deadline = _time.monotonic() + max(0.0, timeout_s)
    while True:
        db.expire_all()   # the callback lands on another session — read fresh
        val = _enrollment_evidence(db, session_id, host, attr, deployment_id)
        if val is not None or _time.monotonic() >= deadline:
            return val
        _time.sleep(poll_s)


def _enroll_host_telemetry(db: Session, dep: Deployment, res: dict, resources: list,
                           session_id, host_name: str, ip: str | None, s,
                           out: dict) -> str:
    """Drive ONE host's enrollment as far as the EVIDENCE allows, committing
    the phase after every step (crash/lost-response resumes, never repeats
    token issuance). A phase advances ONLY on its distinct evidence:
    provisioning rc, service-active, the host's authenticated nonce callback
    (delivery), and an audit event through the installed service (capture).
    `systemctl is-active` alone proves NOTHING about delivery — a shipper
    with a wrong API address, a rejected token or an unreadable input stays
    visibly stuck (audit T-05)."""
    enroll = dict(res.get("telemetry_enroll") or {})
    if enroll.get("phase") == "confirmed":
        # AUDIT F3: a phase that SAYS confirmed is not evidence — a
        # pre-upgrade (phase-only) confirmation, or one whose capability lost
        # its evidence, RESUMES enrollment instead of being trusted.
        if enrollment_evidence_current(db, session_id, host_name, dep.deployment_id):
            return "confirmed"
        enroll = {k: v for k, v in enroll.items()
                  if k not in ("phase", "stage", "error")}
        res["telemetry_enroll"] = enroll
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()

    def persist(**kw) -> str:
        # advancing PAST a failure stage clears the stale failure metadata
        # without inventing new timestamps (audit F3)
        if kw.get("phase") != "confirm_failed":
            enroll.pop("stage", None)
            enroll.pop("error", None)
        enroll.update(kw)
        res["telemetry_enroll"] = enroll
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()
        return enroll["phase"]

    recovered = _recover_telemetry_token(db, session_id, host_name, dep.deployment_id)
    if recovered is None:
        tok, nonce = _enroll_telemetry(db, session_id, host_name, dep.deployment_id)
        res["telemetry_token_ref"] = _token_ref(tok)
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()
    else:
        tok, nonce = recovered
        if not nonce:   # capability issued before the nonce contract: rotate
            row = db.execute(select(ServiceToken).where(
                ServiceToken.token == tok)).scalar_one()
            row.enroll_nonce = uuidlib.uuid4().hex
            db.commit()
            nonce = row.enroll_nonce
    persist(phase="pending_token", token_ref=_token_ref(tok))
    out[host_name] = tok  # plaintext returned to the deployment response
    chan = _enrollment_channel()
    if chan is None or not ip:
        return persist(phase="unconfigured",
                       note="provisioning channel not configured — dev-mode "
                            "relaxation, visible in readiness")
    code, tail = _provision_with_boot_wait(
        chan, ip, _provision_command(host_name, tok, nonce, s),
        s.management_ready_wait_s)
    if code != 0:
        return persist(phase="provision_failed", error=str(tail)[:200])
    persist(phase="provisioned", provisioned_at=_now().isoformat())
    code, tail = chan(ip, "systemctl is-active --quiet sparring-shipper")
    if code != 0:
        return persist(phase="confirm_failed", stage="service_running",
                       error=f"service not active: {str(tail)[:200]}")
    persist(phase="service_running", service_running_at=_now().isoformat())

    # DELIVERY (audit T-05): the provisioned host must call BACK,
    # authenticated by its capability and bound to the fresh nonce. A service
    # that is merely active with a wrong API address / rejected token /
    # blocked delivery never produces this evidence.
    confirmed_at = _wait_for_enrollment_evidence(
        db, session_id, host_name, "enroll_confirmed_at", s.enroll_confirm_timeout_s,
        deployment_id=dep.deployment_id)
    if confirmed_at is None:
        return persist(phase="confirm_failed", stage="delivery_confirmed",
                       error="service active but NO authenticated enrollment "
                             "callback arrived from the provisioned host — API "
                             "address, token or delivery path is broken "
                             f"(timeout {s.enroll_confirm_timeout_s}s)")
    persist(phase="delivery_confirmed", delivery_confirmed_at=confirmed_at.isoformat())

    # CAPTURE (audit T-05): execute a harmless command and require its audit
    # event THROUGH THE INSTALLED SERVICE. Delivery working while capture is
    # broken (unreadable audit input, wrong unit identity) is NOT a healthy
    # evidence stream.
    marker = capture_marker(nonce)
    code, tail = chan(ip, f"/bin/true {marker}")
    if code != 0:
        return persist(phase="confirm_failed", stage="capture_probe",
                       error=f"capture probe failed on host: {str(tail)[:200]}")
    capture_at = _wait_for_enrollment_evidence(
        db, session_id, host_name, "enroll_capture_at", s.enroll_capture_timeout_s,
        deployment_id=dep.deployment_id)
    if capture_at is None:
        return persist(phase="confirm_failed", stage="capture_verified",
                       error="delivery confirmed but the capture probe produced "
                             "NO audit event through the installed service — "
                             "command capture is broken (input unreadable?) "
                             f"(timeout {s.enroll_capture_timeout_s}s)")
    return persist(phase="confirmed", confirmed_at=capture_at.isoformat(),
                   capture_verified_at=capture_at.isoformat())


# ------------------------------------------------------------------- lease ---
def _residual_resources(db: Session, session_id) -> list[dict]:
    """Owned resources that still exist (or whose fate is uncertain) for a
    session — the thing that must NOT be left behind when a lease is taken
    over or released (audit R07)."""
    residual = []
    for dep in db.execute(select(Deployment).where(Deployment.session_id == session_id)
                          .order_by(Deployment.created_at)).scalars().all():
        for r in (dep.resources or []):
            if r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed"):
                residual.append({**r, "deployment_id": str(dep.deployment_id)})
    return residual


def acquire_lease(db: Session, session_id) -> None:
    """Global single-active-range reservation (v1 assumption; see
    docs/ARCHITECTURE_NOTES.md). Row lock serializes concurrent acquirers."""
    row = db.execute(select(RangeLease).where(RangeLease.id == 1)
                     .with_for_update()).scalar_one_or_none()
    held = row is not None and row.released_at is None and str(row.session_id) != str(session_id)
    if held:
        # defensive reconciliation: a lease whose holder session already ended
        # is stale and may be taken over — but ONLY when the holder has no
        # residual machines still holding the range's static addresses
        # (audit R07: ending a session must not hand the same IP space to the
        # next launch while the old VMs are still running).
        holder = db.get(SessionModel, row.session_id) if row.session_id else None
        residual = _residual_resources(db, row.session_id) if row.session_id else []
        if holder is not None and holder.status in ("complete", "failed", "torn_down") and residual:
            raise LeaseConflict(row.session_id, row.acquired_at)
        if holder is None or holder.status in ("complete", "failed", "torn_down"):
            row.session_id, row.acquired_at, row.released_at = session_id, _now(), None
            _log(db, session_id, "lease_takeover", None,
                 {"stale_holder": str(row.session_id), "status": holder.status if holder else None})
            db.commit()   # the reservation must survive any later rollback
            return
        raise LeaseConflict(row.session_id, row.acquired_at)
    if row is None:
        db.add(RangeLease(id=1, session_id=session_id, acquired_at=_now()))
    else:
        row.session_id, row.acquired_at, row.released_at = session_id, _now(), None
    db.commit()   # reserve BEFORE any side effect; survives later failure


def release_lease(db: Session, session_id) -> None:
    row = db.get(RangeLease, 1)
    if row and row.released_at is None and (session_id is None or str(row.session_id) == str(session_id)):
        row.released_at = _now()
        _log(db, row.session_id, "lease_release", None, {})
        db.commit()


def current_lease(db: Session) -> dict | None:
    row = db.get(RangeLease, 1)
    if not row or row.released_at is not None:
        return None
    return {"session_id": str(row.session_id) if row.session_id else None,
            "acquired_at": row.acquired_at.isoformat() if row.acquired_at else None}


# ------------------------------------------------------------------ deploy ---
def _net_spec(s) -> str:
    return f"virtio,bridge={s.range_bridge},tag={s.range_vlan}"


def _pin_host_key(broker, db: Session, session_id, dep: Deployment,
                    res: dict, resources: list, node: str) -> None:
    """Pin the fresh clone's public SSH host key through the broker's typed
    guest-agent FileRead channel (paired 03+04, step 3/4). The pin binds the
    current ownership/generation; fresh clone/reset generations pin fresh
    keys. A same-generation change is refused by the broker (possible
    compromise) and surfaces here as a visible deployment failure — the
    resource stays owned and the lease is retained, never silently re-pinned.
    """
    read = getattr(broker, "read_host_key", None)
    if read is None:
        return  # pre-03+04 broker double in old unit tests — pins unenforced
    key = read(node, int(res["vmid"]), session_id=session_id,
               generation=str(dep.deployment_id))
    res["host_key_ref"] = f"{key[:24]}…{key[-8:]}"
    ip = res.get("ip")
    if ip:
        err = _publish_pinned_host_key(ip, key)
        if err:
            # visible, never silent: the pin exists but clients cannot use
            # it yet — runtime SSH will fail loudly until this is repaired
            res["host_key_publish_error"] = err
            _log(db, session_id, "host_key_publish_failed", res.get("host"),
                 {"vmid": res["vmid"], "error": err})
    dep.resources = resources
    flag_modified(dep, "resources")
    _log(db, session_id, "host_key_pinned", res.get("host"),
         {"vmid": res["vmid"], "key_ref": res["host_key_ref"]})


def _unpublish_pinned_host_key(ip: str) -> None:
    """Invalidate the published pin for a DESTROYED generation (plan 13
    phase 4): once the VM is gone its key is dead truth — a stale line
    would MITM whatever answers that address next. Best-effort per client
    file; the broker ledger keeps the historical pin evidence."""
    import os
    from pathlib import Path

    from srplatform.settings import get_settings
    s = get_settings()
    for path in (s.runner_ssh_known_hosts, s.verifier_ssh_known_hosts,
                 s.bastion_targets_known_hosts):
        if not path:
            continue
        p = Path(path)
        try:
            if not p.exists():
                continue
            lines = p.read_text().splitlines()
            keep = [l for l in lines if l.strip() and l.split()[0] != ip]
            if len(keep) == len(lines):
                continue
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text(("\n".join(keep) + "\n") if keep else "")
            os.replace(tmp, p)
        except OSError:
            pass  # never blocks teardown; the destroyed VM is the authority


def _publish_pinned_host_key(ip: str, key: str) -> str | None:
    """Publish the pinned generation host key to the SSH clients' known_hosts
    files (runner / verifier / bastion). The pin is the truth; the files are
    how the clients learn it. Returns None on success or an error string —
    the caller records it as an event and in the deployment resource, so a
    client that can never connect is loud, not silent (StrictHostKeyChecking
    has no TOFU fallback).
    """
    import os
    from pathlib import Path

    from srplatform.settings import get_settings
    s = get_settings()
    line = f"{ip} {key.strip()}"
    problems = []
    for path in (s.runner_ssh_known_hosts, s.verifier_ssh_known_hosts,
                 s.bastion_targets_known_hosts):
        if not path:
            continue  # role without that client (or test settings)
        p = Path(path)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            keep = [l for l in (p.read_text().splitlines() if p.exists() else [])
                    if l.strip() and l.split()[0] != ip]
            keep.append(line)  # newest pin replaces any prior entry for this IP
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text("\n".join(keep) + "\n")
            os.replace(tmp, p)
            os.chmod(p, 0o644)  # public host keys; every service user reads
        except OSError as e:
            problems.append(f"{path}: {e}")
    return "; ".join(problems) or None


def _reserve_guest_budgets(scenario_id: str, spec: dict) -> dict:
    """Reserve/enforce guest + aggregate CPU/RAM/disk BEFORE any side effect
    (paired 03+04, step 4). Mojang presets must use their pinned templates;
    legacy snapshots are preserved but are NOT release-ready (their budgets
    are checked generically, and readiness requires the mojang manifest).

    Returns the aggregate reservation. Raises RuntimeError (no side effects
    yet) when the topology exceeds the canonical range totals or references
    an unknown template — the caller retains the lease and reports the truth.
    """
    try:
        from infra.images import specs as _specs
    except ImportError as e:  # pragma: no cover — repo layout guarantees this
        raise RuntimeError(f"guest budget specs unavailable: {e}") from e
    total = {"vcpus": 0, "memory_mb": 0, "disk_gb": 0}
    for host in (spec.get("topology") or {}).get("hosts", []):
        role = _specs.guest_for_template(int(host.get("template_vmid", 0)))
        if role is None:
            # Legacy template: generic per-guest ceiling (2 vCPU/2 GiB/16 GiB)
            # so old scenarios keep deploying in tests, but they are not
            # release evidence without manifests (plan step 2).
            total["vcpus"] += 2
            total["memory_mb"] += 2048
            total["disk_gb"] += 16
            continue
        budget = _specs.check_guest_budget(role)
        total["vcpus"] += budget["vcpus"]
        total["memory_mb"] += budget["memory_mb"]
        total["disk_gb"] += budget["disk_gb"]
    # Canonical ceiling for the largest release preset (web+DB): exceeding it
    # is a deployment refusal, never a silent resize.
    ceiling = {"vcpus": 6, "memory_mb": 6144, "disk_gb": 44}
    for k in ("vcpus", "memory_mb", "disk_gb"):
        if total[k] > ceiling[k]:
            raise RuntimeError(
                f"guest budget reservation refused: {total} exceeds release "
                f"ceiling {ceiling} for scenario {scenario_id!r}")
    return total


def _active_deployment(db: Session, session_id, scenario_id: str) -> Deployment | None:
    """Latest deployment for this session+scenario that still OWNS something
    (not torn_down) — the idempotency/resume anchor (audit R08)."""
    q = select(Deployment).where(Deployment.scenario_id == scenario_id)
    if session_id:
        q = q.where(Deployment.session_id == session_id)
    for dep in db.execute(q.order_by(Deployment.created_at.desc())).scalars().all():
        if dep.status in ("preparing", "ready", "failed"):
            return dep
    return None


def deploy(db: Session, session_id, scenario_id: str, broker, resume: bool = True) -> dict:
    """Clone every host in the scenario from its golden template, configure
    network/ownership on the range bridge, and start each with task waiting.
    Caller must hold the lease (acquire_lease first).

    Idempotent + crash-safe (audit R08):
      * an existing ready deployment is RETURNED, not duplicated;
      * a preparing/failed deployment is RESUMED — hosts whose resource row is
        already `created` are skipped;
      * each resource's identity is committed as `pending` BEFORE the clone
        starts, so a crash between side effects still leaves the VM owned.
    """
    s = get_settings()
    # IMMUTABLE SNAPSHOT (audit T04): deployment provisions what the SESSION
    # captured at creation — the same specification the worker executes and
    # the verifier grades. Editing the source YAML after session creation
    # must not change deployed topology independently of the graded spec.
    if session_id is not None:
        from srplatform import verification_service
        spec = verification_service.scenario_spec(db, session_id)
    else:
        spec = load_scenario(scenario_id)
    node = s.proxmox_node
    # Paired 03+04, step 4: explicit clone mode (no silent fallback) +
    # aggregate budget reservation BEFORE any side effect. Unknown retains
    # obligations/lease; stale work is fenced by the claim/generation checks
    # below (preserved from the R08/N01 paths).
    clone_full = str(getattr(s, "deploy_clone_mode", "linked")).lower() == "full"
    _reserve_guest_budgets(scenario_id, spec)

    dep = _active_deployment(db, session_id, scenario_id) if resume else None
    if dep is not None and dep.status == "ready":
        # Idempotent return — but enrollment may have been interrupted
        # (lost response / crashed provisioning): RESUME it, never silently
        # return a "ready" deployment whose clones are unenrolled.
        resources = [dict(r) for r in (dep.resources or [])]
        enrollments = {}
        for r in resources:
            if r.get("state") == "created" and (
                    (r.get("telemetry_enroll") or {}).get("phase") != "confirmed"
                    or not enrollment_evidence_current(db, session_id,
                                                       r.get("host"),
                                                       dep.deployment_id)):
                # F3: a phase-only confirmation with missing/stale capability
                # evidence is re-enrolled (same token), never trusted.
                _enroll_host_telemetry(db, dep, r, resources, session_id,
                                       r.get("host"), r.get("ip"), s, enrollments)
        return {"scenario_id": scenario_id, "action": "deploy", "idempotent": True,
                "deployment_id": str(dep.deployment_id),
                "hosts": [r for r in resources if r.get("state") == "created"],
                "telemetry_enrollments": enrollments}
    if dep is None:
        dep = Deployment(session_id=session_id, scenario_id=scenario_id, status="preparing",
                         resources=[])
        db.add(dep)
        db.flush()
    else:  # resume a partial deployment
        dep.status = "preparing"
        db.flush()

    resources = [dict(r) for r in (dep.resources or [])]
    by_host = {r.get("host"): r for r in resources}
    created = [r for r in resources if r.get("state") == "created"]
    enrollments: dict[str, str] = {}  # host -> plaintext token (returned ONCE)
    try:
        for i, host in enumerate(spec["topology"]["hosts"]):
            name = _vm_name(scenario_id, host["name"], session_id)
            res = by_host.get(host["name"])
            if res and res.get("state") == "created":
                if not res.get("host_key_ref"):
                    # Audit A6: a crash between the created-state commit and
                    # the pin left the resource permanently un-SSH-able —
                    # resume must COMPLETE the missing pin (read + publish),
                    # never skip it. A failing read stays loud (uncertain is
                    # not success); ownership and lease are retained.
                    _pin_host_key(broker, db, session_id, dep, res, resources, node)
                if (res.get("telemetry_enroll") or {}).get("phase") != "confirmed" \
                        or not enrollment_evidence_current(
                            db, session_id, host["name"], dep.deployment_id):
                    # resume path: finish interrupted enrollment (T05), and
                    # RE-ENROLL a phase-only confirmation whose capability
                    # evidence is missing/stale (F3) — the JSON phase alone
                    # is never proof; the same capability is resumed, not
                    # re-cloned.
                    _enroll_host_telemetry(db, dep, res, resources, session_id,
                                           host["name"], res.get("ip"), s, enrollments)
                continue  # already owned & completed — resume skips the clone
            if res and res.get("vmid"):
                vmid = int(res["vmid"])          # reuse the pending intent's VMID
            else:
                vmid = int(broker.next_vmid(node, s.deploy_vmid_base + i,
                                             session_id=session_id))
                res = {"vmid": vmid, "node": node, "name": name, "host": host["name"],
                       "template_vmid": host["template_vmid"], "state": "pending"}
                resources.append(res)
                by_host[host["name"]] = res
                dep.resources = resources
                flag_modified(dep, "resources")
                # DURABLE PENDING INTENT before ANY side effect (audit R08):
                # committed, not merely flushed — a crash after clone-return
                # still finds this VMID inside the cleanup inventory.
                _log(db, session_id, "deploy_intent", host["name"],
                     {"vmid": vmid, "name": name, "template_vmid": host["template_vmid"]})
                db.commit()

            # RECONCILE + POSITIVELY IDENTIFY before ANY mutation (audit N01):
            # a pending VMID is an INTENTION, not proof that the VM currently
            # occupying that number belongs to this deployment. Uncertain
            # reads abort the deployment (intent retained); a foreign machine
            # at the intended VMID receives NO set-config/start/delete call.
            exists = broker.lookup_vm(node, vmid)   # raises when uncertain
            if exists is None:
                broker.clone_and_wait(node, int(host["template_vmid"]), vmid, name,
                                       full=clone_full, session_id=session_id,
                                       generation=str(dep.deployment_id))
            else:
                # The VM exists at our intended VMID. Identity read failures
                # are UNCERTAIN — abort with the intent retained rather than
                # mutate a VM we cannot positively identify (audit N01). The
                # documented creation identity (exact clone name + full-session
                # ownership tag) governs once the read answers again.
                cfg = broker.try_lookup_config(node, vmid)
                if cfg is None:
                    pass  # vanished between reads — set_config will fail loudly
                elif "_unavailable" in (cfg or {}):
                    _log(db, session_id, "deploy_resume_identity_uncertain", host["name"],
                         {"vmid": vmid, "error": cfg["_unavailable"],
                          "note": "refusing to mutate a VM whose identity cannot "
                                  "be read; pending intent retained for retry"})
                    raise RuntimeError(
                        f"cannot verify identity of VMID {vmid} (intended for {name}): "
                        f"{cfg['_unavailable']} — deployment aborted, intent retained")
                else:
                    verdict, why = _classify_identity(cfg, res, session_id)
                    if verdict != "owned":
                        raise ForeignResourceError(
                            f"VMID {vmid} (intended for {name}) is not this deployment's "
                            f"resource — refusing to mutate it: {why}")
                    # CONFIG ROUND-TRIP PROBE before mutating (audit N01): the
                    # resume must not half-configure a VM whose config endpoint
                    # is failing — probe with the SAME request shape the
                    # mutation will use, then skip the mutation when it works.
                    try:
                        broker.set_config(node, vmid,
                                          tags=_ownership_tag(session_id),
                                          session_id=session_id)
                    except Exception as e:  # noqa: BLE001
                        raise RuntimeError(
                            f"config endpoint failing for VMID {vmid} ({name}) — "
                            f"resume mutation aborted, intent retained: {e}") from e
                    # probe succeeded: finish placement (idempotent re-POST)
                    broker.set_config(node, vmid,
                                      ipconfig0=f"ip={host['ip']}/24",
                                      net0=_net_spec(s), session_id=session_id)
                    cfg2 = broker.lookup_config(node, vmid)
                    net0 = (cfg2 or {}).get("net0", "") if isinstance(cfg2, dict) else ""
                    if s.range_bridge not in net0:
                        raise RuntimeError(f"NIC placement validation failed on {name}: "
                                           f"net0={net0!r} does not use bridge {s.range_bridge}")
                    broker.start_and_wait(node, vmid, session_id=session_id)
                    res.update({"state": "created", "ip": host["ip"], "node": node,
                                "name": name})
                    _pin_host_key(broker, db, session_id, dep, res, resources, node)
                    _enroll_host_telemetry(db, dep, res, resources, session_id,
                                           host["name"], host["ip"], s, enrollments)
                    created = [r for r in resources if r.get("state") == "created"]
                    dep.resources = resources
                    flag_modified(dep, "resources")
                    _log(db, session_id, "deploy", host["name"],
                         {"vmid": vmid, "name": name, "clone_full": clone_full, "net0": net0,
                          "resumed": True})
                    db.commit()
                    continue
            # network placement on the range bridge/VLAN + ownership tag (F06)
            broker.set_config(node, vmid,
                              ipconfig0=f"ip={host['ip']}/24",
                              net0=_net_spec(s),
                              tags=_ownership_tag(session_id),
                              session_id=session_id)
            # validate NIC placement (read-back; ANY read failure — injected,
            # transport, 403 — aborts loudly, it is never treated as success)
            try:
                cfg = broker.read_config(node, vmid)
            except Exception as e:  # noqa: BLE001
                raise RuntimeError(f"NIC placement validation could not read the config "
                                   f"of {name} (vmid {vmid}): {e}") from e
            net0 = (cfg or {}).get("net0", "") if isinstance(cfg, dict) else ""
            if s.range_bridge not in net0:
                raise RuntimeError(f"NIC placement validation failed on {name}: "
                                   f"net0={net0!r} does not use bridge {s.range_bridge}")
            broker.start_and_wait(node, vmid, session_id=session_id)
            res.update({"state": "created", "ip": host["ip"], "node": node, "name": name})
            _pin_host_key(broker, db, session_id, dep, res, resources, node)
            _enroll_host_telemetry(db, dep, res, resources, session_id,
                                   host["name"], host["ip"], s, enrollments)
            created = [r for r in resources if r.get("state") == "created"]
            dep.resources = resources
            flag_modified(dep, "resources")
            _log(db, session_id, "deploy", host["name"],
                 {"vmid": vmid, "name": name, "clone_full": clone_full, "net0": net0})
            # OWNERSHIP COMMITTED PER RESOURCE: if a later host fails (or the
            # process dies), everything already created remains accounted for
            db.commit()
        # DB-tier wiring (plan 13 phase 3): owned-IP web config + fresh
        # scoped reader credentials + restricted listener/grants/firewall.
        # Runs for EVERY host once (DB steps first), so resume re-applies
        # idempotently before readiness is judged.
        _provision_guest_configs(db, dep, spec, resources, session_id)
        dep.status = "ready"
        dep.updated_at = _now()
        db.commit()
    except Exception as e:
        dep.resources = resources
        flag_modified(dep, "resources")
        dep.status = "failed"
        dep.error = str(e)[:2000]
        _log(db, session_id, "deploy_failed", None,
             {"error": str(e)[:500], "resources": resources})
        db.commit()   # failure evidence + partial ownership survive the rollback
        raise
    return {"scenario_id": scenario_id, "action": "deploy", "deployment_id": str(dep.deployment_id),
            "hosts": created, "telemetry_enrollments": enrollments}


def _owned_resources(dep: Deployment) -> list[dict]:
    return [r for r in (dep.resources or [])
            if r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed")]


def _sid(session_id) -> str:
    """FULL session identity (32 hex) — collision-resistant, unlike an 8-char
    prefix (audit N01)."""
    if session_id is None:
        return "adhoc"
    if isinstance(session_id, uuidlib.UUID):
        return session_id.hex
    return uuidlib.UUID(str(session_id)).hex


def _ownership_tag(session_id) -> str:
    """PVE-valid tag (pve-tag-list charset; '=' is rejected by real PVE) that
    carries the FULL session identity."""
    return f"srsess-{_sid(session_id)}"


def _vm_name(scenario_id: str, host_name: str, session_id) -> str:
    """Exact creation identity name: always starts with the shipped broker
    policy prefix ('sr-') and ends with the full session id so two sessions
    can never produce the same name; PVE names are <= 63 chars, so the
    readable middle is truncated, NEVER the identity suffix."""
    sid = _sid(session_id)
    prefix = f"sr-{scenario_id}-{host_name}"
    max_prefix = 63 - 1 - len(sid)
    return f"{prefix[:max_prefix].strip('-')}-{sid}"


def _parse_tags(cfg: dict) -> set[str]:
    """EXACT parsed tag set (PVE ';'-separated list) — substring matching can
    be forged by a longer tag (audit N01)."""
    return {t.strip() for t in str((cfg or {}).get("tags", "")).split(";") if t.strip()}


def _classify_identity(cfg: dict, r: dict, session_id) -> tuple[str, str]:
    """Pure identity classification of a READ config dict (see
    _verify_ownership for the policy)."""
    if _ownership_tag(session_id) in _parse_tags(cfg):
        return "owned", "tag-verified"
    if r.get("name") and str(cfg.get("name", "")) == str(r["name"]):
        return "owned", "name-verified (clone-before-tag window)"
    return "foreign", (f"ownership tag {_ownership_tag(session_id)!r} and name "
                       f"{r.get('name')!r} not found (tags={cfg.get('tags')!r} "
                       f"name={cfg.get('name')!r})")


def _verify_ownership(broker, r: dict, session_id) -> tuple[str, str]:
    """Positively identify a resource BEFORE any mutation (audit N01).

    Returns (verdict, why) with verdict in:
      'owned'   — exact ownership tag OR exact creation-identity name match
                  (the name covers the documented clone-before-tag crash
                  window: the clone itself sets this exact name);
      'absent'  — PVE CONFIRMED 404 (idempotent removal, no delete needed);
      'foreign' — the VMID now belongs to someone else: never mutate it.

    Uncertain reads (timeout/403/500/transport) RAISE BrokerUnavailable —
    they are NOT absence and NEVER authorize a mutation.
    """
    node = r.get("node") or get_settings().proxmox_node
    cfg = broker.lookup_config(node, int(r["vmid"]))   # raises when uncertain
    if cfg is None:
        return "absent", "PVE confirms the resource does not exist"
    return _classify_identity(cfg, r, session_id)


def _destroy_owned(db: Session, session_id, dep: Deployment, broker) -> dict:
    """Destroy every still-owned resource of ONE deployment with a positive
    ownership check BEFORE any mutation (audit N01/N02):

      * uncertain identity read  -> resource RETAINED (state untouched),
        reported as failed -> teardown incomplete -> lease retained;
      * confirmed absent         -> idempotent bookkeeping, NO delete call;
      * foreign                  -> disowned, never mutated;
      * owned                    -> destroy; per-resource failures are
        recorded and RETAINED (destroy_failed) for a later retry.

    Every state change is COMMITTED per resource: a later failure or request
    rollback must not lose the evidence of what was already removed or what
    remains uncertain (audit N02 item 7)."""
    removed, failed, skipped = [], [], []
    resources = [dict(r) for r in (dep.resources or [])]
    for r in resources:
        if not (r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed")):
            continue
        node = r.get("node") or get_settings().proxmox_node
        try:
            verdict, why = _verify_ownership(broker, r, session_id)
        except BrokerUnavailable as e:
            # UNCERTAIN: keep the resource owned, keep the lease, tell the truth
            failed.append({"vmid": r["vmid"], "name": r.get("name"),
                           "error": f"identity read unavailable: {e}"[:300]})
            _log(db, session_id, "teardown_identity_unavailable", r.get("host"),
                 {"vmid": r["vmid"], "error": str(e)[:300]})
            dep.resources = resources
            flag_modified(dep, "resources")
            db.commit()   # evidence survives the request rollback
            continue
        if verdict == "absent":
            r["state"] = "removed"
            removed.append(r.get("name"))
            if r.get("ip"):
                _unpublish_pinned_host_key(r["ip"])
            broker.disown(node, int(r["vmid"]), session_id=session_id,
                          reason="confirmed-absent before teardown")
            _log(db, session_id, "teardown_already_absent", r.get("host"),
                 {"vmid": r["vmid"], "note": "confirmed absent — no delete issued"})
        elif verdict == "foreign":
            # positively NOT ours (VMID reused): disown so a later recycling
            # can never delete it either.
            r["state"] = "foreign_released"
            broker.disown(node, int(r["vmid"]), session_id=session_id,
                          reason=f"foreign identity: {why}"[:300])
            skipped.append({"vmid": r["vmid"], "name": r.get("name"), "why": why})
            _log(db, session_id, "teardown_skipped_foreign", r.get("host"),
                 {"vmid": r["vmid"], "reason": why})
        else:
            try:
                outcome = broker.destroy_and_wait(node, int(r["vmid"]),
                                                  session_id=session_id)
            except BrokerError as e:
                r["state"] = "destroy_failed"
                failed.append({"vmid": r["vmid"], "name": r.get("name"),
                               "error": str(e)[:300]})
                _log(db, session_id, "teardown_resource_failed", r.get("host"),
                     {"vmid": r["vmid"], "error": str(e)[:300]})
            else:
                r["state"] = "removed"
                removed.append(r.get("name"))
                if r.get("ip"):
                    _unpublish_pinned_host_key(r["ip"])
                _log(db, session_id, "teardown_resource", r.get("host"),
                     {"vmid": r["vmid"], "outcome": outcome})
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()   # per-resource durable bookkeeping
    return {"removed": removed, "failed": failed, "skipped": skipped}


def teardown(db: Session, session_id, scenario_id: str, broker) -> dict:
    """Remove THIS session's owned resources — every deployment that still
    owns something, not just the newest (audit R07/R08). A deployment is
    marked torn_down ONLY when nothing failed; partial failure keeps the
    remaining resources owned for retry and reports the truth."""
    deps = [d for d in db.execute(
        select(Deployment).where(Deployment.scenario_id == scenario_id,
                                 Deployment.status != "torn_down")
        .order_by(Deployment.created_at.desc()).with_for_update()).scalars().all()
        if session_id is None or str(d.session_id) == str(session_id)]
    if not deps:
        return {"scenario_id": scenario_id, "action": "teardown", "removed": [],
                "complete": True, "note": "no deployment recorded for this session — nothing to remove"}
    removed, failed, skipped = [], [], []
    for dep in deps:
        res = _destroy_owned(db, session_id, dep, broker)
        removed += res["removed"]
        failed += res["failed"]
        skipped += res["skipped"]
        if not res["failed"]:
            dep.status = "torn_down"
        else:
            dep.status = "teardown_failed"
        dep.updated_at = _now()
    complete = not failed
    _log(db, session_id, "teardown", None,
         {"removed": removed, "failed": failed, "skipped_foreign": skipped,
          "complete": complete,
          "deployment_ids": [str(d.deployment_id) for d in deps]})
    # DURABLE BOOKKEEPING (audit N02 item 7): the evidence of what was removed
    # and what remains uncertain must survive a later request rollback — an
    # incomplete teardown that "rolled back" would silently re-own nothing
    # while the machines still exist.
    db.commit()
    out = {"scenario_id": scenario_id, "action": "teardown", "removed": removed,
           "complete": complete}
    if failed:
        out["failed"] = failed
        out["warning"] = "some resources could NOT be destroyed — the range reservation is retained"
    if skipped:
        out["skipped_foreign"] = skipped
    return out


def reset(db: Session, session_id, scenario_id: str, broker) -> dict:
    """Destroy owned resources and redeploy fresh clones. Requires the lease
    (audit R07: a historical session must not reset over another's range)."""
    acquire_lease(db, session_id)
    t = teardown(db, session_id, scenario_id, broker)
    if not t.get("complete", True):
        raise RuntimeError("teardown incomplete — refusing to redeploy over resources "
                           f"that could not be destroyed: {t.get('failed')}")
    d = deploy(db, session_id, scenario_id, broker, resume=False)
    d["action"] = "reset"
    d["removed"] = t["removed"]
    return d


def _latest_deployment(db: Session, session_id, scenario_id: str) -> Deployment | None:
    q = select(Deployment).where(Deployment.scenario_id == scenario_id)
    if session_id:
        q = q.where(Deployment.session_id == session_id)
    return db.execute(q.order_by(Deployment.created_at.desc())).scalars().first()
