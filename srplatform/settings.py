"""Central settings. Everything environment-specific comes from .env / env vars.

Hard constraint #5: secrets never enter the repo — only .env.example is committed.
In production mode (SR_ENV=production) placeholder/default secrets are REJECTED at
startup (audit F23) — misconfiguration fails closed, not open.

Process roles (audit N04): the WORKER is the least-privileged component. It
validates ONLY what it actually uses (API capability, model endpoint, runner
channel) and NEVER loads the controller `.env` — the controller serializes the
worker's settings explicitly into its environment.
"""
from __future__ import annotations

import os
import pathlib
from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _sr_alias(name: str) -> str:
    """Documented ``SR_``-prefixed env name for every field (plan 13 phase
    4: shipped env examples use ``SR_MATCH_*`` etc.; an ignored setting
    must not hide behind its default). With ``populate_by_name`` the bare
    field name keeps resolving too, and matching stays case-insensitive,
    so ``SR_ENV`` still resolves field ``sr_env``."""
    return f"SR_{name.upper()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore",
        alias_generator=_sr_alias, populate_by_name=True)

    # --- Environment mode ------------------------------------------------------
    # dev: local shell fallback runner permitted (explicitly), TLS lab override OK
    # production: no local execution, placeholder secrets rejected
    sr_env: str = "dev"

    # --- Database ---
    postgres_url: str = "postgresql+psycopg2://sr_app:sr_app_dev@localhost:5432/sparring_range"
    postgres_url_owner: str = "postgresql+psycopg2://sr_owner:sr_owner_dev@localhost:5432/sparring_range"
    # Dedicated minimal role for the provider-credential table ONLY
    # (plan 19 review finding 8). Empty means credentials are
    # unreachable BY DESIGN — model calls fail visibly; there is no
    # fallback to the application role, which must never read keys.
    # Round-2 finding 10: the DOCUMENTED deployment name is
    # ``SR_PG_SECRET_URL``; the generator's mechanical form and the bare
    # field name keep resolving (populate_by_name) so existing fixtures
    # and examples never silently stop working.
    postgres_url_secret: str = Field(
        default="",
        validation_alias=AliasChoices("SR_PG_SECRET_URL",
                                      "SR_POSTGRES_URL_SECRET"))
    db_app_role: str = "sr_app"

    # --- API (single front door) ---
    api_base_url: str = "http://localhost:8000"
    # Same-box trusted API for co-located components (the worker is spawned
    # by the API on this host). Server-side callbacks must use this, never
    # the public LAN URL — behind the LAN frontend the public URL serves
    # the UI except under /api, so unprefixed callbacks 404 (live find).
    internal_api_url: str = "http://127.0.0.1:8000"
    # Guest-facing ingest address (review finding): shippers dial the
    # RANGE ingest listener, NEVER the public LAN URL — the public URL is
    # for browsers/operators, the ingest URL is the controller's range
    # address on the isolated network. Falls back to api_base_url only
    # when unset (dev/fixture single-listener mode); production deployments
    # render it from manifest urls.ingest.
    telemetry_ingest_url: str | None = None
    # Explicit LAN origins for the browser (F23: never default teammates to
    # their own localhost). Comma-separated list, e.g. http://gym.lan:3000.
    api_allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    # Public trust material for the telemetry/API HTTPS listener (plan 13
    # phase 4): the CA whose certificate the guests must verify. Provisioned
    # into every enrolled guest; the shipper uses an explicit verified SSL
    # context — TLS checks are never disabled for readiness or delivery.
    telemetry_ca_file: str | None = None
    # Trust anchor for server-to-server calls to api_base_url (the bastion
    # resolves logins and sinks events over LAN HTTPS). The stock web cert
    # is self-signed, so the bastion VM pins its copy here — TLS checks are
    # never disabled. Unset on hosts that never dial the API over TLS.
    api_tls_ca_file: str | None = None
    # Path prefix where the API is mounted behind the LAN frontend
    # (the UI build bakes NEXT_PUBLIC_API_URL=<https://host:8443/api> and
    # nginx routes /api/* to FastAPI, everything else to Next). Server-side
    # API clients (bastion) must prepend it; empty keeps loopback behavior.
    api_route_prefix: str = ""

    # --- Auth (F04) ---
    web_token_ttl_hours: int = 12

    # --- match lifecycle (pilot step 4) ---
    match_default_duration_minutes: int = 30
    match_default_pace_seconds: int = 30   # 0 = no intentional delay
    # web uptime scoring (pilot step 5): separate from the security score
    uptime_scoring_enabled: bool = True
    # control-plane opt-in: background idle-expiry/deadline scheduler + startup
    # match reconcile. OFF by default so shared-database test processes never
    # run background cleanup; the deployment env file enables it.
    match_scheduler_enabled: bool = False
    match_scheduler_interval_s: int = 15
    # A brand-new operator account (empty users table) may bootstrap itself.
    bootstrap_operator_username: str = "drew"

    # --- Proxmox / control plane ---
    proxmox_host: str = "localhost"
    proxmox_user: str = "root@pam"  # token identity's user, e.g. automation@pam!sparring
    proxmox_token_id: str = ""
    proxmox_token_secret: str = ""
    proxmox_tls_verify: bool = True          # verify against CA by default (F05)
    proxmox_tls_ca_file: str | None = None   # path to PVE CA cert
    proxmox_insecure_lab_override: bool = False  # explicit, loud, dev-only
    proxmox_task_timeout_s: int = 300
    # Per-REQUEST HTTP timeout of the proxmoxer session. Every PVE mutation
    # returns a UPID quickly; long work is awaited via bounded task polling,
    # so this stays short — but it must be an explicit, configurable deadline
    # (plan 13 phase 2: client/server/task deadlines are checked together).
    proxmox_http_timeout_s: int = 30
    # First-boot guest-agent readiness after a clone starts (paired 03+04
    # host-key pin). Live find 2026-10-14: PVE answers agent reads with 500
    # "QEMU guest agent is not running" for tens of seconds after the VM is
    # running; the broker waits this long before declaring the read uncertain.
    proxmox_agent_ready_timeout_s: int = 120

    # --- Broker (milestone 02): the ONLY component holding PVE authority ----
    # Controller (API) side: mutual-TLS client material + broker URL. The
    # controller must NOT hold PVE credentials in production — the broker
    # does, and only the broker imports infra/proxmox_client.py.
    broker_url: str | None = None            # legacy https://broker:8443
    # Appliance (milestone 14/15): one local Unix socket replaces remote
    # mutual TLS. The broker verifies the API's peer UID with SO_PEERCRED;
    # broker_url/TLS material are then not used and must not be supplied.
    broker_socket: str | None = None         # /run/sparring-range/broker.sock
    broker_tls_ca_file: str | None = None    # broker CA (verifies server)
    broker_client_cert: str | None = None    # API's client cert (mutual TLS)
    broker_client_key: str | None = None
    broker_heartbeat_s: int = 5              # control-lease renewal cadence
    # Broker role only (SR_PROCESS_ROLE=broker):
    broker_policy_file: str | None = None    # operator allowlist (required)
    broker_ledger_path: str = "var/broker/ledger.sqlite3"
    broker_listen_host: str = "127.0.0.1"
    broker_listen_port: int = 8443
    broker_server_cert: str | None = None
    broker_server_key: str | None = None

    # --- Range network (control-plane-side view) ---
    range_bridge: str = "vmbr1"
    range_vlan: int = 66
    # Bridge PORTS (tap/vnet members) — the bridge-family emergency rules must
    # match ports, not the bridge master (audit R05). Comma-separated; provision
    # from `ls /sys/class/net/<bridge>/brif/`.
    range_bridge_ports: str = ""
    range_cidr: str = "10.66.0.0/24"
    range_gateway: str = "10.66.0.1"
    # The controller's OWN range NIC address (review finding): the trusted
    # external MySQL observer dials DB guests from here, so the address is
    # an explicit setting — never inferred — and the DB tier grants +
    # firewalls exactly this source (plus owned web guests + loopback).
    controller_range_ip: str = "10.66.0.1"
    bastion_address: str = "10.66.0.2"
    # Trusted cron-content pins (plan 18): a release artifact captured from
    # the CLEAN BUILT IMAGE, bound to its digest. The verifier only receives
    # content hashes while this file's pin matches the template AND the
    # artifact digest the deployment resource recorded at clone time;
    # absent/stale/corrupt pins leave the cron check UNKNOWN. Never
    # generated from a running guest.
    cron_baseline_file: str = ""
    # NOTE: there is deliberately NO appliance-manifest setting here. The
    # deployed-artifact identity comes from the typed broker boundary
    # (BrokerService.artifact_for_template — the clone authority's own
    # loaded manifest); an API-side path to the operator manifest was the
    # review finding: it was never rendered into the API environment and
    # a re-read is not proof of deployed bytes.
    # The address MEMBERS actually reach the bastion on (plan 18): the
    # appliance's LAN address. The range-side bastion_address is a planning
    # address that may name no reachable interface from a member's laptop,
    # so every rendered SSH hint prefers this and falls back to the range
    # address only when the installation did not name one.
    bastion_public_address: str = ""
    # Management subnet whose NEW connections to the control plane stay allowed
    management_cidr: str = "10.0.0.0/24"

    # --- Isolated runner (F01): the ONLY place model commands execute ----------
    # transport: ssh (production) | local-dev (dev mode ONLY, explicit opt-in)
    runner_transport: str = "ssh"
    runner_ssh_target: str = ""       # e.g. runner@10.66.0.9 — fixed destination
    runner_ssh_key_path: str = ""     # dedicated low-privilege key, NOT root
    runner_ssh_known_hosts: str = ""  # pinned host key file (TOFU not accepted in prod)
    # path of the runner-side supervisor ON THE RUNNER (infra/runner/
    # runner_supervise.sh installed as this command; absolute path preferred)
    runner_supervisor_bin: str = "runner-supervisor"
    runner_command_timeout_s: int = 120
    runner_max_output_bytes: int = 8000
    # plan 20 timed replay: per-operation bounded output capture, a SEPARATE
    # and larger quota than the model-context bound above (what the replay
    # stores must not shrink what the model sees, or vice versa). Chunks are
    # POSTed through the API as they are read; the server enforces the same
    # quota independently (client honesty is never the only fence).
    runner_output_chunk_bytes: int = 4096
    runner_op_capture_bytes: int = 200_000
    # Review finding 3: rows and the whole session are bounded too — a
    # flood of gap/marker rows or many concurrent operations cannot
    # out-grow the per-operation byte quota.
    runner_op_capture_rows: int = 1000
    runner_session_capture_bytes: int = 5_000_000
    # --- telemetry enrollment evidence bounds (audit T-05) --------------
    # How long provisioning waits for the HOST-ORIGINATED authenticated
    # callback (delivery) and for the capture probe's audit event (capture).
    # A timeout is a visible enrollment failure, never an assumed pass.
    enroll_confirm_timeout_s: int = 30
    # First-boot management-channel race (live find 2026-10-14): right after
    # a clone starts, ssh exits 255 ("session never established") until sshd
    # finishes booting; enrollment retries provisioning within this window.
    management_ready_wait_s: int = 90
    # Durable lifecycle operations (plan 13 phase 5): the declared bound for
    # one launch/reset attempt, recorded BEFORE dispatch so pollers and
    # reconciliation see the same deadline the executor works against.
    deploy_operation_deadline_s: int = 900
    # Plan 13 phase 4 — network-plane separation. The controller serves the
    # SAME app on three listeners (see deploy/README §2): trusted processes
    # on loopback, users on the LAN HTTPS front, and GUESTS on the range
    # address. Only the range listener sets SR_API_INGEST_ONLY=1: it then
    # answers with nothing but the authenticated enrollment/ingest routes
    # (404 elsewhere, bounded bodies) — a compromised guest reaches no
    # general API/web/auth/scoring/model/operator endpoint from there.
    api_ingest_only: bool = False
    ingest_max_body_bytes: int = 262_144
    # Explicit operator authorization (plan 13 phase 4 stage ladder):
    # attack-authorized requires lab-ready PLUS this flag, set only after
    # isolation and emergency-stop verification. Default off; never implied
    # by a successful deployment.
    attack_authorized: bool = False
    enroll_capture_timeout_s: int = 30
    # local-dev command-group identity sidecar directory (audit F7): the
    # LocalDevRunner records each command group's identity here so the API's
    # resolution pass can verify REAL local cessation after a worker death.
    # Empty = ~/.sparring_range/local_ops.
    runner_local_op_dir: str = ""

    # --- Worker supervisor (milestone 15) -----------------------------------
    # Inline is the development/test dispatch (API spawns its own child).
    # Production uses a separate-UID supervisor that claims a durable API
    # assignment and owns the child process group; the API can neither
    # spawn nor signal a worker across that UID boundary.
    worker_dispatch: str = "inline"          # inline | supervisor
    worker_supervisor_token_file: str | None = None
    worker_poll_s: float = 2.0
    worker_heartbeat_s: float = 5.0
    worker_claim_timeout_s: int = 120

    # --- Verifier management exec (trusted backend only, F01/F10) --------------
    verifier_ssh_user: str = "root"
    verifier_ssh_key_path: str = ""
    # PINNED management host keys (audit N11): required in production — the
    # verifier never does trust-on-first-use against range hosts.
    verifier_ssh_known_hosts: str = ""
    verifier_exec_timeout_s: int = 30

    # --- Deploy (M1) ---
    proxmox_node: str = "r740"
    deploy_vmid_base: int = 210
    # Explicit clone mode (paired 03+04, step 4): operator policy selects
    # "linked" or "full" — no silent fallback. The broker validates the mode.
    deploy_clone_mode: str = "linked"

    # --- Golden image templates ---
    template_vmid_web: int = 9001
    template_vmid_win_dc: int = 9002
    template_vmid_win10: int = 9003
    template_vmid_linux: int = 9004
    # Paired 03+04 Mojang guests (new IDs; legacy snapshots preserved).
    template_vmid_attacker: int = 9005
    template_vmid_mojang_web: int = 9011
    template_vmid_mojang_db: int = 9012

    # --- LLM serving (OpenAI-compatible; swappable per Part 6.1) ---
    llm_base_url: str = "http://localhost:8001/v1"
    llm_api_key: str = "dummy"
    # The model credential as a FILE reference (plan 18). The API is the
    # ONLY identity that may hold it — workers reach the model through the
    # API's gateway, never with a key of their own. A reference, never a
    # value: secrets never travel through a shared environment file.
    llm_api_key_file: str = ""
    llm_model_red: str = "qwen2.5-14b-instruct"
    llm_model_coach: str = "qwen2.5-32b-instruct"
    llm_timeout_s: int = 60   # per-call timeout (gateway policy, pilot step 3)
    # Output includes reasoning on compatible thinking-model servers. Keep
    # role budgets explicit, bounded and configurable without changing secrets.
    llm_max_tokens_red: int = Field(default=2048, ge=1, le=32768)
    llm_max_tokens_coach: int = Field(default=3072, ge=1, le=32768)
    # bounded model gateway (F18)
    model_queue_max: int = 32
    model_hint_max_wait_s: int = 150     # declared bound for interactive hints
    model_recovery_interval_s: int = 60  # periodic retry after an outage

    # --- Safety (F02/F03) ---
    safety_state_file: str = "./.safety_state"
    safety_evidence_max_age_h: int = 24
    datapath_controller: str = "static"     # static | noop(dev/test only)
    # The local-dev runner transport is a FIXTURE-ONLY convenience (isolated
    # synthetic acceptance fixtures, explicit opt-in). Normal development and
    # production use the isolated SSH runner; production always refuses.
    allow_local_dev_fixture: bool = False
    killswitch_script: str = "infra/firewall/killswitch.sh"  # operator-run standalone (runbook)
    nft_bin: str = "nft"
    # privileged command prefix for nft operations (e.g. "sudo -n")
    nft_command_prefix: str = ""

    # --- Bastion / recordings ---
    recordings_dir: str = "./recordings"
    bastion_host_key_path: str = "./bastion_ed25519"
    # User allowed to authenticate to the recording bastion (Drew).
    bastion_user: str = "drew"
    bastion_listen_host: str = "0.0.0.0"
    bastion_listen_port: int = 2222
    bastion_authorized_keys_file: str = ""  # member public keys, provisioned by operator
    bastion_targets_known_hosts: str = ""   # pinned range host keys (F08)
    # Guest-side identity for recorded dials (pilot step 7): DEFENDER, not
    # root — the bastion never needs guest root. The bastion authenticates
    # with its own keypair (BASTION_CLIENT_KEY_PATH); the PUBLIC half is
    # baked into the guest templates at build time, rotated per template
    # generation (rebuild + reimport = new key).
    bastion_target_user: str = "defender"
    bastion_client_key_path: str = ""
    # The bastion's SERVICE token: it authenticates the bastion's callbacks
    # to the API.  It is a secret, so it lives in a file the bastion owns
    # (0600), never in a shared environment.
    bastion_token_file: str = ""
    recording_max_bytes: int = 32 * 1024 * 1024

    # --- Telemetry ingest (F09) ---
    ingest_max_body_events: int = 500


def check_private_key(path: str, label: str) -> str:
    """Parse-check a configured SSH PRIVATE key (plan 13 phase 4) and
    return the SHA256 fingerprint of its public half (ssh-keygen format).
    A corrupt or missing key must fail at configuration time, not halfway
    through a live enrollment; the fingerprint lets deployment compare the
    private material against the PUBLIC fingerprints baked into the role
    build manifest (TEMPLATE-INFO.json)."""
    import base64
    import hashlib

    try:
        from cryptography.hazmat.primitives import serialization
        with open(path, "rb") as f:
            key = serialization.load_ssh_private_key(f.read(), password=None)
        pub = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH)
        blob = base64.b64decode(pub.split()[1])
    except Exception as e:  # unreadable/unparseable/wrong format
        raise ValueError(f"{label}: SSH private key {path!r} unusable: {e}") from e
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def public_key_fingerprint(line: str) -> str:
    """SHA256 fingerprint of an OpenSSH PUBLIC key line (same format), for
    comparing baked template keys against configured private material."""
    import base64
    import hashlib
    parts = line.split()
    if len(parts) < 2:
        raise ValueError("not an OpenSSH public key line")
    try:
        blob = base64.b64decode(parts[1])
    except Exception as e:
        raise ValueError(f"public key line undecodable: {e}") from e
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def process_role() -> str:
    """Which component this process is (controller | worker | broker). The
    worker is spawned by the API with SR_PROCESS_ROLE=worker and a SERIALIZED,
    minimal environment — it must not need, and must not silently load,
    controller configuration (audit N04). The broker (milestone 02) is the
    ONLY role that may hold PVE credentials; it validates its own policy/TLS
    material instead of the controller's."""
    return os.environ.get("SR_PROCESS_ROLE", "controller")


def _bastion_token(s: Settings) -> str:
    """The bastion's service token, from the environment or its own file."""
    import os as _os

    token = (_os.environ.get("SR_BASTION_TOKEN") or "").strip()
    if token:
        return token
    if s.bastion_token_file:
        try:
            return pathlib.Path(s.bastion_token_file).read_text().strip()
        except OSError:
            return ""
    return ""


def model_api_key(s: Settings) -> str:
    """The API-only model credential (plan 18).

    When ``llm_api_key_file`` names a file, that file is the credential:
    it is read (never logged, never re-written) and an unreadable or empty
    file resolves to NO credential — a model call then fails loudly with
    the file named, never silently as the literal fallback. Without the
    file setting, the legacy literal applies unchanged."""
    if getattr(s, "llm_api_key_file", ""):
        try:
            return pathlib.Path(s.llm_api_key_file).read_text().strip()
        except OSError:
            return ""
    return s.llm_api_key


def bastion_login_target(s: Settings) -> str:
    """The address a MEMBER's SSH hint must name (plan 18).

    The range-side ``bastion_address`` is a planning address that may name
    no interface reachable from a member's laptop; the appliance renders
    the bastion on every address, so the reachable LAN address wins when
    the installation named one, and the range address is the documented
    fallback (pre-appliance deployments)."""
    return getattr(s, "bastion_public_address", "") or s.bastion_address


def validate_production(s: Settings, role: str = "controller") -> None:
    """Fail CLOSED on misconfiguration in production mode (F23). Validation is
    ROLE-SCOPED (audit N04): every role is validated on exactly the
    capability it holds, never on a credential it must not possess.

    The roles are: the controller (the API), the worker, the broker, the
    recording bastion and the guest-facing ingest listener. The bastion
    never sees the worker-supervisor capability and the API never sees the
    bastion's dial key: each service validates — and reads — only its own.
    """
    problems = []
    if role not in ("controller", "worker", "broker", "bastion", "ingest"):
        raise RuntimeError(f"unknown SR_PROCESS_ROLE {role!r}")
    if s.worker_dispatch not in ("inline", "supervisor"):
        problems.append("worker_dispatch must be 'inline' or 'supervisor'")
    # The worker-supervisor capability is the CONTROLLER's: it validates the
    # supervisor's callbacks. No other role may require (or read) it.
    if s.worker_dispatch == "supervisor" and role == "controller":
        if not s.worker_supervisor_token_file:
            problems.append("worker_supervisor_token_file required for "
                            "supervisor dispatch")
        else:
            try:
                token = pathlib.Path(s.worker_supervisor_token_file).read_text().strip()
                if len(token) < 32:
                    problems.append("worker supervisor token is too short")
                mode = pathlib.Path(s.worker_supervisor_token_file).stat().st_mode
                if mode & 0o077:
                    problems.append("worker supervisor token file must not be "
                                    "group/world readable")
            except OSError as exc:
                problems.append(f"worker supervisor token unreadable: {exc}")
        if not (1 <= s.worker_heartbeat_s < s.worker_claim_timeout_s):
            problems.append("worker heartbeat must be positive and shorter than "
                            "the claim timeout")
    if role == "worker":
        if s.runner_transport != "ssh" or not s.runner_ssh_target \
                or not s.runner_ssh_known_hosts:
            problems.append("isolated runner not configured (runner_transport=ssh"
                            " + fixed target + pinned known_hosts)")
        if not s.api_base_url:
            problems.append("api_base_url missing (worker acts only via its "
                            "session-scoped API capability — including model "
                            "scheduling, audit Stage 5)")
        if s.runner_ssh_key_path:
            try:
                check_private_key(s.runner_ssh_key_path, "runner key")
            except ValueError as e:
                problems.append(str(e))
        if problems:
            raise RuntimeError("production WORKER config invalid:\n  - "
                               + "\n  - ".join(problems))
        return
    if role == "broker":
        # Milestone 02: the broker validates ITS OWN boundary — policy,
        # mutual-TLS server material, PVE token, ledger location. It never
        # needs bastion pins, verifier keys, or the app owner DB.
        if not s.broker_policy_file:
            problems.append("broker_policy_file missing (the broker refuses to "
                            "start without an operator allowlist)")
        for name, val in (("broker_server_cert", s.broker_server_cert),
                          ("broker_server_key", s.broker_server_key),
                          ("broker_tls_ca_file", s.broker_tls_ca_file)):
            if not val:
                problems.append(f"{name} missing (mutual TLS is the broker's "
                                "authentication)")
        if not s.proxmox_token_id or s.proxmox_token_secret in ("", "CHANGE_ME", "CHANGE"):
            problems.append("Proxmox API token missing (broker is the only "
                            "PVE authority)")
        if s.proxmox_insecure_lab_override:
            problems.append("proxmox_insecure_lab_override must be false in production")
        if not s.proxmox_tls_ca_file:
            problems.append("proxmox_tls_ca_file must be configured in production")
        if problems:
            raise RuntimeError("production BROKER config invalid:\n  - "
                               + "\n  - ".join(problems))
        return
    if role == "bastion":
        # The recording bastion: it dials the practice guests with its own
        # key and reports to the API over the public TLS. It holds NO
        # supervisor capability, NO verifier key and NO database credential.
        if not s.api_base_url:
            problems.append("api_base_url missing (the bastion reports the "
                            "recording through the API)")
        if s.api_base_url.startswith("https://") and not s.api_tls_ca_file:
            problems.append("api_tls_ca_file missing (the bastion talks to the "
                            "API over TLS and must verify it)")
        if not s.bastion_authorized_keys_file:
            problems.append("bastion_authorized_keys_file missing (the member "
                            "cannot authenticate without it)")
        if not s.bastion_host_key_path:
            problems.append("bastion_host_key_path missing (the guests pin "
                            "the bastion's host key)")
        if not s.bastion_client_key_path:
            problems.append("bastion_client_key_path missing (the bastion "
                            "presents it when it dials the guests)")
        # The bastion's service token: without it every callback to the API
        # is refused and no member can authenticate.
        if not _bastion_token(s):
            problems.append("the bastion has no service token (SR_BASTION_TOKEN "
                            "or bastion_token_file): its API callbacks would be "
                            "refused and no member could authenticate")
        if s.bastion_client_key_path:
            try:
                check_private_key(s.bastion_client_key_path,
                                  "bastion client key")
            except ValueError as e:
                problems.append(str(e))
        if s.bastion_targets_known_hosts == "":
            problems.append("bastion_targets_known_hosts required (no TOFU to "
                            "range hosts)")
        if problems:
            raise RuntimeError("production BASTION config invalid:\n  - "
                               + "\n  - ".join(problems))
        return
    if role == "ingest":
        # The guest-facing ingest listener: it terminates TLS with the
        # provisioned ingest certificate and writes telemetry. It holds no
        # supervisor capability and no bastion key.
        if not s.telemetry_ca_file:
            problems.append("telemetry_ca_file missing (the guests' trust "
                            "anchor)")
        if "CHANGE_ME" in s.postgres_url:
            problems.append("database credentials are placeholders")
        if problems:
            raise RuntimeError("production INGEST config invalid:\n  - "
                               + "\n  - ".join(problems))
        return
    if role != "controller":
        raise RuntimeError(f"unknown SR_PROCESS_ROLE {role!r}")
    # Controller (API): PVE credentials are BROKER-ONLY (milestone 02).
    if s.proxmox_token_id or s.proxmox_token_secret not in ("", "CHANGE_ME", "CHANGE"):
        problems.append("Proxmox credentials on the controller are forbidden — "
                        "the broker holds the only PVE token")
    if s.proxmox_insecure_lab_override:
        problems.append("proxmox_insecure_lab_override must be false in production "
                        "(and PVE TLS is the broker's concern anyway)")
    if not s.broker_socket and not s.broker_url:
        problems.append("broker_socket (appliance) or broker_url (legacy) is "
                        "missing — the API reaches the deployment boundary only "
                        "through the broker")
    if s.broker_socket and s.broker_url:
        problems.append("broker_socket and broker_url are mutually exclusive")
    if s.broker_url:
        for name, val in (("broker_client_cert", s.broker_client_cert),
                          ("broker_client_key", s.broker_client_key),
                          ("broker_tls_ca_file", s.broker_tls_ca_file)):
            if not val:
                problems.append(f"{name} missing (mutual TLS to the broker)")
    if s.runner_transport == "local-dev":
        problems.append("local-dev runner forbidden in production")
    # Telemetry trust (plan 13 phase 4): enrollment capabilities and audit
    # events cross the range — the API the guests dial is HTTPS with the
    # provisioned public CA, on an address the guests can actually reach.
    if not s.api_base_url.startswith("https://"):
        problems.append("api_base_url must be https in production (guests "
                        "ship authenticated telemetry across the range)")
    if "localhost" in s.api_base_url or "127.0.0.1" in s.api_base_url:
        problems.append("api_base_url must be the controller's range/LAN "
                        "address — guests cannot reach localhost")
    if not s.telemetry_ca_file:
        problems.append("telemetry_ca_file missing (public trust material "
                        "provisioned into guests; verified TLS is mandatory)")
    if s.datapath_controller == "nft":
        problems.append("runtime nft datapath removed — isolation is "
                        "operator-managed static (datapath_controller=static)")
    if s.runner_transport != "ssh" or not s.runner_ssh_target or not s.runner_ssh_known_hosts:
        problems.append("isolated runner not configured (runner_transport=ssh + fixed target + pinned known_hosts)")
    if "CHANGE_ME" in s.postgres_url + s.postgres_url_owner:
        problems.append("database credentials are placeholders")
    if s.bastion_targets_known_hosts == "":
        problems.append("bastion_targets_known_hosts required (no TOFU to range hosts)")
    if s.verifier_ssh_known_hosts == "":
        problems.append("verifier_ssh_known_hosts required (pinned management "
                        "host keys — no TOFU, audit N11)")
    # The model credential (plan 18): when a file reference is configured it
    # must actually carry a credential, and it must stay out of world's
    # reach. The group bit is how the API identity reads its own root-owned
    # file, so only the world bits are refused here.
    if s.llm_api_key_file:
        key_path = pathlib.Path(s.llm_api_key_file)
        try:
            if not key_path.read_text().strip():
                problems.append("llm_api_key_file is empty — the model would "
                                "refuse every completion")
            if key_path.stat().st_mode & 0o007:
                problems.append("llm_api_key_file is world-readable; the model "
                                "credential belongs to the API identity alone")
        except OSError as exc:
            problems.append(f"llm_api_key_file unreadable: {exc}")
    # Parse-check configured private keys BEFORE effects (plan 13 phase 4):
    # a corrupt key must fail at startup, not mid-enrollment; the returned
    # fingerprint is what deployment compares against the role build
    # manifest's baked PUBLIC key fingerprints.
    if s.verifier_ssh_key_path:
        try:
            check_private_key(s.verifier_ssh_key_path, "verifier key")
        except ValueError as e:
            problems.append(str(e))
    if problems:
        raise RuntimeError("production config invalid:\n  - " + "\n  - ".join(problems))


@lru_cache
def get_settings() -> Settings:
    role = process_role()
    if role == "worker":
        # The worker NEVER loads the controller .env (audit N04): whatever the
        # controller wants the worker to know is serialized explicitly into the
        # worker's environment by the spawner — no dotenv fallback, no
        # inherited controller secrets by accident.
        s = Settings(_env_file=None)
    else:
        s = Settings()
    if s.sr_env == "production":
        validate_production(s, role)
    return s
