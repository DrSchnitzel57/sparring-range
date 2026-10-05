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
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Environment mode ------------------------------------------------------
    # dev: local shell fallback runner permitted (explicitly), TLS lab override OK
    # production: no local execution, placeholder secrets rejected
    sr_env: str = "dev"

    # --- Database ---
    postgres_url: str = "postgresql+psycopg2://sr_app:sr_app_dev@localhost:5432/sparring_range"
    postgres_url_owner: str = "postgresql+psycopg2://sr_owner:sr_owner_dev@localhost:5432/sparring_range"
    db_app_role: str = "sr_app"

    # --- API (single front door) ---
    api_base_url: str = "http://localhost:8000"
    # Explicit LAN origins for the browser (F23: never default teammates to
    # their own localhost). Comma-separated list, e.g. http://gym.lan:3000.
    api_allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # --- Auth (F04) ---
    web_token_ttl_hours: int = 12
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

    # --- Range network (control-plane-side view) ---
    range_bridge: str = "vmbr1"
    range_vlan: int = 66
    # Bridge PORTS (tap/vnet members) — the bridge-family emergency rules must
    # match ports, not the bridge master (audit R05). Comma-separated; provision
    # from `ls /sys/class/net/<bridge>/brif/`.
    range_bridge_ports: str = ""
    range_cidr: str = "10.66.0.0/24"
    range_gateway: str = "10.66.0.1"
    bastion_address: str = "10.66.0.2"
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

    # --- Verifier management exec (trusted backend only, F01/F10) --------------
    verifier_ssh_user: str = "root"
    verifier_ssh_key_path: str = ""
    verifier_exec_timeout_s: int = 30

    # --- Deploy (M1) ---
    proxmox_node: str = "r740"
    deploy_vmid_base: int = 210

    # --- Golden image templates ---
    template_vmid_web: int = 9001
    template_vmid_win_dc: int = 9002
    template_vmid_win10: int = 9003
    template_vmid_linux: int = 9004

    # --- LLM serving (OpenAI-compatible; swappable per Part 6.1) ---
    llm_base_url: str = "http://localhost:8001/v1"
    llm_api_key: str = "dummy"
    llm_model_red: str = "qwen2.5-14b-instruct"
    llm_model_coach: str = "qwen2.5-32b-instruct"
    llm_timeout_s: int = 120
    # bounded model gateway (F18)
    model_queue_max: int = 32
    model_hint_max_wait_s: int = 150     # declared bound for interactive hints
    model_recovery_interval_s: int = 60  # periodic retry after an outage

    # --- Safety (F02/F03) ---
    safety_state_file: str = "./.safety_state"
    safety_evidence_max_age_h: int = 24
    datapath_controller: str = "nft"      # nft | noop(dev/test only)
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
    recording_max_bytes: int = 32 * 1024 * 1024

    # --- Telemetry ingest (F09) ---
    ingest_max_body_events: int = 500


def process_role() -> str:
    """Which component this process is (controller | worker). The worker is
    spawned by the API with SR_PROCESS_ROLE=worker and a SERIALIZED, minimal
    environment — it must not need, and must not silently load, controller
    configuration (audit N04)."""
    return os.environ.get("SR_PROCESS_ROLE", "controller")


def validate_production(s: Settings, role: str = "controller") -> None:
    """Fail CLOSED on misconfiguration in production mode (F23). Validation is
    ROLE-SCOPED (audit N04): the worker is validated on exactly the capability
    it holds (API + model + runner channel), never on controller-only secrets
    it must not possess (Proxmox token, owner DB, bastion pins)."""
    problems = []
    if role == "worker":
        if s.runner_transport != "ssh" or not s.runner_ssh_target \
                or not s.runner_ssh_known_hosts:
            problems.append("isolated runner not configured (runner_transport=ssh"
                            " + fixed target + pinned known_hosts)")
        if not s.llm_base_url or not s.llm_model_red:
            problems.append("model endpoint not configured (llm_base_url/llm_model_red)")
        if not s.api_base_url:
            problems.append("api_base_url missing (worker acts only via its "
                            "session-scoped API capability)")
        if problems:
            raise RuntimeError("production WORKER config invalid:\n  - "
                               + "\n  - ".join(problems))
        return
    if not s.proxmox_token_id or s.proxmox_token_secret in ("", "CHANGE_ME"):
        problems.append("Proxmox API token missing")
    if s.proxmox_insecure_lab_override:
        problems.append("proxmox_insecure_lab_override must be false in production")
    if not s.proxmox_tls_ca_file:
        problems.append("proxmox_tls_ca_file must be configured (or TLS via system CA) in production")
    if s.runner_transport != "ssh" or not s.runner_ssh_target or not s.runner_ssh_known_hosts:
        problems.append("isolated runner not configured (runner_transport=ssh + fixed target + pinned known_hosts)")
    if "CHANGE_ME" in s.postgres_url + s.postgres_url_owner:
        problems.append("database credentials are placeholders")
    if s.bastion_targets_known_hosts == "":
        problems.append("bastion_targets_known_hosts required (no TOFU to range hosts)")
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
