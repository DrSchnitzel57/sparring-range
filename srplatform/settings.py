"""Central settings. Everything environment-specific comes from .env / env vars.

Hard constraint #5: secrets never enter the repo — only .env.example is committed.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Database ---
    postgres_url: str = "postgresql+psycopg2://sr_app:sr_app_dev@localhost:5432/sparring_range"
    postgres_url_owner: str = "postgresql+psycopg2://sr_owner:sr_owner_dev@localhost:5432/sparring_range"
    db_app_role: str = "sr_app"

    # --- API (single front door) ---
    api_base_url: str = "http://localhost:8000"

    # --- Proxmox / control plane ---
    proxmox_host: str = "localhost"
    proxmox_user: str = "root@pam"
    proxmox_token_id: str = ""
    proxmox_token_secret: str = ""

    # --- Range network (control-plane-side view) ---
    range_bridge: str = "vmbr1"
    range_vlan: int = 66
    range_gateway: str = "10.66.0.1"
    bastion_address: str = "10.66.0.2"
    kali_container: str = "kali-red-01"

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

    # --- Bastion / recordings ---
    recordings_dir: str = "./recordings"
    bastion_host_key_path: str = "./bastion_ed25519"
    # User allowed to authenticate to the recording bastion (Drew).
    bastion_user: str = "drew"


@lru_cache
def get_settings() -> Settings:
    return Settings()
