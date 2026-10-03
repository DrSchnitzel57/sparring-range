"""Injectable dependencies for the API (proxmox connection etc.).

In prod: real proxmoxer wrapper (token from .env). In tests: FakeProxmox via
set_proxmox(). The API process is the only thing that talks to Postgres, and the
only thing that talks to Proxmox.
"""
from __future__ import annotations

_proxmox = None


def get_proxmox():
    global _proxmox
    if _proxmox is None:
        from infra.proxmox_client import ProxmoxClient

        _proxmox = ProxmoxClient()
    return _proxmox


def set_proxmox(p) -> None:
    global _proxmox
    _proxmox = p
