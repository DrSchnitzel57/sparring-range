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
        import os

        from srplatform.settings import get_settings

        s = get_settings()
        if os.environ.get("SR_DEMO_FAKE_PROXMOX") == "1" and s.sr_env != "production":
            # Explicit DEV-ONLY demo double (browser/dev without a PVE).
            from infra.proxmox_client import FakePVEHttp, ProxmoxClient

            http = FakePVEHttp()
            for vmid in (9001, 9002, 9003, 9004):
                http.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid,
                                  "status": "stopped"}
            _proxmox = ProxmoxClient(api=http)
            return _proxmox
        from infra.proxmox_client import ProxmoxClient

        _proxmox = ProxmoxClient()
    return _proxmox


def set_proxmox(p) -> None:
    global _proxmox
    _proxmox = p
