"""proxmoxer wrapper (Part 2/3): rangectl drives Proxmox with an API token, not root.

Everything host-level goes through this module so there is one place to audit.
`FakeProxmox` (test double) implements the same surface so deploy logic is
testable without the R740 (Drew owns the real host — Part 7).
"""
from __future__ import annotations

from typing import Protocol

from srplatform.settings import get_settings


class ProxmoxLike(Protocol):
    def version(self) -> dict: ...
    def get(self, path: str) -> dict | list: ...
    def post(self, path: str, **kwargs) -> dict | list | None: ...
    def delete(self, path: str) -> dict | list | None: ...


class ProxmoxClient:
    """Thin, transparent wrapper over proxmoxer (token auth)."""

    def __init__(self, host: str | None = None, token_id: str | None = None, token_secret: str | None = None):
        s = get_settings()
        host = host or s.proxmox_host
        token_id = token_id or s.proxmox_token_id
        token_secret = token_secret or s.proxmox_token_secret
        if not token_id or not token_secret:
            raise RuntimeError(
                "Proxmox API token not configured (PROXMOX_TOKEN_ID / PROXMOX_TOKEN_SECRET). "
                "Drew: create the token in Datacenter → Permissions → API Tokens."
            )
        from proxmoxer import ProxmoxAPI  # imported lazily so unit tests don't need the network

        user, _, name = token_id.partition("!")
        self.api = ProxmoxAPI(
            host,
            user=user,
            token_name=name,
            token_value=token_secret,
            verify_ssl=False,  # home lab self-signed; note it, don't silently ignore
        )

    def version(self) -> dict:
        return self.api.version()

    def get(self, path: str) -> dict | list:
        return self.api.get(path)

    def post(self, path: str, **kwargs) -> dict | list | None:
        return self.api.post(path, **kwargs)

    def delete(self, path: str) -> dict | list | None:
        return self.api.delete(path)

    # --- helpers used by the deploy layer (M1) -------------------------------
    def resources(self) -> list[dict]:
        return self.get("/cluster/resources")

    def clone_template(self, template_vmid: int, new_vmid: int, name: str, full: bool = False) -> str:
        """Linked clone (full=False) — the cheap clone that makes per-scenario
        deploy/reset practical. Returns the job id."""
        return self.post(f"/nodes/{{node}}/qemu/{template_vmid}/clone", newid=new_vmid, name=name, full=int(full))

    def start(self, node: str, vmid: int) -> str:
        return self.post(f"/nodes/{node}/qemu/{vmid}/status/start")

    def stop(self, node: str, vmid: int, force: bool = False) -> str:
        return self.post(f"/nodes/{node}/qemu/{vmid}/status/shutdown" if not force else f"/nodes/{node}/qemu/{vmid}/status/stop")

    def destroy(self, node: str, vmid: int) -> str:
        return self.post(f"/nodes/{node}/qemu/{vmid}/destroy")


class FakeProxmox:
    """In-memory double with the same surface, for tests and dry runs."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.vms: dict[int, dict] = {}

    def version(self):
        return {"version": "fake"}

    def get(self, path):
        self.calls.append(("GET", path))
        return []

    def post(self, path, **kwargs):
        self.calls.append(("POST", path, kwargs))
        return "up/0"

    def delete(self, path):
        self.calls.append(("DELETE", path))
        return None

    def clone_template(self, template_vmid, new_vmid, name, full=False):
        self.calls.append(("CLONE", template_vmid, new_vmid, name, full))
        self.vms[new_vmid] = {"name": name, "template": template_vmid, "status": "running"}
        return "job-1"

    def start(self, node, vmid):
        self.calls.append(("START", node, vmid))
        return "job-2"

    def stop(self, node, vmid, force=False):
        self.calls.append(("STOP", node, vmid, force))
        return "job-3"

    def destroy(self, node, vmid):
        self.calls.append(("DESTROY", node, vmid))
        self.vms.pop(vmid, None)
        return "job-4"
