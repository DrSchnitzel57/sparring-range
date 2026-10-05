"""proxmoxer wrapper (Part 2/3): rangectl drives Proxmox with an API token, not root.

Everything host-level goes through this module so there is one place to audit.

F05 repairs:
  * correct documented PVE endpoints and HTTP verbs (resource DELETE for
    destroy; `newvmid` for clone; concrete node paths — no literal braces),
  * asynchronous UPID tasks are WAITED on with bounded polling and the task's
    exit status is checked — callers may no longer proceed on an unfinished
    clone/start/delete,
  * TLS: verify against a configured CA by default; the insecure mode is an
    explicit, logged lab override (never silent),
  * `FakePVEHttp` simulates the API at the proxmoxer BOUNDARY (below this
    adapter) so production call ordering and task states are actually tested.
"""
from __future__ import annotations

import time
from typing import Protocol


class ProxmoxError(RuntimeError):
    pass


class ProxmoxTaskError(ProxmoxError):
    pass


class ProxmoxLike(Protocol):
    def version(self) -> dict: ...
    def get(self, path: str) -> dict | list: ...
    def post(self, path: str, **kwargs) -> dict | list | None: ...
    def delete(self, path: str) -> dict | list | None: ...


class ProxmoxClient:
    """Thin, transparent wrapper over proxmoxer (token auth) + task waiting."""

    def __init__(self, host: str | None = None, token_id: str | None = None,
                 token_secret: str | None = None, api=None):
        from srplatform.settings import get_settings
        s = get_settings()
        if api is None:
            host = host or s.proxmox_host
            token_id = token_id or s.proxmox_token_id
            token_secret = token_secret or s.proxmox_token_secret
            if not token_id or not token_secret:
                raise ProxmoxError(
                    "Proxmox API token not configured (PROXMOX_TOKEN_ID / PROXMOX_TOKEN_SECRET). "
                    "Drew: create the token in Datacenter → Permissions → API Tokens.")
            from proxmoxer import ProxmoxAPI

            insecure = s.proxmox_insecure_lab_override
            verify: object = True
            if s.proxmox_tls_ca_file:
                verify = s.proxmox_tls_ca_file
            if insecure:
                verify = False
                print("WARNING: Proxmox TLS verification DISABLED by explicit lab override")
            user, _, name = token_id.partition("!")
            api = ProxmoxAPI(host, user=user, token_name=name, token_value=token_secret,
                             verify_ssl=verify, timeout=30)
        self.api = api
        self.task_timeout = s.proxmox_task_timeout_s

    # --- raw pass-through ------------------------------------------------------
    def version(self) -> dict:
        return self.api.version()

    def get(self, path: str) -> dict | list:
        return self.api.get(path)

    def post(self, path: str, **kwargs) -> dict | list | None:
        return self.api.post(path, **kwargs)

    def delete(self, path: str) -> dict | list | None:
        return self.api.delete(path)

    # --- async tasks (F05) ------------------------------------------------------
    def wait_for_task(self, node: str, upid: str, timeout: int | None = None,
                      poll_s: float = 1.0) -> dict:
        """Poll a UPID until stopped; raise on error exit status or timeout."""
        if not upid:
            raise ProxmoxTaskError(f"no UPID returned for task on {node}")
        deadline = time.monotonic() + (timeout or self.task_timeout)
        while True:
            status = self.get(f"/nodes/{node}/tasks/{upid}/status")
            if isinstance(status, dict) and status.get("status") == "stopped":
                exit_status = status.get("exitstatus")
                if exit_status == "OK":
                    return status
                raise ProxmoxTaskError(f"task {upid} on {node} failed: exitstatus={exit_status}")
            if time.monotonic() > deadline:
                raise ProxmoxTaskError(f"task {upid} on {node} timed out after "
                                       f"{timeout or self.task_timeout}s")
            time.sleep(poll_s)

    # --- operations used by the deploy layer (concrete node, correct verbs) -----
    def resources(self) -> list[dict]:
        return self.get("/cluster/resources")

    def next_vmid(self, start: int) -> int:
        """Ask PVE for a free VMID (allocator handles concurrency); fall back to
        a scan only if the endpoint is unavailable, and let clone failures be
        handled by the caller as subject to concurrent races."""
        try:
            nid = self.get(f"/cluster/nextid?vmid={start}")
            return int(nid)
        except Exception:
            existing = {int(r["vmid"]) for r in self.resources() if r.get("vmid")}
            cand = start
            while cand in existing:
                cand += 1
            return cand

    def clone_template(self, node: str, template_vmid: int, new_vmid: int, name: str,
                       full: bool = False, storage: str | None = None) -> str:
        """Linked clone (full=False). Returns the UPID — CALLER MUST wait_for_task.

        The documented PVE parameter for the destination id is `newid`
        (https://pve.proxmox.com/pve-docs/api-viewer POST /nodes/{node}/qemu/{vmid}/clone);
        `newvmid` is NOT a parameter and real PVE rejects it."""
        kwargs: dict = {"newid": new_vmid, "name": name, "full": 1 if full else 0}
        if storage:
            kwargs["storage"] = storage
        return self.post(f"/nodes/{node}/qemu/{template_vmid}/clone", **kwargs)

    def set_config(self, node: str, vmid: int, **cfg) -> None:
        self.post(f"/nodes/{node}/qemu/{vmid}/config", **cfg)

    def vm_status(self, node: str, vmid: int) -> str:
        try:
            st = self.get(f"/nodes/{node}/qemu/{vmid}/status/current")
        except Exception:
            return "unknown"  # 404 / missing resource — callers act idempotently
        return (st or {}).get("status", "unknown") if isinstance(st, dict) else "unknown"

    def start(self, node: str, vmid: int) -> str:
        return self.post(f"/nodes/{node}/qemu/{vmid}/status/start")

    def stop(self, node: str, vmid: int, force: bool = False) -> str:
        action = "stop" if force else "shutdown"
        return self.post(f"/nodes/{node}/qemu/{vmid}/status/{action}")

    def delete_vm(self, node: str, vmid: int) -> str:
        """Resource DELETE (the documented operation), returns UPID."""
        return self.delete(f"/nodes/{node}/qemu/{vmid}")

    # --- high-level sequences used by the orchestrator ---------------------------
    def clone_and_wait(self, node, template_vmid, new_vmid, name, full=False) -> None:
        upid = self.clone_template(node, template_vmid, new_vmid, name, full=full)
        self.wait_for_task(node, upid)

    def start_and_wait(self, node, vmid, timeout: int = 90) -> None:
        if self.vm_status(node, vmid) == "running":
            return
        upid = self.start(node, vmid)
        self.wait_for_task(node, upid, timeout=timeout)

    def destroy_and_wait(self, node, vmid, force_stop_timeout: int = 60) -> None:
        st = self.vm_status(node, vmid)
        if st == "unknown":
            return  # idempotent: nothing to delete
        if st == "running":
            upid = self.stop(node, vmid, force=True)
            self.wait_for_task(node, upid, timeout=force_stop_timeout)
        upid = self.delete_vm(node, vmid)
        self.wait_for_task(node, upid, timeout=force_stop_timeout)


class FakePVEHttp:
    """A fake of the proxmoxer HTTP BOUNDARY (get/post/delete + task queue), so
    ProxmoxClient's REAL code paths — URLs, verbs, UPID polling, error
    propagation — are exercised in tests (F05). Configure task behaviour per
    path fragment; default tasks complete OK immediately."""

    def __init__(self):
        self.vms: dict[int, dict] = {}
        self.tasks: dict[str, dict] = {}
        self._upid = 0
        self.requests: list[tuple[str, str, dict]] = []
        # behaviour hooks
        self.task_polls_needed = 0          # how long tasks stay "running"
        self.fail_task_fragments = ()       # URL fragments whose tasks fail
        self.fail_request_fragments = ()    # raise immediately
        self._poll_count: dict[str, int] = {}

    def version(self):
        return {"version": "fake-pve"}

    def _new_upid(self, path: str) -> str:
        self._upid += 1
        upid = f"UPID:fake:{self._upid:08d}:0:0:{self._upid:08d}:qemu:{path}::"
        failed = any(f in path for f in self.fail_task_fragments)
        self.tasks[upid] = {"node": "fake", "status": "running", "_failed": failed,
                            "_path": path}
        return upid

    def get(self, path, **kw):
        self.requests.append(("GET", path, kw))
        if path.startswith("/cluster/resources"):
            return [{"vmid": vmid, "name": v["name"], "node": "fake", "type": "qemu",
                     "status": v["status"]} for vmid, v in self.vms.items()]
        if path.startswith("/cluster/nextid"):
            start = int(path.split("vmid=")[1]) if "vmid=" in path else 200
            existing = set(self.vms)
            cand = start
            while cand in existing:
                cand += 1
            return str(cand)
        if "/tasks/" in path and path.endswith("/status"):
            upid = path.split("/tasks/")[1].rsplit("/status", 1)[0]
            t = self.tasks.get(upid)
            if not t:
                raise KeyError(f"no such task {upid}")
            self._poll_count[upid] = self._poll_count.get(upid, 0) + 1
            if self._poll_count[upid] > self.task_polls_needed:
                t["status"] = "stopped"
                t["exitstatus"] = "ERROR: injected failure" if t["_failed"] else "OK"
                if t["exitstatus"] == "OK" and "_done_cb" in t:
                    t["_done_cb"]()
            return {"status": t["status"], "exitstatus": t.get("exitstatus")}
        if path.endswith("/config"):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise KeyError(f"no VM {vmid}")  # PVE 404s config of missing resources
            return dict(v.get("config", {}))
        if "/status/current" in path:
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise KeyError(f"no VM {vmid}")  # PVE raises 404 for missing resources
            return {"status": v["status"], "vmid": vmid}
        return {}

    #: documented POST /nodes/{node}/qemu/{vmid}/clone parameters (PVE API viewer).
    #: The fake REJECTS anything else so adapter tests cannot agree with an
    #: invented parameter name (audit R06: `newvmid` vs documented `newid`).
    CLONE_PARAMS = {"newid", "name", "description", "full", "storage", "target",
                    "format", "snapname"}

    def post(self, path, **kw):
        self.requests.append(("POST", path, kw))
        if any(f in path for f in self.fail_request_fragments):
            raise RuntimeError(f"injected request failure for {path}")
        if "/clone" in path:
            unknown = set(kw) - self.CLONE_PARAMS
            if unknown:
                # real PVE answers 400 with "unrecognized parameter"
                raise RuntimeError(f"400 unrecognized parameter(s): {sorted(unknown)}")
            if "newid" not in kw:
                raise RuntimeError("400 missing required parameter 'newid'")
            tpl = int(path.split("/qemu/")[1].split("/")[0])
            new = int(kw["newid"])
            if new in self.vms:
                raise RuntimeError(f"VMID {new} in use")
            if tpl not in self.vms:
                raise RuntimeError(f"template {tpl} not found")
            # the clone only materializes when the task COMPLETES (async semantics)
            upid = self._new_upid(path)
            self.tasks[upid]["_done_cb"] = lambda: self.vms.setdefault(
                new, {"name": kw["name"], "template": tpl, "status": "stopped"})
            return upid
        if path.endswith("/status/start"):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise RuntimeError(f"no VM {vmid}")
            upid = self._new_upid(path)
            self.tasks[upid]["_done_cb"] = lambda: v.update(status="running")
            return upid
        if path.endswith(("/status/shutdown", "/status/stop")):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise RuntimeError(f"no VM {vmid}")
            upid = self._new_upid(path)
            self.tasks[upid]["_done_cb"] = lambda: v.update(status="stopped")
            return upid
        if path.endswith("/config"):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise RuntimeError(f"no VM {vmid}")
            v.setdefault("config", {}).update(kw)
            return None
        return None

    def delete(self, path, **kw):
        self.requests.append(("DELETE", path, kw))
        if any(f in path for f in self.fail_request_fragments):
            raise RuntimeError(f"injected request failure for {path}")
        vmid = int(path.rsplit("/", 1)[1])
        if vmid not in self.vms:
            raise RuntimeError(f"no VM {vmid}")  # PVE 404
        upid = self._new_upid(path)
        self.tasks[upid]["_done_cb"] = lambda: self.vms.pop(vmid, None)
        return upid
