"""_ProxmoxerPathAdapter: leading-slash paths must lose the slash.

proxmoxer's url_join uses posixpath.join, where an absolute segment
REPLACES the base — api.get("/nodes/x") requests "/nodes/x" and loses
the /api2/json prefix, so real PVE answers 500 "no such file" for every
call (live-deploy find, 2026-10-14). The adapter normalizes at the one
boundary where the real proxmoxer client is wrapped.
"""
from infra.proxmox_client import _ProxmoxerPathAdapter


class _Recorder:
    def __init__(self):
        self.calls = []

    def get(self, path, **kw):
        self.calls.append(("GET", path, kw))

    def post(self, path, **kw):
        self.calls.append(("POST", path, kw))

    def delete(self, path, **kw):
        self.calls.append(("DELETE", path, kw))

    def version(self):
        return {"version": "9.2"}


def test_leading_slashes_are_stripped_for_proxmoxer():
    a = _ProxmoxerPathAdapter(_Recorder())
    a.get("/nodes/pve/qemu/9005/config")
    a.post("/nodes/pve/qemu/9005/clone", newid=9100)
    a.delete("/nodes/pve/qemu/9100")
    assert [c[:2] for c in a.calls] == [
        ("GET", "nodes/pve/qemu/9005/config"),
        ("POST", "nodes/pve/qemu/9005/clone"),
        ("DELETE", "nodes/pve/qemu/9100"),
    ]
    assert a.calls[1][2] == {"newid": 9100}


def test_relative_paths_pass_through_and_attrs_delegate():
    a = _ProxmoxerPathAdapter(_Recorder())
    a.get("nodes/pve/status")
    assert a.calls == [("GET", "nodes/pve/status", {})]
    assert a.version() == {"version": "9.2"}
