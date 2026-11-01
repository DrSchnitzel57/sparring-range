"""Libvirt/KVM backend for the appliance broker.

This is the production implementation of the typed operations the broker
needs.  It never accepts caller-supplied XML, paths, devices or commands:
the image allowlist, fixed bridge, fixed disk/seed layout and bounded VMID
namespace all come from the validated manifest/policy.  Domains carry an
appliance-owned description record (VMID, installation, session, generation,
role) so ownership is read back from libvirt, never inferred from a name
alone.

QEMU guest agent is used ONLY for the fixed public host-key path and the
fixed first-boot marker.  No arbitrary guest file path and no guest command
is reachable from this API.

Failure policy: libvirt/agent unavailability raises BackendUnavailable
(outcome unknown); it is never folded into "absent" or "stopped".
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from xml.sax.saxutils import escape

from infra.appliance.errors import (BackendReadBackFailed, BackendUnavailable,
                                    ImageIntegrityError)
from infra.appliance.manifest import ApplianceManifest, ImageSpec
from infra.appliance.policy import AppliancePolicy
from infra.appliance.seed import SeedInputs, build_seed

GUEST_HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"
# QEMU user networking (software fixture only): the guest keeps the classic
# SLIRP address and uses the SLIRP gateway.  Production guests are on-link
# with no route at all.
FIXTURE_ADDRESS = "10.0.2.15"
FIXTURE_GATEWAY = "10.0.2.2"
FIRST_BOOT_MARKER = "/var/lib/sparring-range/first-boot-complete"
_DESC_PREFIX = "SRAPPLIANCE:"


def _desc_json(desc: dict) -> str:
    return _DESC_PREFIX + json.dumps(desc, sort_keys=True, separators=(",", ":"))


def _parse_desc(text: str | None) -> dict | None:
    if not text or not text.startswith(_DESC_PREFIX):
        return None
    try:
        obj = json.loads(text[len(_DESC_PREFIX):])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _mac(seed: str) -> str:
    raw = hashlib.sha256(seed.encode()).digest()[:4]
    # 52:54:00 is QEMU's locally administered range; the remaining octets
    # are deterministic per appliance+vmid so a stale domain is recognisable.
    return "52:54:00:%02x:%02x:%02x" % (raw[0], raw[1], raw[2])


@dataclass(frozen=True)
class BackendConfig:
    uri: str = "qemu:///session"
    allow_tcg: bool = False
    fixture_mode: bool = False
    qemu_img: str = "qemu-img"
    qemu_agent_timeout_s: float = 10.0
    connect_timeout_s: float = 10.0


class LibvirtBackend:
    """Duck-typed to the broker's Proxmox adapter (lookup/clone/config/start/...)."""

    GUEST_HOST_KEY_PATH = GUEST_HOST_KEY_PATH

    def __init__(self, manifest: ApplianceManifest, policy: AppliancePolicy,
                 config: BackendConfig | None = None, *, connection=None):
        self.manifest = manifest
        self.policy = policy
        self.cfg = config or BackendConfig()
        self._conn = connection
        self._verified: dict[tuple[str, int, int], str] = {}
        self._img_lock = False

    # ------------------------------------------------------------- connection ---
    def _libvirt(self):
        try:
            import libvirt  # type: ignore
        except ImportError as exc:  # pragma: no cover - host prerequisite
            raise BackendUnavailable(
                "libvirt Python bindings are not installed (install the distro "
                "python3-libvirt and libvirt-daemon-driver-qemu packages)") from exc
        return libvirt

    def connect(self):
        if self._conn is not None:
            return self._conn
        libvirt = self._libvirt()
        try:
            self._conn = libvirt.open(self.cfg.uri)
        except Exception as exc:  # noqa: BLE001
            raise BackendUnavailable(f"cannot open libvirt {self.cfg.uri}: {exc}") from exc
        if self._conn is None:
            raise BackendUnavailable(f"libvirt {self.cfg.uri} returned no connection")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    @property
    def accelerator(self) -> str:
        return "kvm" if self._kvm_available() else "tcg"

    def _kvm_available(self) -> bool:
        return os.access("/dev/kvm", os.R_OK | os.W_OK)

    def _domain_type(self) -> str:
        if self._kvm_available():
            return "kvm"
        if not self.cfg.allow_tcg:
            raise BackendUnavailable(
                "KVM is unavailable (/dev/kvm missing or not writable) and the "
                "backend is not configured to allow TCG. Refusing to silently "
                "emulate the production hypervisor; install KVM/nested virt or "
                "set the explicit software-fixture flag.")
        return "qemu"

    # --------------------------------------------------------------- inspect ---
    def _domains(self):
        conn = self.connect()
        try:
            return list(conn.listAllDomains(0))
        except Exception as exc:  # noqa: BLE001
            raise BackendUnavailable(f"cannot list libvirt domains: {exc}") from exc

    def _desc(self, dom) -> dict | None:
        try:
            xml = dom.XMLDesc(0)
        except Exception as exc:  # noqa: BLE001
            raise BackendUnavailable(f"cannot read domain XML: {exc}") from exc
        m = re.search(r"<description>(.*?)</description>", xml, re.S)
        return _parse_desc(html.unescape(m.group(1)) if m else None)

    def _find(self, vmid: int, node: str | None = None):
        for dom in self._domains():
            d = self._desc(dom)
            if d and int(d.get("vmid", -1)) == int(vmid):
                if node is not None and d.get("node") != node:
                    raise BackendUnavailable(
                        f"VMID {vmid} is owned by a different appliance "
                        f"({d.get('node')!r}), not {node!r}")
                return dom, d
        return None, None

    def lookup_vm(self, node: str, vmid: int):
        dom, desc = self._find(int(vmid), node)
        if dom is None:
            return None
        return {"vmid": int(vmid), "name": desc.get("name") or dom.name(),
                "node": node, "state": "running" if dom.isActive() else "stopped",
                # The domain's own immutable identity.  The VMID is the
                # broker's durable key, but a recreated domain would reuse the
                # VMID: the UUID is what proves the exact guest is the one
                # this deployment created.
                "domain_uuid": self._domain_uuid(dom)}

    def lookup_config(self, node: str, vmid: int):
        dom, desc = self._find(int(vmid), node)
        if dom is None:
            return None
        return self._config_from(dom, desc)

    def try_lookup_config(self, node: str, vmid: int):
        try:
            return self.lookup_config(node, vmid)
        except BackendUnavailable as exc:
            return {"_unavailable": str(exc)}

    @staticmethod
    def _domain_uuid(dom) -> str:
        """The libvirt domain UUID — the guest's own immutable identity."""
        try:
            return str(dom.UUID())
        except Exception:  # noqa: BLE001 — an unreadable UUID is unknown
            return ""

    def _config_from(self, dom, desc: dict) -> dict:
        try:
            xml = dom.XMLDesc(0)
            name = dom.name()
        except Exception as exc:  # noqa: BLE001
            raise BackendUnavailable(f"cannot read config for VMID "
                                     f"{desc.get('vmid')}: {exc}") from exc
        bridge = re.search(r'<source bridge=["\']([^"\']+)["\']', xml)
        ifdesc = re.search(r"<interface\b.*?</interface>", xml, re.S)
        net0 = desc.get("net0") or (
            f"virtio,bridge={bridge.group(1)}" if bridge else "")
        cfg = {"name": desc.get("name") or name, "net0": net0,
               "ipconfig0": desc.get("ipconfig0", ""),
               "tags": desc.get("tags", ""), "vmid": int(desc["vmid"]),
               "role": desc.get("role", ""), "generation": desc.get("generation"),
               "session_id": desc.get("session_id"),
               "domain_uuid": self._domain_uuid(dom)}
        if ifdesc is None:
            cfg["_unavailable"] = "domain has no network interface"
        return cfg

    def vm_status(self, node: str, vmid: int) -> str:
        dom, _ = self._find(int(vmid), node)
        if dom is None:
            return "absent"
        try:
            if not dom.isActive():
                return "stopped"
            state = dom.info()[0]
        except Exception as exc:  # noqa: BLE001
            raise BackendUnavailable(f"cannot read state for VMID {vmid}: {exc}") from exc
        # libvirt VIR_DOMAIN_RUNNING == 1, BLOCKED == 2, PAUSED == 3,
        # SHUTDOWN == 4, SHUTOFF == 5, CRASHED == 6, PMSUSPENDED == 7.
        return {1: "running", 3: "paused", 6: "crashed", 7: "paused"}.get(
            int(state), "unknown")

    def list_owned(self) -> list[dict]:
        out = []
        for dom in self._domains():
            d = self._desc(dom)
            if d:
                out.append({**d, "libvirt_active": dom.isActive(),
                            "domain_name": dom.name()})
        return out

    # --------------------------------------------------------------- images ---
    def _image(self, template_id: int) -> ImageSpec:
        image = self.manifest.image_for_template(int(template_id))
        if image is None:
            raise BackendUnavailable(f"template {template_id} is not an approved image")
        self._verify_image(image)
        return image

    def artifact_for_template(self, template_id: int) -> dict | None:
        """The artifact identity THIS backend clones TEMPLATE_ID from —
        from the manifest loaded at daemon start, the same object whose
        SHA-256 ``_verify_image`` enforces before every clone. The deploy
        authority freezes this into the deployment resource (review
        finding: a separately re-read manifest is not proof of deployed
        bytes). Unknown template: None, i.e. honestly UNKNOWN."""
        return self.manifest.artifact_identity(int(template_id))

    def _verify_image(self, image: ImageSpec) -> None:
        p = pathlib.Path(image.path)
        try:
            st = p.stat()
        except OSError as exc:
            raise ImageIntegrityError(f"image {p} unreadable: {exc}") from exc
        key = (str(p), st.st_size, int(st.st_mtime_ns))
        if self._verified.get(key) == image.sha256:
            return
        if st.st_size != image.size_bytes:
            raise ImageIntegrityError(
                f"image {p} size {st.st_size} does not match manifest "
                f"{image.size_bytes}")
        actual = _sha256_file(p)
        if actual != image.sha256:
            raise ImageIntegrityError(
                f"image {p} sha256 mismatch (expected {image.sha256}, got {actual})")
        self._verified[key] = actual

    # --------------------------------------------------------------- lifecycle ---
    def clone_and_wait(self, node: str, template_vmid: int, new_vmid: int,
                       name: str, full: bool = True, **kwargs) -> None:
        self._require_node(node)
        self.policy.check_vmid(int(new_vmid))
        self.policy.check_name(name)
        if not full:
            raise BackendUnavailable("appliance clones require a full overlay")
        image = self._image(int(template_vmid))
        dom, _ = self._find(int(new_vmid), node)
        if dom is not None:
            raise BackendUnavailable(f"VMID {new_vmid} already has a domain")
        guest_dir = self._guest_dir(int(new_vmid))
        if guest_dir.exists():
            raise BackendUnavailable(
                f"stale appliance state for VMID {new_vmid} exists at {guest_dir}; "
                "run recovery before reusing the id")
        guest_dir.mkdir(parents=True, mode=0o750)
        overlay = guest_dir / "disk.qcow2"
        seed = guest_dir / "seed.iso"
        serial = guest_dir / "serial.log"
        try:
            self._overlay(image, overlay)
            desc = {
                "vmid": int(new_vmid), "node": node, "name": name,
                "role": image.role, "template_id": int(template_vmid),
                "session_id": kwargs.get("session_id"),
                "generation": str(kwargs.get("generation", 1)),
                "overlay": str(overlay), "seed": str(seed),
                "serial": str(serial), "net0": self.policy.net0_expected,
                "ipconfig0": "", "tags": "",
                "accelerator": self.accelerator,
                "fixture_mode": self.cfg.fixture_mode,
                "created_at": time.time(),
            }
            self._write_seed(desc, image, int(new_vmid), name, None)
            xml = self._domain_xml(desc, image)
            conn = self.connect()
            try:
                conn.defineXML(xml)
            except Exception as exc:  # noqa: BLE001
                raise BackendUnavailable(f"cannot define domain for VMID {new_vmid}: {exc}") from exc
        except Exception:
            shutil.rmtree(guest_dir, ignore_errors=True)
            raise
        # Read back identity; defineXML returning is not proof the domain is
        # the one the broker intended.
        dom, got = self._find(int(new_vmid), node)
        if dom is None or (got or {}).get("name") != name:
            raise BackendReadBackFailed(
                f"clone read-back for VMID {new_vmid} did not show {name!r}")

    def _guest_dir(self, vmid: int) -> pathlib.Path:
        root = pathlib.Path(self.manifest.state_dir) / "guests"
        root.mkdir(parents=True, exist_ok=True)
        return root / str(int(vmid))

    def _backing_size_gb(self, image: ImageSpec) -> int:
        """The base image's virtual size in GiB (0 when it cannot be read)."""
        try:
            p = subprocess.run(
                [self.cfg.qemu_img, "info", "--output=json", image.path],
                capture_output=True, text=True, timeout=120)
            if p.returncode != 0:
                return 0
            return int(int(json.loads(p.stdout)["virtual-size"]) // (1024 ** 3))
        except Exception:  # noqa: BLE001 — a smaller overlay is the failure
            return 0

    def _overlay(self, image: ImageSpec, overlay: pathlib.Path) -> None:
        # The overlay must never be SMALLER than its backing image: a smaller
        # qcow2 truncates the partition table, the guest cannot find its root
        # filesystem and drops to an initramfs shell.  The guest therefore
        # sees at least the base's size, and the manifest's disk budget is a
        # floor, not a ceiling on an existing image.
        size_gb = max(int(image.disk_gb), self._backing_size_gb(image))
        cmd = [self.cfg.qemu_img, "create", "-f", "qcow2", "-F", "qcow2",
               "-b", image.path, str(overlay), f"{size_gb}G"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendUnavailable(f"cannot create overlay: {exc}") from exc
        if p.returncode != 0:
            raise BackendUnavailable(f"qemu-img create failed: "
                                     f"{(p.stderr or p.stdout)[:400]}")

    def _write_seed(self, desc: dict, image: ImageSpec, vmid: int,
                    hostname: str, address: str | None) -> None:
        net = self.manifest.network
        if address:
            addr = address
        else:
            offset = max(0, int(vmid) - self.policy.vmid_min)
            addr = str(net.range_cidr.network_address + 10 + offset)
        fmt = "ip=([0-9.]+)/(\\d+)"
        m = re.fullmatch(fmt, desc.get("ipconfig0") or "")
        prefix = int(m.group(2)) if m else net.range_cidr.prefixlen
        seed = pathlib.Path(desc["seed"])
        seed.parent.mkdir(parents=True, exist_ok=True)
        # The software fixture lives on QEMU's user network (10.0.2.0/24 with
        # the SLIRP gateway at 10.0.2.2).  Addressing is STATIC in every
        # mode: a golden image has no machine-id, and systemd-networkd's DHCP
        # client cannot be configured without one.
        if self.cfg.fixture_mode:
            addr, prefix, gateway = FIXTURE_ADDRESS, 24, FIXTURE_GATEWAY
        else:
            gateway = None
        build_seed(seed, SeedInputs(
            manifest=self.manifest, image=image, vmid=vmid,
            session_id=str(desc.get("session_id") or ""), hostname=hostname,
            address=addr, prefix=prefix, gateway=gateway))

    def set_config(self, node: str, vmid: int, **cfg) -> None:
        self._require_node(node)
        dom, desc = self._find(int(vmid), node)
        if dom is None or desc is None:
            raise BackendUnavailable(f"VMID {vmid} has no appliance domain")
        changed = False
        for key in ("name", "net0", "ipconfig0", "tags"):
            if key in cfg and cfg[key] is not None:
                desc[key] = str(cfg[key])
                changed = True
        image = self._image(int(desc["template_id"]))
        if "ipconfig0" in cfg:
            m = re.fullmatch(r"ip=([0-9.]+)/(\d+)", str(cfg["ipconfig0"]))
            if not m:
                raise BackendUnavailable("ipconfig0 must be ip=<addr>/<prefix>")
            self._write_seed(desc, image, int(vmid), desc["name"], m.group(1))
        if changed:
            try:
                dom.setMetadata(0, _desc_json(desc), None, None, 0)
            except Exception:
                # Older bindings/metadata namespaces: redefine the domain
                # with the same identity and updated description.
                xml = self._domain_xml(desc, image)
                try:
                    self.connect().defineXML(xml)
                except Exception as exc:  # noqa: BLE001
                    raise BackendUnavailable(
                        f"cannot update config for VMID {vmid}: {exc}") from exc
        # read-back metadata (name and NIC are policy-relevant)
        dom2, got = self._find(int(vmid), node)
        if dom2 is None or (got or {}).get("name") != desc["name"]:
            raise BackendReadBackFailed(
                f"config read-back for VMID {vmid} lost its identity")

    def start_and_wait(self, node: str, vmid: int, timeout: int = 90) -> None:
        self._require_node(node)
        dom, _ = self._find(int(vmid), node)
        if dom is None:
            raise BackendUnavailable(f"VMID {vmid} has no appliance domain")
        if not dom.isActive():
            self._prepare_qemu_storage(int(vmid))
            try:
                dom.create()
            except Exception as exc:  # noqa: BLE001
                raise BackendUnavailable(f"cannot start VMID {vmid}: {exc}") from exc
        deadline = time.monotonic() + max(1, int(timeout))
        while time.monotonic() < deadline:
            try:
                if dom.isActive():
                    return
            except Exception as exc:  # noqa: BLE001
                raise BackendUnavailable(f"start read-back failed: {exc}") from exc
            time.sleep(0.2)
        raise BackendReadBackFailed(f"VMID {vmid} did not reach running in {timeout}s")

    def _prepare_qemu_storage(self, vmid: int) -> None:
        """Grant the Ubuntu system QEMU identity only its fixed guest files.

        The broker remains unprivileged and owns these paths. Its restrictive
        umask must not prevent libvirt's separate QEMU UID from traversing the
        storage parents. No controller directories are readable/listable, no
        directory write access is granted, and the seed is read-only.
        Session libvirt runs QEMU as the caller and needs no cross-UID ACL.
        """
        if self.cfg.uri != "qemu:///system":
            return
        state = pathlib.Path(self.manifest.state_dir)
        guest = state / "guests" / str(int(vmid))
        parents = (state, state / "guests", guest)
        disk, seed, serial = (guest / name for name in
                              ("disk.qcow2", "seed.iso", "serial.log"))
        try:
            uid = pwd.getpwnam("libvirt-qemu").pw_uid
            for path in (*parents, disk, seed, serial):
                if path.is_symlink():
                    raise ValueError(f"symlink refused in QEMU storage: {path}")
            if not all(path.is_dir() for path in parents):
                raise ValueError("QEMU storage parent is not a directory")
            if not disk.is_file() or not seed.is_file():
                raise ValueError("QEMU disk or seed is missing or not a file")
            if serial.exists() and not serial.is_file():
                raise ValueError("QEMU serial log is not a file")
            # QEMU can write the log but cannot create/replace directory entries.
            serial.touch(mode=0o600, exist_ok=True)
            grants = (("--x", parents), ("rw-", (disk, serial)),
                      ("r--", (seed,)))
            for permissions, paths in grants:
                result = subprocess.run(
                    ["setfacl", "-m", f"u:{uid}:{permissions}",
                     *(str(path) for path in paths)],
                    capture_output=True, text=True, timeout=10)
                if result.returncode:
                    raise RuntimeError(result.stderr.strip()[:400])
        except (OSError, KeyError, ValueError, RuntimeError,
                subprocess.TimeoutExpired) as exc:
            raise BackendUnavailable(
                f"cannot prepare QEMU storage for VMID {vmid}: {exc}") from exc

    def stop(self, node: str, vmid: int, force: bool = False) -> str:
        self._require_node(node)
        dom, _ = self._find(int(vmid), node)
        if dom is None:
            return "already-absent"
        try:
            if dom.isActive():
                dom.destroy()
                return "destroyed"
            return "already-stopped"
        except Exception as exc:  # noqa: BLE001
            raise BackendUnavailable(f"cannot stop VMID {vmid}: {exc}") from exc

    def wait_for_task(self, node: str, token, timeout: int = 60) -> None:
        # libvirt destroy/create are synchronous; stop_and_confirm reads back.
        return None

    def destroy_and_wait(self, node: str, vmid: int,
                         force_stop_timeout: int = 60) -> str:
        self._require_node(node)
        dom, desc = self._find(int(vmid), node)
        outcome = "already-absent"
        if dom is not None:
            try:
                if dom.isActive():
                    dom.destroy()
                flags = 0
                if hasattr(self._libvirt(), "VIR_DOMAIN_UNDEFINE_NVRAM"):
                    flags |= self._libvirt().VIR_DOMAIN_UNDEFINE_NVRAM
                dom.undefineFlags(flags)
                outcome = "destroyed"
            except Exception as exc:  # noqa: BLE001
                raise BackendUnavailable(f"cannot destroy VMID {vmid}: {exc}") from exc
        # Remove only this VMID's run-owned directory, and only after the
        # domain is confirmed gone. Never touch the image cache.
        dom2, _ = self._find(int(vmid), node)
        if dom2 is not None:
            raise BackendReadBackFailed(f"VMID {vmid} still defined after destroy")
        guest_dir = self._guest_dir(int(vmid))
        try:
            if guest_dir.exists():
                shutil.rmtree(guest_dir)
        except OSError as exc:
            raise BackendReadBackFailed(
                f"VMID {vmid} domain gone but files at {guest_dir} could not be "
                f"removed: {exc}") from exc
        return outcome

    # ------------------------------------------------------------- host key ---
    def _qga(self, dom, command: str, timeout_s: float = 10.0) -> str:
        try:
            import libvirt_qemu  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise BackendUnavailable("libvirt_qemu bindings unavailable") from exc
        try:
            return libvirt_qemu.qemuAgentCommand(
                dom, command, int(max(1, timeout_s)), 0)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            transient = ("agent is not running", "Guest agent is not running",
                         "not running", "not connected", "not responding",
                         "timed out", "timeout", "unable to")
            if any(s.lower() in msg.lower() for s in transient):
                return ""
            raise BackendUnavailable(f"guest agent read failed: {msg}") from exc

    def _qga_read(self, dom, path: str, timeout_s: float = 10.0) -> str | None:
        """Read one fixed path through the guest agent.

        Two protocol details matter and are easy to get wrong: the handle
        returned by ``guest-file-open`` IS the ``return`` value (an integer,
        not an object with a "handle" key), and the read payload is named
        ``buf-b64`` by current agents (``buf`` by older ones).
        """
        opened = self._qga(dom, json.dumps({
            "execute": "guest-file-open",
            "arguments": {"path": path, "mode": "r"}}), timeout_s)
        if not opened:
            return None
        try:
            obj = json.loads(opened)
        except json.JSONDecodeError:
            return None
        handle = obj.get("return") if isinstance(obj, dict) else None
        if not isinstance(handle, int):
            return None
        chunks = []
        try:
            for _ in range(8):
                raw = self._qga(dom, json.dumps({
                    "execute": "guest-file-read",
                    "arguments": {"handle": handle, "count": 4096}}), timeout_s)
                if not raw:
                    return None
                obj = json.loads(raw)
                ret = obj.get("return")
                if not isinstance(ret, dict):
                    return None
                buf = ret.get("buf-b64") or ret.get("buf") or ""
                try:
                    chunk = base64.b64decode(buf, validate=False).decode(
                        "utf-8", "replace")
                except Exception:
                    return None
                chunks.append(chunk)
                if ret.get("eof") or len(chunks) >= 8:
                    break
        finally:
            try:
                self._qga(dom, json.dumps({
                    "execute": "guest-file-close",
                    "arguments": {"handle": handle}}), timeout_s)
            except Exception:  # noqa: BLE001
                pass
        return "".join(chunks)

    def read_boot_marker(self, node: str, vmid: int, timeout_s: float = 120,
                         poll_s: float = 2.0) -> bool:
        self._require_node(node)
        dom, _ = self._find(int(vmid), node)
        if dom is None:
            raise BackendUnavailable(f"VMID {vmid} is absent while waiting for first boot")
        deadline = time.monotonic() + max(0.0, float(timeout_s))
        while True:
            try:
                text = self._qga_read(dom, FIRST_BOOT_MARKER,
                                      timeout_s=min(10.0, timeout_s or 10.0))
            except BackendUnavailable:
                raise
            if text is not None and text.strip():
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(max(0.1, min(float(poll_s), deadline - time.monotonic())))

    def read_guest_file_when_ready(self, node: str, vmid: int, path: str,
                                   timeout_s: float = 120,
                                   poll_s: float = 2.0) -> str | None:
        if path != GUEST_HOST_KEY_PATH:
            raise BackendUnavailable("only the fixed host-key path is readable")
        self._require_node(node)
        dom, _ = self._find(int(vmid), node)
        if dom is None:
            raise BackendUnavailable(f"VMID {vmid} is absent while reading host key")
        deadline = time.monotonic() + max(0.0, float(timeout_s))
        while True:
            try:
                text = self._qga_read(dom, path, timeout_s=min(10.0, timeout_s or 10.0))
            except BackendUnavailable:
                raise
            if text:
                line = text.strip().splitlines()[0].strip()
                if line:
                    return line
            if time.monotonic() >= deadline:
                return None
            time.sleep(max(0.1, min(float(poll_s), deadline - time.monotonic())))

    # ------------------------------------------------------------------ XML ---
    def _domain_xml(self, desc: dict, image: ImageSpec) -> str:
        dtype = self._domain_type()
        memory = int(image.memory_mb)
        vcpus = int(image.vcpus)
        bridge = self.policy.bridge
        if self.cfg.fixture_mode:
            iface = ('      <interface type="user">\n'
                     '        <model type="virtio"/>\n'
                     f'        <mac address="{_mac(desc["node"] + ":" + str(desc["vmid"]))}"/>\n'
                     '      </interface>')
        else:
            iface = ('      <interface type="bridge">\n'
                     f'        <source bridge="{escape(bridge)}"/>\n'
                     '        <model type="virtio"/>\n'
                     f'        <mac address="{_mac(desc["node"] + ":" + str(desc["vmid"]))}"/>\n'
                     '      </interface>')
        cpu = ("  <cpu mode=\"host-passthrough\" check=\"none\"/>\n"
               if dtype == "kvm" else "")
        return f"""<domain type="{dtype}">
  <name>{escape(desc["name"])}</name>
  <description>{escape(_desc_json(desc))}</description>
  <memory unit="MiB">{memory}</memory>
  <vcpu placement="static">{vcpus}</vcpu>
  <os>
    <type arch="x86_64" machine="q35">hvm</type>
    <boot dev="hd"/>
  </os>
  <features><acpi/><apic/></features>
{cpu}  <clock offset="utc"/>
  <devices>
    <disk type="file" device="disk">
      <driver name="qemu" type="qcow2" cache="none" discard="unmap"/>
      <source file="{escape(desc["overlay"])}"/>
      <target dev="vda" bus="virtio"/>
    </disk>
    <disk type="file" device="cdrom">
      <source file="{escape(desc["seed"])}"/>
      <target dev="sda" bus="sata"/>
      <readonly/>
    </disk>
{iface}
    <serial type="file">
      <source path="{escape(desc["serial"])}"/>
      <target port="0"/>
    </serial>
    <channel type="unix">
      <target type="virtio" name="org.qemu.guest_agent.0"/>
    </channel>
    <console type="pty"/>
  </devices>
</domain>
"""

    def _require_node(self, node: str) -> None:
        self.policy.check_node(node)
