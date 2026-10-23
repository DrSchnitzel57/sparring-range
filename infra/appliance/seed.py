"""Per-instance NoCloud seed for appliance guests.

The golden image contains software and NO deployment keys.  Every clone gets
a fresh ``instance-id``, its own hostname/address and only the public keys its
role needs (runner→attacker, bastion→defender, management→root).  The seed
also records the fixed first-boot completion marker the broker polls through
QEMU guest agent; a merely running VM is never treated as ready.

Only public keys and non-secret networking values are written here.  Private
keys remain with their consuming service.
"""

from __future__ import annotations

import pathlib
import uuid
from dataclasses import dataclass

import yaml

from .manifest import ApplianceManifest, ImageSpec
from infra.images.guest_seed import build_seed_iso, meta_data

_MARKER_PATH = "/var/lib/sparring-range/first-boot-complete"
_UNSHARE_APPARMOR = (pathlib.Path(__file__).resolve().parents[1]
                     / "runner/apparmor/usr.bin.unshare")


def _role_access(role: str) -> dict[str, tuple[str, ...]]:
    """Which manifest key role lands on which Unix account for a guest role.

    The attack identity gets only the runner public key. The separate guest
    root identity gets the management public key for deterministic provisioning
    and telemetry enrollment, on both attacker and defended guests. Neither
    private key enters a guest; bastion access is limited to defended guests.
    """
    if role == "attacker":
        return {"attacker": ("runner",), "root": ("mgmt",)}
    return {"defender": ("bastion",), "root": ("mgmt",)}


@dataclass(frozen=True)
class SeedInputs:
    manifest: ApplianceManifest
    image: ImageSpec
    vmid: int
    session_id: str
    hostname: str
    address: str
    prefix: int
    gateway: str | None = None       # fixture only; production is on-link
    instance_id: str | None = None
    fixture_http_port: int | None = None
    api_ingest_url: str | None = None


def _authorized_keys(manifest: ApplianceManifest, role: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for user, principals in _role_access(role).items():
        lines: list[str] = []
        for principal in principals:
            if principal in manifest.access_keys:
                key = manifest.public_key_for(principal).strip()
                if key and key not in lines:
                    lines.append(key)
        if lines:
            out[user] = lines
    return out


def render_network_config(inp: SeedInputs) -> str:
    """NoCloud network-config (netplan v2) applied in cloud-init's network stage.

    Keeping this separate from write_files/runcmd is what removes the
    first-boot ``systemd-networkd-wait-online`` stall: the interface is
    addressed before cloud-init's later stages.

    The configuration is STATIC.  A golden appliance image has no machine-id
    (every clone must generate its own), and systemd-networkd's DHCP client
    cannot even be configured without one — so a DHCP-based guest would come
    up with no address at all.  Static addressing also matches the production
    range: an on-link address with no default route.
    """
    nic: dict = {"match": {"name": "en*"}, "dhcp4": False, "dhcp6": False,
                 "optional": True, "addresses": [f"{inp.address}/{inp.prefix}"]}
    if inp.gateway:
        # The isolated fixture network needs a route to its own gateway; the
        # production range deliberately has none.
        nic["routes"] = [{"to": "default", "via": inp.gateway}]
    return yaml.safe_dump({"version": 2, "ethernets": {"range-nic": nic}},
                          sort_keys=False)


def render_user_data(inp: SeedInputs) -> str:
    instance_id = inp.instance_id or f"sr-{inp.image.role}-{uuid.uuid4().hex[:12]}"
    keys = _authorized_keys(inp.manifest, inp.image.role)
    users = []
    for user, lines in sorted(keys.items()):
        entry = {"name": user, "shell": "/bin/bash",
                 "ssh_authorized_keys": lines}
        if user in ("defender", "attacker"):
            entry["groups"] = ["sudo"]
        users.append(entry)
    # cloud-init would otherwise create the default 'ubuntu' user with its
    # build-time key.  Listing users replaces the default set.
    users.append({"name": "srshipper", "system": True, "groups": ["adm"],
                  "shell": "/usr/sbin/nologin"})
    doc: dict = {
        "hostname": inp.hostname,
        "manage_etc_hosts": True,
        "disable_root": False,
        "ssh_pwauth": False,
        "package_update": False,
        "package_upgrade": False,
        "users": users,
        "write_files": [
            {"path": "/etc/sparring-range/role",
             "content": inp.image.role + "\n"},
            # A dedicated late unit makes readiness independent of whether a
            # long-running cloud-init runcmd (package/service work) finishes.
            # It is ordered after cloud-final, so users/keys/network are
            # already applied, and it writes the same fixed marker the broker
            # polls through QGA.
            {"path": "/usr/local/sbin/sr-first-boot-complete",
             "permissions": "0755",
             # Readiness means "a member can actually connect": the script
             # starts SSH and waits for the listener before the marker is
             # published.  SSH must not be started earlier: cloud-init
             # generates the host keys in the config stage, and sshd refuses
             # to start without them.
             "content": "#!/bin/sh\nset -eu\n"
                        "install -d -m 0755 /var/lib/sparring-range\n"
                        "systemctl start --no-block ssh.service "
                        ">/dev/null 2>&1 || true\n"
                        "i=0\n"
                        "while [ \"$i\" -lt 60 ]; do\n"
                        "  if command -v python3 >/dev/null 2>&1; then\n"
                        "    python3 -c 'import socket;"
                        "socket.create_connection((\"127.0.0.1\",22),1).close()'"
                        " >/dev/null 2>&1 && break\n"
                        "  else\n"
                        "    sleep 1\n"
                        "  fi\n"
                        "  i=$((i+1))\n"
                        "  sleep 1\n"
                        "done\n"
                        f"date -u +%FT%TZ > {_MARKER_PATH}\n"},
            {"path": "/etc/systemd/system/sr-first-boot-complete.service",
             "permissions": "0644",
             "content": "[Unit]\nDescription=sparring-range first boot completion\n"
                        "After=cloud-final.service\nWants=cloud-final.service\n"
                        "[Service]\nType=oneshot\n"
                        "ExecStart=/usr/local/sbin/sr-first-boot-complete\n"
                        "[Install]\nWantedBy=multi-user.target\n"},
            # The bastion and the management identities administer the guest;
            # the attack identity does NOT get a blanket sudo rule, so the
            # exercise keeps its own privilege boundaries.
            {"path": "/etc/sudoers.d/sr-management",
             "permissions": "0440",
             "content": "defender ALL=(ALL) NOPASSWD:ALL\n"
                        "root ALL=(ALL) NOPASSWD:ALL\n"},
        ],
        # qemu-guest-agent is installed in the golden image but was not
        # running when the image was built (no virtio channel existed then).
        # Start it WITHOUT blocking: `systemctl --now` waits for the guest
        # agent device, and a guest whose channel is not (yet) visible would
        # hang its whole cloud-init stage.  The unit is deliberately NOT
        # enabled: an enabled unit whose device never appears would block a
        # later boot at multi-user.target.  SSH is started as well — enabling
        # it alone would leave the guest reachable only after a reboot.
        "bootcmd": [
            "systemctl enable ssh.service 2>/dev/null || true",
            "systemctl start --no-block qemu-guest-agent.service "
            "2>/dev/null || true",
        ],
        "runcmd": [
            "install -d -m 0755 /var/lib/sparring-range",
            "systemctl start --no-block qemu-guest-agent.service "
            "2>/dev/null || true",
            "systemctl enable auditd.service 2>/dev/null || true",
            "systemctl enable sr-first-boot-complete.service "
            "2>/dev/null || true",
            # The marker is published last, and only once SSH is listening.
            "/usr/local/sbin/sr-first-boot-complete",
        ],
    }
    # ONE netplan file, ONE interface key ("range-nic"), always static.
    # The same key is used by the NoCloud network-config, so the two
    # descriptions merge instead of defining the same device twice, and
    # nothing in the golden image has to know anything about addressing.
    doc["write_files"].append({
        "path": "/etc/netplan/99-sr-range.yaml",
        "permissions": "0600",
        "content": yaml.safe_dump({
            "network": {"version": 2, "ethernets": {"range-nic": {
                "match": {"name": "en*"},
                "addresses": [f"{inp.address}/{inp.prefix}"],
                "routes": ([{"to": "default", "via": inp.gateway}]
                           if inp.gateway else []),
                "dhcp4": False, "dhcp6": False, "optional": True}}}},
            sort_keys=False),
    })
    doc["runcmd"].insert(0, "netplan apply || true")
    if inp.api_ingest_url:
        doc["write_files"].append({
            "path": "/etc/sparring-range/shipper.conf",
            "content": f"INGEST_URL={inp.api_ingest_url}\n"
                       f"HOST_TAG={inp.hostname}\n",
        })
    if inp.image.role == "attacker":
        # Seed the corrected scoped AppArmor profile and load it before the
        # readiness marker. The guest keeps kernel unprivileged-userns
        # restrictions enabled; a broken profile or namespace boundary withholds
        # readiness instead of allowing uncontained commands.
        doc["write_files"].append({
            "path": "/etc/apparmor.d/usr.bin.unshare",
            "permissions": "0644",
            "content": _UNSHARE_APPARMOR.read_text(),
        })
        doc["runcmd"] = [
            "apparmor_parser -r /etc/apparmor.d/usr.bin.unshare",
            "systemctl start sr-runner-cgroup.service 2>/dev/null || true",
            "su -s /bin/sh attacker -c 'unshare --user --map-root-user "
            "--mount --cgroup --pid --fork --mount-proc /bin/true'",
            *doc["runcmd"],
        ]
    if inp.fixture_http_port:
        # Fixture-only: make nginx listen on the port QEMU forwards. The
        # production image listens on 80 on the isolated bridge.
        doc["runcmd"].append(
            "sed -i 's/listen 80 default_server;/listen 80 default_server;/' "
            "/etc/nginx/sites-enabled/default 2>/dev/null || true")
    return "#cloud-config\n" + yaml.safe_dump(doc, sort_keys=False, width=4096)


def build_seed(path: pathlib.Path, inp: SeedInputs) -> pathlib.Path:
    instance_id = inp.instance_id or f"sr-{inp.image.role}-{uuid.uuid4().hex[:12]}"
    user_data = render_user_data(inp)
    meta = meta_data(instance_id, inp.hostname)
    return build_seed_iso(path, user_data, meta,
                          network_config=render_network_config(inp))


def marker_path() -> str:
    return _MARKER_PATH
