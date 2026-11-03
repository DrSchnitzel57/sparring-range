"""Underpressure Linux golden builds from pinned cloud bases.

The environment lane needs one approved artifact per role profile; the
commissioning base-seeded copies are honest placeholders, not role images.
This builder turns a PINNED cloud base into a profile artifact:

  pinned base (URL + provider SHA)  ->  build boot (cloud-init over the
  NoCloud seed; package fetch ONLY on the SLIRP control path)  ->  qcow2
  overlay whose delta IS the built artifact, its capability inventory
  recorded from the GUEST's own serial evidence (never fabricated).

Scope so far: the Debian-family profiles. Ubuntu/Rocky (mail, ecomm,
desktop) and the router/firewall media follow the same contract later;
Splunk/Windows need their own installers (recorded, not guessed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import time
import sys

from infra.dev import qemu_guest
from infra.images import guest_seed
from infra.images.attacker_tools import ATTACKER_PROFILES

# Pinned provider media. SHA comes from the provider's own checksum file
# (recorded in the build result); a mismatch fails closed BEFORE any boot.
PINS: dict[str, dict] = {
    "debian12": {
        "url": "https://cloud.debian.org/images/cloud/bookworm/latest/"
               "debian-12-genericcloud-amd64.qcow2",
        "sha512": "0464b5d4ae3aa4f658468d88da83af7857b71548b30d46dcb6282"
                  "770955a747fb95a983476db90d25afd0653af607224c7ebd05122ab71"
                  "faa106fd712aaad652",
        "source_checksum_file": "https://cloud.debian.org/images/cloud/"
                                "bookworm/latest/SHA512SUMS",
    },
    "rocky9": {
        "url": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/"
               "Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2",
        "sha256": "92c206cc6f790c61583247eefe87890f8828420662c17cacf"
                  "247cec78ab4eec8",
        "source_checksum_file": "https://download.rockylinux.org/pub/rocky/"
                                "9/images/x86_64/Rocky-9-GenericCloud-Base."
                                "latest.x86_64.qcow2.CHECKSUM",
    },
    "jammy": {
        "url": "https://cloud-images.ubuntu.com/jammy/current/"
               "jammy-server-cloudimg-amd64.img",
        "sha256": "58be26aa7452f3005a4f7370a43928bfb33a7f35a77a8f3b264"
                  "bf00266a17ca0",
        "source_checksum_file": "https://cloud-images.ubuntu.com/jammy/"
                                "current/SHA256SUMS",
    },
}

#: Which pinned provider image each profile builds FROM.
PROFILE_MEDIA: dict[str, str] = {
    "attacker-debian": "debian12",
    "scoring-debian": "debian12",
    "rocky9-ecomm": "rocky9",
    "ubuntu2204-mail": "jammy",
}

#: Distro family per media key: decides the package manager + version probe.
DISTROS: dict[str, str] = {"debian12": "apt", "jammy": "apt",
                          "rocky9": "dnf"}

#: ROLE READINESS: services the role must have RUNNING in the artifact. A
#: missing service is recorded as a gap, never hidden behind an exit code.
ROLE_SERVICES: dict[str, list[str]] = {
    "rocky9-ecomm": ["httpd", "php-fpm"],
    "ubuntu2204-mail": ["postfix", "dovecot"],
}

#: The binary capability contract per profile comes from attacker_tools so
#: the image and the preflight can never disagree. apt package names are
#: the Debian-family truth; anything not packaged is installed by pip or
#: reported as an honest capability gap.
APT_PACKAGES: dict[str, list[str]] = {
    "attacker-debian": [
        "nmap", "openssh-server", "curl", "wget", "openssl",
        "smbclient", "ldap-utils", "krb5-user", "python3", "python3-pip",
        "python3-pymssql", "ruby", "git", "auditd", "qemu-guest-agent",
        "dnsrecon", "ruby-net-ldap",
    ],
    "rocky9-ecomm": ["httpd", "php", "php-fpm", "mod_ssl",
                     "openssh-server", "qemu-guest-agent", "auditd",
                     "policycoreutils", "firewalld"],
    "ubuntu2204-mail": ["postfix", "dovecot-core", "dovecot-imapd",
                        "dovecot-pop3d", "openssh-server",
                        "qemu-guest-agent", "auditd", "ufw"],
    "scoring-debian": [
        "curl", "wget", "openssl", "python3", "python3-pip",
        "ldap-utils", "krb5-user", "python3-pymssql", "qemu-guest-agent",
        "auditd", "dnsutils", "ca-certificates",
    ],
}

#: The scoring vantage is not an ATTACKER_PROFILES entry (it never attacks);
#: its checks are spelled out here so a successful build is never vacuous.
SCORING_BINARIES = ("curl", "wget", "openssl", "python3", "ldapsearch",
                    "kinit", "klist", "dig", "ssh")

#: pip packages that are not apt-packaged (build-phase fetch). Versions are
#: RECORDED from the guest (pip show), never assumed pinned to 'latest'.
PIP_PACKAGES: dict[str, list[str]] = {
    "attacker-debian": ["impacket", "netexec"],
    "scoring-debian": [],
}


def verify_pinned(path: pathlib.Path, pin: dict) -> str:
    """Fail closed when the base bytes are not the provider's bytes."""
    algo = "sha512" if "sha512" in pin else "sha256"
    h = hashlib.new(algo)
    with pathlib.Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = h.hexdigest()
    want = pin[algo].lower()
    if got != want:
        raise RuntimeError(
            f"base image {path} {algo} {got} != pinned {want} "
            f"({pin.get('source_checksum_file', pin['url'])})")
    return f"{algo}:{got}"


def enable_cloud_init(disk: pathlib.Path) -> None:
    """Persist cloud-init's enablement INSIDE the image before first boot.

    Live find 2026-11-03: the Debian 12 genericcloud image ships the
    cloud-init units under cloud-init.target, but nothing pulls the TARGET
    in (systemd's cloud-init generator decided no datasource at first
    boot). The first real build booted to a bare login prompt with ZERO
    cloud-init, no seed consumed, no markers. Enabling the target at
    multi-user.level fixes it permanently; an already-enabled image is
    unchanged (ln -sf). Needs root (qemu-nbd/mount) — the builder runs as
    root on the appliance.
    """
    dev, base = "/dev/nbd0", pathlib.Path("/mnt/sr-build-root")
    subprocess.run(["modprobe", "nbd"], check=False)
    subprocess.run(["qemu-nbd", "-c", dev, str(disk)], check=True, timeout=120)
    try:
        time.sleep(2)
        base.mkdir(parents=True, exist_ok=True)
        mounted = False
        for part in sorted(pathlib.Path("/sys/class/block").glob("nbd0p*")):
            if subprocess.run(["mount", "-t", "ext4", f"/dev/{part.name}",
                               str(base)], capture_output=True).returncode == 0:
                mounted = True
                break
        if not mounted:
            raise RuntimeError(f"{disk}: no mountable root partition")
        try:
            wants = base / "etc/systemd/system/multi-user.target.wants"
            wants.mkdir(parents=True, exist_ok=True)
            link = wants / "cloud-init.target"
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to("/lib/systemd/system/cloud-init.target")
            # Belt-and-braces: pin NoCloud to the seed device EXPLICITLY.
            # Debian 22.4.2 reported DataSourceNone even with SMBIOS
            # ds=nocloud and the target enabled (live finds 2026-11-03);
            # this config removes detection from the equation entirely.
            (base / "etc/cloud/cloud.cfg.d").mkdir(parents=True,
                                                   exist_ok=True)
            (base / "etc/cloud/cloud.cfg.d/99-sr-nocloud.cfg").write_text(
                "datasource_list: [ NoCloud ]\n")
        finally:
            subprocess.run(["umount", str(base)], check=False)
    finally:
        subprocess.run(["qemu-nbd", "-d", dev], check=False)


def render_userdata(*, profile: str, hostname: str,
                    pubkeys: list[str]) -> str:
    """Cloud-init build seed: install the profile's toolset, then REPORT
    the actual capability inventory from inside the guest. Markers go to
    the serial console; a missing binary is a recorded gap, never hidden."""
    if profile in ATTACKER_PROFILES:
        caps = ATTACKER_PROFILES[profile]
        binaries = sorted({b for bins in caps.values() for b in bins})
    else:
        caps = {}
        binaries = list(SCORING_BINARIES)
    pkgs = APT_PACKAGES.get(profile, [])
    pips = PIP_PACKAGES.get(profile, [])
    distro = DISTROS.get(PROFILE_MEDIA.get(profile, "debian12"), "apt")
    pip_set = set(PIP_PACKAGES.get(profile, []))
    library_checks = []
    for lib in sorted(pip_set):
        library_checks.append(
            f'python3 -c "import {lib}" 2>/dev/null && '
            f'echo "SR-GUEST-CAP-OK:{lib}-library" || '
            f'echo "SR-GUEST-CAP-MISSING:{lib}-library"')
    # impacket's wheel installs .py tools, NOT console scripts: the
    # impacket-<tool> binary checks above must stay honest MISSING even
    # after a successful install. The library probe is the real evidence.
    if distro == "apt":
        version_cmds = [
            f"dpkg-query -W -f='${{Package}}=${{Version}}\\n' {p} 2>/dev/null "
            f"| sed 's/^/SR-GUEST-PKG:/' || true" for p in pkgs]
    else:
        version_cmds = [
            f"rpm -q --queryformat 'SR-GUEST-PKG:%{{NAME}}=%{{VERSION}}\\n' "
            f"{p} 2>/dev/null || true" for p in pkgs]
    svc_checks = []
    for svc in ROLE_SERVICES.get(profile, []):
        svc_checks.append(
            f'if systemctl is-active --quiet {svc}; then '
            f'echo "SR-GUEST-SVC-OK:{svc}"; '
            f'else echo "SR-GUEST-SVC-MISSING:{svc}"; fi')
    version_cmds += [
        f"python3 -m pip show {p} 2>/dev/null | sed -n 's/^Version: /"
        f"SR-GUEST-PIP:{p}=/p' || true" for p in sorted(pip_set)]
    check_lines = []
    for b in binaries:
        check_lines.append(
            f'if command -v {b} >/dev/null 2>&1; then '
            f'echo "SR-GUEST-CAP-OK:{b}"; else '
            f'echo "SR-GUEST-CAP-MISSING:{b}"; fi')
    pip_cmds = [f"/usr/bin/python3 -m pip install --break-system-packages "
                f"--disable-pip-version-check {p}" for p in pips]
    script = "\n".join([
        "#!/bin/bash",
        "exec >/dev/ttyS0 2>&1",
        "echo SR-GUEST-BUILD-START",
        *pip_cmds,
        "apt-get -qq update || echo SR-GUEST-APT-UPDATE-FAIL",
        *check_lines,
        *svc_checks,
        *library_checks,
        *version_cmds,
        'echo "SR-GUEST-DONE rc=0"',
        "shutdown -h now",
    ])
    key_block = "\n".join(f"      - {k}" for k in pubkeys)
    return f"""#cloud-config
hostname: {hostname}
manage_etc_hosts: true
package_update: true
package_upgrade: false
packages:
{chr(10).join(f'  - {p}' for p in pkgs)}
users:
  - name: sr
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
{key_block}
write_files:
  - path: /usr/local/sbin/sr-build-finish.sh
    permissions: '0755'
    content: |
{chr(10).join('      ' + line for line in script.splitlines())}
runcmd:
  - [ bash, /usr/local/sbin/sr-build-finish.sh ]
poweroff: true
"""


def build_seed_disk(path: pathlib.Path, user_data: str, meta_data: str,
                    network_config: str | None = None) -> pathlib.Path:
    """Seed as an ext4 DISK labeled CIDATA (live find 2026-11-03).

    NoCloud's label scan runs in init-local ~10 s after boot — a CD-ROM
    device does not exist yet at that moment on this stack, so blkid found
    nothing and the seed was never consumed (DataSourceNone). An ext4 disk
    with LABEL=CIDATA is present immediately (virtio-blk), so the same
    module mounts and reads it with no timing race."""
    subprocess.run(["qemu-img", "create", "-f", "raw", str(path), "16M"],
                   check=True, timeout=60)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-L", "CIDATA", str(path)],
                   check=True, timeout=120)
    mnt = pathlib.Path("/mnt/sr-seed-build")
    mnt.mkdir(parents=True, exist_ok=True)
    subprocess.run(["mount", "-o", "loop", str(path), str(mnt)], check=True)
    try:
        (mnt / "user-data").write_text(user_data, encoding="utf-8")
        (mnt / "meta-data").write_text(meta_data, encoding="utf-8")
        if network_config is not None:
            (mnt / "network-config").write_text(network_config,
                                                encoding="utf-8")
    finally:
        subprocess.run(["umount", str(mnt)], check=False)
    return path


def _network_config() -> str:
    return """version: 2
ethernets:
  primary:
    match:
      name: en*
    dhcp4: true
    dhcp-identifier: mac
"""


def _root_partition(disk: pathlib.Path) -> str:
    """The mountable ext4 root partition name on DISK (via qemu-nbd)."""
    subprocess.run(["modprobe", "nbd"], check=False)
    subprocess.run(["qemu-nbd", "-c", "/dev/nbd0", str(disk)], check=True,
                   timeout=120)
    time.sleep(2)
    for part in sorted(pathlib.Path("/sys/class/block").glob("nbd0p*")):
        probe = subprocess.run(["blkid", "-o", "export", f"/dev/{part.name}"],
                               capture_output=True, text=True)
        if "TYPE=\"ext4\"" in probe.stdout:
            return part.name
        r = subprocess.run(["blkid", f"/dev/{part.name}"],
                           capture_output=True, text=True)
        if "ext4" in r.stdout:
            return part.name
    subprocess.run(["qemu-nbd", "-d", "/dev/nbd0"], check=False)
    raise RuntimeError(f"{disk}: no ext4 root partition found")


def _provision_script(profile: str) -> str:
    pkgs = " ".join(APT_PACKAGES.get(profile, []))
    pips = " ".join(PIP_PACKAGES.get(profile, []))
    caps = ATTACKER_PROFILES.get(profile)
    if caps is None:
        binaries = list(SCORING_BINARIES)
    else:
        binaries = sorted({b for bins in caps.values() for b in bins})
    checks = "".join(
        f'command -v {b} >/dev/null 2>&1 && echo "SR-GUEST-CAP-OK:{b}" '
        f'|| echo "SR-GUEST-CAP-MISSING:{b}"\n' for b in binaries)
    svcs = "".join(
        f'systemctl is-active --quiet {s} && echo "SR-GUEST-SVC-OK:{s}" '
        f'|| echo "SR-GUEST-SVC-MISSING:{s}"\n' for s in ROLE_SERVICES.get(profile, []))
    pip_cmd = (f"pip3 install --break-system-packages -q {pips} "
               f"|| echo SR-GUEST-PIP-FAIL\n") if pips else ""
    return f"""
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
apt-get update -qq
apt-get -y -qq install {pkgs}
{pip_cmd}useradd -m -s /bin/bash sr 2>/dev/null || true
mkdir -p /home/sr/.ssh
chmod 700 /home/sr/.ssh
SRPUBKEY
chown -R sr:sr /home/sr/.ssh
echo 'sr ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sr
chmod 0440 /etc/sudoers.d/sr
systemctl enable ssh qemu-guest-agent auditd >/dev/null 2>&1 || true
# verify-boot reporter (no seed needed): markers on ttyS0, then poweroff
cat > /usr/local/sbin/sr-verify.sh <<'EOS'
#!/bin/bash
exec >/dev/ttyS0 2>&1
echo SR-GUEST-BOOT
{checks}{svcs}dpkg-query -W -f='SR-GUEST-PKG:%{{Package}}=%{{Version}}\n' {pkgs} 2>/dev/null || true
echo "SR-GUEST-DONE rc=0"
systemctl poweroff
EOS
chmod 0755 /usr/local/sbin/sr-verify.sh
cat > /etc/systemd/system/sr-verify.service <<'EOS'
[Unit]
Description=sparring-range build verification marker boot
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sr-verify.sh
[Install]
WantedBy=multi-user.target
EOS
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/sr-verify.service /etc/systemd/system/multi-user.target.wants/sr-verify.service
"""


def provision_chroot(disk: pathlib.Path, *, profile: str,
                     pubkey: pathlib.Path) -> dict:
    """Deterministic offline provisioning: chroot into the fresh overlay and
    install the role with the HOST's network — no cloud-init, no seed, no
    device-detection race (live finds 2026-11-03: NoCloud missed the seed
    at init-local twice: generator disabled, then blkid vs virtio timing).

    Services, ssh key, sudo and a verify-boot reporter are baked in; the
    artifact is then proven by ONE marker boot with no seed attached."""
    dev = "/dev/nbd0"
    part = _root_partition(disk)          # attached by _root_partition
    root = pathlib.Path("/mnt/sr-chroot")
    root.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["mount", "-t", "ext4", f"/dev/{part}", str(root)],
                       check=True, timeout=120)
        try:
            for fs in ("proc", "sys", "dev", "run"):
                (root / fs).mkdir(parents=True, exist_ok=True)
                subprocess.run(["mount", "--bind", f"/{fs}", str(root / fs)],
                               check=False)
            keys = [ln.strip() for ln in pathlib.Path(pubkey).read_text(
                errors="replace").splitlines() if ln.strip()]
            script = _provision_script(profile).replace(
                "SRPUBKEY",
                "\n".join(f"echo '{k}' >> /home/sr/.ssh/authorized_keys"
                           for k in keys))
            subprocess.run(["cp", "/etc/resolv.conf",
                            str(root / "etc/resolv.conf")], check=False)
            subprocess.run(["chroot", str(root), "/bin/bash", "-c", script],
                           check=True, timeout=3600)
            versions = subprocess.run(
                ["chroot", str(root), "dpkg-query", "-W",
                 "-f=${Package}=${Version}\n"] +
                list(APT_PACKAGES.get(profile, [])),
                capture_output=True, text=True)
        finally:
            for fs in ("run", "dev", "sys", "proc"):
                subprocess.run(["umount", str(root / fs)], check=False)
            subprocess.run(["umount", str(root)], check=False)
    finally:
        subprocess.run(["qemu-nbd", "-d", dev], check=False)
    return {"versions": {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in versions.stdout.splitlines() if "=" in line}}


def verify_boot(disk: pathlib.Path, *, profile: str,
                timeout_s: int = 600) -> dict:
    """ONE marker boot with NO seed: proves the provisioned artifact runs,
    reports the same capability inventory, and powers itself off."""
    boot = qemu_guest.boot_full_guest(
        disk=disk, seed_iso=None, memory_mb=2048, smp=2, net="none",
        timeout_s=timeout_s, expect=("SR-GUEST-DONE rc=0",))
    serial = disk.parent / f"{disk.stem}.serial.log"
    observed = serial.read_text(errors="replace").replace("\r", "")
    caps: dict[str, str] = {}
    packages: dict[str, str] = {}
    for line in observed.splitlines():
        if line.startswith("SR-GUEST-CAP-OK:"):
            caps[line.split(":", 1)[1]] = "ok"
        elif line.startswith("SR-GUEST-CAP-MISSING:"):
            caps[line.split(":", 1)[1]] = "missing"
        elif line.startswith("SR-GUEST-SVC-OK:"):
            caps[line.split(":", 1)[1]] = "running"
        elif line.startswith("SR-GUEST-SVC-MISSING:"):
            caps[line.split(":", 1)[1]] = "service-missing"
        elif line.startswith("SR-GUEST-PKG:"):
            key, _, ver = line.split(":", 1)[1].partition("=")
            packages[key] = ver
    return {"boot": boot, "capabilities": caps,
            "packages": packages,
            "missing": sorted(b for b, s in caps.items() if s != "ok")}


def build_profile(*, profile: str, base: pathlib.Path, pubkey: pathlib.Path,
                  run_dir: pathlib.Path, disk_gb: int = 16,
                  memory_mb: int = 2048, smp: int = 2,
                  timeout_s: int = 3600, pin: str | None = None) -> dict:
    """Build one profile artifact. Returns the overlay path, the pinned-base
    evidence and the GUEST-REPORTED capability inventory."""
    if profile not in APT_PACKAGES:
        raise RuntimeError(f"no apt package set for profile {profile!r}")
    base = pathlib.Path(base)
    if not base.is_file():
        raise RuntimeError(f"base image {base} does not exist")
    pin_spec = PINS[pin or PROFILE_MEDIA.get(profile, "debian12")]
    if pin_spec is None:
        raise RuntimeError(f"no pinned media for profile {profile!r}")
    pin_evidence = verify_pinned(base, pin_spec)
    pubkeys = [line.strip() for line in pathlib.Path(pubkey).read_text(
        encoding="utf-8", errors="replace").splitlines() if line.strip()]
    if not pubkeys:
        raise RuntimeError(f"pubkey file {pubkey} is empty")
    run_dir.mkdir(parents=True, exist_ok=True)
    disk = qemu_guest.fresh_role_overlay(base, run_dir, profile, disk_gb)
    provisioned = provision_chroot(disk, profile=profile, pubkey=pubkey)
    verified = verify_boot(disk, profile=profile, timeout_s=timeout_s)
    return {"profile": profile, "artifact": str(disk),
            "base": str(base), "base_pin": pin_evidence,
            "capabilities": verified["capabilities"],
            "missing": verified["missing"],
            "packages": verified["packages"] or provisioned["versions"],
            "boot": verified["boot"], "serial":
                str(run_dir / f"{profile}.serial.log")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="underpressure_build")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--base", required=True, type=pathlib.Path)
    ap.add_argument("--pubkey", required=True, type=pathlib.Path)
    ap.add_argument("--run-dir", required=True, type=pathlib.Path)
    ap.add_argument("--disk-gb", type=int, default=16)
    ap.add_argument("--memory-mb", type=int, default=2048)
    ap.add_argument("--smp", type=int, default=2)
    ap.add_argument("--pin", default=None,
                    help="pinned base key (default: the profile's media)")
    ap.add_argument("--timeout-s", type=int, default=3600)
    ap.add_argument("--out", type=pathlib.Path,
                    help="copy the finished overlay here (else in run-dir)")
    args = ap.parse_args(argv)
    try:
        out = build_profile(profile=args.profile, base=args.base,
                            pubkey=args.pubkey, run_dir=args.run_dir,
                            disk_gb=args.disk_gb, memory_mb=args.memory_mb,
                            smp=args.smp, pin=args.pin,
                            timeout_s=args.timeout_s)
    except RuntimeError as exc:
        print(f"underpressure-build: {exc}", file=sys.stderr)
        return 2
    if args.out:
        # a copied overlay's backing file lives in the run dir — convert to
        # a self-contained artifact so the image never dangles
        subprocess.run(["qemu-img", "convert", "-O", "qcow2",
                        out["artifact"], str(args.out)], check=True,
                       timeout=1800)
        out["artifact"] = str(args.out)
        out["backing_inlined"] = True
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
