"""Install SSH public keys into a golden image under the OWNER'S uid.

Live find 2026-11-04 (cost the bastion gate): a maintenance injection wrote
`/home/sr/.ssh/authorized_keys` and `chown 1000:1000` it. Cloud bases give
`ubuntu` uid 1000, while the appliance account `sr` is 1001, so sshd
StrictModes refused the file for EVERY key — the bastion client key and the
runner key alike — and no guest was reachable even though the file looked
perfect. Ownership is a fact of the IMAGE, so it is read from that image's
own `/etc/passwd`; a hardcoded uid is a bug waiting for the next base.

The mount is the only privileged part; everything that decides the RESULT
(uid/gid lookup, key merging, modes) is a pure function testable without
root.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import time

HOME = pathlib.Path("home/sr")
AUTHORIZED = HOME / ".ssh" / "authorized_keys"


def passwd_ids(passwd_text: str, user: str = "sr") -> tuple[int, int]:
    """The (uid, gid) of USER from an /etc/passwd body. Missing is an error,
    never a default — the wrong uid is exactly what broke the gate."""
    for line in passwd_text.splitlines():
        fields = line.split(":")
        if len(fields) >= 4 and fields[0] == user:
            return int(fields[2]), int(fields[3])
    raise KeyError(f"no {user!r} account in /etc/passwd: the image may not "
                   f"have been provisioned for this appliance")


def merge_keys(existing: str, keys: list[str]) -> str:
    """EXISTING authorized_keys + any key not already present, in order.

    Line-compared, so re-running is idempotent and a key that is already
    there is never duplicated or reordered; trailing blank lines collapse
    to exactly one final newline."""
    present = {line.strip() for line in existing.splitlines() if line.strip()}
    out = [line.rstrip() for line in existing.splitlines() if line.strip()]
    for key in keys:
        k = key.strip()
        if k and k not in present:
            out.append(k)
            present.add(k)
    return "\n".join(out) + "\n" if out else ""


def install_keys(root: pathlib.Path, pubkeys: list[str], *,
                 user: str = "sr", chown=lambda p, u, g: None) -> dict:
    """Write the keys into a MOUNTED guest root at ROOT.

    `chown` is injected so the ownership rule is testable without root; the
    live path passes os.chown. Modes follow sshd's StrictModes expectations:
    home 755 (it is 750 in some bases and sshd accepts either, but the file's
    owner is what matters), .ssh 700, authorized_keys 600.
    """
    root = pathlib.Path(root)
    passwd = root / "etc/passwd"
    uid, gid = passwd_ids(passwd.read_text(errors="replace"), user)
    home = root / HOME
    ssh_dir = root / HOME / ".ssh"
    for d in (home, ssh_dir):
        d.mkdir(parents=True, exist_ok=True)
        chown(d, uid, gid)
        d.chmod(0o700 if d is ssh_dir else 0o750)
    target = root / AUTHORIZED
    existing = target.read_text(errors="replace") if target.exists() else ""
    merged = merge_keys(existing, pubkeys)
    added = len([k for k in pubkeys
                 if k.strip() and k.strip() not in existing])
    target.write_text(merged)
    chown(target, uid, gid)
    target.chmod(0o600)
    return {"user": user, "uid": uid, "gid": gid, "added": added,
            "keys": len(merged.splitlines())}


def check_image_root(root: pathlib.Path, pubkeys: list[str], *,
                     user: str = "sr") -> dict:
    """Read-only audit of a mounted guest root: are the keys present and is
    the file owned by the USER (not by some other uid)?"""
    root = pathlib.Path(root)
    uid, gid = passwd_ids((root / "etc/passwd").read_text(errors="replace"), user)
    target = root / AUTHORIZED
    problems = []
    if not target.is_file():
        problems.append("authorized_keys missing")
        text = ""
    else:
        text = target.read_text(errors="replace")
        st = target.stat()
        if (st.st_uid, st.st_gid) != (uid, gid):
            problems.append(f"authorized_keys owned by {st.st_uid}:{st.st_gid}"
                            f", not {uid}:{gid} (sshd StrictModes rejects it)")
        if st.st_mode & 0o077:
            problems.append(f"authorized_keys mode {oct(st.st_mode & 0o777)}"
                            " is group/world readable")
    for key in pubkeys:
        if key.strip() and key.strip() not in text:
            problems.append(f"missing key {key.split()[0]}…")
    return {"ok": not problems, "uid": uid, "gid": gid, "problems": problems,
            "keys": len([line for line in text.splitlines() if line.strip()])}


# --------------------------------------------------------------- mount ------
_MOUNT = pathlib.Path("/mnt/sr-golden-keys")


def _mount_root(image: pathlib.Path, *, read_only: bool):
    """Attach IMAGE on /dev/nbd0 and mount its ext4 root. Returns a context
    manager; the caller must not reuse /dev/nbd0 concurrently."""
    import contextlib

    @contextlib.contextmanager
    def opened():
        dev = "/dev/nbd0"
        subprocess.run(["modprobe", "nbd", "max_part=16"], check=False)
        args = ["qemu-nbd", *(["-r"] if read_only else []), "-c", dev, str(image)]
        subprocess.run(args, check=True, timeout=120)
        try:
            time.sleep(2)
            _MOUNT.mkdir(parents=True, exist_ok=True)
            mounted = False
            for part in sorted(pathlib.Path("/sys/class/block").glob("nbd0p*")):
                if subprocess.run(["/usr/bin/mount", "-t", "ext4",
                                   *(["-o", "ro"] if read_only else []),
                                   f"/dev/{part.name}", str(_MOUNT)],
                                  capture_output=True).returncode == 0:
                    mounted = True
                    break
            if not mounted:
                raise RuntimeError(f"{image}: no mountable ext4 root")
            try:
                yield _MOUNT
            finally:
                subprocess.run(["/usr/bin/umount", str(_MOUNT)], check=False)
        finally:
            subprocess.run(["qemu-nbd", "-d", dev], check=False)

    return opened()


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os

    ap = argparse.ArgumentParser(prog="golden-keys")
    ap.add_argument("image", nargs="+", help="golden qcow2 images")
    ap.add_argument("--key", action="append", default=[],
                    help="public key file (repeatable)")
    ap.add_argument("--user", default="sr")
    ap.add_argument("--check", action="store_true",
                    help="audit only (read-only mount), exit 1 on a problem")
    args = ap.parse_args(argv)
    keys = [pathlib.Path(k).read_text().strip() for k in args.key]
    if not keys:
        print("refusing: pass at least one --key", file=sys.stderr)
        return 2
    bad = 0
    for image in args.image:
        path = pathlib.Path(image)
        if not path.is_file():
            print(f"{path.name}: missing")
            continue
        with _mount_root(path, read_only=args.check) as root:
            if args.check:
                r = check_image_root(root, keys, user=args.user)
                flag = "OK" if r["ok"] else "PROBLEM"
                print(f"{path.name}: {flag} uid={r['uid']} keys={r['keys']} "
                      f"{'; '.join(r['problems'])}")
                bad += 0 if r["ok"] else 1
            else:
                r = install_keys(root, keys, user=args.user,
                                 chown=lambda p, u, g: os.chown(p, u, g))
                print(f"{path.name}: installed uid={r['uid']} "
                      f"added={r['added']} keys={r['keys']}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
