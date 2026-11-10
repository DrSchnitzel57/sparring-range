#!/usr/bin/env python3
"""Boot-gate a Windows golden image: OOBE done, agent alive, writable clone.

`ImageState` in `setupact.log` does NOT record OOBE completion (proven
2026-11-10: the rebuilt image reached the first-logon shell and shut down on
its own timer, yet the last logged transition was still
SPECIALIZE_RESEAL_TO_OOBE). The only honest check is the one the appliance
itself will do: boot a COPY of the image, wait for the guest agent, and ask
Windows directly whether OOBE is still in progress.

Runs one QEMU on a qcow2 overlay so the golden is never written, then:
  * guest-ping until the agent answers (the qemu-ga the build installed);
  * `HKLM\\SYSTEM\\Setup\\OOBEInProgress` must read 0x0;
  * `HKLM\\...\\Setup\\State\\ImageState` must read IMAGE_STATE_COMPLETE;
  * ACPI shutdown through the same command; the overlay is deleted.

Exit 0 = golden may be registered. 1 = golden is broken (evidence printed).
2 = the box was not clean (another QEMU was running).

Usage (appliance, root):
    .venv/bin/python -m infra.dev.verify_win_image \
        --image /var/lib/sparring-range/builds/win2022/sr-win2022.qcow2
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import socket
import subprocess
import sys
import time

STATE_KEY = ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State")
OOBE_KEY = "HKLM\\SYSTEM\\Setup"


class QgaExec:
    """guest-exec over a QEMU chardev socket (plain JSON, one per message).

    Dev-only: the production path is the broker's typed guest_exec against
    the SAME agent protocol, and this tool exists to prove the image the
    broker will boot."""

    def __init__(self, path: str, timeout: float = 20.0):
        self.path = path
        self.timeout = timeout
        self._buf = b""
        self._sock: socket.socket | None = None

    def _ask(self, payload: dict) -> dict:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect(self.path)
        self._sock.sendall(json.dumps(payload).encode() + b"\n")
        while b"\n" not in self._buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise OSError("agent closed the channel")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        answer = json.loads(line.decode())
        if "error" in answer:
            raise RuntimeError(str(answer["error"])[:400])
        return answer

    def ping(self) -> None:
        self._ask({"execute": "guest-ping"})

    def run(self, exe: str, *args: str) -> tuple[int, str, str]:
        started = self._ask({"execute": "guest-exec",
                             "arguments": {"path": exe, "arg": list(args),
                                           "capture-output": True}})
        pid = started["return"]["pid"]
        deadline = time.time() + 120
        while time.time() < deadline:
            answer = self._ask({"execute": "guest-exec-status",
                                "arguments": {"pid": pid}})["return"]
            if answer.get("exited"):
                out = base64.b64decode(answer.get("out", "")).decode(
                    errors="replace")
                err = base64.b64decode(answer.get("err", "")).decode(
                    errors="replace")
                return int(answer.get("exitcode", -1)), out, err
            time.sleep(0.5)
        raise RuntimeError(f"guest-exec pid {pid} did not finish in 120s")


def _monitor(path: pathlib.Path, command: str) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(str(path))
        s.sendall(command.encode() + b"\n")
        time.sleep(0.2)
        try:
            s.recv(4096)
        except socket.timeout:
            pass


def verify(image: pathlib.Path, work: pathlib.Path) -> int:
    work.mkdir(parents=True, exist_ok=True)
    overlay = work / "verify-overlay.qcow2"
    monitor = work / "monitor.sock"
    agent = work / "qga.sock"
    serial = work / "serial.log"
    for stale in (overlay, monitor, agent):
        stale.unlink(missing_ok=True)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2",
                    "-b", str(image), "-F", "qcow2", str(overlay),
                    "64G"], check=True, timeout=120)
    cmd = [
        "qemu-system-x86_64", "-machine", "pc", "-accel", "kvm",
        "-cpu", "host,hv_relaxed=on,hv_spinlocks=0x1fff",
        "-m", "4096", "-smp", "2",
        # the SAME virtio disk the broker's domain XML hands the guest
        "-drive", f"file={overlay},format=qcow2,if=virtio",
        "-chardev", f"socket,id=qga,path={agent},server=on,wait=off",
        "-device", "virtio-serial-pci",
        "-device", "virtserialport,chardev=qga,name=org.qemu.guest_agent.0",
        "-monitor", f"unix:{monitor},server=on,wait=off",
        "-display", "none", "-vga", "std",
        "-serial", f"file:{serial}",
        "-nic", "none", "-name", "sr-golden-verify",
        "-rtc", "base=localtime",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    evidence: dict = {"image": str(image)}
    ok = False
    try:
        client = QgaExec(str(agent))
        deadline = time.time() + 420
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("qemu exited before the agent answered")
            try:
                client.ping()
                break
            except (OSError, RuntimeError, socket.timeout):
                time.sleep(3)
        else:
            raise RuntimeError("guest agent did not answer in 420s")
        code, out, _err = client.run(
            "C:\\Windows\\system32\\reg.exe", "query", OOBE_KEY,
            "/v", "OOBEInProgress")
        evidence["oobe_in_progress"] = out.strip() or f"exit {code}"
        oobe_done = "0x0" in out and code == 0
        code, out, _err = client.run(
            "C:\\Windows\\system32\\reg.exe", "query", STATE_KEY,
            "/v", "ImageState")
        evidence["image_state"] = out.strip() or f"exit {code}"
        state_done = "IMAGE_STATE_COMPLETE" in out
        code, out, _err = client.run(
            "C:\\Windows\\system32\\cmd.exe", "/c", "hostname")
        evidence["hostname"] = out.strip()
        ok = bool(oobe_done and state_done)
        try:
            client.run("C:\\Windows\\system32\\shutdown.exe", "/s", "/t", "0")
        except (OSError, RuntimeError):
            _monitor(monitor, "system_powerdown")
    except Exception as exc:  # noqa: BLE001 — every path is evidence
        evidence["error"] = f"{type(exc).__name__}: {exc}"[:400]
        _monitor(monitor, "system_powerdown")
    finally:
        try:
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=30)
        overlay.unlink(missing_ok=True)
        for leftover in (monitor, agent, serial):
            leftover.unlink(missing_ok=True)
    print(json.dumps({"ok": ok, "evidence": evidence}, indent=2,
                     sort_keys=True))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", type=pathlib.Path, required=True)
    ap.add_argument("--work-dir", type=pathlib.Path,
                    default=pathlib.Path("/var/lib/sparring-range/builds/golden-verify"))
    args = ap.parse_args()
    from infra.images.windows_build import qemu_alone_preflight
    try:
        qemu_alone_preflight(4096)
    except RuntimeError as exc:  # the preflight refuses a busy box
        print(f"preflight refused: {exc}", file=sys.stderr)
        return 2
    return verify(args.image, args.work_dir)


if __name__ == "__main__":
    sys.exit(main())
