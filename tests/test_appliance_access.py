"""Real guest SSH + recording replay acceptance (access layer).

Boots an actual Ubuntu qcow2 with a NoCloud seed, forwards its SSH port through
QEMU user networking, authenticates as the guest's role user with a generated
key, then connects through the real recording bastion and proves the .cast file
contains the command output.  No host key is accepted by TOFU: the guest's key
is read from the live SSH handshake and pinned in a known_hosts file before the
bastion dials.

The base image, QEMU and (optionally) KVM are prerequisites.  In required mode
(`SR_REQUIRE_ACCESS=1`) absence is a FAILURE.  The guest is disposable and the
fixture clearly labels the software-emulation path.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import shutil
import socket
import subprocess
import time

import pytest

from infra.appliance.manifest import ApplianceManifest
from infra.appliance.seed import (SeedInputs, render_network_config,
                                 render_user_data)
from infra.dev import qemu_guest
from infra.images.guest_seed import build_seed_iso, meta_data
from tests.test_appliance_install import _manifest as install_manifest

pytestmark = pytest.mark.access


def _require(condition: bool, message: str) -> None:
    if condition:
        return
    if os.environ.get("SR_REQUIRE_ACCESS") == "1":
        pytest.fail(message)
    pytest.skip(message)


def _base_image() -> pathlib.Path:
    raw = os.environ.get("SR_APPLIANCE_BASE_IMAGE", "").strip()
    _require(bool(raw), "SR_APPLIANCE_BASE_IMAGE is required for the access gate")
    p = pathlib.Path(raw)
    _require(p.is_file(), f"SR_APPLIANCE_BASE_IMAGE is not a file: {p}")
    return p


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _guest_user_data(tmp_path: pathlib.Path, base: pathlib.Path) -> tuple[
        ApplianceManifest, pathlib.Path, pathlib.Path, pathlib.Path]:
    raw = install_manifest(tmp_path)
    # The real base replaces the synthetic image; the schema test keys remain
    # valid and are still required for a strict manifest.
    import hashlib
    h = hashlib.sha256()
    with base.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    raw["images"]["attacker"] = {
        "template_id": 9005, "path": str(base), "sha256": h.hexdigest(),
        "size_bytes": base.stat().st_size, "disk_gb": 8,
        "memory_mb": 1536, "vcpus": 2,
    }
    raw["budgets"].update({"max_memory_mb": 8192, "max_vcpus": 6,
                           "max_disk_gb": 44})
    m = ApplianceManifest.from_dict(raw, verify_images=True)
    image = m.image_for_role("attacker")
    seed_path = tmp_path / "access-seed.iso"
    inp = SeedInputs(
        manifest=m, image=image, vmid=230, session_id="access-gate",
        hostname="sr-access", address="10.0.2.15", prefix=24,
        fixture_dhcp=True, gateway=None)
    user_data = render_user_data(inp)
    network_config = render_network_config(inp)
    # A serial-visible marker lets the test distinguish "SSH answered" from a
    # stale boot; it is not accepted as a substitute for the SSH proof.
    import yaml
    doc = yaml.safe_load(user_data.removeprefix("#cloud-config\n"))
    doc["runcmd"].append("echo SR-GUEST-ACCESS-READY")
    user_data = "#cloud-config\n" + yaml.safe_dump(doc, sort_keys=False,
                                                    width=4096)
    build_seed_iso(seed_path, user_data,
                   meta_data(f"iid-access-{os.getpid()}", "sr-access"),
                   network_config=network_config)
    runner_key = tmp_path / "runner"
    member_key = tmp_path / "member"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                    "-f", str(member_key)], check=True, capture_output=True)
    return m, seed_path, runner_key, member_key


def _wait_marker(proc: subprocess.Popen, serial: pathlib.Path,
                 timeout_s: float = 900) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            text = serial.read_text(errors="replace")
        except OSError:
            text = ""
        if "SR-GUEST-ACCESS-READY" in text:
            return text
        if proc.poll() is not None:
            raise AssertionError(
                f"QEMU exited {proc.returncode} before the access marker; "
                f"serial tail={text[-1200:]!r}")
        time.sleep(2)
    raise AssertionError(
        f"no access marker within {timeout_s}s; serial tail="
        f"{serial.read_text(errors='replace')[-1200:]!r}")


async def _ssh_and_record(m: ApplianceManifest, port: int, runner_key: pathlib.Path,
                          member_key: pathlib.Path, recordings: pathlib.Path,
                          known_hosts: pathlib.Path):
    import asyncssh

    # Read the guest's key from the live handshake, then pin it explicitly.
    deadline = time.monotonic() + 600
    last = None
    known_key = None
    while time.monotonic() < deadline:
        try:
            async with asyncssh.connect(
                    "127.0.0.1", port, username="runner",
                    client_keys=[str(runner_key)], known_hosts=None,
                    connect_timeout=5, login_timeout=10) as conn:
                known_key = conn.get_server_host_key()
                result = await conn.run("cat /etc/sparring-range/role; id -u",
                                        check=False)
                assert result.exit_status == 0, result.stderr
                assert "attacker" in (result.stdout or ""), result.stdout
                break
        except Exception as exc:  # noqa: BLE001 — boot retry
            last = exc
            await asyncio.sleep(3)
    else:
        raise AssertionError(f"guest SSH never became usable: {last!r}")
    assert known_key is not None
    export = getattr(known_key, "export_public_key", None) or getattr(
        known_key, "render_public_key")
    pub = export().decode().strip()
    known_hosts.write_text(f"[127.0.0.1]:{port} {pub}\n")

    # The real bastion proxy: token auth, pinned target key, cast writer.
    from srplatform.bastion.proxy import BastionProxy
    from srplatform.settings import get_settings
    os.environ.update({
        "SR_ENV": "dev",
        "SR_BASTION_TARGET_USER": "runner",
        "SR_BASTION_CLIENT_KEY_PATH": str(runner_key),
        "SR_BASTION_TARGETS_KNOWN_HOSTS": str(known_hosts),
        "SR_RECORDINGS_DIR": str(recordings),
    })
    get_settings.cache_clear()
    events: list[dict] = []

    async def resolve(token: str):
        if token != "tok-access":
            return None
        return {"session_id": "access-session", "username": "member",
                "target_host": "127.0.0.1", "target_port": port,
                "target_host_key": ""}

    async def sink(event: dict):
        events.append(event)

    async def register(session_id: str, cast_path: str):
        return "rec-access"

    host_key = recordings / "bastion_host_key"
    proxy = BastionProxy(resolve, sink, register, recordings_dir=recordings,
                         host_key_path=host_key,
                         authorized_keys=lambda username, _key: username == "member")
    await proxy.start("127.0.0.1", 0)
    bastion_port = proxy._server.sockets[0].getsockname()[1]  # noqa: SLF001
    try:
        async with asyncssh.connect(
                "127.0.0.1", bastion_port, username="tok-access",
                client_keys=[str(member_key)], known_hosts=None,
                connect_timeout=10, login_timeout=15) as conn:
            result = await conn.run("cat /etc/sparring-range/role; id -u",
                                    check=False)
            assert result.exit_status == 0, result.stderr
            assert "attacker" in (result.stdout or ""), result.stdout
    finally:
        await proxy.stop()
        get_settings.cache_clear()

    casts = list(recordings.glob("*.cast"))
    assert len(casts) == 1, casts
    lines = casts[0].read_text().splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2
    assert header["session_id"] == "access-session"
    output = "".join(json.loads(line)[2] for line in lines[1:]
                     if json.loads(line)[1] == "o")
    assert "attacker" in output, output
    assert any(e["action_type"] == "bastion_session_start" for e in events)
    assert any(e["action_type"] == "command" for e in events)
    assert any(e["action_type"] == "bastion_session_end" for e in events)
    return {"cast": str(casts[0]), "events": len(events), "target_key": pub}


def test_real_guest_ssh_and_bastion_cast_replay(tmp_path):
    qemu = qemu_guest.qemu_binary()
    _require(qemu is not None, "QEMU (qemu-system-x86_64) is required for access")
    _require(shutil.which("ssh-keygen") is not None, "ssh-keygen is required")
    base = _base_image()
    m, seed, runner_key, member_key = _guest_user_data(tmp_path, base)
    run_dir = qemu_guest.make_run_dir()
    serial = run_dir / "access.serial.log"
    port = _free_port()
    use_kvm = os.environ.get("SR_ACCESS_KVM") == "1" and pathlib.Path(
        "/dev/kvm").exists()
    accel = ["-accel", "kvm"] if use_kvm else ["-accel", "tcg,thread=multi"]
    disk = qemu_guest.make_overlay(base, run_dir, "access")
    cmd = [qemu, "-M", "q35", "-m", "1536", "-smp", "2",
           "-drive", f"file={disk},format=qcow2,if=virtio",
           "-drive", f"file={seed},format=raw,media=cdrom,readonly=on",
           "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:22",
           "-device", "virtio-net-pci,netdev=n0",
           "-nographic", "-serial", f"file:{serial}", "-no-reboot",
           "-display", "none", *accel]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        _wait_marker(proc, serial)
        recordings = tmp_path / "recordings"
        recordings.mkdir()
        known = tmp_path / "known_hosts"
        out = asyncio.run(_ssh_and_record(m, port, runner_key, member_key,
                                          recordings, known))
        assert "ssh-" in out["target_key"]
        print("access accelerator:", "kvm" if use_kvm else "tcg",
              "cast:", out["cast"], "events:", out["events"], flush=True)
    except Exception:
        dbg = pathlib.Path("/tmp/opencode/sr-gate-debug")
        dbg.mkdir(parents=True, exist_ok=True)
        try:
            (dbg / f"access-{os.getpid()}.serial.log").write_text(
                serial.read_text(errors="replace"))
        except OSError:
            pass
        raise
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=15)
        shutil.rmtree(run_dir, ignore_errors=True)
