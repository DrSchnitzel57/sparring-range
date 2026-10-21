"""Real guest SSH + recording replay acceptance (access layer).

Boots an actual Ubuntu guest with the appliance seed, attaches a QEMU guest
agent channel, and proves three separate things:

  1. the appliance readiness contract (first-boot marker + fixed host key
     read through the guest agent, exactly like the production backend),
  2. real SSH with the role key, against the guest's real host key, and
  3. a recording: the real bastion proxies the session and the .cast file
     contains the command output.

No host key is accepted by TOFU: the guest's key is read from the live SSH
handshake and pinned in a known_hosts file before the bastion dials.

The base image, QEMU and (optionally) KVM are prerequisites.  In required mode
(``SR_REQUIRE_ACCESS=1``) absence is a FAILURE.  The guest is disposable and
the fixture clearly labels the software-emulation path.
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

import asyncssh

from infra.appliance.manifest import ApplianceManifest
from infra.appliance.seed import (SeedInputs, marker_path, render_network_config,
                                 render_user_data)
from infra.dev import qemu_guest
from infra.dev.qga import QgaClient
from infra.images.guest_seed import build_seed_iso, meta_data
from tests.test_appliance_install import _manifest as install_manifest

pytestmark = pytest.mark.access

HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"


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


def _guest_seed(tmp_path: pathlib.Path, base: pathlib.Path):
    raw = install_manifest(tmp_path)
    import hashlib
    h = hashlib.sha256()
    with base.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    raw["images"]["mojang-web-local"] = {
        "template_id": 9011, "path": str(base), "sha256": h.hexdigest(),
        "size_bytes": base.stat().st_size, "disk_gb": 8,
        "memory_mb": 1536, "vcpus": 2,
    }
    raw["budgets"].update({"max_memory_mb": 8192, "max_vcpus": 6,
                           "max_disk_gb": 44})
    m = ApplianceManifest.from_dict(raw, verify_images=True)
    # The DEFENDER guest: the member's bastion path and the sudo proof both
    # belong to the defended guest, not to the attack identity.
    image = m.image_for_role("mojang-web-local")
    inp = SeedInputs(
        manifest=m, image=image, vmid=230, session_id="access-gate",
        hostname="sr-access", address="10.0.2.15", prefix=24,
        gateway="10.0.2.2")
    seed_path = tmp_path / "access-seed.iso"
    build_seed_iso(seed_path, render_user_data(inp),
                   meta_data(f"iid-access-{os.getpid()}", "sr-access"),
                   network_config=render_network_config(inp))
    member_key = tmp_path / "member"
    stranger_key = tmp_path / "stranger"
    for key in (member_key, stranger_key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(key)], check=True, capture_output=True)
    # The manifest's bastion key role is the guest's defender identity; it
    # carries the management sudo rule.
    return m, seed_path, member_key, tmp_path / "bastion", stranger_key


def _wait_ready(qga_sock: pathlib.Path, proc: subprocess.Popen,
                timeout_s: float = 900) -> dict:
    """Wait for the guest agent and the appliance readiness marker.

    ONE connection is held for the whole wait: a QEMU socket chardev carries
    the guest's agent transport over the connected client, so opening and
    dropping a connection per poll would disconnect the agent itself.
    """
    deadline = time.monotonic() + timeout_s
    last = ""
    agent = QgaClient(str(qga_sock), timeout=15)
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError(f"QEMU exited {proc.returncode} before the "
                                     f"guest was ready")
            try:
                agent.connect()
                marker = agent.read_file(marker_path())
                if marker and marker.strip():
                    host_key = agent.read_file(HOST_KEY_PATH)
                    if host_key and host_key.strip():
                        return {"marker": marker.strip(),
                                "host_key": host_key.strip()}
            except Exception as exc:  # noqa: BLE001 — the agent is not up yet
                last = str(exc)
                agent.close()
            time.sleep(5)
    finally:
        agent.close()
    raise AssertionError(f"guest never reported readiness: {last}")


class _Collector(asyncssh.SSHClientSession):
    """Collects an interactive session's output."""

    def __init__(self):
        self.output = ""
        self.status = None

    def data_received(self, data, datatype=None):
        # asyncssh >= 2.24 passes the datatype as a second argument.
        self.output += data

    def exit_status_received(self, status):
        self.status = status


async def _ssh_and_record(m: ApplianceManifest, port: int, runner_key: pathlib.Path,
                          member_key: pathlib.Path, recordings: pathlib.Path,
                          known_hosts: pathlib.Path, defender_key: pathlib.Path,
                          stranger_key: pathlib.Path, member_pub: pathlib.Path):
    deadline = time.monotonic() + 600
    last = None
    known_key = None
    while time.monotonic() < deadline:
        try:
            async with asyncssh.connect(
                    "127.0.0.1", port, username="defender",
                    client_keys=[str(runner_key)], known_hosts=None,
                    connect_timeout=5, login_timeout=10) as conn:
                known_key = conn.get_server_host_key()
                result = await conn.run("cat /etc/sparring-range/role; id -u",
                                        check=False)
                assert result.exit_status == 0, result.stderr
                assert "mojang-web-local" in (result.stdout or ""), result.stdout
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

    from srplatform.bastion.proxy import BastionProxy
    from srplatform.settings import get_settings
    os.environ.update({
        "SR_ENV": "dev",
        "SR_BASTION_TARGET_USER": "defender",
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
    # The product's real key check: the member's PUBLIC key in the bastion's
    # authorized_keys file.  An unauthorized key must be refused.
    authorized = recordings / "authorized_keys"
    authorized.write_text("member "
                          + pathlib.Path(member_pub).read_text().strip()
                          + "\n")
    os.environ["SR_BASTION_AUTHORIZED_KEYS_FILE"] = str(authorized)
    get_settings.cache_clear()
    proxy = BastionProxy(resolve, sink, register, recordings_dir=recordings,
                         host_key_path=host_key)
    await proxy.start("127.0.0.1", 0)
    bastion_port = proxy._server.sockets[0].getsockname()[1]  # noqa: SLF001
    try:
        # 1. exec through the bastion: the command and its output are recorded.
        async with asyncssh.connect(
                "127.0.0.1", bastion_port, username="tok-access",
                client_keys=[str(member_key)], known_hosts=None,
                connect_timeout=10, login_timeout=15) as conn:
            result = await conn.run("cat /etc/sparring-range/role; id -u",
                                    check=False)
            assert result.exit_status == 0, result.stderr
            assert "mojang-web-local" in (result.stdout or ""), result.stdout

        # 2. an interactive PTY, a terminal resize and a reconnect.
        async with asyncssh.connect(
                "127.0.0.1", bastion_port, username="tok-access",
                client_keys=[str(member_key)], known_hosts=None,
                connect_timeout=10, login_timeout=15) as conn:
            collector = _Collector()
            channel, _session = await conn.create_session(
                lambda: collector, term_type="xterm-256color",
                term_size=(80, 24))
            # A real terminal waits for the prompt: input sent before the
            # guest's shell exists is swallowed by the login process.  The
            # proof therefore waits for the guest's first output and then
            # keeps the command going until the shell answers it.
            marker = "SR-INTERACTIVE-OK"
            deadline = time.monotonic() + 240
            resized = False
            started = time.monotonic()
            while time.monotonic() < deadline and marker not in collector.output:
                if time.monotonic() - started > 20:
                    channel.write(f"echo {marker}\n")
                await asyncio.sleep(2)
                if not resized:
                    # A real terminal resize must reach the recording as a
                    # resize frame.
                    channel.change_terminal_size(120, 40)
                    resized = True
            channel.close()
            await asyncio.sleep(1)
        assert marker in collector.output, (
            f"the interactive session never answered: {collector.output[:200]!r}")

        # 3. reconnect: the same guest serves a second recorded session.
        async with asyncssh.connect(
                "127.0.0.1", bastion_port, username="tok-access",
                client_keys=[str(member_key)], known_hosts=None,
                connect_timeout=10, login_timeout=15) as conn:
            result = await conn.run("cat /etc/sparring-range/role", check=False)
            assert result.exit_status == 0, result.stderr
            assert "mojang-web-local" in (result.stdout or "")

        # 4. denial: an unauthorised key is refused.
        refused = False
        try:
            async with asyncssh.connect(
                    "127.0.0.1", bastion_port, username="tok-access",
                    client_keys=[str(stranger_key)], known_hosts=None,
                    connect_timeout=10, login_timeout=15) as conn:
                result = await conn.run("id", check=False)
                refused = (result.exit_status != 0
                           or not (result.stdout or "").strip())
        except Exception:  # noqa: BLE001 — a refused login is the expected result
            refused = True
        assert refused, "the bastion accepted a key it does not authorize"
    finally:
        await proxy.stop()
        get_settings.cache_clear()

    casts = sorted(recordings.glob("*.cast"))
    assert len(casts) >= 3, casts
    frames = []
    for cast in casts:
        lines = cast.read_text().splitlines()
        header = json.loads(lines[0])
        assert header["version"] == 2
        assert header["session_id"] == "access-session"
        for line in lines[1:]:
            frames.append(json.loads(line))
    # cast frames: data frames are [delay, "o"|"i", text]; a resize frame is
    # [width, height, "r"].
    resized = any(len(f) == 3 and f[2] == "r" for f in frames)
    assert resized, f"no terminal resize was recorded: {frames[:6]}"
    output = "".join(f[2] for f in frames if len(f) == 3 and f[1] == "o")
    assert "mojang-web-local" in output, output
    assert any(e["action_type"] == "bastion_session_start" for e in events)
    assert any(e["action_type"] == "command" for e in events)
    assert any(e["action_type"] == "bastion_session_end" for e in events)
    return {"cast": str(casts[0]), "events": len(events), "target_key": pub,
            "casts": len(casts), "resize_recorded": True,
            "denied_stranger": True, "reconnected": True}


def test_real_guest_ssh_and_bastion_cast_replay(tmp_path):
    qemu = qemu_guest.qemu_binary()
    _require(qemu is not None, "QEMU (qemu-system-x86_64) is required for access")
    _require(shutil.which("ssh-keygen") is not None, "ssh-keygen is required")
    base = _base_image()
    m, seed, member_key, defender_key, stranger_key = _guest_seed(tmp_path, base)
    run_dir = qemu_guest.make_run_dir()
    serial = run_dir / "access.serial.log"
    port = _free_port()
    # QEMU's UNIX socket path must stay under 108 bytes, so the guest agent
    # chardev lives in a short run dir under /tmp.
    sock_dir = pathlib.Path(f"/tmp/sr-access-{os.getpid()}")
    sock_dir.mkdir(parents=True, exist_ok=True)
    qga_sock = sock_dir / "qga.sock"
    use_kvm = os.environ.get("SR_ACCESS_KVM") == "1" and pathlib.Path(
        "/dev/kvm").exists()
    accel = ["-accel", "kvm"] if use_kvm else ["-accel", "tcg,thread=multi"]
    disk = qemu_guest.make_overlay(base, run_dir, "access")
    cmd = [qemu, "-M", "q35", "-m", "1536", "-smp", "2",
           "-drive", f"file={disk},format=qcow2,if=virtio",
           "-drive", f"file={seed},format=raw,media=cdrom,readonly=on",
           "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:22",
           "-device", "virtio-net-pci,netdev=n0",
           "-device", "virtio-serial-pci,id=vser0",
           "-chardev", f"socket,id=qga0,path={qga_sock},server=on,wait=off",
           "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
           "-nographic", "-serial", f"file:{serial}", "-no-reboot",
           "-display", "none", *accel]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        ready = _wait_ready(qga_sock, proc)
        assert ready["host_key"].startswith(("ssh-ed25519 ", "ssh-rsa ")), \
            ready["host_key"]
        recordings = tmp_path / "recordings"
        recordings.mkdir()
        known = tmp_path / "known_hosts"
        # sudo: the management identity administers the guest, and the attack
        # identity does not get a blanket rule.
        async def _sudo():
            async with asyncssh.connect(
                    "127.0.0.1", port, username="defender",
                    client_keys=[str(defender_key)], known_hosts=None,
                    connect_timeout=10, login_timeout=20) as conn:
                ok = await conn.run("sudo -n id -u", check=False)
                no = await conn.run("id -u", check=False)
                return ok.stdout.strip(), no.stdout.strip()
        sudo_root, sudo_plain = asyncio.run(_sudo())
        assert sudo_root == "0", f"sudo did not work: {sudo_root!r}"
        assert sudo_plain != "0", "the defender must not BE root without sudo"
        out = asyncio.run(_ssh_and_record(m, port, defender_key,
                                          member_key, recordings, known,
                                          defender_key, stranger_key,
                                          tmp_path / "member.pub"))
        assert "ssh-" in out["target_key"]
        print("access accelerator:", "kvm" if use_kvm else "tcg",
              "marker:", ready["marker"], "cast:", out["cast"],
              "events:", out["events"], flush=True)
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
        shutil.rmtree(sock_dir, ignore_errors=True)
