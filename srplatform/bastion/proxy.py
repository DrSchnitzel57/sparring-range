"""The recording bastion (M2 — F08/F16 repairs):

  (a) member authentication: operator-provisioned public keys (authorized_keys
      file); the token login (`ssh bastion -p 2222 -l tok_x`) resolves through
      the API with a bastion SERVICE TOKEN — target selection is bound to the
      session-owned inventory on the server side, so the bastion cannot dial
      arbitrary management destinations,
  (b) target host-key verification: pinned known_hosts file; production refuses
      to connect with TOFU,
  (c) tees BOTH interactive PTY and non-interactive exec streams to an
      exclusively-created .cast file (UUID name — tokens never become paths),
      registers the recording via the API (opaque recording_id in events),
  (d) writes session events through the API only.

Command-level truth stays with auditd; the .cast is replay evidence.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Protocol

import asyncssh

from srplatform.bastion.cast import CastWriter
from srplatform.settings import get_settings


class TokenResolver(Protocol):
    async def __call__(self, token: str) -> dict | None: ...  # -> {session_id, target_host, target_port}


class RecordingRegistrar(Protocol):
    async def __call__(self, session_id: str, cast_path: str) -> str | None: ...  # -> recording_id


class EventSink(Protocol):
    async def __call__(self, event: dict) -> None: ...


class PinRefused(RuntimeError):
    """The deployment-served host-key pin is unusable — fail closed.

    Raised BEFORE any dial. The member sees only the failure class (never
    pin material); the operator reads the journal. A target that carries a
    (broken) pin never falls back to TOFU or a stale file: that is exactly
    how a truncated display ref masqueraded as a dial mismatch and cost a
    live debugging session (2026-10-16).
    """


def _deployment_known_hosts(target: dict) -> bytes:
    """known_hosts line built from the deployment-served pin.

    The value must be a parseable public key; a truncated display ref or
    any other malformed shape raises :class:`PinRefused` instead of becoming
    a known_hosts line asyncssh silently ignores (zero trusted keys ->
    HostKeyNotVerifiable on every dial). Never include the value in the
    error — the class is loud, the material is not leaked.
    """
    pin = (target.get("target_host_key") or "").strip()
    try:
        asyncssh.import_public_key(pin)
    except asyncssh.KeyImportError as e:
        raise PinRefused("deployment pin malformed — refusing dial") from e
    return f"{target['target_host']} {pin}".encode()


def load_authorized_keys(path: str | None) -> dict[str, list[str]]:
    """`user <pubkey...>` lines -> {user: [keys]}."""
    out: dict[str, list[str]] = {}
    if not path:
        return out
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        user, _, key = line.partition(" ")
        if key.strip():
            out.setdefault(user, []).append(key.strip())
    return out


class _BastionServer(asyncssh.SSHServer):
    def __init__(self, bastion: "BastionProxy"):
        self.bastion = bastion

    async def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    async def validate_public_key(self, username: str, key) -> bool:
        # 1) direct member login
        if self.bastion.authorized_keys(username, key):
            return True
        # 2) token login: validate the key of the MEMBER who owns the token
        target = await self.bastion.resolve_token(username)
        if not target:
            return False
        owner = target.get("username")
        return bool(owner and self.bastion.authorized_keys(owner, key))


class BastionProxy:
    def __init__(self, resolve_token: TokenResolver, event_sink: EventSink,
                 register_recording: RecordingRegistrar | None = None,
                 recordings_dir: Path | str | None = None,
                 host_key_path: Path | str | None = None,
                 authorized_keys: Callable[[str, object], bool] | None = None):
        s = get_settings()
        self.resolve_token = resolve_token
        self.event_sink = event_sink
        self.register_recording = register_recording
        self.recordings_dir = Path(recordings_dir or s.recordings_dir)
        self.recordings_dir.mkdir(parents=True, exist_ok=True)
        self.host_key_path = Path(host_key_path or s.bastion_host_key_path)
        self._auth_keys = load_authorized_keys(s.bastion_authorized_keys_file)
        self._authorized_keys_override = authorized_keys
        self._server: asyncssh.SSHListener | None = None

    def authorized_keys(self, username: str, key) -> bool:
        if self._authorized_keys_override is not None:
            return self._authorized_keys_override(username, key)
        keys = self._auth_keys.get(username)
        if not keys:
            return False
        # asyncssh renamed the renderer across versions; try both, then str()
        pub = None
        for renderer in ("render_public_key", "export_public_key"):
            fn = getattr(key, renderer, None)
            if fn is not None:
                try:
                    pub = fn().decode()
                    break
                except Exception:  # noqa: BLE001
                    pub = None
        if pub is None:
            pub = str(key)
        return any(pub.split()[:2] == k.split()[:2] for k in keys)

    async def start(self, host: str | None = None, port: int | None = None) -> int:
        s = get_settings()
        host = host if host is not None else s.bastion_listen_host
        port = port if port is not None else s.bastion_listen_port
        if not self.host_key_path.exists():
            key = asyncssh.generate_private_key("ssh-ed25519")
            key.write_private_key(self.host_key_path)
        self._server = await asyncssh.create_server(
            lambda: _BastionServer(self), host, port,
            server_host_keys=[str(self.host_key_path)],
            process_factory=self._handle_session,
            line_editor=False,  # transparent pipe: the TARGET's PTY edits/echoes
        )
        return self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------ sessions
    async def _handle_session(self, process: asyncssh.SSHServerProcess) -> None:
        username = process.get_extra_info("username")
        target = await self.resolve_token(username)
        if not target:
            # Direct member logins and dead tokens carry no session: say so
            # instead of closing silently (an unexplained exit 1 reads as a
            # network fault and cost an hour of live debugging).
            process.stderr.write(
                "no session attached to this login — connect with a session "
                "token login from the session page\r\n")
            process.exit(1)
            return

        session_id = target.get("session_id")
        s = get_settings()
        # opaque, exclusive recording name (F16: tokens never become paths)
        rec_uuid = uuid.uuid4()
        cast_path = self.recordings_dir / f"{rec_uuid}.cast"
        width = getattr(process, "width", 0) or 120
        height = getattr(process, "height", 0) or 32
        cast = CastWriter(cast_path, width=width, height=height,
                          metadata={"session_id": session_id, "target": target["target_host"]},
                          max_bytes=s.recording_max_bytes)
        recording_id = None
        if self.register_recording and session_id:
            recording_id = await self.register_recording(session_id, str(cast_path))
        # resize frames (F08: capture terminal size as supported)
        process.on_resize = lambda w, h: cast.resize(w, h)

        ref = recording_id or str(cast_path)
        await self.event_sink({
            "session_id": session_id, "actor": None, "host": "bastion",
            "action_type": "bastion_session_start",
            "payload": {"token_hint": username[:4] + "***", "target": target["target_host"],
                        "recording_id": recording_id},
            "raw_ref": ref,
        })
        try:
            # ONE production pin source (milestone 14): the deployment serves
            # the broker-pinned guest host key with the token, and the pin
            # that travels with the login can never go stale across
            # relaunches the way a copied file does.  The local known_hosts
            # file is NOT a production fallback any more: a stale local file
            # is exactly the trust path this design rejected, so in
            # production a missing deployment pin is a refusal, not a
            # downgrade to a file (and never TOFU).
            api_pin = (target.get("target_host_key") or "").strip() or None
            if api_pin:
                print("[bastion] pin source: deployment evidence", flush=True)
                known = _deployment_known_hosts(target)
            elif s.sr_env == "production":
                raise RuntimeError(
                    "the deployment served no guest host-key pin — refusing to "
                    "dial the range host on a local file or on TOFU")
            else:
                # Development only: a local known_hosts file may stand in for
                # the deployment pin, and a missing one means TOFU in a
                # non-production environment.
                known = s.bastion_targets_known_hosts or None
                if isinstance(known, str):
                    if os.path.exists(known):
                        print("[bastion] pin source: local file "
                              "(no deployment pin)", flush=True)
                    else:
                        known = None
            # PILOT STEP 7: dial guests as the DEFENDER identity with the
            # bastion's own keypair (public half baked into the templates);
            # never the implicit root default.
            client_keys = ([s.bastion_client_key_path]
                           if s.bastion_client_key_path else None)
            async with asyncssh.connect(
                target["target_host"], target.get("target_port", 22),
                username=s.bastion_target_user,
                client_keys=client_keys,
                known_hosts=known,
            ) as real:
                if process.command is not None:
                    # non-interactive exec: parseable command AND its output are
                    # recorded (F16: exec-channel output goes to the cast too)
                    await self.event_sink({
                        "session_id": session_id, "actor": None, "host": "bastion",
                        "action_type": "command",
                        "payload": {"channel": "exec", "command": process.command,
                                    "source": "bastion-exec", "recording_id": recording_id},
                        "raw_ref": ref,
                    })
                    result = await real.run(process.command, check=False)
                    out = (result.stdout or "") + (result.stderr or "")
                    cast.write("o", out)
                    process.stdout.write(result.stdout or "")
                    process.stderr.write(result.stderr or "")
                    process.exit(result.exit_status if result.exit_status is not None else 0)
                else:
                    # send_eof=False: the guest's shell must keep its stdin
                    # OPEN.  asyncssh's create_process() sends EOF on the
                    # remote stdin by default, which makes the guest's login
                    # shell exit immediately - the member's interactive
                    # session then dies before they can type a command.
                    remote = await real.create_process(term_type="xterm-256color",
                                                       term_size=(width, height),
                                                       send_eof=False)
                    # A member's keystrokes must not be typed into a shell
                    # that does not exist yet: the guest's login process
                    # swallows input that arrives before the prompt, and a
                    # login process that receives stray input can end the
                    # session outright.  The member's input is therefore held
                    # until the guest has produced its first output (the
                    # shell is up), with a bounded wait so a silent target
                    # still receives input.
                    shell_ready = asyncio.Event()

                    async def _tee_in(reader, writer, cast, direction):
                        while True:
                            try:
                                data = await reader.read(4096)
                            except asyncssh.TerminalSizeChanged as exc:
                                # The member resized the terminal.  asyncssh
                                # delivers a window change as an exception
                                # from the read, so it must be handled here:
                                # the resize is recorded AND passed on to the
                                # guest, otherwise the recorded session and
                                # the live guest disagree about the geometry.
                                width, height = exc.term_size[0], \
                                    exc.term_size[1]
                                cast.resize(width, height)
                                try:
                                    remote.change_terminal_size(width, height)
                                except Exception:  # noqa: BLE001
                                    pass
                                continue
                            if not data:
                                break
                            try:
                                await asyncio.wait_for(shell_ready.wait(),
                                                       timeout=30)
                            except asyncio.TimeoutError:
                                pass
                            cast.write(direction, data)
                            writer.write(data)
                            await writer.drain()

                    async def _tee_out(reader, writer, cast, direction):
                        while True:
                            try:
                                data = await reader.read(4096)
                            except asyncssh.TerminalSizeChanged as exc:
                                cast.resize(exc.term_size[0], exc.term_size[1])
                                continue
                            if not data:
                                break
                            shell_ready.set()
                            cast.write(direction, data)
                            writer.write(data)
                            await writer.drain()

                    copy_out = asyncio.create_task(
                        _tee_out(remote.stdout, process.stdout, cast, "o"))
                    copy_in = asyncio.create_task(
                        _tee_in(process.stdin, remote.stdin, cast, "i"))
                    done, pending = await asyncio.wait({copy_out, copy_in},
                                                       return_when=asyncio.FIRST_COMPLETED)
                    for t in pending:
                        t.cancel()
                        await asyncio.gather(t, return_exceptions=True)
                    process.exit(0)
        except Exception as e:  # noqa: BLE001 — guest dials fail for
            # network/auth/pin reasons; asyncssh.Error alone misses OSError
            # (refused/timeout), which used to abort the member session
            # with no output at all. Report the failure CLASS only — never
            # keys, tokens, or pin material — to the member, the cast, and
            # the (root-only) journal, so a stale pin is loud, not silent.
            cast.write("o", f"\n[bastion] target connection failed: {e}\n")
            print(f"[bastion] guest dial failed: {type(e).__name__}", flush=True)
            process.stderr.write(
                "target connection failed (%s) — retry, or ask the operator "
                "to check range health\r\n" % type(e).__name__)
            process.exit(255)
        finally:
            cast.close()
            await self.event_sink({
                "session_id": session_id, "actor": None, "host": "bastion",
                "action_type": "bastion_session_end",
                "payload": {"recording_id": recording_id, "truncated": cast.truncated},
                "raw_ref": ref,
            })

    @staticmethod
    async def _tee(reader, writer, cast: CastWriter, direction: str):
        while True:
            data = await reader.read(4096)
            if not data:
                break
            if isinstance(data, bytes):
                data = data.decode("utf-8", "replace")
            cast.write(direction, data)
            writer.write(data)
            await writer.drain()


# ---------------------------------------------------------------- production wiring
def _svc_headers() -> dict:
    tok = os.environ.get("SR_BASTION_TOKEN", "")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


async def api_resolve_token(token: str) -> dict | None:
    import httpx

    s = get_settings()
    async with httpx.AsyncClient(verify=s.api_tls_ca_file or True) as c:
        r = await c.get(f"{s.api_base_url}{s.api_route_prefix}/tokens/{token}", headers=_svc_headers(), timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        # The API resolves the OWNER's authenticated username server-side
        # (audit R02); the key check binds the login to that member's
        # provisioned key. A token with no resolvable owner cannot authorize
        # any key — fail closed rather than fall through.
        data["username"] = data.get("username")
        return data


async def api_register_recording(session_id: str, cast_path: str) -> str | None:
    import httpx

    s = get_settings()
    async with httpx.AsyncClient(verify=s.api_tls_ca_file or True) as c:
        r = await c.post(f"{s.api_base_url}{s.api_route_prefix}/sessions/{session_id}/recordings",
                         json={"cast_path": cast_path}, headers=_svc_headers(), timeout=10)
        return r.json().get("recording_id") if r.status_code == 201 else None


async def api_event_sink(event: dict) -> None:
    import httpx

    s = get_settings()
    event = dict(event)
    event.pop("actor", None)  # server assigns the actor from the capability
    async with httpx.AsyncClient(verify=s.api_tls_ca_file or True) as c:
        r = await c.post(f"{s.api_base_url}{s.api_route_prefix}/events", json=event, headers=_svc_headers(), timeout=10)
        if r.status_code >= 400:
            print(f"[bastion] event sink failed: {r.status_code} {r.text[:200]}", flush=True)


async def main():
    s = get_settings()
    if s.api_base_url.startswith("https://") and not s.api_tls_ca_file:
        raise SystemExit(
            "bastion refuses to start: api_base_url is https but API_TLS_CA_FILE "
            "is unset — pin the API certificate (TLS checks are never disabled)")
    proxy = BastionProxy(api_resolve_token, api_event_sink,
                         register_recording=api_register_recording)
    port = await proxy.start()
    print(f"[bastion] recording proxy listening on :{port}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
