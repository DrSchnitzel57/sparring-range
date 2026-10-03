"""The recording bastion (M2) — an asyncssh SSH server that:
  (a) lets you pick a target via token login (`ssh drew@bastion -l tok_web01`),
  (b) dials the real VM on the range side,
  (c) TEES the byte stream to an asciinema .cast file for replay,
  (d) writes session events to the platform event log.

Command-level truth comes from auditd (Part 6.2) — the .cast is for REPLAY; the
non-interactive exec channel IS parsed into command events (allowed), but the
interactive PTY stream is recorded verbatim, not parsed for grading.

Everything environment-specific is injected (token resolver + event sink) so the
proxy logic is testable; the production wiring resolves tokens through the API
(front-door rule) and the event sink posts to the API.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Protocol

import asyncssh

from srplatform.bastion.cast import CastWriter
from srplatform.settings import get_settings


class TokenResolver(Protocol):
    async def __call__(self, token: str) -> dict | None: ...  # -> {session_id, target_host, target_port}


class EventSink(Protocol):
    async def __call__(self, event: dict) -> None: ...


class _BastionServer(asyncssh.SSHServer):
    """LAN trust boundary (hard constraint #6): Drew's key(s) via
    authorized_client_keys when configured; token users are resolved by the
    injected resolver."""

    def __init__(self, bastion: "BastionProxy"):
        self.bastion = bastion

    async def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    async def validate_public_key(self, username: str, key) -> bool:
        ak = self.bastion.authorized_keys
        if ak is not None:
            return await ak(username, key)
        return True  # LAN trust; set authorized_keys for real deployments


class BastionProxy:
    def __init__(self, resolve_token: TokenResolver, event_sink: EventSink,
                 recordings_dir: Path | str | None = None, host_key_path: Path | str | None = None,
                 authorized_keys: Callable | None = None):
        s = get_settings()
        self.resolve_token = resolve_token
        self.event_sink = event_sink
        self.recordings_dir = Path(recordings_dir or s.recordings_dir)
        self.recordings_dir.mkdir(parents=True, exist_ok=True)
        self.host_key_path = Path(host_key_path or s.bastion_host_key_path)
        self.authorized_keys = authorized_keys
        self._server: asyncssh.SSHListener | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        if not self.host_key_path.exists():
            key = asyncssh.generate_private_key("ssh-ed25519")
            key.write_private_key(self.host_key_path)
        self._server = await asyncssh.create_server(
            lambda: _BastionServer(self), host, port,
            server_host_keys=[str(self.host_key_path)],
            process_factory=self._handle_session,
            # transparent pipe: no local line editing/echo/history (the TARGET's
            # PTY does that; emulating it here would double-echo input)
            line_editor=False,
        )
        return self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server:
            self._server.close()
            await self._wait_closed()

    async def _wait_closed(self):
        try:
            await self._server.wait_closed()
        except Exception:
            pass

    # ------------------------------------------------------------------ sessions
    async def _handle_session(self, process: asyncssh.SSHServerProcess) -> None:
        username = process.get_extra_info("username")
        target = await self.resolve_token(username)
        if not target:
            process.exit(1)
            return

        session_id = target.get("session_id")
        cast_path = self.recordings_dir / f"{username}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.cast"
        cast = CastWriter(cast_path, metadata={"session_id": session_id, "token": username,
                                              "target": target["target_host"]})

        await self.event_sink({
            "session_id": session_id, "actor": f"blue:{username}", "host": "bastion",
            "action_type": "bastion_session_start",
            "payload": {"token": username, "target": target["target_host"], "cast": str(cast_path)},
            "raw_ref": str(cast_path),
        })

        try:
            async with asyncssh.connect(
                target["target_host"], target.get("target_port", 22),
                username=get_settings().bastion_user, known_hosts=None,
            ) as real:
                if process.command is not None:
                    # non-interactive exec channel: parseable, log the command (Part 6.2)
                    await self.event_sink({
                        "session_id": session_id, "actor": f"blue:{username}", "host": "bastion",
                        "action_type": "command",
                        "payload": {"channel": "exec", "command": process.command, "source": "bastion-exec"},
                    })
                    result = await real.run(process.command, check=False)
                    process.stdout.write(result.stdout or "")
                    process.stderr.write(result.stderr or "")
                    process.exit(result.exit_status if result.exit_status is not None else 0)
                else:
                    # interactive PTY: tee raw bytes BOTH directions to the .cast
                    remote = await real.create_process(term_type="xterm-256color",
                                                      term_size=(120, 32))
                    copy_out = asyncio.create_task(self._tee(remote.stdout, process.stdout, cast, "o"))
                    copy_in = asyncio.create_task(self._tee(process.stdin, remote.stdin, cast, "i"))
                    # when EITHER side closes (target exits, or client disconnects),
                    # end the session — otherwise the other tee hangs forever
                    done, pending = await asyncio.wait({copy_out, copy_in},
                                                       return_when=asyncio.FIRST_COMPLETED)
                    for t in pending:
                        t.cancel()
                        await asyncio.gather(t, return_exceptions=True)
                    process.exit(0)
        finally:
            cast.close()
            await self.event_sink({
                "session_id": session_id, "actor": f"blue:{username}", "host": "bastion",
                "action_type": "bastion_session_end",
                "payload": {"token": username, "cast": str(cast_path)},
                "raw_ref": str(cast_path),
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
async def api_resolve_token(token: str) -> dict | None:
    import httpx

    s = get_settings()
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{s.api_base_url}/tokens/{token}", timeout=10)
        return r.json() if r.status_code == 200 else None


async def api_event_sink(event: dict) -> None:
    import httpx

    s = get_settings()
    async with httpx.AsyncClient() as c:
        await c.post(f"{s.api_base_url}/events", json=event, timeout=10)


async def main():
    proxy = BastionProxy(api_resolve_token, api_event_sink)
    port = await proxy.start()
    print(f"[bastion] recording proxy listening on :{port}")
    await asyncio.Event().wait()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
