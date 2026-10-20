"""Minimal QEMU guest agent client over a virtio-serial Unix socket.

The appliance backend reads the guest's readiness marker and its fixed
host-key path through libvirt's ``libvirt_qemu`` binding.  The isolated
QEMU fixtures (access gate, base-image build) have no libvirt, so this
module speaks the same agent protocol directly over the QEMU chardev
socket.

Framing: over a QEMU *socket* chardev the agent exchanges PLAIN JSON
messages — one JSON object per message, no length header.  (The 4-byte
big-endian length header belongs to the raw virtio-serial port transport;
sending one here is answered with "JSON parse error".)

Only read-only operations are exposed:

* ``guest-ping`` — liveness of the agent.
* ``guest-file-open`` / ``guest-file-read`` / ``guest-file-close`` — read ONE
  file the caller names.  There is no exec and no write: which paths are
  acceptable is the caller's policy, exactly like the production backend,
  which refuses anything but the fixed host-key path.
"""
from __future__ import annotations

import base64
import json
import socket
import time

_DECODER = json.JSONDecoder()


class QgaError(RuntimeError):
    pass


class QgaClient:
    """One connection to a guest agent chardev socket."""

    def __init__(self, path: str, timeout: float = 15.0):
        self.path = path
        self.timeout = float(timeout)
        self._sock: socket.socket | None = None
        self._buf = ""

    # ------------------------------------------------------------ transport ---
    def connect(self) -> "QgaClient":
        if self._sock is not None:
            return self
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.path)
        except OSError as exc:
            raise QgaError(f"cannot connect to guest agent {self.path}: {exc}") from exc
        self._sock = s
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self._buf = ""

    def __enter__(self) -> "QgaClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def _send(self, payload: dict) -> None:
        assert self._sock is not None
        self._sock.sendall(json.dumps(payload).encode("utf-8"))

    def _recv_message(self) -> dict:
        """Read one JSON message; extra bytes stay buffered for the next one."""
        assert self._sock is not None
        deadline = time.monotonic() + self.timeout
        while True:
            stripped = self._buf.lstrip()
            if stripped:
                try:
                    obj, end = _DECODER.raw_decode(stripped)
                except ValueError:
                    obj = None
                if obj is not None:
                    self._buf = stripped[end:]
                    return obj
            if time.monotonic() >= deadline:
                raise QgaError("guest agent did not answer in time")
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout as exc:
                raise QgaError("guest agent did not answer in time") from exc
            if not chunk:
                raise QgaError("guest agent closed the channel")
            self._buf += chunk.decode("utf-8", "replace")

    # --------------------------------------------------------------- commands ---
    def execute(self, command: dict, *, retries: int = 1) -> dict:
        """Send one agent command and return its ``return`` payload.

        A failed command leaves the connection DESYNCHRONIZED: the agent may
        answer late, and that late answer would be read as the reply to the
        NEXT command.  The connection is therefore dropped on every error, so
        the next call starts from a clean socket and can never return another
        file's content.
        """
        last: Exception | None = None
        for attempt in range(max(1, retries)):
            try:
                self._send({"execute": command["execute"],
                            "arguments": command.get("arguments", {})})
                deadline = time.monotonic() + self.timeout
                while time.monotonic() < deadline:
                    msg = self._recv_message()
                    if "error" in msg:
                        raise QgaError(f"guest agent error: {msg['error']}")
                    if "return" in msg:
                        return msg["return"]
                raise QgaError("guest agent did not answer in time")
            except (QgaError, OSError) as exc:
                last = exc
                self.close()
                if attempt + 1 < max(1, retries):
                    time.sleep(1)
        raise QgaError(str(last))

    def ping(self) -> bool:
        try:
            self.execute({"execute": "guest-ping"})
            return True
        except QgaError:
            return False

    def read_file(self, path: str, *, max_bytes: int = 65536) -> str | None:
        """Read one file; ``None`` when the agent is not ready or the file is
        absent.  A failing read is never reported as empty content, and the
        connection is dropped on failure so no later read can inherit a
        stale answer."""
        try:
            handle = self.execute({"execute": "guest-file-open",
                                   "arguments": {"path": path, "mode": "r"}})
        except QgaError:
            self.close()
            return None
        if not isinstance(handle, int):
            self.close()
            return None
        chunks: list[str] = []
        try:
            for _ in range(64):
                try:
                    data = self.execute({
                        "execute": "guest-file-read",
                        "arguments": {"handle": handle, "count": 4096}})
                except QgaError:
                    break
                if not isinstance(data, dict):
                    break
                # QEMU 10 names the field "buf-b64"; older agents used "buf"
                # for the same base64 payload.
                buf = data.get("buf-b64") or data.get("buf") or ""
                if buf:
                    chunks.append(base64.b64decode(buf, validate=False)
                                  .decode("utf-8", "replace"))
                if data.get("eof"):
                    break
                if sum(len(c) for c in chunks) >= max_bytes:
                    break
        finally:
            try:
                self.execute({"execute": "guest-file-close",
                              "arguments": {"handle": handle}})
            except QgaError:
                self.close()
        if not chunks:
            return None
        return "".join(chunks)
