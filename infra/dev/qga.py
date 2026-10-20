"""Minimal QEMU guest agent client over a virtio-serial Unix socket.

The appliance backend reads the guest's readiness marker and its fixed
host-key path through libvirt's ``libvirt_qemu`` binding.  The isolated
QEMU fixtures (access gate, base-image build) have no libvirt, so this
module speaks the same agent protocol directly over the QEMU chardev
socket: 4-byte big-endian length + JSON request, same framing for the
reply.

Only two operations are exposed, both fixed and read-only:

* ``guest-ping`` — liveness of the agent.
* ``guest-file-open`` / ``guest-file-read`` / ``guest-file-close`` — read ONE
  file the caller names.  There is no exec, no write and no arbitrary path
  policy here: the caller decides which paths are acceptable, exactly like
  the production backend, which refuses anything but the fixed host-key path.
"""
from __future__ import annotations

import base64
import json
import socket
import struct
import time

_LEN = struct.Struct(">I")


class QgaError(RuntimeError):
    pass


class QgaClient:
    """One connection to a guest agent chardev socket."""

    def __init__(self, path: str, timeout: float = 15.0):
        self.path = path
        self.timeout = float(timeout)
        self._sock: socket.socket | None = None
        self._buf = b""

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

    def __enter__(self) -> "QgaClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def _send(self, payload: dict) -> None:
        assert self._sock is not None
        data = json.dumps(payload).encode("utf-8")
        self._sock.sendall(_LEN.pack(len(data)) + data)

    def _recv_exact(self, count: int) -> bytes:
        assert self._sock is not None
        chunks = []
        remaining = count
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise QgaError("guest agent closed the channel")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _recv_message(self) -> dict:
        header = self._recv_exact(_LEN.size)
        (length,) = _LEN.unpack(header)
        if length > 8 * 1024 * 1024:
            raise QgaError(f"guest agent message too large: {length}")
        body = self._recv_exact(length)
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise QgaError("guest agent sent invalid JSON") from exc

    # --------------------------------------------------------------- commands ---
    def execute(self, command: dict, *, retries: int = 1) -> dict:
        """Send one agent command and return its ``return`` payload."""
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
        absent.  A failing read is never reported as empty content."""
        try:
            opened = self.execute({"execute": "guest-file-open",
                                   "arguments": {"path": path, "mode": "r"}})
        except QgaError:
            return None
        handle = opened.get("handle") if isinstance(opened, dict) else None
        if not handle:
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
                buf = data.get("buf", "")
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
                pass
        if not chunks:
            return None
        return "".join(chunks)
