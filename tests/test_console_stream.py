"""The browser side of a console: RFB over WebSocket, password still hidden.

The API adapts a WebSocket to the SAME stream-shaped relay that already has
socket-level tests. These tests drive that relay through the adapters, so the
websocket path is proven with a real fake VNC server rather than a mock of
itself: the browser receives "no auth" and never a credential.
"""
from __future__ import annotations

import asyncio
import contextlib

import pytest

from srplatform.bastion.console import RFB_VERSION, relay
from srplatform.api.lab_routes import _WSReader, _WSWriter

PASSWORD = "a1b2c3d4"
CHALLENGE = b"C" * 16


class FakeWS:
    """A Starlette-shaped WebSocket: queued inbound, recorded outbound."""

    def __init__(self, incoming=(b"",), hang: bool = False):
        self._queue = [(m, "websocket.receive") for m in incoming]
        self._hang = hang
        self.sent = bytearray()
        self.frames: list[bytes] = []
        self.closed = False

    async def receive(self):
        if self._hang:
            # a LIVE browser stays connected after its last frame; the relay's
            # two pumps keep running until the test cancels them
            while not self._queue:
                await asyncio.sleep(0.005)
        elif not self._queue:
            return {"type": "websocket.disconnect", "code": 1000}
        data, _ = self._queue.pop(0)
        if isinstance(data, str):
            return {"type": "websocket.receive", "text": data}
        return {"type": "websocket.receive", "bytes": data}

    async def send_bytes(self, data):
        self.frames.append(bytes(data))
        self.sent.extend(data)

    async def close(self, code=1000, reason=None):
        self.closed = True


async def _fake_vnc_server(ready: asyncio.Event, received: asyncio.Event):
    """RFB 3.8 + VNC auth, then echo — the relay's upstream peer."""
    import hashlib  # noqa: F401 — parity with the socket-level fake

    def handle(reader, writer):
        pass

    async def handle(reader, writer):
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(12), 5)
        writer.write(bytes([1, 2]))
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(1), 5)
        writer.write(CHALLENGE)
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(16), 5)
        writer.write(b"\x00\x00\x00\x00")
        await writer.drain()
        ready.set()
        data = await asyncio.wait_for(reader.read(1024), 5)
        received.set()
        writer.write(data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_reader_reassembles_across_frames_and_text(temp_name="x"):
    async def run():
        ws = FakeWS([b"ab", "cd"])
        r = _WSReader(ws)
        assert await r.readexactly(4) == b"abcd"
        ws2 = FakeWS([b"hello"])
        assert await _WSReader(ws2).read(5) == b"hello"
        ws3 = FakeWS([b"ab"])
        with pytest.raises(asyncio.IncompleteReadError):
            await _WSReader(ws3).readexactly(4)

    asyncio.run(run())


def test_writer_batches_until_drain_and_sends_one_frame():
    async def run():
        ws = FakeWS([])
        w = _WSWriter(ws)
        w.write(b"RFB ")
        w.write(b"003.008\n")
        assert ws.frames == []            # nothing before drain
        await w.drain()
        assert ws.frames == [b"RFB 003.008\n"]
        w.write(b"x")
        w.close()                          # no-op, no frame
        assert ws.frames == [b"RFB 003.008\n"]

    asyncio.run(run())


def test_the_websocket_relay_hides_the_password_and_pipes_frames():
    async def run():
        ready = asyncio.Event()
        received = asyncio.Event()
        server, port = await _fake_vnc_server(ready, received)
        # browser: version reply, then the chosen security type (1 = None),
        # then its first data frame after the greeting
        ws = FakeWS([RFB_VERSION, b"\x01", b"FRAMEDATA"], hang=True)
        task = asyncio.create_task(
            relay(port, PASSWORD, _WSReader(ws), _WSWriter(ws)))
        try:
            await asyncio.wait_for(ready.wait(), 5)
            await asyncio.wait_for(received.wait(), 5)
            # let the echo pump flush its frame, then the browser "closes"
            for _ in range(50):
                if b"FRAMEDATA" in bytes(ws.sent):
                    break
                await asyncio.sleep(0.01)
        finally:
            task.cancel()
            server.close()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        blob = bytes(ws.sent)
        assert blob.startswith(RFB_VERSION)
        assert b"FRAMEDATA" in blob
        # security type None (1), never VNC auth (2) toward the browser
        assert bytes([1]) in blob
        assert PASSWORD.encode() not in blob

    asyncio.run(run())
