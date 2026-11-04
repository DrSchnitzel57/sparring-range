"""The VNC console relay: real RFB auth against a fake server, no hypervisor.

The security property under test is that the BROWSER never learns the guest
password: the relay authenticates upstream with it and then tells the client
"no auth required", so a member cannot reuse it.
"""
from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from srplatform.bastion.console import ConsoleError, RFB_VERSION, \
    auth_response, relay

PASSWORD = "a1b2c3d4"


def _des_encrypt(key: bytes, data: bytes) -> bytes:
    k = key.ljust(8, b"\0")
    enc = Cipher(algorithms.TripleDES(k * 3), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


async def _fake_vnc_server(password: str, challenge: bytes,
                           ready: asyncio.Event, received: asyncio.Event):
    """A one-shot RFB 3.8 server: version, [VNC auth], challenge, result,
    then echoes back whatever it receives."""
    async def handle(reader, writer):
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(12), 5)
        writer.write(bytes([1, 2]))          # one type: VNC auth
        await writer.drain()
        chosen = await asyncio.wait_for(reader.readexactly(1), 5)
        assert chosen == b"\x02"
        writer.write(challenge)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(16), 5)
        key = password.encode()[:8]
        ok = reply == _des_encrypt(key, challenge)
        writer.write(b"\x00\x00\x00\x00" if ok else b"\x00\x00\x00\x01")
        await writer.drain()
        ready.set()
        data = await asyncio.wait_for(reader.read(1024), 5)
        received.set()
        writer.write(data)                   # echo
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


class _ClientRecorder:
    """The browser side, as asyncio streams."""
    def __init__(self):
        self.reader = asyncio.StreamReader()
        self.written = bytearray()

    async def drain(self):
        return None

    def write(self, b):
        self.written.extend(b)

    def close(self):
        return None


def test_the_auth_reply_is_DES_over_the_challenge():
    challenge = bytes(range(16))
    assert auth_response(challenge, PASSWORD) == _des_encrypt(
        PASSWORD.encode(), challenge)
    with pytest.raises(ConsoleError, match="16 bytes"):
        auth_response(b"short", PASSWORD)


def test_the_relay_authenticates_upstream_and_hides_the_password():
    """End to end over real sockets: fake VNC server upstream, a fake BROWSER
    downstream. The browser must never see the challenge or the DES reply."""
    async def scenario():
        ready = asyncio.Event()
        challenge = b"C" * 16
        server, port = await _fake_vnc_server(PASSWORD, challenge, ready,
                                              asyncio.Event())
        seen = bytearray()

        async def browser(r, w):
            seen.extend(await r.readexactly(12))      # server version
            w.write(RFB_VERSION)                     # client version reply
            await w.drain()
            count = (await r.readexactly(1))[0]
            types = await r.readexactly(count)
            assert list(types) == [1]                 # None offered
            seen.extend(types)
            w.write(b"\x01")                          # choose None
            await w.drain()
            seen.extend(await r.readexactly(4))       # security result
            w.write(b"FRAMEDATA")                     # screen bytes
            await w.drain()
            seen.extend(await r.readexactly(9))       # echoed back
            w.close()

        bserver = await asyncio.start_server(browser, "127.0.0.1", 0)
        bport = bserver.sockets[0].getsockname()[1]
        cr, cw = await asyncio.open_connection("127.0.0.1", bport)
        task = asyncio.create_task(relay(port, PASSWORD, cr, cw))
        await asyncio.wait_for(ready.wait(), 5)
        await asyncio.wait_for(task, 5)
        bserver.close()
        server.close()
        assert seen.startswith(b"RFB 003.008\n")
        assert challenge not in seen
        assert b"FRAMEDATA" in seen

    asyncio.new_event_loop().run_until_complete(scenario())


def test_a_server_that_offers_no_vnc_auth_is_refused_before_screen_data():
    async def scenario():
        async def handle(reader, writer):
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(12), 5)
            writer.write(bytes([1, 1]))     # only "None": not acceptable
            await writer.drain()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = _ClientRecorder()
        client.reader.feed_data(b"RFB 003.008\n")
        with pytest.raises(ConsoleError, match="only VNC auth"):
            await relay(port, PASSWORD, client.reader, client)
        server.close()
        await server.wait_closed()

    asyncio.new_event_loop().run_until_complete(scenario())


def test_a_rejected_password_is_a_console_error():
    async def scenario():
        async def handle(reader, writer):
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(12), 5)
            writer.write(bytes([1, 2]))
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(1), 5)
            writer.write(b"Z" * 16)
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(16), 5)
            writer.write(b"\x00\x00\x00\x01")   # failed
            await writer.drain()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = _ClientRecorder()
        with pytest.raises(ConsoleError, match="rejected"):
            await relay(port, "wrong", client.reader, client)
        server.close()
        await server.wait_closed()

    asyncio.new_event_loop().run_until_complete(scenario())


def test_an_unreachable_port_is_loud_not_silent():
    async def scenario():
        client = _ClientRecorder()
        with pytest.raises(ConsoleError, match="unreachable"):
            await relay(1, PASSWORD, client.reader, client)

    asyncio.new_event_loop().run_until_complete(scenario())
