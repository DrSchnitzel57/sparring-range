"""RFB (VNC) console relay for guests with no sshd.

A member's browser speaks RFB to this relay; the relay talks RFB to the
guest's VNC server on its loopback port and authenticates with the password
the broker handed it. The browser never sees that password: the relay
impersonates a server that offers security type **None** *after* it has
already authenticated upstream, so a member cannot extract a reusable
credential from their own session.

Only the standard VNC authentication (security type 2, DES-ECB over a 16-byte
challenge) is spoken to the guest. Anything else (TLS/SASL/VeNCrypt) is
refused before a byte of screen data moves: an unknown security type on a
modern server is a loud UNKNOWN, never a silent downgrade.
"""
from __future__ import annotations

import asyncio

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RFB_VERSION = b"RFB 003.008\n"
_SEC_TYPE_NONE = 1
_SEC_TYPE_VNC_AUTH = 2


class ConsoleError(RuntimeError):
    """The console could not be reached or authenticated (UNKNOWN, loud)."""


def auth_response(challenge: bytes, password: str) -> bytes:
    """The VNC auth reply: DES-ECB over the challenge with the password as key.

    RFB pads/truncates the password to 8 bytes and single-DES is exactly
    TripleDES with K1=K2=K3, which is why no DES implementation is vendored.
    """
    if len(challenge) != 16:
        raise ConsoleError(f"challenge must be 16 bytes, got {len(challenge)}")
    # SAME key three times: TripleDES then computes single DES exactly, and
    # the 24-byte form is the one `cryptography` still supports (the 8-byte
    # single-key mode is deprecated).
    key = password.encode("utf-8")[:8].ljust(8, b"\0")
    enc = Cipher(algorithms.TripleDES(key * 3), modes.ECB()).encryptor()
    return enc.update(challenge) + enc.finalize()


async def _read_exact(reader: asyncio.StreamReader, n: int,
                      what: str) -> bytes:
    try:
        got = await asyncio.wait_for(reader.readexactly(n), timeout=10.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
        raise ConsoleError(f"console closed while reading {what}") from exc
    return got


async def authenticate(reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter, password: str) -> None:
    """Complete the upstream VNC handshake, leaving the stream at the point
    where the session is authenticated and ready for client messages."""
    version = await _read_exact(reader, 12, "protocol version")
    if not version.startswith(b"RFB "):
        raise ConsoleError(f"not an RFB server: {version!r}")
    writer.write(version)
    await writer.drain()
    count = (await _read_exact(reader, 1, "security type count"))[0]
    types = await _read_exact(reader, count, "security types")
    if _SEC_TYPE_VNC_AUTH not in types:
        raise ConsoleError(
            f"guest offers security types {list(types)}; only VNC auth (2) "
            "is supported")
    writer.write(bytes([_SEC_TYPE_VNC_AUTH]))
    await writer.drain()
    challenge = await _read_exact(reader, 16, "auth challenge")
    writer.write(auth_response(challenge, password))
    await writer.drain()
    result = await _read_exact(reader, 4, "auth result")
    if result != b"\x00\x00\x00\x00":
        raise ConsoleError("guest rejected the console password")


async def greet_client(reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
    """Present ourselves to the browser as a server requiring NO auth.

    The member is already authenticated by the capability token; asking for
    the guest's password again would hand them a reusable credential.
    """
    writer.write(RFB_VERSION)
    await writer.drain()
    await _read_exact(reader, 12, "client version")
    writer.write(bytes([1, _SEC_TYPE_NONE]))
    await writer.drain()
    chosen = (await _read_exact(reader, 1, "chosen security type"))[0]
    if chosen != _SEC_TYPE_NONE:
        raise ConsoleError(f"client chose security type {chosen}")
    writer.write(b"\x00\x00\x00\x00")
    await writer.drain()


async def pump(reader: asyncio.StreamReader,
               writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def relay(port: int, password: str, client_reader, client_writer,
                *, host: str = "127.0.0.1", connect=None,
                timeout_s: float = 10.0) -> None:
    """Authenticate upstream, greet the browser, then pipe both directions.

    `connect` is injectable so tests drive a fake VNC server without a
    hypervisor; production uses asyncio's loopback TCP.
    """
    opener = connect or asyncio.open_connection
    try:
        reader, writer = await asyncio.wait_for(opener(host, port),
                                                timeout=timeout_s)
    except (OSError, asyncio.TimeoutError) as exc:
        raise ConsoleError(f"console port {port} unreachable: {exc}") from exc
    try:
        await authenticate(reader, writer, password)
        await greet_client(client_reader, client_writer)
        await asyncio.gather(pump(reader, client_writer),
                             pump(client_reader, writer))
    except ConsoleError:
        writer.close()
        raise
