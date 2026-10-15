"""Controller-side authenticated MySQL business transactions (review finding).

The loopback and web-origin probes execute the mysql CLIENT inside guests —
a guest-root attacker can forge their stdout. This module performs the
SAME read-only business query as a DIRECT controller→DB TCP connection
using mysql_native_password auth, with pure-stdlib socket code (no new
dependencies): no guest code executes anywhere on this path, so a
compromised web guest cannot forge its result — forging requires
intercepting the controller↔DB TCP stream itself.

Trust model (documented limitation): the controller is trusted, the DB
guest's mysqld is trusted to answer truthfully, and the reader credential
is SELECT-only. A fully DB-root-compromised guest can lie to ANY observer;
the loopback/via/controller triangle reports disagreement as integrity
failure instead of averaging it away.

Only SELECT COUNT(*) style single-row/single-column reads are supported —
this is a prober, not a driver.
"""
from __future__ import annotations

import hashlib
import socket
import struct
import time

PORT = 3306

_CAP_PROTOCOL_41 = 0x0200
_CAP_SECURE_CONNECTION = 0x8000
_CAP_PLUGIN_AUTH = 0x00080000
_CLIENT_CAPS = _CAP_PROTOCOL_41 | _CAP_SECURE_CONNECTION | _CAP_PLUGIN_AUTH


class MySQLError(RuntimeError):
    pass


def _read_packet(sock, buf: bytearray, timeout_s: float, started: float):
    """Read one server packet: 3-byte LE length, 1-byte sequence, payload.
    Returns (seq, payload). Bounded: overlong lengths fail closed."""
    while len(buf) < 4:
        chunk = sock.recv(4096)
        if not chunk:
            raise MySQLError("connection closed mid-packet")
        buf += chunk
        if time.monotonic() - started > timeout_s:
            raise MySQLError("read timeout")
    length = buf[0] | (buf[1] << 8) | (buf[2] << 16)
    if length > 16 * 1024 * 1024:
        raise MySQLError(f"absurd packet length {length}")
    seq = buf[3]
    del buf[:4]
    while len(buf) < length:
        chunk = sock.recv(min(65536, length - len(buf)))
        if not chunk:
            raise MySQLError("connection closed mid-payload")
        buf += chunk
        if time.monotonic() - started > timeout_s:
            raise MySQLError("read timeout")
    payload = bytes(buf[:length])
    del buf[:length]
    return seq, payload


def _send(sock, seq: int, payload: bytes) -> None:
    sock.sendall(struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload)


def _parse_handshake(payload: bytes) -> tuple[bytes, bool]:
    """Return (auth_seed, ok). Only mysql_native_password is accepted —
    anything else (including an auth-switch request) fails closed."""
    if len(payload) < 32 or payload[0] != 10:
        return b"", False
    nul = payload.find(b"\x00", 1)
    if nul < 0 or len(payload) < nul + 31:
        return b"", False
    # layout: conn_id[4] part1[8] filler[1] cap1[2] charset[1]
    # status[2] cap2[2] plugin_len[1] reserved[10] part2[..] plugin NUL
    part1 = payload[nul + 5:nul + 13]
    more = payload[nul + 13:]
    if len(more) < 20:
        return b"", False
    maxlen = max(more[8] - 8, 13)
    part2 = more[19:19 + maxlen].split(b"\x00")[0]
    plugin = more[19 + maxlen:].split(b"\x00")[0]
    if plugin and plugin != b"mysql_native_password":
        return b"", False
    return part1 + part2, True


def _scramble(password: str, seed: bytes) -> bytes:
    stage1 = hashlib.sha1(password.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(seed + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def _lenenc_int(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first < 0xFB:
        return first, pos + 1
    if first == 0xFC:
        return struct.unpack("<H", buf[pos + 1:pos + 3])[0], pos + 3
    if first == 0xFD:
        return (buf[pos + 1] | (buf[pos + 2] << 8)
                | (buf[pos + 3] << 16)), pos + 4
    n = struct.unpack("<Q", buf[pos + 1:pos + 9])[0]
    return n, pos + 9


def select_one(db_ip: str, user: str, password: str, database: str,
               query: str, *, port: int = PORT, timeout_s: float = 5.0,
               connect=None) -> str:
    """Run one read-only query controller-side. Only SELECT/SHOW/EXPLAIN
    are sent (anything else is refused client-side). Returns the first
    column of the first row as text. Raises MySQLError on any transport,
    auth, or protocol anomaly. `connect` is the socket seam for tests."""
    head = query.strip().split(None, 1)[0].upper() if query.strip() else ""
    if head not in ("SELECT", "SHOW", "EXPLAIN"):
        raise MySQLError(f"refusing non-read query {head!r}")
    started = time.monotonic()
    opener = connect or socket.create_connection
    sock = opener((db_ip, port), timeout=timeout_s)
    buf = bytearray()
    try:
        if hasattr(sock, "settimeout"):
            try:
                sock.settimeout(max(0.5, timeout_s - (time.monotonic() - started)))
            except OSError:
                pass
        seq, payload = _read_packet(sock, buf, timeout_s, started)
        if seq != 0:
            raise MySQLError(f"bad handshake sequence {seq}")
        seed, ok = _parse_handshake(payload)
        if not ok:
            raise MySQLError("unsupported handshake (need mysql_native_password)")
        token = _scramble(password, seed)
        auth = (struct.pack("<I", _CLIENT_CAPS) + struct.pack("<I", 1 << 24)
                + b"\x21" + b"\x00" * 23 + user.encode() + b"\x00"
                + bytes([len(token)]) + token + database.encode() + b"\x00"
                + b"mysql_native_password\x00")
        _send(sock, 1, auth)
        seq, payload = _read_packet(sock, buf, timeout_s, started)
        if payload[:1] == b"\xff":
            raise MySQLError(f"auth refused: {payload[3:120]!r}")
        if payload[:1] != b"\x00":
            raise MySQLError(f"unexpected auth reply {payload[:1]!r}")
        _send(sock, 0, b"\x03" + query.encode())
        seq, payload = _read_packet(sock, buf, timeout_s, started)
        if payload[:1] == b"\xff":
            raise MySQLError(f"query refused: {payload[3:160]!r}")
        ncols, pos = _lenenc_int(payload, 0)
        if ncols < 1:
            raise MySQLError("empty result set")
        # skip column definitions + EOF, then read the first row
        for _ in range(ncols + 1):
            seq, payload = _read_packet(sock, buf, timeout_s, started)
            if payload[:1] == b"\xff":
                raise MySQLError(f"column error: {payload[3:160]!r}")
        seq, payload = _read_packet(sock, buf, timeout_s, started)
        if not payload:
            raise MySQLError("empty row packet")
        if payload[:1] == b"\xff":
            raise MySQLError("row error")
        if payload[0] == 0xFB:  # SQL NULL — impossible for COUNT(*)
            raise MySQLError("unexpected NULL value")
        try:
            length, pos = _lenenc_int(payload, 0)
            value = payload[pos:pos + length].decode(errors="replace")
        except (struct.error, IndexError) as e:
            raise MySQLError(f"malformed row: {e}") from e
        if len(value) != length:
            raise MySQLError("truncated row value")
        return value
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
