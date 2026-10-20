"""Controller-side authenticated MySQL business transactions (review finding).

The loopback and web-origin probes execute the mysql CLIENT inside guests —
a guest-root attacker can forge their stdout. This module performs the
SAME read-only business query as a DIRECT controller→DB TCP connection:
no guest code executes anywhere on this path, so a compromised web guest
cannot forge its result — forging requires intercepting the controller↔DB
TCP stream itself.

Trust model (documented limitation): the controller is trusted, the DB
guest's mysqld is trusted to answer truthfully, and the reader credential
is SELECT-only. A fully DB-root-compromised guest can lie to ANY observer;
the loopback/via/controller triangle reports disagreement as integrity
failure instead of averaging it away.

Milestone 15 replaces the earlier hand-written wire implementation with the
locked PyMySQL driver. Only SELECT/SHOW/EXPLAIN reach the driver; timeouts are
bounded, credentials are never logged, and every driver/transport failure is
classified into the same stable ``MySQLError`` messages the probes depend on.
"""
from __future__ import annotations

import math

import pymysql

PORT = 3306
_READ_HEADS = frozenset({"SELECT", "SHOW", "EXPLAIN"})
_AUTH_CODES = frozenset({1044, 1045, 1698, 3118})
_TRANSPORT_HINTS = (
    "can't connect", "connection refused", "unknown host", "timed out",
    "timeout", "lost connection", "gone away", "server has gone away",
    "connection reset", "broken pipe",
)


class MySQLError(RuntimeError):
    pass


def _classify(exc: BaseException) -> MySQLError:
    """Map a driver exception to a probe-safe message with no credential."""
    text = str(exc)[:240]
    code = None
    if isinstance(exc, pymysql.MySQLError) and exc.args:
        first = exc.args[0]
        if isinstance(first, int):
            code = first
    low = text.lower()
    if code in _AUTH_CODES or "access denied" in low or "auth" in low:
        return MySQLError(f"auth refused: {text}")
    if code in (2002, 2003, 2005, 2006, 2013) or any(
            hint in low for hint in _TRANSPORT_HINTS):
        return MySQLError(f"connect failed: {text}")
    if code is not None:
        return MySQLError(f"mysql error {code}: {text}")
    return MySQLError(f"query failed: {text}")


def select_one(db_ip: str, user: str, password: str, database: str,
               query: str, *, port: int = PORT, timeout_s: float = 5.0,
               connect=None) -> str:
    """Run one read-only query controller-side through PyMySQL.

    Only SELECT/SHOW/EXPLAIN are sent (anything else is refused client-side).
    Returns the first column of the first row as text. Raises MySQLError on
    any transport, auth, or protocol anomaly. ``connect`` is the PyMySQL
    connector seam for tests; production always uses ``pymysql.connect``.
    """
    if timeout_s <= 0 or not math.isfinite(timeout_s):
        raise MySQLError("timeout must be a positive finite number")
    head = query.strip().split(None, 1)[0].upper() if query.strip() else ""
    if head not in _READ_HEADS:
        raise MySQLError(f"refusing non-read query {head!r}")
    opener = connect or pymysql.connect
    kwargs = dict(
        host=db_ip, port=int(port), user=user, password=password,
        database=database or None,
        connect_timeout=max(1, int(math.ceil(timeout_s))),
        read_timeout=max(1, int(math.ceil(timeout_s))),
        write_timeout=max(1, int(math.ceil(timeout_s))),
        autocommit=True, charset="utf8mb4",
    )
    conn = None
    try:
        conn = opener(**kwargs)
        with conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
        if row is None:
            raise MySQLError("empty result set")
        if not isinstance(row, (tuple, list)) or len(row) < 1:
            # DictCursor-shaped rows are also accepted by column name only
            # if the call returns a mapping; keep this prober deliberately
            # narrow (single column) so ambiguity fails closed.
            raise MySQLError("unexpected result shape")
        value = row[0]
        if value is None:
            raise MySQLError("unexpected NULL value")
        return str(value)
    except MySQLError:
        raise
    except OSError as exc:
        raise MySQLError(f"connect failed: {str(exc)[:200]}") from exc
    except pymysql.MySQLError as exc:
        raise _classify(exc) from exc
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
