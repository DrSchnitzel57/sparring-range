"""Protected durable broker ledger (SQLite, independent of the app DB).

Everything the broker intends to do to the outside world is written HERE
before the side effect, and confirmed after. On restart the ledger is the
authority: pending intents are reconciled against reality (backend reads),
never blindly replayed; active claims whose control lease has lapsed force
the fail-closed stop path.

Tables:
  claims       VMs the broker owns (reserved/creating/created/enrolled/
               stopping/destroyed/unknown) with session + generation
  intents      idempotency records: key -> op + args-hash + state + result
  latch        single row: cessation engaged (reason, time)
  lease        single row: control-plane heartbeat (holder, armed, renewed)
  obligations  unresolved duties (stop/destroy not confirmed) that block
               release and survive every restart
  audit        append-only broker-local trail
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from .errors import BrokerConflict

CLAIM_STATES = ("reserved", "creating", "created", "enrolled", "stopping",
                "destroying", "destroyed", "unknown")
ACTIVE_CLAIM_STATES = ("reserved", "creating", "created", "enrolled", "stopping",
                       "destroying", "unknown")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS claims (
  vmid INTEGER PRIMARY KEY, node TEXT NOT NULL, name TEXT, session_id TEXT,
  generation TEXT NOT NULL DEFAULT '1', kind TEXT NOT NULL DEFAULT 'clone',
  state TEXT NOT NULL, task_upid TEXT, detail TEXT,
  created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS intents (
  key TEXT PRIMARY KEY, op TEXT NOT NULL, args_hash TEXT NOT NULL,
  state TEXT NOT NULL, result TEXT,
  created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS latch (
  id INTEGER PRIMARY KEY CHECK (id = 1), latched INTEGER NOT NULL,
  reason TEXT, latched_at REAL
);
CREATE TABLE IF NOT EXISTS lease (
  id INTEGER PRIMARY KEY CHECK (id = 1), holder TEXT, armed INTEGER NOT NULL,
  renewed_at REAL
);
CREATE TABLE IF NOT EXISTS obligations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, vmid INTEGER, kind TEXT NOT NULL,
  state TEXT NOT NULL, detail TEXT,
  created_at REAL NOT NULL, resolved_at REAL
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
  kind TEXT NOT NULL, detail TEXT
);
"""


def args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True,
                                     default=str).encode()).hexdigest()


class Ledger:
    """Small, locked, WAL-mode SQLite store. Every mutation is committed
    immediately — the ledger never relies on an ambient transaction."""

    def __init__(self, path: str | Path, now=time.time):  # noqa: ARG002
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._now = now
        self._lock = threading.RLock()
        self._con = sqlite3.connect(str(self.path), check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=FULL")
        with self._lock:
            self._con.executescript(_SCHEMA)
            self._con.commit()

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # ---------------------------------------------------------------- intents ---
    def begin_intent(self, key: str, op: str, args: dict) -> tuple[str, object]:
        """Returns ('execute', None) when this caller must perform the effect,
        or ('replay', result) when a DONE intent for the SAME args exists.
        Same key, different args -> BrokerConflict (never silent).
        A 'pending' intent means a previous attempt died mid-effect: the
        caller must RECONCILE (inspect reality), not assume either outcome."""
        h = args_hash(args)
        now = self._now()
        with self._lock:
            row = self._con.execute(
                "SELECT op, args_hash, state, result FROM intents WHERE key = ?",
                (key,)).fetchone()
            if row is not None:
                if row[1] != h:
                    raise BrokerConflict(
                        f"idempotency key {key!r} reused with different args")
                if row[2] == "done":
                    return "replay", json.loads(row[3]) if row[3] is not None else None
                return "pending", None
            self._con.execute(
                "INSERT INTO intents(key, op, args_hash, state, created_at, updated_at) "
                "VALUES(?, ?, ?, 'pending', ?, ?)", (key, op, h, now, now))
            self._con.commit()
            return "execute", None

    def finish_intent(self, key: str, state: str, result=None) -> None:
        assert state in ("done", "failed")
        with self._lock:
            self._con.execute(
                "UPDATE intents SET state = ?, result = ?, updated_at = ? WHERE key = ?",
                (state, json.dumps(result, default=str) if result is not None else None,
                 self._now(), key))
            self._con.commit()

    def pending_intents(self) -> list[dict]:
        with self._lock:
            rows = self._con.execute(
                "SELECT key, op, created_at FROM intents WHERE state = 'pending' "
                "ORDER BY created_at").fetchall()
        return [{"key": k, "op": o, "created_at": c} for k, o, c in rows]

    # ----------------------------------------------------------------- claims ---
    def upsert_claim(self, vmid: int, *, node: str, name: str | None = None,
                     session_id: str | None = None, generation: str | int = 1,
                     kind: str = "clone", state: str, task_upid: str | None = None,
                     detail: dict | None = None) -> None:
        assert state in CLAIM_STATES, state
        now = self._now()
        session_id = str(session_id) if session_id is not None else None
        generation = str(generation)
        with self._lock:
            cur = self._con.execute("SELECT state FROM claims WHERE vmid = ?", (vmid,))
            row = cur.fetchone()
            if row is None:
                self._con.execute(
                    "INSERT INTO claims(vmid, node, name, session_id, generation, kind, "
                    "state, task_upid, detail, created_at, updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (vmid, node, name, session_id, generation, kind, state, task_upid,
                     json.dumps(detail or {}), now, now))
            else:
                self._con.execute(
                    "UPDATE claims SET node=?, name=COALESCE(?, name), "
                    "session_id=COALESCE(?, session_id), generation=?, kind=?, state=?, "
                    "task_upid=COALESCE(?, task_upid), detail=?, updated_at=? WHERE vmid=?",
                    (node, name, session_id, generation, kind, state, task_upid,
                     json.dumps(detail or {}), now, vmid))
            self._con.commit()

    def get_claim(self, vmid: int) -> dict | None:
        with self._lock:
            row = self._con.execute(
                "SELECT vmid,node,name,session_id,generation,kind,state,task_upid,detail,"
                "created_at,updated_at FROM claims WHERE vmid = ?", (vmid,)).fetchone()
        if row is None:
            return None
        keys = ("vmid", "node", "name", "session_id", "generation", "kind", "state",
                "task_upid", "detail", "created_at", "updated_at")
        d = dict(zip(keys, row))
        d["detail"] = json.loads(d["detail"] or "{}")
        return d

    def active_claims(self) -> list[dict]:
        q = ("SELECT vmid FROM claims WHERE state IN (%s) ORDER BY vmid"
             % ",".join("?" * len(ACTIVE_CLAIM_STATES)))
        with self._lock:
            vmids = [r[0] for r in self._con.execute(q, ACTIVE_CLAIM_STATES).fetchall()]
        out = []
        for v in vmids:
            c = self.get_claim(v)
            if c:
                out.append(c)
        return out

    def all_claims(self) -> list[dict]:
        with self._lock:
            vmids = [r[0] for r in self._con.execute(
                "SELECT vmid FROM claims ORDER BY vmid").fetchall()]
        return [c for v in vmids if (c := self.get_claim(v))]

    # ------------------------------------------------------- latch and lease ---
    def set_latch(self, latched: bool, reason: str | None = None) -> None:
        now = self._now()
        with self._lock:
            if latched:
                cur = self._con.execute("SELECT latched, reason FROM latch WHERE id=1").fetchone()
                if cur and cur[0]:
                    return  # FIRST latch reason wins — never overwritten
                self._con.execute(
                    "INSERT INTO latch(id,latched,reason,latched_at) VALUES(1,1,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET latched=1, reason=excluded.reason, "
                    "latched_at=excluded.latched_at", (reason, now))
            else:
                self._con.execute(
                    "INSERT INTO latch(id,latched,reason,latched_at) VALUES(1,0,NULL,NULL) "
                    "ON CONFLICT(id) DO UPDATE SET latched=0, reason=NULL, latched_at=NULL")
            self._con.commit()

    def get_latch(self) -> dict:
        with self._lock:
            row = self._con.execute(
                "SELECT latched, reason, latched_at FROM latch WHERE id=1").fetchone()
        if row is None:
            return {"latched": False, "reason": None, "latched_at": None}
        return {"latched": bool(row[0]), "reason": row[1], "latched_at": row[2]}

    def renew_lease(self, holder: str) -> dict:
        now = self._now()
        with self._lock:
            self._con.execute(
                "INSERT INTO lease(id,holder,armed,renewed_at) VALUES(1,?,1,?) "
                "ON CONFLICT(id) DO UPDATE SET holder=excluded.holder, armed=1, "
                "renewed_at=excluded.renewed_at", (holder, now))
            self._con.commit()
        return {"armed": True, "renewed_at": now}

    def disarm_lease(self) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO lease(id,holder,armed,renewed_at) VALUES(1,NULL,0,NULL) "
                "ON CONFLICT(id) DO UPDATE SET armed=0, holder=NULL, renewed_at=NULL")
            self._con.commit()

    def get_lease(self) -> dict:
        with self._lock:
            row = self._con.execute(
                "SELECT holder, armed, renewed_at FROM lease WHERE id=1").fetchone()
        if row is None:
            return {"holder": None, "armed": False, "renewed_at": None}
        return {"holder": row[0], "armed": bool(row[1]), "renewed_at": row[2]}

    # ------------------------------------------------------------ obligations ---
    def add_obligation(self, kind: str, vmid: int | None = None,
                       detail: str = "") -> int:
        with self._lock:
            cur = self._con.execute(
                "INSERT INTO obligations(vmid, kind, state, detail, created_at) "
                "VALUES(?,?, 'open', ?, ?)", (vmid, kind, detail, self._now()))
            self._con.commit()
            return int(cur.lastrowid)

    def open_obligations(self) -> list[dict]:
        with self._lock:
            rows = self._con.execute(
                "SELECT id, vmid, kind, detail, created_at FROM obligations "
                "WHERE state = 'open' ORDER BY id").fetchall()
        return [{"id": i, "vmid": v, "kind": k, "detail": d, "created_at": c}
                for i, v, k, d, c in rows]

    def resolve_obligation(self, oid: int) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE obligations SET state='resolved', resolved_at=? "
                "WHERE id=? AND state='open'", (self._now(), oid))
            self._con.commit()

    # ------------------------------------------------------------------ audit ---
    def audit(self, kind: str, detail: dict | None = None) -> None:
        with self._lock:
            self._con.execute("INSERT INTO audit(ts, kind, detail) VALUES(?,?,?)",
                              (self._now(), kind, json.dumps(detail or {}, default=str)))
            self._con.commit()

    def audit_tail(self, n: int = 50) -> list[dict]:
        with self._lock:
            rows = self._con.execute(
                "SELECT seq, ts, kind, detail FROM audit ORDER BY seq DESC LIMIT ?",
                (n,)).fetchall()
        return [{"seq": s, "ts": t, "kind": k, "detail": json.loads(d or "{}")}
                for s, t, k, d in reversed(rows)]
