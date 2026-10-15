"""Web uptime scoring (pilot step 5) — control-plane HTTP+content probes.

Every 10 s (5 s timeout) the control plane fetches the target's catalogue
and checks the content marker. Samples are IDENTITY-BOUND (session +
deployment generation + host) and APPEND-ONLY. The score is % up among
VALID checks only:

  * up      — HTTP 200 AND the content marker present
  * down    — connection refused / HTTP error / marker missing (confirmed)
  * unknown — timeout or ambiguous transport error (awards nothing)

Zero valid checks => UNSCORED (never 0% and never 100%). A CONFIRMED
probe-infrastructure failure (the prober itself is broken — not the
target) INTERRUPTS the match truthfully instead of fabricating downtime.
This score stays SEPARATE from the security scorecard — no combined grade.
"""
from __future__ import annotations

import functools
import threading
import time
from datetime import datetime, timezone

CONTENT_MARKER = "Minecraft Legends"
INTERVAL_S = 10.0
TIMEOUT_S = 5.0


class ProbeInfraError(RuntimeError):
    """The PROBE machinery itself failed (not the target): the match cannot
    be scored honestly while this persists, so it is interrupted."""


def probe_once(url: str, *, timeout_s: float = TIMEOUT_S, marker: str = CONTENT_MARKER,
               _get=None) -> tuple[str, int | None, str | None]:
    """One probe -> (state, latency_ms, detail). `_get` is the transport
    seam (tests inject a fake): callable(url, timeout=..) -> resp with
    .status_code/.text, raising transport errors."""
    import httpx

    get = _get or (lambda u, timeout: httpx.get(u, timeout=timeout))
    t0 = time.monotonic()
    try:
        resp = get(url, timeout=timeout_s)
    except httpx.TimeoutException as e:   # ambiguous: blackhole vs slow app
        return "unknown", None, f"timeout: {e}"[:200]
    except httpx.ConnectError as e:       # refused/no-route to an IP target:
        return "down", None, f"connect failed: {e}"[:200]  # confirmed down
    except httpx.HTTPError as e:
        return "unknown", None, f"http transport: {e}"[:200]
    except TimeoutError as e:
        return "unknown", None, f"timeout: {e}"[:200]
    except ConnectionRefusedError as e:
        return "down", None, f"refused: {e}"[:200]
    except OSError as e:
        return "unknown", None, f"transport: {e}"[:200]
    latency = int((time.monotonic() - t0) * 1000)
    status = getattr(resp, "status_code", None)
    if status == 200 and marker in (getattr(resp, "text", "") or ""):
        return "up", latency, None
    if status is None:
        raise ProbeInfraError("probe transport returned no status")
    return "down", latency, f"http {status}, marker missing"[:200]


def summarize(samples: list[dict], *, now: datetime | None = None,
              stale_after_s: int = 30) -> dict:
    """Aggregate samples (oldest→newest dicts with state/ts/latency_ms).
    Score = % up among VALID (up|down) checks; unknown awards nothing;
    zero valid => unscored. Freshness/coverage are shown so a stale or
    low-coverage view can never masquerade as a score."""
    now = now or datetime.now(timezone.utc)
    n = len(samples)
    up = sum(1 for s in samples if s["state"] == "up")
    down = sum(1 for s in samples if s["state"] == "down")
    unknown = n - up - down
    valid = up + down
    latest = samples[-1] if samples else None
    freshness = None
    if latest and latest.get("ts"):
        ts = latest["ts"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        freshness = max(0, int((now - ts).total_seconds()))
    return {
        "samples": n, "up": up, "down": down, "unknown": unknown,
        "valid_checks": valid,
        "scored": valid > 0,
        "pct_up": round(100.0 * up / valid, 1) if valid else None,
        "coverage_pct": round(100.0 * valid / n, 1) if n else None,
        "latest": ({"state": latest["state"], "ts": str(latest.get("ts")),
                    "latency_ms": latest.get("latency_ms"),
                    "detail": latest.get("detail")} if latest else None),
        "freshness_s": freshness,
        "stale": freshness is None or freshness > stale_after_s,
    }


def summarize_for_session(db, session_id) -> dict:
    from sqlalchemy import select
    from srplatform.db.models import UptimeSample
    rows = db.execute(select(UptimeSample).where(
        UptimeSample.session_id == session_id)
        .order_by(UptimeSample.ts, UptimeSample.id)).scalars().all()
    return summarize([{"state": r.state, "ts": r.ts, "latency_ms": r.latency_ms,
                       "detail": r.detail, "host": r.host} for r in rows])


def coverage(states: list[str], *, started_at: datetime,
             ended_at: datetime | None, interval_s: float = INTERVAL_S) -> dict:
    """Schedule-aware coverage (plan 13 phase 6): the EXPECTED schedule
    comes from the match clock, so GAPS are visible evidence — received
    samples alone can never look like full coverage. Nothing is fabricated:
    a missing slot is `missed`, an ambiguous sample is `unknown`, and
    neither counts as downtime. Zero valid checks => UNSCORED.

    A scorer/prober that was itself down is therefore distinguishable from
    a target that was down (separate `missed` vs `down` accounting)."""
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    end = ended_at or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    span = max(0.0, (end - started_at).total_seconds())
    expected = int(span // interval_s)
    up = sum(1 for s in states if s == "up")
    down = sum(1 for s in states if s == "down")
    unknown = sum(1 for s in states if s not in ("up", "down"))
    valid = up + down
    missed = max(0, expected - len(states))
    return {
        "expected_checks": expected, "received": len(states),
        "up": up, "down": down, "unknown": unknown, "missed": missed,
        "valid_checks": valid,
        "scored": valid > 0,
        "coverage_pct": round(100.0 * len(states) / expected, 1) if expected else None,
        "pct_up": round(100.0 * up / valid, 1) if valid else None,
    }


def coverage_for_session(db, session_id, *, started_at, ended_at=None,
                         interval_s: float = INTERVAL_S) -> dict:
    from sqlalchemy import select
    from srplatform.db.models import UptimeSample
    rows = db.execute(select(UptimeSample.state).where(
        UptimeSample.session_id == session_id)).scalars().all()
    return coverage(list(rows), started_at=started_at, ended_at=ended_at,
                    interval_s=interval_s)


def live_projection(db, session_id) -> dict:
    """The LIVE availability projection (plan 13 phase 7): received-sample
    scoring PLUS the schedule-aware coverage denominator, keyed to the
    match clock when one exists (else the session clock). Gaps are
    `missed` evidence — a dead prober can never masquerade as coverage,
    and unknown/missed never count as downtime. Zero valid => unscored."""
    from srplatform import lifecycle
    from srplatform.db.models import Session as SessionModel
    base = summarize_for_session(db, session_id)
    m = lifecycle.get_match(db, session_id)
    if m is not None and m.started_at is not None:
        started = m.started_at
        # Clock discipline: while running, the window ends NOW (the future
        # is not evidence — counting it manufactures "missed" checks);
        # once terminal, the window freezes at ended_at (later reads must
        # not keep deteriorating completed coverage).
        ended = None if m.state == "running" else m.ended_at
    else:
        sess = db.get(SessionModel, session_id)
        started = (sess.started_at if sess is not None
                   and sess.started_at else datetime.now(timezone.utc))
        ended = None
    try:
        cov = coverage_for_session(db, session_id, started_at=started,
                                   ended_at=ended)
    except Exception:  # noqa: BLE001 — coverage never breaks the projection
        cov = {"expected_checks": None, "missed": None, "coverage_pct": None}
    base["expected_checks"] = cov.get("expected_checks")
    base["missed"] = cov.get("missed")
    if cov.get("coverage_pct") is not None:
        base["coverage_pct"] = cov["coverage_pct"]
    return base


# ------------------------------------------------- MySQL business probe ------
#: Pinned seed facts (paired 03+04): the seeded catalogue has exactly this
#: many purchase rows; a business transaction that answers anything else is
#: NOT healthy, however bright the process looks.
MYSQL_TABLE = "purchases"
MYSQL_EXPECTED_ROWS = 12


def mysql_probe_command(table: str = MYSQL_TABLE) -> str:
    """SELECT-only by construction; the reader password is read INSIDE the
    guest (never crosses the channel), and the connection is loopback on the
    owned DB guest — the same authenticated path the mysql_rows verifier
    uses (plan 13 phase 6: business transactions, not target-local claims
    of health)."""
    return ("mysql --protocol=TCP --host=127.0.0.1 --batch --skip-column-names "
            '-u mojang_reader --password="$(cat /etc/mojang-web/reader-pw)" '
            f"mojang -e 'SELECT COUNT(*) FROM `{table}`'")


def probe_mysql_via(runner, via_ip: str, db_ip: str, password: str, *,
                    table: str = MYSQL_TABLE,
                    expected: int = MYSQL_EXPECTED_ROWS):
    """The NETWORK service path (review finding): execute the SAME
    read-only business transaction FROM an owned web guest AGAINST the DB
    guest's range address. The loopback probe proves the DB answers; this
    proves the grants, firewall, listener and network path the application
    actually depends on. The credential is the deployment's own reader
    password (already present on both guests); it never appears in
    recorded details (see classification below)."""
    import shlex
    cmd = ("mysql --protocol=TCP "
           f"--host={db_ip} --batch --skip-column-names "
           f"-u mojang_reader --password={shlex.quote(password)} "
           f"mojang -e 'SELECT COUNT(*) FROM `{table}`'")
    t0 = time.monotonic()
    try:
        code, out = runner(via_ip, cmd)
    except ProbeInfraError:
        raise
    except Exception as e:  # noqa: BLE001 — channel itself unhealthy
        raise ProbeInfraError(f"management channel call failed: {e}") from e
    latency = int((time.monotonic() - t0) * 1000)
    text = str(out or "").strip()
    if code == 255:
        return ("unknown", latency,
                "ssh session not established — cannot tell whether the "
                "query ran")
    if code == 0:
        last = text.splitlines()[-1].strip() if text else ""
        if last == str(expected):
            return "up", latency, f"{table}={expected} via network path"
        return "down", latency, f"{table} count wrong via network path"
    low = text.lower()
    if "access denied" in low or "unknown user" in low:
        raise ProbeInfraError(f"probe credential refused by target: {text[:120]}")
    if ("refused" in low or "can't connect" in low or "unknown host" in low
            or "timed out" in low or "timeout" in low):
        # the NETWORK path is broken (grants/firewall/listener/service) —
        # this is target downtime even when the loopback probe is green.
        return "down", latency, f"network path: {text[:120]}"
    return "unknown", latency, f"exit {code}"


def probe_mysql(runner, ip: str, *, table: str = MYSQL_TABLE,
                expected: int = MYSQL_EXPECTED_ROWS):
    """One authenticated read-only business transaction through the
    management channel. Classification keeps the three truths separate:
    wrong answer from a reachable DB is DOWN; an unestablished session is
    UNKNOWN (cannot tell whether the query ran); broken probe credentials
    are a PROBE INFRASTRUCTURE failure, never target downtime."""
    t0 = time.monotonic()
    try:
        code, out = runner(ip, mysql_probe_command(table))
    except ProbeInfraError:
        raise
    except Exception as e:  # noqa: BLE001 — channel itself unhealthy
        raise ProbeInfraError(f"management channel call failed: {e}") from e
    latency = int((time.monotonic() - t0) * 1000)
    text = str(out or "").strip()
    if code == 255:
        return ("unknown", latency,
                "ssh session not established — cannot tell whether the "
                "query ran")
    if code == 0:
        last = text.splitlines()[-1].strip() if text else ""
        if last == str(expected):
            return "up", latency, f"{table}={expected}"
        return "down", latency, f"{table} count wrong: {last[:60]!r}"
    low = text.lower()
    if "access denied" in low or "unknown user" in low:
        # OUR credential is broken — scoring truth is compromised, this is
        # not the target's downtime.
        raise ProbeInfraError(f"probe credential refused by target: {text[:120]}")
    if "refused" in low or "can't connect" in low or "unknown host" in low:
        return "down", latency, text[:120]
    return "unknown", latency, f"exit {code}: {text[:120]}"


# ------------------------------------------------------------------ prober ---
class Prober:
    """One thread per running match: probes every 10 s, appends samples,
    and on a CONFIRMED infrastructure failure records the truth and
    interrupts the match (via the injected `interrupt` callback).

    Targets are ``(host, url)`` for HTTP/content checks or
    ``(host, "mysql", callable)`` where the callable performs one
    authenticated business transaction and returns
    ``(state, latency_ms, detail)`` (plan 13 phase 6: availability is
    proven by real transactions against owned targets, not by pings)."""

    def __init__(self, session_id, targets: list[tuple], *,
                 interval_s: float = INTERVAL_S, timeout_s: float = TIMEOUT_S,
                 record, interrupt, get=None, marker: str = CONTENT_MARKER):
        self.session_id = session_id
        self.targets = targets           # [(host, url)] or [(host, "mysql", fn)]
        self.interval_s = interval_s
        self.timeout_s = timeout_s
        self._record = record            # (host, state, latency_ms, detail) -> None
        self._interrupt = interrupt      # (reason) -> None
        self._get = get
        self._marker = marker
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> None:
        for target in self.targets:
            host, kind, spec = (target[0], target[1], target[2]) \
                if len(target) == 3 else (target[0], "http", target[1])
            try:
                if kind == "mysql":
                    state, latency, detail = spec()
                else:
                    state, latency, detail = probe_once(
                        spec, timeout_s=self.timeout_s, marker=self._marker,
                        _get=self._get)
            except ProbeInfraError as e:
                self._interrupt(f"probe infrastructure failure: {e}")
                self._stop.set()
                return
            self._record(host, state, latency, detail)

    def loop(self) -> None:
        # FIRST sample immediately (the dashboard must not stare at
        # "unscored" for a whole interval after Begin), then every interval
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as e:  # noqa: BLE001 — DB hiccup is unknown, not fatal
                for target in self.targets:
                    try:
                        self._record(target[0], "unknown", None,
                                     f"prober error: {e}"[:160])
                    except Exception:  # noqa: BLE001 — DB fully down: keep
                        break            # looping; the schedule gap shows
            self._stop.wait(self.interval_s)

    def alive(self) -> bool:
        """Is the probe thread actually running? A dead prober must never
        masquerade as coverage: gaps stay visible as `missed`, and the
        staleness flag tells the viewer the probe itself stopped."""
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> "Prober":
        self._thread = threading.Thread(
            target=self.loop, daemon=True,
            name=f"uptime-{str(self.session_id)[:8]}")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_s + 2)


_probers: dict[str, Prober] = {}
_lock = threading.Lock()


def start_for_session(db, sess, dep, *, get=None) -> bool:
    """Begin hook: start probing this session's HTTP hosts. Targets come
    from the READY deployment's resources (identity-bound). No HTTP host or
    scoring disabled -> no prober (and the dashboard says 'unscored')."""
    from srplatform.settings import get_settings
    s = get_settings()
    if not getattr(s, "uptime_scoring_enabled", True) or dep is None:
        return False
    # which hosts serve HTTP comes from the SESSION SNAPSHOT topology (never
    # the mutable YAML); deployment resources supply the generation + IPs.
    from srplatform import verification_service
    try:
        spec = verification_service.scenario_spec(db, sess.session_id)
    except Exception:  # noqa: BLE001 — no spec => nothing provable => unscored
        return False
    http_hosts = {h.get("name") for h in (spec.get("topology") or {}).get("hosts", [])
                  if "http" in (h.get("services") or [])}
    targets = [(r.get("host", "web"), f"http://{r['ip']}/")
               for r in (dep.resources or [])
               if r.get("ip") and r.get("host") in http_hosts]
    # plan 13 phase 6: hosts whose DB tier was provisioned also get an
    # authenticated read-only BUSINESS TRANSACTION probe every cycle —
    # availability is proven by the seeded data answering correctly, not
    # by the port being open. No channel => no mysql target (never a
    # fabricated or claim-based probe).
    # ONLY resources the deploy provisioned as a DB tier (mysql_probe):
    # web guests carry db_configured too (their config targets the DB),
    # but MySQL is disabled there — probing them would fabricate downtime.
    db_hosts = [r for r in (dep.resources or [])
                if r.get("ip") and r.get("mysql_probe")]
    by_host = {r.get("host"): r for r in (dep.resources or [])}
    if db_hosts:
        from srplatform.scenario_engine.orchestrator import management_runner
        runner = management_runner()
        if runner is not None:
            for r in db_hosts:
                targets.append((r.get("host", "db"), "mysql",
                                functools.partial(probe_mysql, runner,
                                                  r["ip"])))
            # Network-path probes: every web guest whose SPEC declares
            # a db_ref executes the business transaction against its
            # OWNED DB address (resolved through the deployment
            # inventory — never topology IPs). A green loopback probe
            # with a broken web→DB path is DOWN for the application —
            # this target makes that visible.
            refs = {h.get("name"): h.get("db_ref")
                    for h in (spec.get("topology") or {}).get("hosts", [])}
            for r in (dep.resources or []):
                db_res = by_host.get(refs.get(r.get("host")) or "")
                pw = (db_res or {}).get("db_reader_password")
                if (r.get("ip") and db_res is not None
                        and db_res.get("ip") and pw):
                    targets.append((r.get("host", "web") + ":db-path",
                                    "mysql", functools.partial(
                                        probe_mysql_via, runner, r["ip"],
                                        db_res["ip"], pw)))
    if not targets:
        return False
    deployment_id = str(dep.deployment_id)
    session_id = sess.session_id

    def record(host, state, latency, detail):
        from srplatform.db.session import db as db_ctx
        from srplatform.db.models import UptimeSample
        with db_ctx() as s2:
            s2.add(UptimeSample(session_id=session_id, deployment_id=deployment_id,
                                host=host, state=state, latency_ms=latency,
                                detail=detail))
            s2.commit()

    def interrupt(reason):
        from srplatform import lifecycle
        from srplatform.api.deps import get_broker
        from srplatform.db.session import db as db_ctx
        from srplatform.db.models import Event
        with db_ctx() as s2:
            s2.add(Event(session_id=session_id, ts=datetime.now(timezone.utc),
                         actor="system", action_type="uptime_probe_failed",
                         payload={"reason": reason,
                                  "note": "match interrupted — probe truth over "
                                          "fabricated downtime"}))
            s2.commit()
            try:
                lifecycle.finalize_match(s2, session_id, "probe_failure",
                                         broker=get_broker(), actor="uptime-prober")
                s2.commit()
            except lifecycle.MatchBlocked:
                pass  # scheduler retries; the interruption stays visible

    with _lock:
        old = _probers.pop(str(session_id), None)
        if old:
            old.stop()
        p = Prober(session_id, targets, record=record, interrupt=interrupt,
                   get=get).start()
        _probers[str(session_id)] = p
    return True


def stop_for_session(session_id) -> None:
    with _lock:
        p = _probers.pop(str(session_id), None)
    if p:
        p.stop()
