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


# ------------------------------------------------------------------ prober ---
class Prober:
    """One thread per running match: probes every 10 s, appends samples,
    and on a CONFIRMED infrastructure failure records the truth and
    interrupts the match (via the injected `interrupt` callback)."""

    def __init__(self, session_id, targets: list[tuple[str, str]], *,
                 interval_s: float = INTERVAL_S, timeout_s: float = TIMEOUT_S,
                 record, interrupt, get=None, marker: str = CONTENT_MARKER):
        self.session_id = session_id
        self.targets = targets           # [(host, url)]
        self.interval_s = interval_s
        self.timeout_s = timeout_s
        self._record = record            # (host, state, latency_ms, detail) -> None
        self._interrupt = interrupt      # (reason) -> None
        self._get = get
        self._marker = marker
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> None:
        for host, url in self.targets:
            try:
                state, latency, detail = probe_once(
                    url, timeout_s=self.timeout_s, marker=self._marker,
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
                for host, _ in self.targets:
                    try:
                        self._record(host, "unknown", None, f"prober error: {e}"[:160])
                    except Exception:  # noqa: BLE001
                        break
            self._stop.wait(self.interval_s)

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
