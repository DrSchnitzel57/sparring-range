"""Bounded timed output capture for red-agent command operations (plan 20).

The command output stream feeds TWO INDEPENDENT consumers: the existing
hard-bounded result buffer (model context / final facts, capped by
``runner_max_output_bytes``) and this capture, which persists ordered,
timestamped chunks so a later review can replay attacker output on the
session clock. Rules this class enforces:

* BOUNDED MEMORY AND PERSISTENCE — fixed-size chunks, a byte quota per
  operation, and a single ``truncated`` marker when the quota closes the
  capture; everything past it is counted, never silently dropped;
* NEVER BLOCKS THE RUN OR STOP — ``emit`` failures (the transport POSTing
  a chunk) are swallowed and counted as gaps; the reader keeps draining
  the pipe regardless. Capture is additive evidence: exit code, timeout,
  truncation and containment facts live on the operation row and the
  action_result event even when nothing here persists;
* HONEST GAPS — a failed chunk, an aborted stream, or a quota drop are
  first-class rows/summary numbers, so playback can say "capture failed
  at #N" instead of pretending silence was the real output.

The summary returned by :meth:`summary` rides the action_result event —
the operation stays explicable even if every chunk POST failed.
"""
from __future__ import annotations

from typing import Callable

KIND_OUTPUT = "output"
KIND_GAP = "gap"
KIND_TRUNCATED = "truncated"
VALID_KINDS = (KIND_OUTPUT, KIND_GAP, KIND_TRUNCATED)


class OutputCapture:
    """Chunk a byte stream into quota-bounded, seq-numbered emits.

    ``emit(seq, kind, text, dropped_bytes) -> bool`` must never raise
    (failures are also handled here anyway); returning False counts the
    chunk as a persistence gap. Text is decoded with replacement —
    terminal control sequences stay literal data for the safe renderer;
    nothing here interprets them.
    """

    def __init__(self, emit: Callable[[int, str, str | None, int | None],
                                      bool],
                 *, chunk_bytes: int = 4096, quota_bytes: int = 200_000):
        self._emit = emit
        self.chunk_bytes = max(1, int(chunk_bytes))
        self.quota_bytes = max(0, int(quota_bytes))
        self._pending = bytearray()
        self._seq = 0
        self._bytes_sent = 0
        self._chunks_sent = 0
        self._chunks_failed = 0
        self._gaps = 0
        self._dropped_after_quota = 0
        self._truncated_marked = False
        self._closed = False

    # ------------------------------------------------------------------ #
    def feed(self, data: bytes) -> None:
        """Consume output bytes as they are read. Never raises."""
        if self._closed or not data:
            return
        if self._truncated_marked:
            self._dropped_after_quota += len(data)
            return
        self._pending.extend(data)
        while len(self._pending) >= self.chunk_bytes:
            self._take(self.chunk_bytes)

    def finish(self, *, error: str | None = None) -> dict:
        """Flush the tail, record an honest final gap (if any) and return
        the summary. Idempotent: only the first close persists."""
        if self._closed:
            return self.summary()
        if self._pending and not self._truncated_marked:
            self._take(len(self._pending))
        elif self._pending and self._truncated_marked:
            # bytes buffered before the marker line but never sent are
            # dropped too — counted, never silently discarded
            self._dropped_after_quota += len(self._pending)
            self._pending.clear()
        if error:
            self._gaps += 1
            if not self._emit_gap(reason=error):
                self._chunks_failed += 1
        self._closed = True
        return self.summary()

    def summary(self) -> dict:
        return {
            "chunks": self._chunks_sent,
            "bytes_captured": self._bytes_sent,
            "chunks_failed": self._chunks_failed,
            "gaps": self._gaps,
            "quota_bytes": self.quota_bytes,
            "truncated": self._truncated_marked,
            "dropped_after_quota": self._dropped_after_quota,
            "complete": bool(self._closed and self._chunks_failed == 0
                             and self._gaps == 0
                             and not self._truncated_marked),
        }

    # ------------------------------------------------------------------ #
    def _take(self, n: int) -> None:
        chunk = bytes(self._pending[:n])
        del self._pending[:n]
        room = self.quota_bytes - self._bytes_sent
        if room <= 0:
            self._mark_truncated()
            self._dropped_after_quota += len(chunk)
            return
        if len(chunk) > room:
            # split at the quota line: the fitting part persists, then
            # the marker, then the remainder counts as dropped
            fit, rest = chunk[:room], chunk[room:]
            self._send(KIND_OUTPUT, fit.decode("utf-8", "replace"), None)
            self._mark_truncated()
            self._dropped_after_quota += len(rest)
            return
        self._send(KIND_OUTPUT, chunk.decode("utf-8", "replace"), None)

    def _mark_truncated(self) -> None:
        if self._truncated_marked:
            return
        self._truncated_marked = True
        if self._try_emit(self._seq, KIND_TRUNCATED,
                          "output capture quota reached — later output is "
                          "not replayable", None):
            self._seq += 1
            self._chunks_sent += 1
        else:
            self._chunks_failed += 1

    def _emit_gap(self, *, reason: str) -> bool:
        dropped = self._dropped_after_quota
        ok = self._try_emit(self._seq, KIND_GAP, reason,
                            dropped if dropped else None)
        if ok:
            self._seq += 1
        else:
            self._chunks_failed += 1
        return ok

    def _try_emit(self, seq: int, kind: str, text: str | None,
                  dropped: int | None) -> bool:
        try:
            return bool(self._emit(seq, kind, text, dropped))
        except Exception:  # noqa: BLE001 — capture never breaks the run
            return False

    def _send(self, kind: str, text: str, dropped: int | None) -> None:
        ok = self._try_emit(self._seq, kind, text, dropped)
        if ok:
            self._seq += 1
            self._chunks_sent += 1
            self._bytes_sent += len(text.encode("utf-8", "replace"))
        else:
            # count the lost bytes as an honest gap, keep the stream going
            self._chunks_failed += 1
            self._gaps += 1
