"""Bounded timed output capture for red-agent command operations (plan 20).

The command output stream feeds TWO INDEPENDENT consumers: the existing
hard-bounded result buffer (model context / final facts, capped by
``runner_max_output_bytes``) and this capture, which persists ordered,
timestamped chunks so a later review can replay attacker output on the
session clock. Rules this class enforces:

* THE PIPE READER NEVER WAITS ON THE NETWORK (review finding 2) —
  ``feed`` only copies bytes into a bounded queue and returns; ONE
  bounded consumer thread performs the transport POSTs. A slow, hanging
  or failing endpoint therefore cannot delay the drain, the command
  deadline, the kill path or the containment check. ``finish`` joins the
  consumer with an explicit time BUDGET; anything undeliverable becomes
  an honest gap/drop in the summary — never a blocked stop path, never
  an unbounded queue or thread pile-up (one worker per capture, lazily
  started, bounded queue, daemon thread with an idle exit).
* MONOTONIC PRODUCER SEQUENCES (review finding 9) — every item is
  assigned its sequence number HERE, once, before delivery is even
  attempted. A retry sends the SAME seq and the SAME content; a lost
  acknowledgement can never make a later payload reuse an ambiguous
  seq. The transport returns a status string: ``stored``/``duplicate``
  are success, ``conflict`` (same seq, different bytes) is a counted
  gap, ``quota`` stops further sends, exhausted retries count as gaps.
* OBSERVED READ TIMES (review finding 10) — each feed carries the
  wall-clock instant the bytes were READ from the child pipe. Reads that
  arrive within a small merge window share one row (the window size is
  reported as ``timing_precision_s``); writes separated by real pauses
  keep their own read timestamps, independent of persist time. When no
  read timestamp was supplied the row falls back to persist time and
  the summary says so honestly (``read_timed=False``) — completeness
  and timing precision claims are never stronger than what was seen.
* HONEST GAPS — a failed chunk, a dropped queue overflow, a conflict, an
  aborted stream, or a quota drop are first-class summary numbers (and
  gap rows where possible), so playback can say "capture failed at #N"
  instead of pretending silence was the real output.

The summary returned by :meth:`summary` rides the action_result event —
the operation stays explicable even if every chunk POST failed.
"""
from __future__ import annotations

import queue
import threading
import time
from typing import Callable

KIND_OUTPUT = "output"
KIND_GAP = "gap"
KIND_TRUNCATED = "truncated"
VALID_KINDS = (KIND_OUTPUT, KIND_GAP, KIND_TRUNCATED)

# Transport status contract (finding 9): the server distinguishes an
# idempotent re-delivery from a content conflict; the producer must
# honour both without ever renumbering.
STATUS_ACCEPTED = ("stored", "duplicate")

_SENTINEL = object()


class _Item:
    __slots__ = ("seq", "kind", "text", "dropped_bytes", "read_ts", "nbytes")

    def __init__(self, seq: int, kind: str, text: str | None,
                 dropped_bytes: int | None, read_ts: float | None):
        self.seq = seq
        self.kind = kind
        self.text = text
        self.dropped_bytes = dropped_bytes
        self.read_ts = read_ts
        self.nbytes = len(text.encode("utf-8", "replace")) if text else 0


class OutputCapture:
    """Chunk a byte stream into quota-bounded, seq-numbered, timed emits.

    ``emit(seq, kind, text, dropped_bytes, read_ts) -> str`` performs ONE
    delivery attempt and returns the transport status string (an
    exception or unknown return is treated as ``"error"``). It runs ONLY
    on the bounded consumer thread — never on the pipe reader. Text is
    decoded with replacement — terminal control sequences stay literal
    data for the safe renderer; nothing here interprets them.
    """

    def __init__(self, emit: Callable[..., str],
                 *, chunk_bytes: int = 4096, quota_bytes: int = 200_000,
                 queue_size: int = 256, merge_window_s: float = 0.25,
                 flush_budget_s: float = 2.0, retries: int = 2,
                 retry_backoff_s: float = 0.2,
                 idle_exit_s: float = 300.0):
        self._emit = emit
        self.chunk_bytes = max(1, int(chunk_bytes))
        self.quota_bytes = max(0, int(quota_bytes))
        self.merge_window_s = max(0.0, float(merge_window_s))
        self._flush_budget_s = max(0.0, float(flush_budget_s))
        self._retries = max(0, int(retries))
        self._retry_backoff_s = float(retry_backoff_s)
        self._idle_exit_s = max(1.0, float(idle_exit_s))

        self._q: queue.Queue = queue.Queue(maxsize=max(1, int(queue_size)))
        self._worker: threading.Thread | None = None
        self._worker_lock = threading.Lock()

        # producer state (pipe-reader thread + finish())
        self._lock = threading.Lock()
        self._buf = bytearray()
        self._buf_read_ts: float | None = None
        self._seq = 0
        self._queued = 0             # items handed to the consumer
        self._bytes_produced = 0     # output bytes given a sequence
        self._truncated_marked = False
        self._closed = False
        self._read_timed = False

        # delivery state (consumer thread; reported under self._lock)
        self._acked = 0
        self._bytes_acked = 0
        self._conflicts = 0
        self._gaps = 0               # finish-reason gap rows persisted
        self._lost_items = 0         # queued items that could not land
        self._queue_drops = 0        # bytes dropped at feed time (queue full)
        self._dropped_after_quota = 0
        self._server_quota = False
        self._budget_exceeded = False
        self._abandoned = False

    # ------------------------------------------------------------------ #
    # producer side — pipe reader (NEVER blocks, NEVER raises)
    # ------------------------------------------------------------------ #
    def feed(self, data: bytes, *, at: float | None = None) -> None:
        """Consume output bytes as they are READ. ``at`` is the
        wall-clock instant of the read (``time.time()``); when the reader
        cannot supply it the capture records persist-time semantics
        honestly instead of inventing a timestamp."""
        if self._closed or not data:
            return
        if at is None:
            at = time.time()
        else:
            self._read_timed = True
        with self._lock:
            if self._closed:
                return
            if self._truncated_marked:
                self._dropped_after_quota += len(data)
                return
            # close the current merge window if this read arrived after
            # a real pause — two writes seconds apart must not share a
            # timestamp (finding 10)
            if (self._buf and self._buf_read_ts is not None
                    and at - self._buf_read_ts > self.merge_window_s):
                self._flush_locked()
            if not self._buf:
                self._buf_read_ts = at
            self._buf.extend(data)
            while len(self._buf) >= self.chunk_bytes:
                self._take_locked()
                if not self._buf:
                    self._buf_read_ts = None
        self._start_worker()

    def finish(self, *, error: str | None = None) -> dict:
        """Flush the merge window, record an honest final gap (if any)
        and join the consumer with a BOUNDED budget. Never raises and
        never blocks longer than the budget: undelivered items become
        counted gaps and the stop path proceeds. Idempotent."""
        if self._closed:
            return self.summary()
        with self._lock:
            if self._buf and not self._truncated_marked:
                self._flush_locked()
            elif self._buf and self._truncated_marked:
                # bytes buffered before the marker line but never sent
                # are dropped too — counted, never silently discarded
                self._dropped_after_quota += len(self._buf)
                self._buf.clear()
                self._buf_read_ts = None
            if error:
                self._gaps += 1
                self._enqueue_locked(_Item(
                    self._seq_alloc(), KIND_GAP, error, None, None))
            self._closed = True
        if self._queued:
            self._start_worker()
        try:
            self._q.put_nowait(_SENTINEL)
        except queue.Full:
            # a full backlog means the consumer is wedged on the network:
            # waiting for it here would put the network back on the stop
            # path (finding 2) — leave the flag and let the idle exit
            # retire the worker; everything pending is counted lost below
            self._budget_exceeded = True
        w = self._worker
        if w is not None:
            w.join(self._flush_budget_s)
            if w.is_alive():
                # bounded budget exceeded: whatever is still queued (or
                # in a retry) may never land — say so honestly
                self._budget_exceeded = True
        self._drain_unqueued_as_lost()
        return self.summary()

    def summary(self) -> dict:
        with self._lock:
            complete = bool(
                self._closed
                and self._acked == self._queued
                and self._conflicts == 0 and self._gaps == 0
                and self._queue_drops == 0 and self._lost_items == 0
                and not self._truncated_marked
                and not self._server_quota
                and not self._budget_exceeded
                and not self._abandoned)
            return {
                "chunks": self._acked,
                "bytes_captured": self._bytes_acked,
                "chunks_failed": self._lost_items + self._conflicts,
                "gaps": self._gaps,
                "quota_bytes": self.quota_bytes,
                "truncated": self._truncated_marked or self._server_quota,
                "dropped_after_quota": self._dropped_after_quota,
                # --- review-fix round additions (honesty metadata) ---
                "queued": self._queued,
                "queue_dropped_bytes": self._queue_drops,
                "server_quota": self._server_quota,
                "persist_budget_exceeded": self._budget_exceeded,
                "abandoned": self._abandoned,
                "read_timed": self._read_timed,
                "timing_precision_s": (self.merge_window_s
                                       if self._read_timed else None),
                "complete": complete,
            }

    # ------------------------------------------------------------------ #
    # producer helpers (pipe-reader / finish, under self._lock)
    # ------------------------------------------------------------------ #
    def _seq_alloc(self) -> int:
        seq = self._seq
        self._seq += 1
        return seq

    def _flush_locked(self) -> None:
        if not self._buf:
            return
        text = bytes(self._buf).decode("utf-8", "replace")
        read_ts = self._buf_read_ts
        self._buf.clear()
        self._buf_read_ts = None
        self._enqueue_locked(_Item(self._seq_alloc(), KIND_OUTPUT, text,
                                   None, read_ts))

    def _take_locked(self) -> None:
        chunk = bytes(self._buf[:self.chunk_bytes])
        del self._buf[:self.chunk_bytes]
        room = self.quota_bytes - self._bytes_produced
        if room <= 0:
            self._mark_truncated_locked()
            self._dropped_after_quota += len(chunk)
            return
        if len(chunk) > room:
            fit, rest = chunk[:room], chunk[room:]
            self._enqueue_locked(_Item(
                self._seq_alloc(), KIND_OUTPUT,
                fit.decode("utf-8", "replace"), None, self._buf_read_ts))
            self._mark_truncated_locked()
            self._dropped_after_quota += len(rest)
            return
        self._enqueue_locked(_Item(
            self._seq_alloc(), KIND_OUTPUT,
            chunk.decode("utf-8", "replace"), None, self._buf_read_ts))

    def _mark_truncated_locked(self) -> None:
        if self._truncated_marked:
            return
        self._truncated_marked = True
        self._enqueue_locked(_Item(
            self._seq_alloc(), KIND_TRUNCATED,
            "output capture quota reached — later output is not replayable",
            None, None))

    def _enqueue_locked(self, item: _Item) -> None:
        if item.kind == KIND_OUTPUT:
            self._bytes_produced += item.nbytes
        try:
            self._q.put_nowait(item)
            self._queued += 1
        except queue.Full:
            # bounded memory beats bounded fidelity: the overflow is a
            # counted drop and the stream stays honest (finding 2)
            self._queue_drops += max(item.nbytes, 1)

    # ------------------------------------------------------------------ #
    # consumer side — ONE bounded worker thread
    # ------------------------------------------------------------------ #
    def _start_worker(self) -> None:
        with self._worker_lock:
            if self._worker is not None:
                return
            self._worker = threading.Thread(
                target=self._consume, name="output-capture", daemon=True)
            self._worker.start()

    def _consume(self) -> None:
        idle_s = 0.0
        while True:
            try:
                item = self._q.get(timeout=1.0)
            except queue.Empty:
                if self._closed:
                    return
                idle_s += 1.0
                if idle_s >= self._idle_exit_s:
                    # finish() was never called — the capture was
                    # abandoned; exit honestly instead of living forever
                    self._abandoned = True
                    return
                continue
            idle_s = 0.0
            if item is _SENTINEL:
                return
            self._deliver(item)

    def _deliver(self, item: _Item) -> None:
        if self._server_quota and item.kind == KIND_OUTPUT:
            # the server said the budget is closed: later output cannot
            # be stored; count it as quota-lost, keep the stream honest
            with self._lock:
                self._dropped_after_quota += item.nbytes
                self._lost_items += 1
            return
        for attempt in range(self._retries + 1):
            try:
                status = self._emit(item.seq, item.kind, item.text,
                                    item.dropped_bytes, item.read_ts)
            except Exception:  # noqa: BLE001 — capture never breaks a run
                status = "error"
            if status in STATUS_ACCEPTED:
                with self._lock:
                    self._acked += 1
                    if item.kind == KIND_OUTPUT:
                        self._bytes_acked += item.nbytes
                return
            if status == "conflict":
                # same seq, different bytes: the server holds something
                # else for this sequence — the chunk is lost, counted,
                # and the sequence was NEVER reused (finding 9)
                with self._lock:
                    self._conflicts += 1
                return
            if status == "quota":
                self._server_quota = True
                return
            if attempt < self._retries:
                time.sleep(self._retry_backoff_s * (attempt + 1))
        with self._lock:
            self._lost_items += 1

    def _drain_unqueued_as_lost(self) -> None:
        lost = 0
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is not _SENTINEL:
                lost += 1
        if lost:
            with self._lock:
                self._lost_items += lost
