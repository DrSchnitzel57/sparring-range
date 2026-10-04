"""Bounded model scheduling (F18): ALL calls sharing one model server pass
through ONE priority gateway per process.

  * One worker slot (== one model request at a time — what a single GPU can
    honestly serve); priority queue: interactive hints (0) over red loop
    turns (5) over AAR batches (9). Priority schedules the QUEUE; a request
    already running is never preempted — the declared interactive bound
    accounts for one in-flight request (documented, not claimed preemption).
  * Bounded queue (max_queue): overflow raises QueueFull — visible failure,
    not silent memory growth.
  * Every failure is recorded (metrics) and surfaced; a model outage does not
    poison the gateway — the next attempt may succeed (recovery). No DB
    transactions are held here: callers pass plain data.
"""
from __future__ import annotations

import heapq
import itertools
import threading
from concurrent.futures import Future


class QueueFull(RuntimeError):
    pass


PRIORITY_HINT = 0
PRIORITY_RED = 5
PRIORITY_AAR = 9


class ModelGateway:
    def __init__(self, workers: int = 1, max_queue: int = 32):
        if workers != 1:
            raise ValueError("v1 serves one model request at a time (single model slot)")
        self.max_queue = max_queue
        self._q: list[tuple] = []
        self._lock = threading.Lock()
        self._has_work = threading.Condition(self._lock)
        self._seq = itertools.count()
        self._worker = threading.Thread(target=self._run, daemon=True, name="model-gateway")
        self._worker.start()
        self.metrics = {"submitted": 0, "completed": 0, "failed": 0,
                        "rejected": 0, "last_error": None}

    def submit(self, priority: int, name: str, fn, *args, **kwargs) -> Future:
        fut: Future = Future()
        with self._lock:
            if len(self._q) >= self.max_queue:
                self.metrics["rejected"] += 1
                raise QueueFull(f"model gateway queue full ({self.max_queue})")
            heapq.heappush(self._q, (priority, next(self._seq), name, fn, args, kwargs, fut))
            self.metrics["submitted"] += 1
            self._has_work.notify()
        return fut

    def wait(self, fut: Future, timeout: float):
        """Wait for a result; cancel the queue entry if the caller gives up
        (so abandoned AAR batches don't run later for nobody)."""
        try:
            return fut.result(timeout=timeout)
        except TimeoutError:
            fut.cancel()
            raise

    def depth(self) -> int:
        with self._lock:
            return len(self._q)

    def _run(self):
        while True:
            with self._lock:
                while not self._q:
                    self._has_work.wait()
                priority, _, name, fn, args, kwargs, fut = heapq.heappop(self._q)
            if fut.cancelled():
                continue
            try:
                fut.set_result(fn(*args, **kwargs))
                self.metrics["completed"] += 1
            except Exception as e:  # noqa: BLE001
                fut.set_exception(e)
                self.metrics["failed"] += 1
                self.metrics["last_error"] = str(e)[:200]


_gateway: ModelGateway | None = None
_gateway_lock = threading.Lock()


def get_model_gateway(max_queue: int = 32) -> ModelGateway:
    global _gateway
    with _gateway_lock:
        if _gateway is None:
            from srplatform.settings import get_settings
            _gateway = ModelGateway(max_queue=get_settings().model_queue_max)
        return _gateway


def set_model_gateway(g: ModelGateway | None) -> None:
    global _gateway
    with _gateway_lock:
        _gateway = g
