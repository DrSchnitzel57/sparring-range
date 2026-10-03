"""Priority request queue (M5): interactive work (hints) must never starve
behind the red agent's 200th recon call or a giant AAR batch on one GPU box
(Part 6.5). One worker thread == one model slot; tasks carry a priority."""
from __future__ import annotations

import heapq
import itertools
import threading
from concurrent.futures import Future


class PriorityTaskQueue:
    def __init__(self, workers: int = 1):
        self._q: list[tuple[int, int, object, object, tuple, dict, Future]] = []
        self._lock = threading.Lock()
        self._has_work = threading.Condition(self._lock)
        self._seq = itertools.count()
        self._workers = [threading.Thread(target=self._run, daemon=True) for _ in range(workers)]
        for w in self._workers:
            w.start()
        self.finished_order: list[str] = []

    def submit(self, priority: int, name: str, fn, *args, **kwargs) -> Future:
        fut: Future = Future()
        with self._lock:
            heapq.heappush(self._q, (priority, next(self._seq), name, fn, args, kwargs, fut))
            self._has_work.notify()
        return fut

    def _run(self):
        while True:
            with self._lock:
                while not self._q:
                    self._has_work.wait()
                priority, _, name, fn, args, kwargs, fut = heapq.heappop(self._q)
            try:
                fut.set_result(fn(*args, **kwargs))
            except Exception as e:  # noqa: BLE001
                fut.set_exception(e)
            finally:
                self.finished_order.append(name)


# singleton used by the API (coach calls only; red-loop traffic goes through
# the relay endpoint when Drew enables single-model serialization)
coach_queue = PriorityTaskQueue(workers=1)
