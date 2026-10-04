"""asciinema cast v2 writer (plan Part 2: recordings are .cast files for replay).

Format: first line = JSON header (`timestamp` = the RECORDING's epoch — the web
player aligns absolute event times to it, F17); following lines =
[elapsed_seconds, "o"|"i", data] plus ["width","height","r"] resize frames.

F16/F08 fixes here: exclusive creation (never overwrite evidence), monotonic
elapsed time, per-line flush (crash tolerance with the buffer drained before
close), and an honest byte cap (visible TRUNCATED marker frame, not silent).
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class CastWriter:
    def __init__(self, path: Path | str, width: int = 120, height: int = 32,
                 metadata: dict | None = None, max_bytes: int = 32 * 1024 * 1024):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self._t0 = time.time()
        self._mono = time.monotonic()
        self._closed = False
        self.truncated = False
        # exclusive create — recordings never overwrite each other (F16)
        self._f = self.path.open("x", encoding="utf-8")
        header = {"version": 2, "width": width, "height": height, "timestamp": int(self._t0)}
        header.update(metadata or {})
        self._f.write(json.dumps(header) + "\n")
        self._f.flush()

    def write(self, direction: str, data: str) -> None:
        """direction: 'o' (target output) or 'i' (client input)."""
        if not data or self._closed:
            return
        if self.path.stat().st_size > self.max_bytes:
            if not self.truncated:
                self.truncated = True
                delay = round(time.monotonic() - self._mono, 6)
                self._f.write(json.dumps([delay, "o",
                                          "\n[recording truncated at size cap]"]) + "\n")
                self._f.flush()
            return
        delay = round(time.monotonic() - self._mono, 6)
        self._f.write(json.dumps([delay, direction, data]) + "\n")
        self._f.flush()

    def resize(self, width: int, height: int) -> None:
        if self._closed:
            return
        delay = round(time.monotonic() - self._mono, 6)
        self._f.write(json.dumps([width, height, "r"]) + "\n")
        self._f.flush()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
