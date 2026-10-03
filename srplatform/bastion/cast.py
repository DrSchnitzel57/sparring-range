"""asciinema cast v2 writer (plan Part 2: recordings are .cast files for replay).

Format: first line = JSON header; following lines = [delay_seconds, "o"|"i", data].
The bastion tees BOTH directions: 'o' = target->client, 'i' = client->target.
Replay later with `asciinema play file.cast` (or the M7 web player).
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class CastWriter:
    def __init__(self, path: Path | str, width: int = 120, height: int = 32, metadata: dict | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._t0 = time.time()
        self._f = self.path.open("w", encoding="utf-8")
        header = {"version": 2, "width": width, "height": height, "timestamp": int(self._t0)}
        header.update(metadata or {})
        self._f.write(json.dumps(header) + "\n")

    def write(self, direction: str, data: str) -> None:
        """direction: 'o' (target output) or 'i' (client input)."""
        if not data:
            return
        delay = round(time.time() - self._t0, 6)
        self._f.write(json.dumps([delay, direction, data]) + "\n")

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
