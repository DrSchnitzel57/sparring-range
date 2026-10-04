"""Root conftest: pin the repo root first on sys.path so `tests.*` and project
imports resolve to this checkout, never to a globally installed look-alike."""
import pathlib
import sys

_ROOT = str(pathlib.Path(__file__).resolve().parent)
if sys.path and sys.path[0] != _ROOT:
    sys.path.insert(0, _ROOT)
