# makes `from tests.helpers import ...` resolve to THIS package (root conftest
# pins the repo root first on sys.path, so a global `tests` package can't shadow)
