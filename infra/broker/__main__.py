"""Broker daemon entry point: python -m infra.broker"""
from __future__ import annotations

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
