"""HTTP client for rangectl — authenticated (F04). Token from SR_CLI_TOKEN or
~/.rangectl/token (written by `rangectl login`, mode 0600). The CLI never
touches Postgres or SSHs to targets; it is a pure API client.
"""
from __future__ import annotations

import os
from pathlib import Path

import httpx

from srplatform.settings import get_settings


def base() -> str:
    return get_settings().api_base_url


def token_file() -> Path:
    return Path(os.environ.get("RANGECTL_TOKEN_FILE", str(Path.home() / ".rangectl" / "token")))


def get_token() -> str | None:
    tok = os.environ.get("SR_CLI_TOKEN")
    if tok:
        return tok.strip()
    f = token_file()
    return f.read_text().strip() if f.exists() else None


def save_token(tok: str) -> None:
    f = token_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(tok)
    os.chmod(f, 0o600)


def headers() -> dict:
    tok = get_token()
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def call(method: str, path: str, **kw) -> httpx.Response:
    r = httpx.request(method, f"{base()}{path}", headers=headers(), timeout=kw.pop("timeout", 60), **kw)
    if r.status_code == 401:
        raise SystemExit("not authenticated — run: rangectl login")
    if r.status_code == 403:
        raise SystemExit(f"forbidden: {_detail(r)}")
    if r.status_code == 409:
        raise SystemExit(f"conflict: {_detail(r)}")
    if r.status_code == 423:
        raise SystemExit(f"blocked by safety gate:\n{_detail(r)}")
    if r.status_code >= 400:
        raise SystemExit(f"API error {r.status_code}: {_detail(r)}")
    return r


def await_operation(session_id: str, operation_id: str,
                    timeout_s: float = 600.0) -> dict:
    """Poll a 202 lifecycle operation to terminal (plan 13 phase 5). The
    CLI never re-posts: a duplicate could never create a second deployment,
    but polling is the honest client contract."""
    import time as _t
    deadline = _t.monotonic() + timeout_s
    while True:
        op = call("GET", f"/sessions/{session_id}/operation").json()
        if op["operation_id"] != operation_id:
            return op  # superseded by a newer attempt
        if op["state"] in ("succeeded", "failed", "interrupted"):
            return op
        if _t.monotonic() > deadline:
            raise SystemExit(f"operation {operation_id} stuck in "
                             f"{op['state']}/{op['phase']}")
        _t.sleep(2.0)


def _detail(r: httpx.Response) -> str:
    try:
        d = r.json().get("detail", r.text)
        if isinstance(d, dict):
            reasons = d.get("reasons")
            if reasons:
                return "\n  - " + "\n  - ".join(reasons)
            return str(d)
        return str(d)
    except Exception:
        return r.text[:300]
