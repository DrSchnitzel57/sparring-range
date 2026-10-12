"""Mojang-guest verifiers (paired 03+04, step 2).

Business transactions are checked as OBSERVED BEHAVIOR, not disk images:

- `http_content`: the web tier serves the fictional catalogue over HTTP and
  the body contains pinned seed text (game titles / purchase count).
- `mysql_rows`: an authenticated READ-ONLY SELECT over the seeded lab data
  returns the exact pinned row count/content. The verifier builds the query
  itself from typed args; scenario data can never inject writes. Raw live
  MySQL disk hashes (`sha256sum /var/lib/mysql/ibdata1`) are NOT release
  evidence — normal DB writes change those bytes by design.

Both verifiers run through the trusted management exec channel against the
session's OWNED inventory (no DNS fallback). Probe failures are UNKNOWN.
"""
from __future__ import annotations

import re
import shlex

from pydantic import BaseModel, Field, field_validator

from verifiers.base import Context, Verifier


class HttpContentArg(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    expected_text: str = Field(min_length=1, max_length=512)
    path: str = Field(default="/", max_length=256)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", v):
            raise ValueError("host must be a bare hostname/IP")
        return v

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not v.startswith("/") or ".." in v.split("/") or " " in v:
            raise ValueError("path must be absolute and traversal-free")
        return v


class MysqlRowsArg(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    table: str = Field(min_length=1, max_length=64)
    expected_count: int = Field(ge=0, le=1000000)
    expected_text: str | None = Field(default=None, max_length=512)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", v):
            raise ValueError("host must be a bare hostname/IP")
        return v

    @field_validator("table")
    @classmethod
    def _table(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", v):
            raise ValueError("table must be a bare SQL identifier")
        return v


def _run(ctx: Context, host: str, cmd: str) -> tuple[int | None, str]:
    try:
        code, out = ctx.exec(host, cmd)
        return code, out or ""
    except Exception as e:  # noqa: BLE001
        return None, f"exec failed: {e}"


class HttpContent(Verifier):
    id = "http_content"
    description = "Web tier serves pinned catalogue text over HTTP"
    observed_condition = "HTTP body contains the pinned seed text"
    mitre = ["T1190"]
    version = "1"
    args_model = HttpContentArg

    def observe(self, ctx: Context, host: str, expected_text: str, path: str = "/"):
        # Local loopback probe through the management channel: the golden
        # template serves nginx on 127.0.0.1; no browser, no DNS, no WAN.
        cmd = f"curl -sf --max-time 5 http://127.0.0.1{shlex.quote(path)}"
        code, out = _run(ctx, host, cmd)
        if code is None or code != 0:
            return None, {"host": host, "path": path}, f"probe failed (exit {code})"
        ok = expected_text in out
        return ok, {"host": host, "path": path, "bytes": len(out),
                    "matches": ok}, None


class MysqlRows(Verifier):
    id = "mysql_rows"
    description = "Seeded lab rows visible through an authenticated read-only SELECT"
    observed_condition = "SELECT COUNT(*) matches the pinned seed count"
    mitre = ["T1005"]
    version = "1"
    args_model = MysqlRowsArg

    def observe(self, ctx: Context, host: str, table: str, expected_count: int,
                expected_text: str | None = None):
        # SELECT-only by construction: the query is built here from a bare
        # identifier + COUNT; scenario args can never smuggle writes.
        q = f"SELECT COUNT(*) FROM `{table}`"
        cmd = ("mysql --batch --skip-column-names --user=mojang_reader "
               f"--execute={shlex.quote(q)} mojang")
        code, out = _run(ctx, host, cmd)
        if code is None or code != 0:
            return None, {"host": host, "table": table}, f"probe failed (exit {code})"
        m = re.search(r"(\d+)", out.strip())
        if not m:
            return None, {"host": host, "table": table}, "count output unparsable"
        count = int(m.group(1))
        if count != expected_count:
            return False, {"host": host, "table": table, "count": count,
                            "expected": expected_count}, None
        if expected_text is not None:
            q2 = f"SELECT purchase_id, game_id, buyer FROM `{table}`"
            cmd2 = ("mysql --batch --skip-column-names --user=mojang_reader "
                    f"--execute={shlex.quote(q2)} mojang")
            code2, out2 = _run(ctx, host, cmd2)
            if code2 is None or code2 != 0:
                return None, {"host": host, "table": table}, \
                    f"content probe failed (exit {code2})"
            ok = expected_text in out2
            return ok, {"host": host, "table": table, "count": count,
                        "matches": ok}, None
        return True, {"host": host, "table": table, "count": count}, None
