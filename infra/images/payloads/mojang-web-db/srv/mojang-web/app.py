#!/usr/bin/env python3
"""Mojang catalogue app (paired 03+04): local nginx/Python guest app.

Backends:
- local: reads fictional purchases from /srv/mojang-web/seeds.json.
- mysql: reads the same rows from MySQL through PyMySQL as the read-only
  `mojang_reader` role (SELECT-only; no writes, no admin credential here).

The app exposes:
- GET /            catalogue (three games + purchase count).
- GET /health      liveness (for service checks, not scoring).
- GET /diagnostic?cmd=<name>  DELIBERATELY VULNERABLE lab flaw: runs a
  constrained command as the limited `web-user` account and writes
  /tmp/mojang-diag-proof.txt. Documented fix (preserves service):
  set MOJANG_DIAG_ENABLED=off in /etc/mojang-web/config.env and
  `systemctl restart mojang-web` — the catalogue keeps serving.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

SEEDS_PATH = pathlib.Path(
    os.environ.get("MOJANG_SEED_PATH", "/srv/mojang-web/seeds.json"))
BACKEND = os.environ.get("MOJANG_DATA_BACKEND", "local")
DIAG_ENABLED = os.environ.get("MOJANG_DIAG_ENABLED", "on") == "on"
PORT = int(os.environ.get("MOJANG_PORT", "8080"))

# Constrained diagnostic allowlist: names only, no shell metacharacters, no
# paths, no arguments. Anything else is refused (and the refusal is the
# repair signal, not a bypass).
DIAG_ALLOW = {"whoami", "id", "uptime"}


def load_purchases() -> list[dict]:
    if BACKEND == "mysql":
        import pymysql  # noqa: WPS433 — guest-only dependency, pinned in manifest

        conn = pymysql.connect(
            host=os.environ.get("MOJANG_MYSQL_HOST", "127.0.0.1"),
            user=os.environ.get("MOJANG_MYSQL_USER", "mojang_reader"),
            password=os.environ.get("MOJANG_MYSQL_PASSWORD", ""),
            database=os.environ.get("MOJANG_MYSQL_DB", "mojang"),
            connect_timeout=5)
        try:
            with conn.cursor() as cur:
                # SELECT-only by construction (same contract as the verifier).
                cur.execute("SELECT purchase_id, game_id, buyer, price_cents FROM purchases")
                rows = cur.fetchall()
                return [{"purchase_id": r[0], "game_id": r[1], "buyer": r[2],
                         "price_cents": r[3]} for r in rows]
        finally:
            conn.close()
    data = json.loads(SEEDS_PATH.read_text())
    return data["purchases"]


def catalogue_body() -> str:
    data = json.loads(SEEDS_PATH.read_text())
    games = [g["title"] for g in data["games"]]
    try:
        purchases = load_purchases()
    except Exception as e:  # noqa: BLE001 — downtime is downtime, not a crash
        return ("<html><body><h1>Mojang shop (degraded)</h1>"
                f"<p>data unavailable: {e}</p></body></html>")
    lines = ["<html><body><h1>Mojang shop (fictional catalogue)</h1><ul>"]
    for title in games:
        lines.append(f"<li>{title}</li>")
    lines.append("</ul>")
    lines.append(f"<p>{len(purchases)} fictional purchases</p>")
    for p in purchases[:12]:
        lines.append(f"<p>{p['purchase_id']} {p['game_id']} {p['buyer']}</p>")
    lines.append("</body></html>")
    return "\n".join(lines)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet lab logs; no secrets ever logged
        pass

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/health":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parts.path == "/diagnostic":
            if not DIAG_ENABLED:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"diagnostic disabled\n")
                return
            cmd = parse_qs(parts.query).get("cmd", [""])[0]
            if cmd not in DIAG_ALLOW:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"unknown diagnostic\n")
                return
            # Deliberate flaw: runs as the limited web-user account.
            p = subprocess.run(["sudo", "-n", "-u", "web-user", cmd],
                               capture_output=True, text=True, timeout=10)
            pathlib.Path("/tmp/mojang-diag-proof.txt").write_text(
                f"DIAG{{web-user}} {cmd} {p.stdout[:200]}")
            body = f"ran {cmd} as web-user\n".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parts.path in ("/", "/index.html"):
            body = catalogue_body().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def main() -> None:
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
