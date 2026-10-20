"""Live MySQL 8.0 proof through the locked PyMySQL driver: the
controller-side client must authenticate against the DEPLOYED server
family, not just a fake connector. Spins the pinned `mysql:8.0.36` image,
proves native-password auth + business reads, and proves a wrong password
is classified as refusal (not a hang or a forged success).

Runs in the capture gate (docker present); fails loudly without docker.
"""
from __future__ import annotations

import re
import subprocess
import time
import uuid

import pytest

pytestmark = pytest.mark.capture

IMAGE = "mysql:8.0.36"


def _docker(*args, timeout=120):
    r = subprocess.run(["docker", *args], capture_output=True, text=True,
                       timeout=timeout)
    if r.returncode != 0:
        pytest.fail(f"docker {' '.join(args[:3])} failed — prerequisite: "
                    f"{(r.stderr or r.stdout)[-800:]}")
    return r.stdout.strip()


@pytest.fixture()
def mysql():
    name = f"sr-mysql-live-{uuid.uuid4().hex[:8]}"
    _docker("run", "-d", "--rm", "--name", name,
            "-p", "127.0.0.1::3306",
            "-e", "MYSQL_RANDOM_ROOT_PASSWORD=yes", IMAGE)
    try:
        port = None
        for _ in range(60):
            out = _docker("port", name, "3306")
            if ":" in out:  # "127.0.0.1:49153"
                port = int(out.rsplit(":", 1)[1])
                break
            time.sleep(2)
        assert port, "mysql port never published"
        # readiness: TCP greeting (no auth needed, no guest code)
        from srplatform.uptime import probe_mysql_banner
        deadline = time.monotonic() + 180
        while True:
            st, _, _ = probe_mysql_banner("127.0.0.1", port=port,
                                          timeout_s=2.0)
            if st == "up":
                break
            assert time.monotonic() < deadline, "mysqld never greeted"
            time.sleep(2)
        log = _docker("logs", name)
        m = re.search(r"GENERATED ROOT PASSWORD:\s*(\S+)", log)
        assert m, f"no generated root password in log:\n{log[-500:]}"
        yield {"name": name, "host": "127.0.0.1", "port": port,
               "rootpw": m.group(1)}
    finally:
        # Cleanup is verified, not assumed — and scoped to THIS fixture's
        # own mounts (a host-wide volume diff false-positives on unrelated
        # concurrent docker work). Record the container's volumes, remove
        # with -v, then prove each recorded volume is actually gone.
        import json as _json
        owned = []
        insp = subprocess.run(
            ["docker", "inspect", name],
            capture_output=True, text=True, timeout=60)
        if insp.returncode == 0:
            try:
                for m in _json.loads(insp.stdout)[0].get("Mounts", []):
                    if m.get("Type") == "volume" and m.get("Name"):
                        owned.append(m["Name"])
            except (ValueError, KeyError, IndexError, TypeError):
                pass
        rm = subprocess.run(["docker", "rm", "-f", "-v", name],
                            capture_output=True, text=True, timeout=60)
        assert rm.returncode == 0, \
            f"fixture cleanup failed: {(rm.stderr or rm.stdout)[-400:]}"
        gone = subprocess.run(
            ["docker", "inspect", name],
            capture_output=True, text=True, timeout=60)
        assert gone.returncode != 0, f"container still present: {name}"
        for vol in owned:
            still = subprocess.run(
                ["docker", "volume", "inspect", vol],
                capture_output=True, text=True, timeout=60)
            assert still.returncode != 0, \
                f"fixture volume leaked: {vol}"


def _dexec(mysql, sql):
    r = subprocess.run(
        ["docker", "exec", mysql["name"], "mysql",
         "--user=root", f"--password={mysql['rootpw']}",
         "--protocol=socket", "-e", sql],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, (sql[:80], (r.stderr or r.stdout)[-500:])
    return r.stdout


def test_live_native_password_business_read(mysql):
    """End to end against real 8.0.36, provisioned exactly like the guest
    provisioning does (native-password reader, SELECT-only grant)."""
    from srplatform import mysql_direct
    host, port = mysql["host"], mysql["port"]
    # A wrong password against stock caching_sha2_password root must be a
    # bounded, classified refusal — never a hang or a forged success.
    with pytest.raises(mysql_direct.MySQLError, match="refused|auth|connect"):
        mysql_direct.select_one(host, "root", "wrong-" + mysql["rootpw"], "",
                                "SELECT 1", port=port, timeout_s=10.0)
    _dexec(mysql,
           "CREATE DATABASE IF NOT EXISTS mojang; "
           "CREATE TABLE IF NOT EXISTS mojang.purchases "
           "(purchase_id INT PRIMARY KEY, game_id INT, buyer VARCHAR(64)); "
           + " ".join(
               f"INSERT IGNORE INTO mojang.purchases VALUES ({i},{i},'b{i}');"
               for i in range(1, 13))
           + " CREATE USER IF NOT EXISTS 'mojang_reader'@'%' "
             "IDENTIFIED WITH mysql_native_password BY 'readerpw'; "
             "GRANT SELECT ON mojang.* TO 'mojang_reader'@'%'; "
             "FLUSH PRIVILEGES;")
    got = mysql_direct.select_one(
        host, "mojang_reader", "readerpw", "mojang",
        "SELECT COUNT(*) FROM purchases", port=port, timeout_s=10.0)
    assert got.strip() == "12", got
    # wrong password reads as refusal, never success or hang
    with pytest.raises(mysql_direct.MySQLError, match="refused"):
        mysql_direct.select_one(
            host, "mojang_reader", "wrongpw", "mojang",
            "SELECT COUNT(*) FROM purchases", port=port, timeout_s=10.0)
    # non-read statements are refused client-side before any packet
    with pytest.raises(mysql_direct.MySQLError, match="non-read"):
        mysql_direct.select_one(
            host, "mojang_reader", "readerpw", "mojang",
            "DROP TABLE purchases", port=port, timeout_s=10.0)
