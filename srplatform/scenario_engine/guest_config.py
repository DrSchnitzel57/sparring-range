"""Deploy-time guest configuration (plan 13 phase 3).

Templates ship SAFE DEFAULTS only: MySQL bound to loopback, a synthetic
build-time reader credential, no knowledge of its peers. Deployment is what
turns the topology into a working system, per host role:

* DB host (referenced by any web host's ``db_ref``): a FRESH per-deployment
  reader password; grants ONLY for the owned web guest(s) and the loopback
  probe; the listener binds loopback + the guest's OWNED range address only;
  the firewall narrows 3306 to the owned web source. No live credential is
  ever baked into a template, and every clone generation re-provisions.
* Web host with ``db_ref``: ``/etc/mojang-web/config.env`` rewritten
  atomically to target the OWNED DB IP with the per-deployment reader
  credential, then the app is restarted and the write is READ BACK.

All commands are idempotent (deterministic user names, IF NOT EXISTS,
grep-guarded firewall, atomic writes) so resume re-runs them safely, and
every failure propagates loudly — an unprovisioned guest is a failed
deployment, never a silently half-configured one. The reader password lives
in the deployment row (ephemeral, per generation) and on the guests; it is
never logged (commands are built so the secret appears only in-file writes
and single-quoted SQL, and events record only the fact of provisioning).
"""
from __future__ import annotations

import ipaddress
import secrets

CONFIG_ENV_PATH = "/etc/mojang-web/config.env"
READER_PW_PATH = "/etc/mojang-web/reader-pw"
READER_USER = "mojang_reader"
MYSQL_DB = "mojang"


def _ip(value: str, field: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid IP address: {value!r}") from exc


def plan_db_provisioning(spec: dict) -> list[dict]:
    """Pure plan from the scenario topology: DB hosts first (with the owned
    web sources that must reach them), then web hosts that reference a DB.
    Returns [] for scenarios without a DB tier (web-local preset)."""
    hosts = {h["name"]: h for h in spec["topology"]["hosts"]}
    db_sources: dict[str, list[str]] = {}
    web_needs: list[tuple[str, str]] = []
    for h in spec["topology"]["hosts"]:
        ref = h.get("db_ref")
        if not ref:
            continue
        if ref not in hosts:
            raise ValueError(f"host {h['name']!r} db_ref {ref!r} is not in "
                             "the topology")
        db_sources.setdefault(ref, []).append(h["name"])
        web_needs.append((h["name"], ref))
    plan: list[dict] = []
    for db_name, web_names in sorted(db_sources.items()):
        db_host = hosts[db_name]
        plan.append({
            "kind": "db", "host": db_name,
            "ip": _ip(db_host["ip"], f"{db_name}.ip"),
            "web_sources": sorted(
                (hosts[w]["name"], _ip(hosts[w]["ip"], f"{w}.ip"))
                for w in web_names),
        })
    for web_name, db_name in web_needs:
        plan.append({
            "kind": "web", "host": web_name,
            "db_ref": db_name,
            "db_ip": _ip(hosts[db_name]["ip"], f"{db_name}.ip"),
        })
    return plan


def reader_password(deployment_resources: list[dict], db_host: str) -> str:
    """Fresh per-deployment-generation credential, REUSED on resume (the
    same generation must keep working; a new generation re-provisions)."""
    for res in deployment_resources:
        if res.get("host") == db_host and res.get("db_reader_password"):
            return str(res["db_reader_password"])
    return secrets.token_hex(16)


def db_provision_command(plan: dict, password: str) -> str:
    """Idempotent in-guest provisioning for the DB tier (run as root via
    the management channel)."""
    web_ips = [ip for _, ip in plan["web_sources"]]
    # Converging idempotence: CREATE guards first-run, ALTER ALWAYS sets
    # the password (a retry after an uncertain result must converge the
    # guest to the persisted credential, never keep a stale one — CREATE
    # IF NOT EXISTS alone would silently preserve the wrong password).
    sql_users = "; ".join(
        [f"CREATE USER IF NOT EXISTS '{READER_USER}'@'{ip}' "
         f"IDENTIFIED BY '{password}'" for ip in web_ips]
        + [f"ALTER USER '{READER_USER}'@'{ip}' IDENTIFIED BY '{password}'"
           for ip in web_ips]
        + [f"ALTER USER '{READER_USER}'@'127.0.0.1' "
           f"IDENTIFIED BY '{password}'"]
        + [f"GRANT SELECT ON {MYSQL_DB}.* TO '{READER_USER}'@'{ip}'"
           for ip in web_ips])
    # ufw itself skips an existing identical rule — idempotent by design.
    ufw_rules = " ; ".join(
        f"ufw allow from {ip} to any port 3306 proto tcp" for ip in web_ips)
    # Read-back WITHOUT pretending to be the web guest: prove the new
    # password works over loopback TCP, and prove each owned-source grant
    # row exists. (Connecting from the DB host to itself as the web-host
    # grant could never match — the source address would be wrong.)
    grant_rows = " ; ".join(
        f"mysql -N -B -e \"SELECT user,host FROM mysql.user WHERE "
        f"user='{READER_USER}'\" | grep -q {ip}" for ip in web_ips)
    readback = (
        f"mysql --protocol=TCP --host=127.0.0.1 --batch --skip-column-names "
        f"--user={READER_USER} --password='{password}' "
        f"-e 'SELECT 1' {MYSQL_DB} >/dev/null ; {grant_rows}")
    return (
        "set -e\n"
        "install -d -m 0750 /etc/mojang-web\n"
        f"umask 077; printf '%s' '{password}' > {READER_PW_PATH}.tmp\n"
        f"mv {READER_PW_PATH}.tmp {READER_PW_PATH}\n"
        f"chown root:root {READER_PW_PATH}; chmod 0640 {READER_PW_PATH}\n"
        # listener: loopback (probe) + the guest's OWNED range address only
        f"printf '[mysqld]\\nbind-address = 127.0.0.1,{plan['ip']}\\n' "
        "> /etc/mysql/mysql.conf.d/z-sr-range.cnf\n"
        "chmod 0640 /etc/mysql/mysql.conf.d/z-sr-range.cnf\n"
        "systemctl restart mysql\n"
        "for i in $(seq 1 60); do mysqladmin --silent ping >/dev/null 2>&1 "
        "&& break; sleep 2; done\n"
        "mysqladmin --silent ping\n"
        f"mysql -e \"{sql_users}; FLUSH PRIVILEGES;\"\n"
        # narrow the template's broad 3306 rule to the owned web sources
        "ufw delete allow 3306/tcp >/dev/null 2>&1 || true\n"
        f"{ufw_rules}\n"
        f"{readback}\n"
    )


def web_provision_command(plan: dict, password: str) -> str:
    """Idempotent config.env rewrite targeting the OWNED DB IP, with
    read-back and app restart (management channel, root)."""
    env = (
        "MOJANG_DATA_BACKEND=mysql\n"
        "MOJANG_SEED_PATH=/srv/mojang-web/seeds.json\n"
        f"MOJANG_MYSQL_HOST={plan['db_ip']}\n"
        f"MOJANG_MYSQL_DB={MYSQL_DB}\n"
        f"MOJANG_MYSQL_USER={READER_USER}\n"
        f"MOJANG_MYSQL_PASSWORD='{password}'\n"
        "MOJANG_DIAG_ENABLED=on\n")
    return (
        "set -e\n"
        "install -d -m 0755 /etc/mojang-web\n"
        "umask 027\n"
        f"cat > {CONFIG_ENV_PATH}.tmp <<'SR-ENVEOF'\n{env}SR-ENVEOF\n"
        f"if [ -f {CONFIG_ENV_PATH} ] && cmp -s {CONFIG_ENV_PATH}.tmp "
        f"{CONFIG_ENV_PATH}; then rm -f {CONFIG_ENV_PATH}.tmp; "
        "systemctl is-active --quiet mojang-web || systemctl restart "
        "mojang-web; exit 0; fi\n"
        f"chown root:web-user {CONFIG_ENV_PATH}.tmp\n"
        f"chmod 0640 {CONFIG_ENV_PATH}.tmp\n"
        f"mv {CONFIG_ENV_PATH}.tmp {CONFIG_ENV_PATH}\n"
        "systemctl restart mojang-web\n"
        f"grep -q 'MOJANG_MYSQL_HOST={plan['db_ip']}' {CONFIG_ENV_PATH}\n"
    )
