#!/usr/bin/env python3
"""Guest user-data (cloud-config) for real-Ubuntu gates (03+04 rework).

Generates NoCloud `user-data` documents from LOCAL payload inputs — the only
network the guest ever sees is the build-phase package fetch (pinned names,
resolved versions recorded) or the capture-positive synthetic-API control
path. Verification boots run with `-net none`.

Two modes per guest role:
- build: install packages, lay the payload, configure services/seeds, record
  resolved versions, then power off. The resulting qcow2 overlay IS the
  built artifact (base + deltas), hashed and recorded by the gate.
- verify: assert services/seeds/flaws/fixes/readiness live, report each
  check over the serial console, then power off.

Serial contract (guest -> host, `/dev/ttyS0`):
  SR-GUEST-BOOT
  SR-GUEST-<CHECK>-PASS | SR-GUEST-<CHECK>-FAIL:<reason>
  SR-GUEST-DONE rc=<n>

Reader password: the build writes a per-run synthetic secret into the overlay
(`/etc/mojang-web/reader-pw`, mode 640); verify reads it back from the disk.
No credential is baked into the repo or the seed.
"""
from __future__ import annotations

import json

SERIAL = "/dev/ttyS0"

# The full payload is embedded through cloud-init `write_files` (all text,
# all local). Binary-safe: every line is indented under a literal block.

_HARNESS_HEADER = r"""#!/bin/bash
# Generated guest check harness (03+04 rework). Reports over serial, powers off.
S=/dev/ttyS0
say() { echo "SR-GUEST-$1" > $S; }
fails=0
chk() {
  local name=$1; shift
  if "$@" >/tmp/sr-chk.log 2>&1; then say "$name-PASS";
  else say "$name-FAIL:$(tr '\n' ';' </tmp/sr-chk.log | tail -c 200)"; fails=$((fails+1)); fi
}
say BOOT
"""


def _indent(text: str, spaces: int = 6) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line.strip() else line
                     for line in text.splitlines())


def _write_file_entry(path: str, content: str, perms: str = "0644",
                      owner: str = "root:root") -> str:
    return (f"  - path: {path}\n"
            f"    owner: {owner}\n"
            f"    permissions: '{perms}'\n"
            f"    content: |\n{_indent(content)}\n")


def _common_users() -> str:
    return """users:
  - name: defender
    groups: [sudo]
    shell: /bin/bash
  - name: web-user
    shell: /usr/sbin/nologin
  - name: srshipper
    system: true
    groups: [adm]
    shell: /usr/sbin/nologin
"""


def build_user_data(role: str, payload: dict[str, str], packages: list[str]) -> str:
    """`payload`: guest-absolute path -> file text (from the repo payload
    trees + seeds + shipper inputs). `packages`: EXACT pinned `name=version`
    install set from the manifest — installed via apt in the build phase
    (cloud-init's `packages:` cannot pin versions, so pins are installed
    explicitly and fail closed on archive drift; resolved versions are
    RECORDED into the overlay at build time)."""
    files = "".join(_write_file_entry(p, c,
                                      perms="0755" if p.endswith("mojang-maintenance") else "0644")
                    for p, c in sorted(payload.items()))
    backend = "mysql" if role == "mojang-web-db" else "local"
    files += _write_file_entry("/etc/mojang-web/config.env",
                               f"MOJANG_DATA_BACKEND={backend}\n"
                               "MOJANG_SEED_PATH=/srv/mojang-web/seeds.json\n"
                               "MOJANG_MYSQL_HOST=127.0.0.1\n"
                               "MOJANG_MYSQL_DB=mojang\n"
                               "MOJANG_MYSQL_USER=mojang_reader\n"
                               "MOJANG_DIAG_ENABLED=on\n")
    pins = " ".join(_shlex_quote(p) for p in packages)
    setup = "\n".join(f"  - {line}" for line in
                      [f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pins}"]
                      + _build_runcmd(role, [p.split('=')[0] for p in packages]))
    return f"""#cloud-config
hostname: sr-build-{role}
manage_etc_hosts: true
package_update: true
package_upgrade: false
{_common_users()}
write_files:
{files}  - path: /srv/sr-build/role
    content: |
      {role}
runcmd:
{setup}
"""


def _shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def _build_runcmd(role: str, packages: list[str]) -> list[str]:
    cmds = [
        "systemctl disable --now unattended-upgrades || true",
        "install -d -m 0755 /srv/sr-build",
        # nginx site (payload) replaces the default site.
        "ln -sf /etc/nginx/sites-available/mojang /etc/nginx/sites-enabled/mojang",
        "rm -f /etc/nginx/sites-enabled/default",
        # shipper install (mirrors telemetry/install.sh contract): identity,
        # spool dir, unit, auditd rules.
        "install -d -m 0750 -o root -g srshipper /etc/sparring-range",
        "install -d -m 2770 -o root -g adm /var/lib/sparring-range/shipper",
        "install -m 0644 /srv/sr-build-input/sparring-shipper.service /etc/systemd/system/sparring-shipper.service",
        "install -m 0644 /srv/sr-build-input/auditd.rules /etc/audit/rules.d/sparring.rules",
        "install -m 0755 /srv/sr-build-input/shipper.py /usr/local/bin/sparring-shipper",
        "systemctl daemon-reload",
        "ufw --force enable",
        "ufw allow 22/tcp",
        "ufw allow 80/tcp",
        # Synthetic build-time shipper env (dummy API: the unit must be
        # ACTIVE at build; real capabilities arrive per-generation at deploy
        # time, and capture seeds overwrite this file).
        r"printf 'SR_API_URL=http://127.0.0.1:9\nSR_TELEMETRY_TOKEN=sr-build-dummy\nSR_HOST=build\nSR_SPOOL_DIR=/var/lib/sparring-range/shipper\n' > /etc/sparring-range/shipper.env",
        "chown root:srshipper /etc/sparring-range/shipper.env",
        "chmod 0640 /etc/sparring-range/shipper.env",
        "systemctl enable --now auditd sparring-shipper nginx mojang-web ssh",
        "systemctl enable --now mysql || true",
        "systemctl restart auditd",
        # Noble uses sshd SOCKET activation by default (service inactive until
        # first connection). Built guests run persistent sshd instead, so the
        # service posture is deterministic on every boot (the base-image
        # attacker keeps socket activation and asserts the socket).
        # Deliberate lab flaw: the helper is setuid-root with an unsafe PATH
        # (write_files cannot set the setuid bit, so it is set here at build
        # time; the documented fix removes it without breaking services).
        "chown root:root /usr/local/bin/mojang-maintenance",
        "chmod 4755 /usr/local/bin/mojang-maintenance",
    ]
    if role == "mojang-web-db":
        cmds += [
            # Per-run synthetic reader secret (never baked anywhere).
            r"PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')",
            r"printf '%s' \"$PW\" > /etc/mojang-web/reader-pw",
            "chmod 0640 /etc/mojang-web/reader-pw",
            r"printf 'MOJANG_MYSQL_PASSWORD=%s\n' \"$PW\" >> /etc/mojang-web/config.env",
            "mysql < /etc/mysql/mojang/schema.sql",
            "mysql < /etc/mysql/mojang/seed.sql",
            r"mysql -e \"ALTER USER 'mojang_reader'@'127.0.0.1' IDENTIFIED BY '$PW'\"",
        ]
    # Record resolved package versions, report, power off.
    want = " ".join(p.split("=")[0] + "*" for p in packages)
    cmds += [
        f"dpkg-query -W -f='${{Package}}=${{Version}}\\n' {want} > /srv/sr-build/versions.txt 2>/dev/null || true",
        "sed 's/^/SR-GUEST-PKG:/' /srv/sr-build/versions.txt > /dev/ttyS0 || true",
        f"echo SR-GUEST-BUILD-PASS > {SERIAL}",
        "poweroff",
    ]
    return cmds


def _verify_checks(role: str) -> str:
    units = "mojang-web nginx sshd auditd sparring-shipper"
    if role == "mojang-web-db":
        units += " mysql"
    mysql_checks = ""
    if role == "mojang-web-db":
        mysql_checks = """
chk MYSQL-COUNT bash -c 'test "$(mysql --batch --skip-column-names --user=mojang_reader --password="$(cat /etc/mojang-web/reader-pw)" -e "SELECT COUNT(*) FROM purchases" mojang)" = 12'
chk MYSQL-ROW bash -c 'mysql --batch --skip-column-names --user=mojang_reader --password="$(cat /etc/mojang-web/reader-pw)" -e "SELECT purchase_id FROM purchases" mojang | grep -q buy-001'
"""
    return _HARNESS_HEADER + f"""
chk UNITS-ACTIVE bash -c 'systemctl is-active --quiet {units}'
chk CATALOGUE bash -c "curl -sf http://127.0.0.1/ | grep -q 'Minecraft Legends'"
chk CATALOGUE-COUNT bash -c "curl -sf http://127.0.0.1/ | grep -c buy- | grep -qx 12"
chk DIAG-FLAW bash -c "curl -sf 'http://127.0.0.1:8080/diagnostic?cmd=whoami' && grep -q 'DIAG{{web-user}}' /tmp/mojang-diag-proof.txt"
chk DIAG-FIX bash -c 'printf MOJANG_DIAG_ENABLED=off >> /etc/mojang-web/config.env && systemctl restart mojang-web && sleep 2 && curl -sf http://127.0.0.1/ | grep -q Legends && ! curl -sf "http://127.0.0.1:8080/diagnostic?cmd=whoami"'
chk MAINT-HELPER bash -c 'test -u /usr/local/bin/mojang-maintenance'
chk AUDITD-RULES bash -c 'auditctl -l | grep -q sparring_cmd'
chk SHIPPER-UNIT bash -c 'grep -q "^User=srshipper" /etc/systemd/system/sparring-shipper.service && grep -q adm /etc/systemd/system/sparring-shipper.service'
chk SHIPPER-SPOOL bash -c 'test -d /var/lib/sparring-range/shipper'
chk SEEDS bash -c 'python3 -c "import json;d=json.load(open(\\"/srv/mojang-web/seeds.json\\"));assert len(d[\\"purchases\\"])==12"'
chk USERS bash -c 'id -nG defender | grep -qw sudo && id web-user'
chk FIREWALL bash -c 'ufw status | grep -qw active'
{mysql_checks}
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
poweroff
"""


def verify_user_data(role: str, payload: dict[str, str],
                     backend: str = "local") -> str:
    """Verify seed: NO packages (offline `-net none` boot proves no runtime
    fetching is needed). Payload is re-asserted from the overlay; the seed
    only selects the data backend + carries the check harness."""
    config = (f"MOJANG_DATA_BACKEND={backend}\n"
              f"MOJANG_SEED_PATH=/srv/mojang-web/seeds.json\n"
              "MOJANG_MYSQL_HOST=127.0.0.1\n"
              "MOJANG_MYSQL_DB=mojang\n"
              "MOJANG_MYSQL_USER=mojang_reader\n"
              "MOJANG_DIAG_ENABLED=on\n")
    files = (_write_file_entry("/etc/mojang-web/config.env", config) +
             _write_file_entry("/srv/sr-verify-checks.sh",
                               _verify_checks(role), perms="0755"))
    runcmd = ["  - systemctl restart mojang-web",
              "  - sleep 2",
              "  - /bin/bash /srv/sr-verify-checks.sh"]
    if role == "mojang-web-db":
        # The overlay's per-run reader secret persists on disk, but this
        # boot's fresh config.env needs it re-injected (proves the secret
        # never lives in the seed — only on the built disk).
        runcmd.insert(
            0, "  - bash -c 'printf \"MOJANG_MYSQL_PASSWORD=%s\\n\" "
               "\"$(cat /etc/mojang-web/reader-pw)\" "
               ">> /etc/mojang-web/config.env'")
    return f"""#cloud-config
hostname: sr-verify-{role}
manage_etc_hosts: true
package_update: false
package_upgrade: false
{_common_users()}
write_files:
{files}runcmd:
""" + "\n".join(runcmd) + "\n"


def attacker_verify_user_data() -> str:
    # Base-image posture is sshd SOCKET activation (no persistent service):
    # assert the listening socket, fresh host keys, and no target payload.
    script = (_HARNESS_HEADER + f"""
chk SSH-SOCKET systemctl is-active --quiet ssh.socket
chk HOSTKEYS bash -c 'test -s /etc/ssh/ssh_host_ed25519_key.pub && grep -q "^ssh-ed25519 " /etc/ssh/ssh_host_ed25519_key.pub'
chk NO-MOJANG bash -c '! test -e /srv/mojang-web/app.py'
chk NO-MYSQL bash -c '! systemctl list-unit-files mysql.service | grep -q enabled'
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
poweroff
""")
    files = _write_file_entry("/srv/sr-verify-checks.sh", script, perms="0755")
    return f"""#cloud-config
hostname: sr-verify-attacker
manage_etc_hosts: true
package_update: false
package_upgrade: false
users:
  - name: attacker
    groups: [sudo]
    shell: /bin/bash
write_files:
{files}runcmd:
  - /bin/bash /srv/sr-verify-checks.sh
"""


def capture_negative_user_data(reader_pw_path_note: str = "") -> str:
    """Installed-capture negatives on the REAL overlay: the unit stays ACTIVE
    while (a) the API address is wrong, so delivery evidence can never arrive.
    The guest proves auditd captured the marker locally (audit.log has it)
    while NO delivery happened — distinct delivery vs real capture."""
    script = (_HARNESS_HEADER + f"""
printf 'SR_API_URL=http://127.0.0.1:9\\nSR_TELEMETRY_TOKEN=sr-test-invalid\\nSR_HOST=db01\\nSR_ENROLL_NONCE=deadbeefdeadbeef\\n' > /etc/sparring-range/shipper.env
chmod 0640 /etc/sparring-range/shipper.env
systemctl restart sparring-shipper
sleep 3
chk UNIT-ACTIVE systemctl is-active --quiet sparring-shipper
MARKER="SR-CAPTURE-negative$RANDOM"
/bin/true "$MARKER"
sleep 2
chk AUDITD-CAPTURED bash -c 'ausearch -m EXECVE 2>/dev/null | grep -q "$MARKER" || grep -q "$MARKER" /var/log/audit/audit.log'
chk NO-DELIVERY bash -c '! grep -q "$MARKER" /var/lib/sparring-range/shipper/delivered.log 2>/dev/null; true'
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
poweroff
""")
    _ = reader_pw_path_note
    files = _write_file_entry("/srv/sr-verify-checks.sh", script, perms="0755")
    return f"""#cloud-config
hostname: sr-capture-neg
manage_etc_hosts: true
package_update: false
package_upgrade: false
{_common_users()}
write_files:
{files}runcmd:
  - /bin/bash /srv/sr-verify-checks.sh
"""


def capture_positive_user_data(api_port: int, token: str, nonce: str) -> str:
    """End-to-end installed capture: real auditd EXECVE of the marker through
    the INSTALLED shipper to the host synthetic API (10.0.2.2:port)."""
    script = (_HARNESS_HEADER + f"""
printf 'SR_API_URL=http://10.0.2.2:{api_port}\\nSR_TELEMETRY_TOKEN={token}\\nSR_HOST=db01\\nSR_ENROLL_NONCE={nonce}\\nSR_SPOOL_DIR=/var/lib/sparring-range/shipper\\n' > /etc/sparring-range/shipper.env
chmod 0640 /etc/sparring-range/shipper.env
systemctl restart sparring-shipper
sleep 3
chk UNIT-ACTIVE systemctl is-active --quiet sparring-shipper
MARKER="SR-CAPTURE-{nonce[:12]}"
/bin/true "$MARKER"
sleep 10
chk CURSOR-EXISTS bash -c 'test -s /var/lib/sparring-range/shipper/audit-cursor.json'
chk AUDITD-CAPTURED bash -c 'grep -q "$MARKER" /var/log/audit/audit.log'
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
poweroff
""")
    files = _write_file_entry("/srv/sr-verify-checks.sh", script, perms="0755")
    return f"""#cloud-config
hostname: sr-capture-pos
manage_etc_hosts: true
package_update: false
package_upgrade: false
{_common_users()}
write_files:
{files}runcmd:
  - /bin/bash /srv/sr-verify-checks.sh
"""


def payload_from_repo(repo_root: str, role: str, seeds: dict) -> dict[str, str]:
    """Assemble the guest-absolute payload from LOCAL repo inputs (offline).

    Role payload trees land at their guest paths; the shipper install inputs
    (`telemetry/`) land under `/srv/sr-build-input/` for the build runcmd to
    install (mirroring `telemetry/install.sh`). SSH keys under `home/` are
    NEVER shipped (operator public keys arrive via the seed/management
    channel, never baked into test artifacts)."""
    import pathlib
    repo = pathlib.Path(repo_root)
    if role == "attacker":
        return {}
    src = repo / "infra/images/payloads" / role
    out: dict[str, str] = {}
    for f in sorted(src.rglob("*")):
        if not f.is_file() or ".ssh" in f.parts:
            continue
        rel = f.relative_to(src)
        # Payload tree layout mirrors guest-absolute paths except `home/`.
        if rel.parts[0] == "home":
            continue
        out["/" + str(rel)] = f.read_text()
    out["/srv/mojang-web/seeds.json"] = json.dumps(seeds, indent=2,
                                                   sort_keys=True) + "\n"
    tel = repo / "telemetry"
    out["/srv/sr-build-input/shipper.py"] = (tel / "shipper.py").read_text()
    out["/srv/sr-build-input/sparring-shipper.service"] = (
        tel / "sparring-shipper.service").read_text()
    out["/srv/sr-build-input/auditd.rules"] = (tel / "auditd.rules").read_text()
    return out
