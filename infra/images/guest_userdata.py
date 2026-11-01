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
import pathlib
import shlex

SERIAL = "/dev/ttyS0"

# The full payload is embedded through cloud-init `write_files` (all text,
# all local). Binary-safe: every line is indented under a literal block.

_HARNESS_HEADER = r"""#!/bin/bash
# Generated guest check harness (03+04 rework). Reports over serial, powers off.
S=/dev/ttyS0
# Serial integrity (pilot): the Ubuntu image keeps the kernel console on
# ttyS0, and under TCG load printk lines interleave into marker lines and
# corrupt them (observed: a PASS marker lost with no FAIL and DONE rc=0 —
# an impossible script outcome, proven to be line loss). Silence console
# noise, stop the serial getty, and emit every marker TWICE: two
# independent writes being corrupted alike is negligible.
dmesg -n 1 2>/dev/null || true
systemctl stop serial-getty@ttyS0 2>/dev/null || true
say() { echo "SR-GUEST-$1" > $S; echo "SR-GUEST-$1" > $S; }
fails=0
chk() {
  local name=$1; shift
  if "$@" >/tmp/sr-chk.log 2>&1; then say "$name-PASS";
  else say "$name-FAIL:$(tr '\n' ';' </tmp/sr-chk.log | tail -c 200)"; fails=$((fails+1)); fi
}
wchk() {
  # Wait-then-check (bounded): TCG service starts are slow; poll the probe
  # up to budget*2s before calling it a failure — never a fixed sleep race.
  local name=$1 budget=$2; shift 2
  local t=0
  while ! "$@" >/tmp/sr-chk.log 2>&1; do
    t=$((t+1))
    if [ $t -ge $budget ]; then
      say "$name-FAIL:$(tr '\n' ';' </tmp/sr-chk.log | tail -c 200)"
      fails=$((fails+1)); return 0
    fi
    sleep 2
  done
  say "$name-PASS"
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


def _payload_perms(path: str) -> str:
    """Mode policy for payload files landing through cloud-init write_files.
    The maintenance helper is executable (root-owned, NOT setuid — Linux
    ignores setuid on scripts); its scoped sudo rule needs sudoers modes."""
    if path.startswith("/etc/sudoers.d/"):
        return "0440"
    if path.endswith("/usr/local/bin/mojang-maintenance"):
        return "0755"
    return "0644"


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
    files = "".join(_write_file_entry(p, c, perms=_payload_perms(p))
                    for p, c in sorted(payload.items()))
    if role != "mojang-web-db":
        backend = "local"
        files += _write_file_entry(
            "/etc/mojang-web/config.env",
            f"MOJANG_DATA_BACKEND={backend}\n"
            "MOJANG_SEED_PATH=/srv/mojang-web/seeds.json\n"
            "MOJANG_MYSQL_HOST=127.0.0.1\n"
            "MOJANG_MYSQL_DB=mojang\n"
            "MOJANG_MYSQL_USER=mojang_reader\n"
            "MOJANG_DIAG_ENABLED=on\n")
    pins = " ".join(_shlex_quote(p) for p in packages)
    setup_script = _setup_script(role, [p.split('=')[0] for p in packages])
    files += _write_file_entry("/srv/sr-build.sh", setup_script, perms="0755")
    setup = "\n".join(f"  - {line}" for line in
                      [f"timeout 1200 env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold {pins} && echo SR-GUEST-BUILD-APT-OK > /dev/ttyS0 || {{ echo SR-GUEST-BUILD-APT-FAIL > /dev/ttyS0; poweroff; }}",
                       "bash /srv/sr-build.sh"])
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


def _setup_script(role: str, packages: list[str]) -> str:
    """The whole post-install setup as ONE script with per-stage serial
    markers and `timeout` on every slow step: a stall names itself in the
    serial tail instead of dying silently mid-list, and the total is bounded.
    `packages` here are bare names (pins were installed by the apt item).

    Plan 13 phase 3 — the DB tier is a DATABASE, not a second all-in-one
    app: only web roles enable nginx/mojang-web; only the DB role enables
    MySQL and opens 3306 (reachable only from the range — guests have no
    default route). The capture path (auditd + shipper) is identical on
    every role."""
    want = " ".join(p + "*" for p in packages)
    if role == "mojang-web-db":
        service_units = "auditd sparring-shipper ssh mysql"
        mysql_state = "timeout 120 systemctl enable --now mysql || true"
        web_lines = ""
        ufw_lines = ("ufw --force enable\nufw allow 22/tcp\nufw allow 3306/tcp\n")
        gate = ("test \"$(mysql --batch --skip-column-names -e "
                "'SELECT COUNT(*) FROM purchases' mojang)\" = 12")
    else:
        service_units = "auditd sparring-shipper nginx mojang-web ssh"
        mysql_state = ("timeout 120 systemctl disable --now mysql "
                       ">/dev/null 2>&1 || true")
        web_lines = (
            "ln -sf /etc/nginx/sites-available/mojang "
            "/etc/nginx/sites-enabled/mojang\n"
            "rm -f /etc/nginx/sites-enabled/default\n"
            "chown root:root /usr/local/bin/mojang-maintenance "
            "/etc/sudoers.d/mojang-maintenance\n"
            "chmod 0755 /usr/local/bin/mojang-maintenance\n"
            "chmod 0440 /etc/sudoers.d/mojang-maintenance\n"
            "visudo -cf /etc/sudoers.d/mojang-maintenance "
            "|| { mark SUDOERS-FAIL; poweroff; }\n"
            "install -d -o web-user -g web-user -m 0775 "
            "/srv/mojang-web/tools\n")
        ufw_lines = ("ufw --force enable\nufw allow 22/tcp\nufw allow 80/tcp\n")
        gate = "true"
    db_setup = ""
    if role == "mojang-web-db":
        # Fresh per-build synthetic reader credential — synthetic lab data,
        # never a live credential; deploy-time provisioning replaces it with
        # per-deployment scoped grants for the owned web/probe sources.
        db_setup = """install -d -m 0750 /etc/mojang-web
PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
printf '%s' "$PW" > /etc/mojang-web/reader-pw
chmod 0640 /etc/mojang-web/reader-pw
for i in $(seq 1 120); do mysqladmin --silent ping >/dev/null 2>&1 && break; sleep 2; done
timeout 120 mysqladmin --silent ping && mark MYSQL-READY || { mark MYSQL-FAIL; poweroff; }
timeout 300 mysql < /etc/mysql/mojang/schema.sql || { mark SCHEMA-FAIL; poweroff; }
timeout 300 mysql < /etc/mysql/mojang/seed.sql || { mark SEED-FAIL; poweroff; }
timeout 120 mysql -e "ALTER USER 'mojang_reader'@'127.0.0.1' IDENTIFIED BY '$PW'" || { mark GRANT-FAIL; poweroff; }
"""
    script = f"""#!/bin/bash
S=/dev/ttyS0
mark() {{ echo "SR-GUEST-BUILD-$1" > $S; echo "SR-GUEST-BUILD-$1" > $S; }}
dmesg -n 1 2>/dev/null || true
systemctl stop serial-getty@ttyS0 2>/dev/null || true
systemctl disable --now unattended-upgrades || true
install -d -m 0755 /srv/sr-build
install -d -m 0750 -o root -g srshipper /etc/sparring-range
install -d -m 2770 -o root -g adm /var/lib/sparring-range/shipper
install -m 0644 /srv/sr-build-input/sparring-shipper.service /etc/systemd/system/sparring-shipper.service
install -m 0644 /srv/sr-build-input/auditd.rules /etc/audit/rules.d/sparring.rules
install -m 0755 /srv/sr-build-input/shipper.py /usr/local/bin/sparring-shipper
systemctl daemon-reload
{ufw_lines}printf 'SR_API_URL=http://127.0.0.1:9\\nSR_TELEMETRY_TOKEN=sr-build-dummy\\nSR_HOST=build\\nSR_SPOOL_DIR=/var/lib/sparring-range/shipper\\n' > /etc/sparring-range/shipper.env
chown root:srshipper /etc/sparring-range/shipper.env
chmod 0640 /etc/sparring-range/shipper.env
timeout 120 systemctl enable --now {service_units} || {{ mark UNITS-FAIL; poweroff; }}
{mysql_state}
timeout 60 systemctl restart auditd || true
{web_lines}{db_setup}mark SETUP-OK
dpkg-query -W -f='${{Package}}=${{Version}}\\n' {want} > /srv/sr-build/versions.txt 2>/dev/null || true
while IFS= read -r l; do echo "SR-GUEST-PKG:$l" > $S; done < /srv/sr-build/versions.txt || true
# versioned image user baseline (rogue-account checks compare against the
# ACTUAL built image, never a hand-written list): emitted last, after every
# useradd in this script, so the recorded set is the shipped set.
cut -d: -f1 /etc/passwd | while IFS= read -r u; do echo "SR-GUEST-USER:$u" > $S; done
if {gate}; then mark PASS; else mark FAIL; fi
poweroff
"""
    lines = script.splitlines()
    return "bash -c " + _shlex_quote("\n".join(lines))


def _build_runcmd(role: str, packages: list[str]) -> list[str]:  # pragma: no cover
    raise AssertionError("retired: setup now ships as one script item")


#: Clean-artifact cron inventory probe (plan 18). The verify boot is a
#: CLEAN BUILT ARTIFACT boot (offline, before any lab use), so it is the
#: only legitimate place to learn what clean cron state is. The emitted
#: single-line JSON is captured at release-build time by
#: `infra/images/cron_baseline` and bound to the artifact digest; pins
#: are NEVER learned from a running or compromised guest.
_CRON_PIN_PY = r"""
import hashlib, json, os
def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()
d = "/etc/cron.d"
files = {}
for name in sorted(os.listdir(d)):
    path = os.path.join(d, name)
    if os.path.islink(path) or not os.path.isfile(path):
        continue
    files[name] = _sha(path)
tab = "/var/spool/cron/crontabs/root"
out = {"files": files,
       "root_crontab_sha256": _sha(tab) if os.path.isfile(tab) else None}
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
"""

def _verify_checks(role: str) -> str:
    # Plan 13 phase 3: role-separated verification. The DB tier proves the
    # DATABASE contract (mysql data + capture + firewall), never the web
    # app; web roles prove the app/chain and must NOT have mysql enabled.
    if role == "mojang-web-db":
        units = "sshd auditd sparring-shipper mysql"
        web_checks = (
            "chk NO-WEB-APP bash -c '! systemctl is-enabled --quiet "
            "nginx mojang-web 2>/dev/null; ! test -e "
            "/srv/mojang-web/app.py'\n")
        # NOTE: --protocol=TCP is load-bearing: the reader grant is
        # 'mojang_reader'@'127.0.0.1' (TCP); the CLI would otherwise use the
        # local socket as 'localhost' and be refused. Mysqld is waited on
        # (bounded) since verify boots start it fresh under slow TCG.
        mysql_checks = """
wchk MYSQL-READY 45 mysqladmin --silent ping
wchk MYSQL-COUNT 30 bash -c 'pw=$(cat /etc/mojang-web/reader-pw 2>/dev/null); test -n "$pw" || { echo READER-PW-MISSING-OR-EMPTY >&2; exit 9; }; test "$(mysql --protocol=TCP --host=127.0.0.1 --batch --skip-column-names --user=mojang_reader --password="$pw" -e "SELECT COUNT(*) FROM purchases" mojang)" = 12'
wchk MYSQL-ROW 30 bash -c 'pw=$(cat /etc/mojang-web/reader-pw 2>/dev/null); test -n "$pw" || { echo READER-PW-MISSING-OR-EMPTY >&2; exit 9; }; mysql --protocol=TCP --host=127.0.0.1 --batch --skip-column-names --user=mojang_reader --password="$pw" -e "SELECT purchase_id FROM purchases" mojang | grep -q buy-001'
"""
    else:
        units = "mojang-web nginx sshd auditd sparring-shipper"
        web_checks = """wchk CATALOGUE 30 bash -c "curl -sf http://127.0.0.1/ | grep -q 'Minecraft Legends'"
chk CATALOGUE-COUNT bash -c "curl -sf http://127.0.0.1/ | grep -c buy- | grep -qx 12"
chk DIAG-FLAW /srv/sr-chain-checks.sh diag-flaw
chk ROOT-FLAW /srv/sr-chain-checks.sh root-flaw
chk MAINT-HELPER bash -c 'test -x /usr/local/bin/mojang-maintenance && ! test -u /usr/local/bin/mojang-maintenance && test -e /etc/sudoers.d/mojang-maintenance && [ "$(stat -c %U /srv/mojang-web/tools)" = web-user ]'
chk MAINT-FIX /srv/sr-chain-checks.sh maint-fix
chk DIAG-FIX /srv/sr-chain-checks.sh diag-fix
chk SEEDS bash -c 'python3 -c "import json;d=json.load(open(\\"/srv/mojang-web/seeds.json\\"));assert len(d[\\"purchases\\"])==12"'
"""
        mysql_checks = (
            "chk NO-MYSQL-ENABLED bash -c '! systemctl is-enabled --quiet "
            "mysql 2>/dev/null'\n")
    return _HARNESS_HEADER + f"""
chk UNITS-ACTIVE bash -c 'systemctl is-active --quiet {units}'
chk CRON-STATE bash -c 'python3 /srv/sr-cron-pin.py >/dev/null'
say "CRON-PIN $(python3 /srv/sr-cron-pin.py 2>/dev/null | tr -d '\n')"
{web_checks}chk AUDITD-RULES bash -c 'auditctl -l | grep -q sparring_cmd'
chk SHIPPER-UNIT bash -c 'grep -q "^User=srshipper" /etc/systemd/system/sparring-shipper.service && grep -q adm /etc/systemd/system/sparring-shipper.service'
chk SHIPPER-SPOOL bash -c 'test -d /var/lib/sparring-range/shipper'
chk USERS bash -c 'id -nG defender | grep -qw sudo && id web-user'
chk FIREWALL bash -c 'ufw status | grep -qw active'
{mysql_checks}
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}; echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
poweroff
"""


# Pilot step 1: the documented attack chain, proven on the INSTALLED guest
# and driven entirely over HTTP — through the real mojang-web service, so
# every executed command carries the REAL web-user identity (and the sudo
# transition is real). The trojan below is what the chain plants as the
# helper's PATH-hijacked `backup-tool`; it records the identity it achieved.
_TROJAN_B64 = "IyEvYmluL3NoCmlkIC11ID4gL3RtcC9zci1yb290LXByb29mCmlkIC11biA+PiAv" \
              "dG1wL3NyLXJvb3QtcHJvb2YK"


def _chain_script() -> str:
    """Standalone chain-proof script landed by the verify seed. Each mode is
    one acceptance check; exit 0 = the expected real-world outcome held."""
    return f"""#!/bin/bash
# Generated attack-chain proof (pilot step 1). Modes:
#  diag-flaw   — /diagnostic achieves GENUINE web-user execution (identity
#                proven by a file the command itself writes + the proof file)
#  root-flaw   — documented chain (plant backup-tool, run helper via the
#                scoped sudo rule) achieves uid=0 (real identity change)
#  maint-fix   — after revoking the sudo rule, the same chain yields NO root
#                and services stay active
#  diag-fix    — after disabling the endpoint it refuses (403) and executes
#                nothing, while the catalogue keeps serving (http_content)
S=/dev/ttyS0
DIAG() {{ curl -s --max-time 20 --get --data-urlencode "cmd=$1" \\
    http://127.0.0.1:8080/diagnostic; }}
case "$1" in
  diag-flaw)
    rm -f /tmp/sr-diag-rce /tmp/mojang-diag-proof.txt
    DIAG 'id -un > /tmp/sr-diag-rce; id -un' | grep -q web-user || exit 1
    [ "$(cat /tmp/sr-diag-rce 2>/dev/null)" = web-user ] || exit 1
    grep -q 'DIAG{{web-user}}' /tmp/mojang-diag-proof.txt || exit 1
    ;;
  root-flaw)
    rm -f /tmp/sr-root-proof
    DIAG 'echo {_TROJAN_B64} | base64 -d > /srv/mojang-web/tools/backup-tool && chmod 0775 /srv/mojang-web/tools/backup-tool' >/dev/null
    DIAG 'sudo -n /usr/local/bin/mojang-maintenance' >/dev/null
    sleep 1
    [ "$(head -1 /tmp/sr-root-proof 2>/dev/null)" = 0 ] || exit 1
    [ "$(tail -1 /tmp/sr-root-proof 2>/dev/null)" = root ] || exit 1
    ;;
  maint-fix)
    rm -f /etc/sudoers.d/mojang-maintenance /tmp/sr-root-proof
    DIAG 'sudo -n /usr/local/bin/mojang-maintenance' >/dev/null
    sleep 1
    [ ! -e /tmp/sr-root-proof ] || exit 1
    systemctl is-active --quiet mojang-web nginx || exit 1
    ;;
  diag-fix)
    rm -f /tmp/sr-post-fix /tmp/sr-post-fix2
    DIAG 'touch /tmp/sr-post-fix' >/dev/null
    [ -e /tmp/sr-post-fix ] || exit 1
    printf 'MOJANG_DIAG_ENABLED=off\\n' >> /etc/mojang-web/config.env
    systemctl restart mojang-web
    for i in $(seq 1 30); do curl -sf http://127.0.0.1:8080/ >/dev/null 2>&1 && break; sleep 2; done
    curl -sf http://127.0.0.1/ | grep -q Legends || exit 1
    code=$(curl -s -o /dev/null -w '%{{http_code}}' --get --data-urlencode 'cmd=touch /tmp/sr-post-fix2' http://127.0.0.1:8080/diagnostic)
    [ "$code" = 403 ] || exit 1
    [ ! -e /tmp/sr-post-fix2 ] || exit 1
    ;;
  *) exit 2;;
esac
"""


def verify_user_data(role: str, payload: dict[str, str],
                     backend: str = "local") -> str:
    """Verify seed: NO packages (offline `-net none` boot proves no runtime
    fetching is needed). Payload is re-asserted from the overlay; the seed
    only selects the data backend + carries the check harness. The DB tier
    has no web app, so it gets no app config at all."""
    files = (_write_file_entry("/srv/sr-chain-checks.sh", _chain_script(),
                               perms="0755") +
             _write_file_entry("/srv/sr-cron-pin.py", _CRON_PIN_PY,
                               perms="0644") +
             _write_file_entry("/srv/sr-verify-checks.sh",
                               _verify_checks(role), perms="0755"))
    if role != "mojang-web-db":
        config = (f"MOJANG_DATA_BACKEND={backend}\n"
                  f"MOJANG_SEED_PATH=/srv/mojang-web/seeds.json\n"
                  "MOJANG_MYSQL_HOST=127.0.0.1\n"
                  "MOJANG_MYSQL_DB=mojang\n"
                  "MOJANG_MYSQL_USER=mojang_reader\n"
                  "MOJANG_DIAG_ENABLED=on\n")
        files = (_write_file_entry("/etc/mojang-web/config.env", config)
                 + files)
    runcmd = ["  - systemctl restart mojang-web",
              "  - sleep 2",
              "  - /bin/bash /srv/sr-verify-checks.sh"]
    if role == "mojang-web-db":
        runcmd = ["  - /bin/bash /srv/sr-verify-checks.sh"]
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
    # Plan 13 phase 3: the attacker ALSO carries the capture path (auditd +
    # shipper) and the runner boundary (cgroup delegation unit + scoped
    # AppArmor profile) — deployment requires every guest's evidence.
    script = (_HARNESS_HEADER + f"""
chk SSH-SOCKET systemctl is-active --quiet ssh.socket
chk HOSTKEYS bash -c 'test -s /etc/ssh/ssh_host_ed25519_key.pub && grep -q "^ssh-ed25519 " /etc/ssh/ssh_host_ed25519_key.pub'
chk NO-MOJANG bash -c '! test -e /srv/mojang-web/app.py'
chk NO-MYSQL bash -c '! systemctl list-unit-files mysql.service | grep -q enabled'
chk AUDITD-ACTIVE systemctl is-active --quiet auditd
chk SHIPPER-UNIT bash -c 'systemctl is-active --quiet sparring-shipper && grep -q "^User=srshipper" /etc/systemd/system/sparring-shipper.service'
chk SHIPPER-SPOOL bash -c 'test -d /var/lib/sparring-range/shipper && test -s /etc/sparring-range/shipper.env'
chk AUDITD-RULES bash -c 'auditctl -l | grep -q sparring_cmd'
chk CGROUP-DELEGATION bash -c 'systemctl is-enabled --quiet sr-runner-cgroup.service && systemctl is-active --quiet sr-runner-cgroup.service && test -d /sys/fs/cgroup/user.slice/user-$(id -u attacker).slice/sr-runner && grep -q RUNNER_CGROUP_ROOT /etc/environment'
chk APPARMOR-PROFILE bash -c 'test -s /etc/apparmor.d/usr.bin.unshare && systemctl is-enabled --quiet apparmor && apparmor_parser -r /etc/apparmor.d/usr.bin.unshare'
chk RUNNER-BOUNDARY bash -c 'test -x /usr/local/bin/runner-supervisor && su -s /bin/sh attacker -c "unshare --user --map-root-user --mount --cgroup --pid --fork --mount-proc /bin/true"'
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}; echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
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
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}; echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
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
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}; echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
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


def attacker_build_user_data(payload: dict[str, str], packages: list[str],
                             key_manifest: dict[str, str]) -> str:
    """Build seed for the ATTACKER template (plan 13 phase 3): pinned base +
    attacker role file + runner-supervisor + **auditd/shipper** (deployment
    requires EVERY guest's delivery/capture evidence — the attacker is not
    exempt) + reboot-persistent runner cgroup delegation + the scoped
    AppArmor profile for the trusted launcher. Keys land per role_keys
    policy: the runner key authenticates ONLY to `attacker`, mgmt/emergency
    separately — never one key everywhere, never a private key. Host
    keys/machine-id are scrubbed by the finalize boot so every clone
    regenerates fresh identity."""
    from infra.images.role_keys import bake_script
    files = "".join(_write_file_entry(p, c, perms=_payload_perms(p))
                    for p, c in sorted(payload.items()))
    files += _write_file_entry(
        "/usr/local/bin/runner-supervisor",
        (pathlib.Path(__file__).resolve().parents[2]
         / "infra/runner/runner_supervise.sh").read_text(), perms="0755")
    repo = pathlib.Path(__file__).resolve().parents[2]
    files += _write_file_entry(
        "/srv/sr-build-input/sr-runner-cgroup.service",
        (repo / "infra/runner/sr-runner-cgroup.service").read_text())
    files += _write_file_entry(
        "/srv/sr-build-input/setup_cgroup.sh",
        (repo / "infra/runner/setup_cgroup.sh").read_text())
    files += _write_file_entry(
        "/srv/sr-build-input/usr.bin.unshare",
        (repo / "infra/runner/apparmor/usr.bin.unshare").read_text())
    tel = repo / "telemetry"
    files += _write_file_entry("/srv/sr-build-input/shipper.py",
                               (tel / "shipper.py").read_text())
    files += _write_file_entry(
        "/srv/sr-build-input/sparring-shipper.service",
        (tel / "sparring-shipper.service").read_text())
    files += _write_file_entry("/srv/sr-build-input/auditd.rules",
                               (tel / "auditd.rules").read_text())
    pins = " ".join(_shlex_quote(p) for p in packages)
    # Presence of an emergency key in the manifest IS the explicit operator
    # decision (the template CLI only accepts it via --emergency-key).
    bake = bake_script("attacker", key_manifest,
                       include_emergency="emergency" in key_manifest)
    files += _write_file_entry("/srv/sr-bake-keys.sh", bake, perms="0755")
    files += _write_file_entry("/srv/sr-attacker-build.sh", f"""#!/bin/bash
S=/dev/ttyS0
mark() {{ echo "SR-GUEST-BUILD-$1" > $S; echo "SR-GUEST-BUILD-$1" > $S; }}
dmesg -n 1 2>/dev/null || true
systemctl stop serial-getty@ttyS0 2>/dev/null || true
systemctl disable --now unattended-upgrades || true
timeout 1200 env DEBIAN_FRONTEND=noninteractive apt-get install -y \\
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold {pins} \\
  && mark APT-OK || {{ mark APT-FAIL; poweroff; }}
# capture path IDENTICAL to defender guests (canonical telemetry inputs)
install -d -m 0750 -o root -g srshipper /etc/sparring-range
install -d -m 2770 -o root -g adm /var/lib/sparring-range/shipper
install -m 0644 /srv/sr-build-input/sparring-shipper.service /etc/systemd/system/sparring-shipper.service
install -m 0644 /srv/sr-build-input/auditd.rules /etc/audit/rules.d/sparring.rules
install -m 0755 /srv/sr-build-input/shipper.py /usr/local/bin/sparring-shipper
printf 'SR_API_URL=http://127.0.0.1:9\\nSR_TELEMETRY_TOKEN=sr-build-dummy\\nSR_HOST=build\\nSR_SPOOL_DIR=/var/lib/sparring-range/shipper\\n' > /etc/sparring-range/shipper.env
chown root:srshipper /etc/sparring-range/shipper.env
chmod 0640 /etc/sparring-range/shipper.env
# runner boundary: reboot-persistent cgroup delegation + scoped AppArmor
install -m 0644 /srv/sr-build-input/sr-runner-cgroup.service /etc/systemd/system/sr-runner-cgroup.service
install -d -m 0755 /usr/local/libexec
install -m 0755 /srv/sr-build-input/setup_cgroup.sh /usr/local/libexec/sr-runner-cgroup-setup
install -m 0644 /srv/sr-build-input/usr.bin.unshare /etc/apparmor.d/usr.bin.unshare
command -v apparmor_parser >/dev/null || {{ mark APPARMOR-MISSING; poweroff; }}
systemctl enable sr-runner-cgroup.service apparmor || mark APPARMOR-EN-FAIL
systemctl daemon-reload
systemctl start sr-runner-cgroup.service || {{ mark CGROUP-DELEGATION-FAIL; poweroff; exit 1; }}
apparmor_parser -r /etc/apparmor.d/usr.bin.unshare || {{ mark APPARMOR-LOAD-FAIL; poweroff; }}
timeout 120 systemctl enable --now auditd sparring-shipper || {{ mark UNITS-FAIL; poweroff; }}
timeout 60 systemctl restart auditd || true
bash /srv/sr-bake-keys.sh || {{ mark KEYS-FAIL; poweroff; }}
ufw --force enable; ufw allow 22/tcp
systemctl enable --now ssh qemu-guest-agent || true
# package report BEFORE the completion marker: the harness powers off on
# SETUP-OK, so anything printed after it never reaches the serial log.
for p in {pins}; do n=${{p%%=*}}; v=$(dpkg-query -W -f='${{Version}}' "$n" 2>/dev/null || echo unknown); echo "SR-GUEST-PKG:$n=$v" > $S; done
cut -d: -f1 /etc/passwd | while IFS= read -r u; do echo "SR-GUEST-USER:$u" > $S; done
mark SETUP-OK
poweroff
""", perms="0755")
    return f"""#cloud-config
hostname: sr-build-attacker
manage_etc_hosts: true
package_update: true
package_upgrade: false
users:
  - name: attacker
    groups: [sudo]
    shell: /bin/bash
  - name: srshipper
    system: true
    groups: [adm]
    shell: /usr/sbin/nologin
write_files:
{files}runcmd:
  - bash /srv/sr-attacker-build.sh
"""


def finalize_user_data(role: str = "mojang-web-local",
                       key_manifest: dict[str, str] | None = None,
                       *, include_emergency: bool = False) -> str:
    """Template finalize boot (plan 13 phase 3): bake ONLY the role-appropriate
    PUBLIC keys per the role_keys policy (runner→attacker only, bastion→
    defender, mgmt→approved management account, emergency only when
    explicitly included; deduplicated; private keys refused), then scrub
    per-clone identity from the BUILT template so every clone regenerates
    fresh SSH host keys and machine-id via cloud-init — the contract the
    broker's guest-agent host-key pinning depends on. Offline (`-net none`)."""
    bake_files, bake_call = "", ""
    if key_manifest:
        from infra.images.role_keys import bake_script
        bake = bake_script(role, key_manifest,
                           include_emergency=include_emergency
                           or "emergency" in key_manifest)
        bake_files = _write_file_entry("/srv/sr-bake-keys.sh", bake,
                                       perms="0755")
        bake_call = "chk BAKE /srv/sr-bake-keys.sh\n"
    script = (_HARNESS_HEADER + f"""
{bake_call}chk SCRUB bash -c 'rm -f /etc/ssh/ssh_host_*; truncate -s 0 /etc/machine-id; rm -f /var/lib/dbus/machine-id; cloud-init clean --logs --seed 2>/dev/null || rm -rf /var/lib/cloud/instances/seed; ! ls /etc/ssh/ssh_host_* 2>/dev/null | grep -q .'
chk NO-BUILD-LOGS bash -c '! test -s /root/.bash_history; rm -rf /srv/sr-build; true'
# versioned image user baseline (rogue-account checks compare against the
# ACTUAL finalized image): emitted AFTER the key bake, so role accounts
# (attacker/emergency) are included in the shipped set.
cut -d: -f1 /etc/passwd | while IFS= read -r u; do echo "SR-GUEST-USER:$u" > {SERIAL}; done
echo "SR-GUEST-DONE rc=$fails" > {SERIAL}; echo "SR-GUEST-DONE rc=$fails" > {SERIAL}
poweroff
""")
    files = (_write_file_entry("/srv/sr-verify-checks.sh", script, perms="0755")
             + bake_files)
    return f"""#cloud-config
hostname: sr-finalize
manage_etc_hosts: true
package_update: false
package_upgrade: false
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
