"""Executable planning for service-check transactions (availability lane).

The registry declares WHAT counts as availability (`environment_specs/
checks.py`); this module renders each check into a transaction the TRUSTED
SCORING VANTAGE can actually run — a vetted, parameterised script per check
KIND, never an arbitrary command string from data:

  * the target guest and address come from the validated blueprint;
  * credential REFS (`credential:...`) are passed as environment variable
    NAMES to the vantage (`SR_CRED_<REF_UPPER>`), so no secret value is ever
    part of a plan, an event or a log;
  * the script exits 0 only when the transaction COMPLETED with the expected
    result; any other exit is an observation the caller must classify
    (target failure vs. scorer error) before it can become downtime;
  * what the plan MEANS is `srplatform/availability.py`'s decision table —
    this module never decides.

Nothing here samples anything: plans are data until an executor runs them
on the vantage and hands the observations back.
"""
from __future__ import annotations

import re

from .environment_specs.blueprint import EnvironmentBlueprint
from .environment_specs.checks import CheckKind, ServiceCheck, ServiceCheckRegistry

_CRED_REF = re.compile(r"^credential:([a-z][a-z0-9._-]{1,63})$")

#: Fixed transaction timeout per kind (seconds) — a check that cannot finish
#: within it is a SCORER timeout (unknown), never downtime.
TRANSACTION_TIMEOUT_S: dict[CheckKind, int] = {
    CheckKind.HTTPS_CONTENT: 15,
    CheckKind.MAIL_ROUNDTRIP: 45,
    CheckKind.WEB_LOGIN: 20,
    CheckKind.DNS_RECORDS: 15,
    CheckKind.DIRECTORY_AUTH: 20,
    CheckKind.SQL_SEED_READ: 30,
    CheckKind.SPLUNK_SEARCH: 30,
}


def _cred_env(ref: str) -> str:
    m = _CRED_REF.match(ref)
    if m is None:
        raise ValueError(f"not a credential ref: {ref!r}")
    return "SR_CRED_" + m.group(1).upper().replace(".", "_").replace("-", "_")


def _guest_address(bp: EnvironmentBlueprint, guest: str) -> str:
    g = bp.guest(guest)
    for iface in g.interfaces:
        if iface.ipv4 is not None and iface.ipv4.address:
            return str(iface.ipv4.address)
    raise ValueError(f"guest {guest!r} has no static address")


def _script(check: ServiceCheck, address: str) -> str:
    p = check.params
    kind = check.kind
    if kind == CheckKind.HTTPS_CONTENT:
        host = p.get("host_header") or address
        verify = "true" if p.get("verify_tls_against_lab_ca", True) else "false"
        return f"""python3 - <<'PY'
import ssl, sys, urllib.error, urllib.request

# A CLOSED port is the TARGET answering, not the scorer failing: the
# transaction ran and the service is down, so it is real downtime (3), never
# `unknown` — otherwise a dead service could never deduct a point.
def _closed(exc):
    if isinstance(getattr(exc, "reason", exc),
                  (ConnectionRefusedError, ConnectionResetError)):
        sys.exit(3)
    raise exc

ctx = ssl.create_default_context()
if "{verify}" == "false":
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
url = f"https://{address}{p['url_path']}"
req = urllib.request.Request(url, headers={{"Host": "{host}"}})
try:
    body = urllib.request.urlopen(req, timeout=10, context=ctx).read().decode(errors="replace")
except urllib.error.URLError as e:
    _closed(e)
sys.exit(0 if {p['expected_text']!r} in body else 3)
PY"""
    if kind == CheckKind.MAIL_ROUNDTRIP:
        protos = ",".join(p.get("protocols") or ["imap"])
        return f"""python3 - <<'PY'
import imaplib, os, poplib, smtplib, sys, time
sender = os.environ["{_cred_env(p['sender_ref'])}"]
reader = os.environ["{_cred_env(p['recipient_ref'])}"]
prefix = "{p.get('subject_prefix', 'SRPRB')}"
subject = prefix + "-" + str(int(time.time()))
try:
    smtp = smtplib.SMTP("{address}", 25, timeout=20)
    smtp.sendmail(sender, [reader], f"Subject: {{subject}}\\n\\nprobe")
    smtp.quit()
except (ConnectionRefusedError, ConnectionResetError):
    sys.exit(3)   # the mail port answered closed: real downtime
ok = False
for proto in "{protos}".split(","):
    if proto == "imap":
        try:
            c = imaplib.IMAP4("{address}", 143)
        except (ConnectionRefusedError, ConnectionResetError):
            sys.exit(3)
        c.login(reader.split("@")[0], os.environ["{_cred_env(p['recipient_ref'])}"])
        c.select("INBOX")
        _, data = c.search(None, "SUBJECT", subject)
        ok = ok or bool(data and data[0])
        c.logout()
    elif proto == "pop3":
        try:
            c = poplib.POP3("{address}", 110, timeout=20)
        except (ConnectionRefusedError, ConnectionResetError):
            sys.exit(3)
        c.user(reader.split("@")[0])
        c.pass_(os.environ["{_cred_env(p['recipient_ref'])}"])
        ok = ok or any(subject.encode() in line for line in c.list()[1])
        c.quit()
sys.exit(0 if ok else 3)
PY"""
    if kind == CheckKind.WEB_LOGIN:
        verify = "true" if p.get("verify_tls_against_lab_ca", True) else "false"
        return f"""python3 - <<'PY'
import os, ssl, sys, urllib.error, urllib.parse, urllib.request

def _closed(exc):
    if isinstance(getattr(exc, "reason", exc),
                  (ConnectionRefusedError, ConnectionResetError)):
        sys.exit(3)   # the port answered closed: the service is down
    raise exc

ctx = ssl.create_default_context()
if "{verify}" == "false":
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
acct = os.environ["{_cred_env(p['account_ref'])}"]
user, _, password = acct.partition(":")
data = urllib.parse.urlencode({{"_user": user, "_pass": password,
                               "_task": "login", "_action": "login"}}).encode()
try:
    body = urllib.request.urlopen(
        f"https://{address}{p['url_path']}", data=data, timeout=15,
        context=ctx).read().decode(errors="replace")
except urllib.error.URLError as e:
    _closed(e)
sys.exit(0 if {p['success_text']!r} in body else 3)
PY"""
    if kind == CheckKind.DNS_RECORDS:
        lines = []
        for name, types in p["records"].items():
            for rtype in types:
                lines.append(f'  ("{name}", "{rtype}"),')
        return f"""python3 - <<'PY'
import subprocess, sys
want = [
{chr(10).join(lines)}
]
bad = []
for name, rtype in want:
    out = subprocess.run(["dig", "+short", rtype, name, "@{address}"],
                         capture_output=True, text=True, timeout=8).stdout.strip()
    if not out:
        bad.append(name + "/" + rtype)
sys.exit(0 if not bad else 3)
PY"""
    if kind == CheckKind.DIRECTORY_AUTH:
        if p.get("method") == "kerberos-asreq":
            return f"""python3 - <<'PY'
import os, subprocess, sys
out = subprocess.run(["kinit", os.environ["{_cred_env(p['account_ref'])}"]],
                     capture_output=True, text=True, timeout=15,
                     env={{**os.environ, "KRB5CCNAME": "/tmp/sr-krb5"}})
sys.exit(0 if out.returncode == 0 else 3)
PY"""
        return f"""python3 - <<'PY'
import os, subprocess, sys
acct = os.environ["{_cred_env(p['account_ref'])}"]
user, _, password = acct.partition(":")
out = subprocess.run(
    ["ldapsearch", "-x", "-H", "ldap://{address}", "-D", user,
     "-w", password, "-b", "", "-s", "base", "(objectClass=*)", "dn"],
    capture_output=True, text=True, timeout=15)
sys.exit(0 if out.returncode == 0 and "dn:" in out.stdout else 3)
PY"""
    if kind == CheckKind.SQL_SEED_READ:
        return f"""python3 - <<'PY'
import os, sys
import pymssql
acct = os.environ["{_cred_env(p['app_account_ref'])}"]
user, _, password = acct.partition(":")
conn = pymssql.connect(server="{address}", user=user, password=password,
                       database="{p['database']}", timeout=20)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM sysobjects WHERE type = 'U'")
rows = cur.fetchone()[0]
conn.close()
sys.exit(0 if rows > 0 else 3)
PY"""
    if kind == CheckKind.SPLUNK_SEARCH:
        return f"""python3 - <<'PY'
import base64, json, os, sys, time, urllib.error, urllib.parse, urllib.request
acct = os.environ["{_cred_env(p['ingest_account_ref'])}"]
user, _, password = acct.partition(":")
base = "https://{address}:8089"
req = urllib.request.Request(
    base + "/services/search/jobs",
    data=urllib.parse.urlencode({{"search": "search index={p['index']} | head 1",
                                  "output_mode": "json"}}).encode(),
    headers={{"Authorization": "Basic " + base64.b64encode(
        f"{{user}}:{{password}}".encode()).decode()}})
try:
    body = json.loads(urllib.request.urlopen(req, timeout=20).read())
except urllib.error.URLError as e:
    if isinstance(getattr(e, "reason", e), (ConnectionRefusedError,
                                            ConnectionResetError)):
        sys.exit(3)   # the search API answered closed: real downtime
    raise
sid = body.get("sid")
for _ in range(20):
    time.sleep(1)
    req = urllib.request.Request(
        base + f"/services/search/jobs/{{sid}}/results?output_mode=json",
        headers={{"Authorization": "Basic " + base64.b64encode(
            f"{{user}}:{{password}}".encode()).decode()}})
    res = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if res.get("results"):
        sys.exit(0)
sys.exit(3)
PY"""
    raise ValueError(f"no transaction template for kind {kind.value}")


def plan_transactions(registry: ServiceCheckRegistry,
                      blueprint: EnvironmentBlueprint) -> list[dict]:
    """One executable plan per registered check, in registry order."""
    plans: list[dict] = []
    for check in registry.checks:
        address = _guest_address(blueprint, check.guest)
        plans.append({
            "check": check.id,
            "kind": check.kind.value,
            "guest": check.guest,
            "address": address,
            "timeout_s": TRANSACTION_TIMEOUT_S[check.kind],
            "script": _script(check, address),
            # env var NAMES only — the executor resolves the values from the
            # protected credential store; a plan never carries a secret.
            "credential_env": sorted({
                _cred_env(ref) for ref in _credential_refs(check)
            }),
            "interval_class": check.interval_class,
        })
    return plans


def _credential_refs(check: ServiceCheck) -> list[str]:
    refs: list[str] = []
    for value in check.params.values():
        if isinstance(value, str) and value.startswith("credential:"):
            refs.append(value)
    return refs
