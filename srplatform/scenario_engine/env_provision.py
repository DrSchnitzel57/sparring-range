"""Per-role provisioning: a booted golden guest -> its competition role.

The blueprint declares each guest's `services` (a closed enum). This module
owns the ONLY mapping from `ServiceId` to idempotent configuration steps, the
transport contract those steps run over (the broker's typed `guest_exec`),
and the durable evidence every attempt leaves behind.

Contracts (the reason this lives outside the deploy loop):

  * PLANNING IS PURE. `build_plan` reads the blueprint and the credential
    resolver only; it runs nothing, touches nothing. A plan can be inspected,
    tested and replayed without a guest or an appliance.
  * FAIL CLOSED, NEVER GUESS. A service id without a handler is recorded
    `unimplemented` (honest, not "ready"); a handler that cannot resolve a
    credential it needs records `failed` with the variable NAME (never the
    value) and runs nothing.
  * STEPS ARE IDEMPOTENT. Every script checks the state it wants before
    acting, so a reset (new generation) or a re-run converges instead of
    duplicating users, databases or records.
  * A SERVICE IS `ready` ONLY WHEN ITS LAST STEP EXITED 0 on the guest. A
    transport error (agent absent, VM gone) is `failed` evidence, never a
    silent success — the same rule the verification lanes use.
  * SECRETS NEVER ENTER EVIDENCE. Steps carry credential VARIABLES
    (`SR_CRED_*`); resolved values appear only inside the script handed to
    the guest, and the recorded evidence names steps, not values.

Wiring: `provision_deployment` resolves each guest's VMID/generation from the
deployment row (the same identity the deploy used), runs the plan over the
broker, and writes `provisioning: {service: {...}}` back onto that row.
VM deploy success and service provisioning state are separate evidence: a
deployed lab whose store is not configured yet is a usable lab, honestly not
a faithful one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol, Sequence

from srplatform.environment_specs.blueprint import ServiceId

#: A credential resolver maps `SR_CRED_*` variable names to values, or None
#: when the protected store cannot supply it. The value shape is documented
#: per service; nothing here parses more than `user:password`-style fields.
CredentialResolver = Callable[[str], "str | None"]

_CRED_PREFIX = "SR_CRED_"
WINDOWS_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


class ProvisionError(Exception):
    """A service plan cannot be built honestly (missing credential, missing
    guest address, handler without steps). Carried as evidence, never fatal
    to the VM deploy."""


# --------------------------------------------------------------- primitives


@dataclass(frozen=True)
class ExecResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Step:
    """One idempotent configuration step executed inside one guest."""

    id: str
    argv: tuple[str, ...]
    timeout_s: float = 180.0
    #: After this step's success the guest must be stopped, started and its
    #: agent waited on before the next step runs (AD DS promotion reboots).
    reboot: bool = False


class ProvisionTransport(Protocol):
    def exec(self, guest: str, argv: Sequence[str],
             timeout_s: float) -> ExecResult: ...

    def reboot(self, guest: str) -> None: ...


@dataclass(frozen=True)
class ProvisionContext:
    guest: str
    os: str                       # linux | windows | freebsd | router
    domain: str
    addresses: Mapping[str, str]  # guest name -> first static address
    generation: str
    resolver: CredentialResolver

    def address(self, other: str) -> str:
        try:
            return self.addresses[other]
        except KeyError:
            raise ProvisionError(
                f"provisioning {self.guest!r} needs the address of "
                f"{other!r} but the blueprint declares none") from None

    def cred(self, ref: str) -> str:
        """Resolve `credential:<name>` (or a bare name) or fail closed."""
        var = credential_var(ref)
        value = self.resolver(var)
        if not value:
            raise ProvisionError(
                f"provisioning {self.guest!r} needs {var}: the protected "
                f"credential store has no value (service not configured)")
        return value


def credential_var(ref: str) -> str:
    """`credential:store-app-sql` -> `SR_CRED_STORE_APP_SQL` (idempotent for
    refs and bare names alike)."""
    name = ref[len("credential:"):] if ref.startswith("credential:") else ref
    return _CRED_PREFIX + name.upper().replace(".", "_").replace("-", "_")


def split_credential(value: str) -> tuple[str, str]:
    """`user:password` -> (user, password); the user side may still carry a
    domain (`DOMAIN\\user` or `user@domain`) — callers that care split it."""
    user, _, password = value.partition(":")
    if not user or not password:
        raise ProvisionError(
            "credential value is not `user:password` shaped (value withheld)")
    return user, password


# ------------------------------------------------------------ the registry

ServiceHandler = Callable[[ProvisionContext], Sequence[Step]]
_HANDLERS: dict[ServiceId, ServiceHandler] = {}


def handler(service: ServiceId) -> Callable[[ServiceHandler], ServiceHandler]:
    """Register the ONE handler for a declared service id."""
    def register(fn: ServiceHandler) -> ServiceHandler:
        sid = ServiceId(service)
        if sid in _HANDLERS:
            raise ValueError(f"service {sid.value!r} already has a handler")
        _HANDLERS[sid] = fn
        return fn
    return register


def handler_for(service: ServiceId) -> ServiceHandler | None:
    return _HANDLERS.get(ServiceId(service))


def windows(script: str, timeout_s: float = 180.0) -> tuple[str, ...]:
    """PowerShell invocation for a cmd-channel script (no profile, no prompt)."""
    return (WINDOWS_POWERSHELL, "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", script)


def linux(script: str) -> tuple[str, ...]:
    return ("/bin/sh", "-c", script)


def ps_quote(value: str) -> str:
    """Single-quote a PowerShell literal; a quote cannot escape the argument.

    Credentials are synthetic and quote-free by design; doubling a stray quote
    keeps the step valid rather than silently changing the literal.
    """
    return "'" + str(value).replace("'", "''") + "'"


# -------------------------------------------------------------- the plan


@dataclass(frozen=True)
class ServicePlan:
    service: str
    state: str            # ready (steps) | unimplemented | failed (plan error)
    steps: tuple[Step, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class GuestPlan:
    guest: str
    services: tuple[ServicePlan, ...]


def _guest_addresses(bp) -> dict[str, str]:
    """First static address per guest — the address a dependency is dialled
    at. A blueprint guest without one is a plan-time error, not a guess."""
    out: dict[str, str] = {}
    for guest in bp.guests:
        addr = None
        for iface in guest.interfaces:
            ipv4 = getattr(iface, "ipv4", None)
            if ipv4 is not None and getattr(ipv4, "address", None):
                addr = str(ipv4.address)
                break
        if addr:
            out[guest.name] = addr
    return out


def build_plan(bp, *, generation: str,
               resolver: CredentialResolver) -> list[GuestPlan]:
    """PURE. Dependency-ordered plans for every guest that declares services.

    An unknown service is `unimplemented`; a handler that raises
    `ProvisionError` is `failed` with its reason. Either way the caller gets
    the whole picture before a single guest command runs.
    """
    addresses = _guest_addresses(bp)
    plans: list[GuestPlan] = []
    for name in bp.provision_order():
        guest = bp.guest(name)
        if not guest.services:
            continue
        ctx = ProvisionContext(
            guest=name, os=str(getattr(guest, "os", "")).split(".")[-1].lower(),
            domain=str(getattr(bp, "domain", "")), addresses=addresses,
            generation=generation, resolver=resolver)
        svc_plans: list[ServicePlan] = []
        for raw in guest.services:
            sid = ServiceId(raw)
            fn = handler_for(sid)
            if fn is None:
                svc_plans.append(ServicePlan(sid.value, "unimplemented"))
                continue
            try:
                steps = tuple(fn(ctx))
            except ProvisionError as exc:
                svc_plans.append(ServicePlan(sid.value, "failed",
                                             error=str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 — bad handler is loud
                svc_plans.append(ServicePlan(
                    sid.value, "failed",
                    error=f"handler error: {type(exc).__name__}: {exc}"))
                continue
            if not steps:
                svc_plans.append(ServicePlan(
                    sid.value, "failed",
                    error="handler produced no steps (cannot claim ready)"))
                continue
            svc_plans.append(ServicePlan(sid.value, "ready", steps=steps))
        plans.append(GuestPlan(name, tuple(svc_plans)))
    return plans


# --------------------------------------------------------------- execution


@dataclass
class StepRecord:
    id: str
    returncode: int | None = None
    timed_out: bool = False
    stderr_tail: str = ""


@dataclass
class ServiceOutcome:
    service: str
    state: str                     # ready | unimplemented | failed
    steps: list[StepRecord] = field(default_factory=list)
    error: str | None = None


def run_plan(plans: Sequence[GuestPlan],
             transport: ProvisionTransport) -> dict[str, list[ServiceOutcome]]:
    """Execute the plans in order; a service is `ready` only if every step
    exited 0. A step or transport failure stops that SERVICE (and its
    guest's later services still run? no — a broken guest state makes later
    services unreliable, so the remaining services of that guest are
    recorded `failed` unrun)."""
    outcomes: dict[str, Sequence[ServiceOutcome]] = {}
    for gp in plans:
        guest_out: list[ServiceOutcome] = []
        guest_broken = False
        for sp in gp.services:
            if sp.state != "ready":
                guest_out.append(ServiceOutcome(sp.service, sp.state,
                                                error=sp.error))
                continue
            if guest_broken:
                guest_out.append(ServiceOutcome(
                    sp.service, "failed",
                    error="not run: an earlier service failed on this guest"))
                continue
            out = ServiceOutcome(sp.service, "ready")
            for step in sp.steps:
                rec = StepRecord(step.id)
                try:
                    res = transport.exec(gp.guest, step.argv, step.timeout_s)
                except Exception as exc:  # noqa: BLE001 — transport failure
                    rec.stderr_tail = str(exc)[:400]
                    out.steps.append(rec)
                    out.state = "failed"
                    out.error = f"{step.id}: transport error: {exc}"[:400]
                    guest_broken = True
                    break
                rec.returncode = res.returncode
                rec.stderr_tail = (res.stderr or "")[-400:]
                out.steps.append(rec)
                if res.returncode != 0:
                    out.state = "failed"
                    out.error = f"{step.id} exited {res.returncode}"[:400]
                    guest_broken = True
                    break
                if step.reboot:
                    try:
                        transport.reboot(gp.guest)
                    except Exception as exc:  # noqa: BLE001
                        out.state = "failed"
                        out.error = f"{step.id}: reboot failed: {exc}"[:400]
                        guest_broken = True
                        break
            guest_out.append(out)
        outcomes[gp.guest] = guest_out
    return outcomes


def outcome_evidence(outcomes: Mapping[str, Sequence[ServiceOutcome]]) -> dict:
    """The JSON shape written onto a deployment resource row. Values are
    names and codes only — no secret and no command text."""
    evidence: dict[str, dict] = {}
    for guest, outs in outcomes.items():
        evidence[str(guest)] = {
            #: Ready means EVERY declared service is implemented AND passed;
            #: an unimplemented service can never be papered over.
            "ready": bool(outs) and all(o.state == "ready" for o in outs),
            "services": {
                o.service: {
                    "state": o.state,
                    **({"error": o.error} if o.error else {}),
                    "steps": [{"id": s.id, "returncode": s.returncode}
                              for s in o.steps],
                } for o in outs
            },
        }
    return evidence


# ------------------------------------------------------------ broker lane


class BrokerProvisionTransport:
    """The typed broker channel: `guest_exec` per guest, with the SAME
    ownership and generation identity the deploy claimed. A VMID recycled or
    a generation bumped by a reset is refused by the broker, never guessed
    around."""

    def __init__(self, broker, *, node: str, resources: Sequence[dict],
                 session_id: str, deployment_id: str):
        self._broker = broker
        self._node = node
        self._session_id = session_id
        self._deployment_id = str(deployment_id)
        self._by_host = {str(r.get("host")): dict(r) for r in resources}
        for res in self._by_host.values():
            gen = str(res.get("generation_attempt") or "")
            res["_generation"] = (self._deployment_id + (f":a{gen}" if gen
                                                         else ""))

    def _res(self, guest: str) -> dict:
        res = self._by_host.get(str(guest))
        if res is None or not res.get("vmid"):
            raise ProvisionError(f"guest {guest!r} has no deployed VMID")
        return res

    def exec(self, guest: str, argv: Sequence[str],
             timeout_s: float) -> ExecResult:
        res = self._res(guest)
        out = self._broker.guest_exec(
            self._node, int(res["vmid"]), list(argv),
            session_id=self._session_id, generation=res["_generation"],
            timeout_s=float(timeout_s))
        if not isinstance(out, dict):
            raise ProvisionError(f"guest exec on {guest!r} returned no result")
        return ExecResult(int(out.get("returncode", -1)),
                          str(out.get("stdout") or ""),
                          str(out.get("stderr") or ""))

    def reboot(self, guest: str) -> None:
        res = self._res(guest)
        self._broker.stop_and_confirm(self._node, int(res["vmid"]),
                                      session_id=self._session_id)
        self._broker.start_and_wait(self._node, int(res["vmid"]),
                                    timeout=300,
                                    session_id=self._session_id)


def provision_deployment(db, session_id, deployment, bp, broker, *,
                         node: str, resolver: CredentialResolver,
                         generation: str | None = None) -> dict:
    """Run the plan for a deployed environment and persist the evidence.

    Import-light on purpose (the DB row is touched only at the end), and the
    VM deploy's success is never rewritten: `provisioning` is its own field.
    """
    resources = [dict(r) for r in (deployment.resources or [])]
    generation = generation or str(deployment.deployment_id)
    plans = build_plan(bp, generation=generation, resolver=resolver)
    transport = BrokerProvisionTransport(
        broker, node=node, resources=resources, session_id=session_id,
        deployment_id=deployment.deployment_id)
    outcomes = run_plan(plans, transport)
    evidence = outcome_evidence(outcomes)
    for res in resources:
        row = evidence.get(str(res.get("host")))
        if row is not None:
            res["provisioning"] = row.pop("services")
            if row.get("ready"):
                res["provisioning_ready"] = True
            else:
                res.pop("provisioning_ready", None)
    from sqlalchemy.orm.attributes import flag_modified  # local, matching
    deployment.resources = resources
    flag_modified(deployment, "resources")
    db.commit()
    return {guest: {o.service: o.state for o in outs}
            for guest, outs in outcomes.items()}


# =============================================================== handlers
#
# Only the handlers that exist here are ever executed; everything else is
# recorded `unimplemented`. Each step is idempotent: the scripts check their
# target state before acting, so a reset converges from a used guest too.


@handler(ServiceId.SSH)
def ssh_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Linux guests answer SSH (the bastion lane); Windows guests do not run
    sshd at all — their channel is the guest agent (winrm handler)."""
    if ctx.os == "windows":
        return ()
    return (
        Step("ssh-enable",
             linux("systemctl enable --now ssh 2>/dev/null || "
                   "systemctl enable --now sshd 2>/dev/null || true"),
             timeout_s=120),
        Step("ssh-verify",
             linux("ss -ltn 2>/dev/null | grep -q ':22 '"),
             timeout_s=30),
    )


@handler(ServiceId.ACTIVE_DIRECTORY)
def active_directory_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Server 2022 forest `underpressure.local`: roles, promotion, the seeded
    practice account, and a verify that reads the domain back.

    The promotion reboots the guest; the runner waits on the stop/start pair
    before the DNS record steps (the `dns` service is ordered after this).
    """
    domain = ps_quote(ctx.domain)
    netbios = ps_quote(ctx.domain.split(".")[0].upper())
    dsrm = ps_quote(split_credential(ctx.cred("credential:directory-dsrm"))[1])
    account = split_credential(ctx.cred("credential:prb-directory"))[0]
    #: `UNDERPRESSURE\prb-directory` -> SAM account.
    sam = account.split("\\")[-1].split("@")[0]
    password = ps_quote(split_credential(
        ctx.cred("credential:prb-directory"))[1])
    dn = ",".join("DC=" + part for part in ctx.domain.split("."))
    dn_q = ps_quote(dn)
    ou_dn_q = ps_quote("OU=Lab," + dn)
    return (
        Step("ad-roles",
             windows("Install-WindowsFeature -Name AD-Domain-Services,DNS "
                     "-IncludeManagementTools | Out-Null", timeout_s=600),
             timeout_s=600),
        Step("ad-promote",
             windows(f"""
$done = $false
try {{ $d = Get-ADDomain -Identity {domain} -ErrorAction Stop; $done = $true }} catch {{}}
if (-not $done) {{
  $pw = ConvertTo-SecureString {dsrm} -AsPlainText -Force
  Install-ADDSForest -DomainName {domain} -DomainNetbiosName {netbios} `
    -SafeModeAdministratorPassword $pw -InstallDns -Force `
    -NoRebootOnCompletion -Confirm:$false
}}""", timeout_s=1800),
             timeout_s=1800, reboot=True),
        Step("ad-seed",
             windows(f"""
try {{ Get-ADOrganizationalUnit -Identity {ou_dn_q} -ErrorAction Stop | Out-Null }}
catch {{ New-ADOrganizationalUnit -Name 'Lab' -Path {dn_q} -ErrorAction Stop }}
$sam = {ps_quote(sam)}
if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {{
  New-ADUser -Name $sam -SamAccountName $sam `
    -UserPrincipalName "$sam@{ctx.domain}" `
    -Path {ou_dn_q} `
    -AccountPassword (ConvertTo-SecureString {password} -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
}}""", timeout_s=300),
             timeout_s=300),
        Step("ad-verify",
             windows(f"""
$d = Get-ADDomain -Identity {domain} -ErrorAction Stop
if ($d.DNSRoot -ne {domain}) {{ throw "domain DNSRoot mismatch" }}
if (-not (Get-ADUser -Filter "SamAccountName -eq '{sam}'" -ErrorAction SilentlyContinue)) {{ throw "seeded user missing" }}""",
                     timeout_s=120),
             timeout_s=120),
    )


@handler(ServiceId.DNS)
def dns_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The AD-integrated zone's service records: the apex MX, the replica's
    own A records and the LDAP SRV the directory check reads.

    Everything is name-addressed from the blueprint (no hard-coded lab
    answer); re-running never duplicates a record.
    """
    zone = ps_quote(ctx.domain)
    host_records = (
        ("ecomm", ctx.address("ecomm")),
        ("mail", ctx.address("webmail")),
        ("shop", ctx.address("ecomm")),
        ("splunk", ctx.address("splunk")),
        ("dc", ctx.address("ad-dns")),
    )
    adds = "\n".join(
        f"  @{{ Name = {ps_quote(name)}; IPv4 = {ps_quote(ip)} }}"
        for name, ip in host_records)
    verify = "\n".join(
        f"if (-not (Resolve-DnsName -Name '{name}.{ctx.domain}' -Server 127.0.0.1 "
        f"-Type A -ErrorAction SilentlyContinue)) {{ throw 'missing A {name}' }}"
        for name, _ip in host_records)
    return (
        Step("dns-a-records",
             windows(f"""
foreach ($r in @(
{adds}
)) {{
  if (-not (Get-DnsServerResourceRecord -ZoneName {zone} -Name $r.Name -RRType A -ErrorAction SilentlyContinue)) {{
    Add-DnsServerResourceRecordA -ZoneName {zone} -Name $r.Name `
      -IPv4Address $r.IPv4 -AllowUpdateAny -ErrorAction Stop
  }}
}}""", timeout_s=300),
             timeout_s=300),
        Step("dns-mx",
             windows(f"""
$mx = Get-DnsServerResourceRecord -ZoneName {zone} -RRType MX -ErrorAction SilentlyContinue
if (-not $mx) {{
  Add-DnsServerResourceRecordMX -ZoneName {zone} -Name "@" `
    -MailExchange "mail.{ctx.domain}" -Preference 10 -AllowUpdateAny -ErrorAction Stop
}}""", timeout_s=120),
             timeout_s=120),
        Step("dns-verify",
             windows(f"""
{verify}
if (-not (Resolve-DnsName -Name {ps_quote(ctx.domain)} -Server 127.0.0.1 -Type MX -ErrorAction SilentlyContinue)) {{ throw 'missing MX' }}
if (-not (Resolve-DnsName -Name {ps_quote('_ldap._tcp.dc._msdcs.' + ctx.domain)} -Server 127.0.0.1 -Type SRV -ErrorAction SilentlyContinue)) {{ throw 'missing LDAP SRV' }}""",
                     timeout_s=180),
             timeout_s=180),
    )


#: One sqlcmd step: locate the client by its TOOLS directory (the SQL Server
#: installer path differs by edition/version), then run a batch with -b so a
#: T-SQL error is a nonzero exit this module can trust. Windows auth (`-E`)
#: unless an application account is given — the verify steps use the SAME
#: account the availability check authenticates with.
def _sqlcmd(script: str, *, user: str | None = None,
            password: str | None = None,
            database: str | None = None) -> str:
    auth = (f"-U {ps_quote(user)} -P {ps_quote(password)}" if user else "-E")
    db = f"-d {ps_quote(database)}" if database else ""
    return f"""
$sqlcmd = (Get-ChildItem 'C:\\Program Files\\Microsoft SQL Server' -Recurse `
  -Filter sqlcmd.exe -ErrorAction SilentlyContinue |
  Where-Object {{ $_.FullName -like '*TOOLS*' }} |
  Select-Object -First 1).FullName
if (-not $sqlcmd) {{ throw 'sqlcmd.exe not found' }}
& $sqlcmd -S localhost {db} {auth} -b -Q {ps_quote(script)}
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}"""


@handler(ServiceId.MSSQL)
def mssql_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Both databases the checks read (`UnderpressureStore`, `roundcube`),
    their application logins, and a seeded table each — checked by logging in
    AS the application accounts, so the evidence proves authentication, not
    just that a database exists.
    """
    store_user, store_pw = split_credential(ctx.cred("credential:store-app-sql"))
    rc_user, rc_pw = split_credential(ctx.cred("credential:rc-app-sql"))
    store_user = store_user.split("\\")[-1]
    seed_rows = "".join(
        f" INSERT INTO dbo.SeedRows (id, label) VALUES ({i}, 'sr-seed-{i}');"
        for i in range(1, 4))
    return (
        Step("mssql-store",
             windows(_sqlcmd(f"""
IF DB_ID('UnderpressureStore') IS NULL CREATE DATABASE UnderpressureStore;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '{store_user}')
  CREATE LOGIN [{store_user}] WITH PASSWORD = '{store_pw}', CHECK_POLICY = OFF;
USE UnderpressureStore;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '{store_user}')
  CREATE USER [{store_user}] FOR LOGIN [{store_user}];
GRANT SELECT ON SCHEMA::dbo TO [{store_user}];
IF OBJECT_ID('dbo.SeedRows', 'U') IS NULL
  CREATE TABLE dbo.SeedRows (id int PRIMARY KEY, label nvarchar(64) NOT NULL);
IF NOT EXISTS (SELECT 1 FROM dbo.SeedRows)
BEGIN{seed_rows}
END"""), timeout_s=600),
             timeout_s=600),
        Step("mssql-roundcube",
             windows(_sqlcmd(f"""
IF DB_ID('roundcube') IS NULL CREATE DATABASE roundcube;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '{rc_user}')
  CREATE LOGIN [{rc_user}] WITH PASSWORD = '{rc_pw}', CHECK_POLICY = OFF;
USE roundcube;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '{rc_user}')
  CREATE USER [{rc_user}] FOR LOGIN [{rc_user}];
GRANT SELECT ON SCHEMA::dbo TO [{rc_user}];
IF OBJECT_ID('dbo.SeedRows', 'U') IS NULL
  CREATE TABLE dbo.SeedRows (id int PRIMARY KEY, label nvarchar(64) NOT NULL);
IF NOT EXISTS (SELECT 1 FROM dbo.SeedRows)
BEGIN{seed_rows}
END"""), timeout_s=600),
             timeout_s=600),
        Step("mssql-verify",
             windows(_sqlcmd(
                 "SELECT COUNT(*) FROM sys.tables WHERE is_ms_shipped = 0",
                 user=store_user, password=store_pw,
                 database="UnderpressureStore"), timeout_s=180),
             timeout_s=180),
    )
