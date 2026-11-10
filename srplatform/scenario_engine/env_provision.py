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


class LabPKI(Protocol):
    """The little bit of the replica CA a handler is allowed to use: issue a
    service certificate for a name + SANs, and hand out the PUBLIC anchor.
    The CA key never reaches a provision step."""

    def issue(self, common_name: str, sans: Sequence[str]):
        """Return an object with `certificate_pem` and `key_pem` bytes."""

    def trust_pem(self) -> bytes: ...


@dataclass(frozen=True)
class ProvisionContext:
    guest: str
    os: str                       # linux | windows | freebsd | router
    domain: str
    addresses: Mapping[str, str]  # guest name -> first static address
    generation: str
    resolver: CredentialResolver
    pki: LabPKI | None = None
    #: Public VIPs that DNAT to this guest (the addresses the scoring
    #: vantage actually dials through the edge).
    public_vips: tuple[str, ...] = ()
    #: The blueprint's declared DNS records (name, type, value, preference),
    #: so the zone is the documented one and not a hand-typed subset.
    dns_records: tuple = ()
    #: The validated blueprint itself: edge handlers need segments, routes and
    #: public forwards, and restating them as tuples would be a second source
    #: of truth that could drift.
    bp: object | None = None

    def own_prefix(self) -> int:
        """The prefix length of this guest's first address (from its segment)."""
        import ipaddress
        if self.bp is None:
            return 24
        addr = ipaddress.ip_address(self.own_address())
        for seg in getattr(self.bp, "segments", []):
            net = ipaddress.ip_network(str(seg.cidr), strict=False)
            if addr in net:
                return net.prefixlen
        return 24

    def own_address(self) -> str:
        return self.address(self.guest)

    def certificate(self, hostname: str) -> tuple[str, str]:
        """(certificate, key) PEM for THIS guest's address under `hostname`.
        The IP SAN is what makes `verify_tls_against_lab_ca` pass: the check
        dials the guest ADDRESS and hostname-verifies against it."""
        if self.pki is None:
            raise ProvisionError(
                f"provisioning {self.guest!r} needs the replica CA for TLS "
                f"but no CA was supplied to the plan")
        issued = self.pki.issue(hostname,
                                [hostname, self.own_address(),
                                 *self.public_vips])
        return (issued.certificate_pem.decode(),
                issued.key_pem.decode())

    def ca_pem(self) -> str:
        if self.pki is None:
            raise ProvisionError("replica CA unavailable")
        return self.pki.trust_pem().decode()

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


def linux(script: str, timeout_s: float | None = None) -> tuple[str, ...]:
    """`sh -c` invocation; `timeout_s` is accepted only so handlers can pass
    the same number to both the argv and the Step (the Step is authoritative)."""
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
               resolver: CredentialResolver,
               pki: "LabPKI | None" = None) -> list[GuestPlan]:
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
        vips = tuple(str(f.vip) for f in getattr(bp, "public_forwards", [])
                     if f.target_guest == name)
        dns_records = tuple(
            (str(r.name), str(r.type), str(r.value), getattr(r, "preference", None))
            for r in getattr(bp, "dns_records", []))
        ctx = ProvisionContext(
            guest=name, os=str(getattr(guest, "os", "")).split(".")[-1].lower(),
            domain=str(getattr(bp, "domain", "")), addresses=addresses,
            generation=generation, resolver=resolver, pki=pki,
            public_vips=vips, dns_records=dns_records, bp=bp)
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


def resolver_from_settings(settings) -> CredentialResolver:
    """The protected store as a resolver, for whatever identity calls this.

    Readability is the CALLER's property, not a fallback: `credentials.load`
    refuses a mis-owned/mis-moded file (the rule that keeps it a secret), and
    a resolver bound without rights simply answers None for every name — the
    lab still deploys, its credential-dependent services record `failed` with
    the variable name. Root-run gates and the operator path can read it; the
    API identity cannot unless the operator says so.
    """
    from srplatform.credentials import DEFAULT_PATH, resolver

    path = getattr(settings, "environment_credentials_file", "") or DEFAULT_PATH
    try:
        inner = resolver(path)
    except Exception:  # noqa: BLE001 — unreadable now, re-checked per name
        return lambda name: None

    def resolve(name: str) -> str | None:
        try:
            return inner(name)
        except Exception:  # noqa: BLE001 — never fatal to a deploy
            return None

    return resolve


def provision_deployment(db, session_id, deployment, bp, broker, *,
                         node: str, resolver: CredentialResolver,
                         pki: "LabPKI | None" = None,
                         generation: str | None = None) -> dict:
    """Run the plan for a deployed environment and persist the evidence.

    Import-light on purpose (the DB row is touched only at the end), and the
    VM deploy's success is never rewritten: `provisioning` is its own field.
    """
    resources = [dict(r) for r in (deployment.resources or [])]
    generation = generation or str(deployment.deployment_id)
    plans = build_plan(bp, generation=generation, resolver=resolver, pki=pki)
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
    ip = ctx.own_address()
    prefix = ctx.own_prefix()
    return (
        Step("ad-address",
             windows(f"""
$if = (Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} |
       Select-Object -First 1)
Set-NetIPInterface -InterfaceAlias $if.Name -Dhcp Disabled -ErrorAction SilentlyContinue
if (-not (Get-NetIPAddress -IPAddress {ps_quote(ip)} -ErrorAction SilentlyContinue)) {{
  New-NetIPAddress -InterfaceAlias $if.Name -IPAddress {ps_quote(ip)} `
    -PrefixLength {prefix} -ErrorAction Stop
}}
Set-DnsClientServerAddress -InterfaceAlias $if.Name -ServerAddresses '127.0.0.1'""",
                     timeout_s=120),
             timeout_s=120),
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
    """The AD-integrated zone seeded with EVERY record the blueprint declares
    (A, MX, CNAME); the LDAP SRV is created by the promotion and only
    verified here. Re-running never duplicates a record."""
    if not ctx.dns_records:
        raise ProvisionError(
            "the blueprint declares no dns_records — the zone cannot be "
            "seeded without them")
    zone = ps_quote(ctx.domain)
    suffix = "." + ctx.domain

    def rel(name: str) -> str:
        return name[:-len(suffix)] if name.endswith(suffix) else name

    a_recs = [(rel(n), v) for n, kind, v, _p in ctx.dns_records
              if kind == "A"]
    cname_recs = [(rel(n), v) for n, kind, v, _p in ctx.dns_records
                  if kind == "CNAME"]
    mx_recs = [(v, p) for n, kind, v, p in ctx.dns_records if kind == "MX"]

    adds = []
    for name, addr in a_recs:
        adds.append(
            f"if (-not (Get-DnsServerResourceRecord -ZoneName {zone} "
            f"-Name {ps_quote(name)} -RRType A -ErrorAction SilentlyContinue)) {{"
            f" Add-DnsServerResourceRecordA -ZoneName {zone} -Name "
            f"{ps_quote(name)} -IPv4Address {ps_quote(addr)} "
            f"-AllowUpdateAny -ErrorAction Stop }}")
    for name, alias in cname_recs:
        adds.append(
            f"if (-not (Get-DnsServerResourceRecord -ZoneName {zone} "
            f"-Name {ps_quote(name)} -RRType CNAME -ErrorAction SilentlyContinue)) {{"
            f" Add-DnsServerResourceRecordCName -ZoneName {zone} -Name "
            f"{ps_quote(name)} -HostNameAlias {ps_quote(alias)} "
            f"-AllowUpdateAny -ErrorAction Stop }}")
    if mx_recs:
        exchange, preference = mx_recs[0]
        adds.append(
            f"if (-not (Get-DnsServerResourceRecord -ZoneName {zone} "
            f"-RRType MX -ErrorAction SilentlyContinue)) {{ "
            f"Add-DnsServerResourceRecordMX -ZoneName {zone} -Name '@' "
            f"-MailExchange {ps_quote(exchange)} -Preference "
            f"{int(preference or 10)} -AllowUpdateAny -ErrorAction Stop }}")
    seed = "\n".join(adds)
    verify_lines = [
        f"if (-not (Resolve-DnsName -Name {ps_quote(n)} -Server 127.0.0.1 "
        f"-ErrorAction SilentlyContinue)) {{ throw 'missing {n}' }}"
        for n in [rel(x[0]) for x in a_recs] + [rel(x[0]) for x in cname_recs]
    ]
    verify = "\n".join(verify_lines)
    return (
        Step("dns-records",
             windows(f"""
{seed}""", timeout_s=300),
             timeout_s=300),
        Step("dns-mx",
             windows(f"""
if (-not (Resolve-DnsName -Name {ps_quote(ctx.domain)} -Server 127.0.0.1 -Type MX -ErrorAction SilentlyContinue)) {{ throw 'missing MX' }}""",
                     timeout_s=120),
             timeout_s=120),
        Step("dns-verify",
             windows(f"""
{verify}
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
    dns = ctx.address("ad-dns")
    ip = ctx.own_address()
    prefix = ctx.own_prefix()
    return (
        Step("mssql-address",
             windows(f"""
$if = (Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} |
       Select-Object -First 1)
Set-NetIPInterface -InterfaceAlias $if.Name -Dhcp Disabled -ErrorAction SilentlyContinue
if (-not (Get-NetIPAddress -IPAddress {ps_quote(ip)} -ErrorAction SilentlyContinue)) {{
  New-NetIPAddress -InterfaceAlias $if.Name -IPAddress {ps_quote(ip)} `
    -PrefixLength {prefix} -ErrorAction Stop
}}
Set-DnsClientServerAddress -InterfaceAlias $if.Name -ServerAddresses {ps_quote(dns)}""",
                     timeout_s=120),
             timeout_s=120),
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


@handler(ServiceId.WINRM)
def winrm_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The reported weak opening state: WinRM over HTTP, 5985, plainly
    encrypted-optional — reproduced deliberately, because the entry-path
    security task is graded on it. Idempotent; the verify proves the listener
    answers on the port the defenders have to remediate.
    """
    return (
        Step("winrm-enable",
             windows("""
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value $true -Force
Set-Item WSMan:\\localhost\\Client\\AllowUnencrypted -Value $true -Force
Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value $true -Force
Set-Item WSMan:\\localhost\\Client\\Auth\\Basic -Value $true -Force
Set-Service -Name WinRM -StartupType Automatic
Restart-Service WinRM -Force""", timeout_s=300),
             timeout_s=300),
        Step("winrm-verify",
             windows("""
$l = Get-NetTCPConnection -LocalPort 5985 -State Listen `
  -ErrorAction SilentlyContinue
if (-not $l) { throw '5985 is not listening' }""", timeout_s=60),
             timeout_s=60),
    )


@handler(ServiceId.SSSD_AD)
def sssd_ad_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Linux domain join: the resolver points at AD DNS, then realmd joins the
    forest with the directory admin account, then the practice account is
    looked up BY NAME — SSSD join evidence, not a package list.

    Password travels on stdin, never on the argument list the broker audits.
    """
    admin = split_credential(ctx.cred("credential:directory-join"))[0]
    password = split_credential(ctx.cred("credential:directory-join"))[1]
    dns = ps_quote(ctx.address("ad-dns"))
    return (
        Step("sssd-dns-client",
             linux(f"""
printf 'nameserver %s\\nsearch {ctx.domain}\\noptions timeout:2 attempts:2\\n' > /etc/resolv.conf
if command -v resolvectl >/dev/null 2>&1 && systemctl is-active -q systemd-resolved; then
  resolvectl dns "$(ip route show default | awk '{{print $5}}' | head -1)" {dns} >/dev/null 2>&1 || true
  resolvectl domain "$(ip route show default | awk '{{print $5}}' | head -1)" {ctx.domain} >/dev/null 2>&1 || true
fi
getent hosts {ctx.address("ad-dns")} >/dev/null"""),
             timeout_s=120),
        Step("sssd-packages",
             linux("export DEBIAN_FRONTEND=noninteractive; "
                   "dpkg -s sssd realmd adcli oddjob-mkhomedir >/dev/null 2>&1 || "
                   "apt-get -y install sssd realmd adcli oddjob-mkhomedir "
                   "libnss-sss libpam-sss >/dev/null 2>&1 || true"),
             timeout_s=900),
        Step("sssd-join",
             linux(f"""
realm list 2>/dev/null | grep -qi {ps_quote(ctx.domain)} && exit 0
echo {ps_quote(password)} | realm join --user={ps_quote(admin)} --computer-ou='/CN=Computers,DC={ctx.domain.replace(".", ",DC=")}' {ctx.domain} 2>&1 | tail -5
realm list 2>/dev/null | grep -qi {ps_quote(ctx.domain)}""", timeout_s=600),
             timeout_s=600),
        Step("sssd-verify",
             linux(f"getent passwd {ps_quote('prb-directory@' + ctx.domain)} "
                   "> /dev/null"),
             timeout_s=120),
    )


#: Splunk's first start in the build seed uses `--accept-license --no-prompt`,
#: which leaves the shipped default admin credential. It is a synthetic lab
#: value, replaced here by the protected store entry, never assumed.
SPLUNK_INPUTS_CONF = """[UDP://sr-syslog]
connection_host = dns
port = 5514
"""


@handler(ServiceId.SPLUNK)
def splunk_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Splunk answers an AUTHENTICATED search as the practice account, after
    proving it accepts events end to end (UDP -> index -> searchable)."""
    admin_user, admin_pw = split_credential(ctx.cred("credential:splunk-admin"))
    prb_user, prb_pw = split_credential(ctx.cred("credential:splunk-prb"))
    return (
        Step("splunk-listen",
             linux(f"""
/opt/splunk/bin/splunk enable listen 9997 -auth {admin_user}:{admin_pw} >/dev/null 2>&1 || true
ss -ltn | grep -q ':9997 '""", timeout_s=300),
             timeout_s=300),
        Step("splunk-user",
             linux(f"""
pw=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" {ps_quote(prb_pw)})
if ! curl -s -k -u {admin_user}:{admin_pw} \
     https://127.0.0.1:8089/services/authentication/users/{ps_quote(prb_user)} \
     -o /dev/null; then
  curl -s -k -u {admin_user}:{admin_pw} -X POST \
    https://127.0.0.1:8089/services/authentication/users \
    -d "name={prb_user}" -d "password=$pw" -d "roles=user" >/dev/null
fi
curl -s -k -u {admin_user}:{admin_pw} \
  https://127.0.0.1:8089/services/authentication/users/{ps_quote(prb_user)} \
  -o /dev/null""", timeout_s=300),
             timeout_s=300),
        Step("splunk-verify",
             linux(f"""
/opt/splunk/bin/splunk search 'search index=main | head 1' \
  -auth {admin_user}:{admin_pw} -maxout 1 >/dev/null 2>&1 || exit 1""",
                   timeout_s=300),
             timeout_s=300),
    )


@handler(ServiceId.SYSLOG_RECEIVER)
def syslog_receiver_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The 5514 UDP input AND a seed event that proves the chain: the guest
    sends one synthetic line to its own input, waits, and finds it by search.
    A listening port alone never counts."""
    admin_user, admin_pw = split_credential(ctx.cred("credential:splunk-admin"))
    return (
        Step("syslog-input",
             linux(f"""
mkdir -p /opt/splunk/etc/system/local
grep -q '\\[UDP://sr-syslog\\]' /opt/splunk/etc/system/local/inputs.conf 2>/dev/null || cat >> /opt/splunk/etc/system/local/inputs.conf <<'CONF'
{SPLUNK_INPUTS_CONF}CONF
ss -lun | grep -q ':5514 ' || /opt/splunk/bin/splunk restart --no-prompt >/dev/null 2>&1 || systemctl restart Splunkd
ss -lun | grep -q ':5514 '""", timeout_s=600),
             timeout_s=600),
        Step("syslog-seed",
             linux(f"""
python3 - <<'PY'
import socket, time
marker = "SRPRB-syslog-" + str(int(time.time()))
with open("/tmp/sr-syslog-marker", "w") as fh:
    fh.write(marker)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto((marker + " synthetic edge event").encode(), ("127.0.0.1", 5514))
PY
sleep 8
marker=$(cat /tmp/sr-syslog-marker)
/opt/splunk/bin/splunk search "search index=main $marker" \
  -auth {admin_user}:{admin_pw} -maxout 1 2>/dev/null | grep -q "$marker" """,
                   timeout_s=300),
             timeout_s=300),
    )



# ------------------------------------------------------------- store role
#
# The golden is Rocky 9 with httpd+PHP (built that way); the reported stack was
# nginx + nopCommerce/.NET. Provisioning uses what the image actually carries
# and the substitution is recorded in fidelity.yaml — never claimed as
# nopCommerce.

STORE_PAGE = """<!doctype html>
<html><head><title>Underpressure Water Authority Store</title></head>
<body>
<h1>Underpressure Water Authority Store</h1>
<p>Water accounts, conservation kits and meter services.</p>
<ul class="catalogue">
  <li data-sku="WATER-KIT-01">Household Water Kit</li>
  <li data-sku="METER-SVC-02">Meter Service Plan</li>
  <li data-sku="TANK-VALVE-03">Tank Valve Assembly</li>
</ul>
</body></html>
"""


def _write_pem_step(stem: str, cert: str, key: str) -> str:
    """Write a certificate/key pair without shell interpolation of PEM."""
    import base64 as _b64
    c = _b64.b64encode(cert.encode()).decode()
    k = _b64.b64encode(key.encode()).decode()
    return f"""
install -d -m 755 /etc/pki/sr
printf '%s' '{c}' | base64 -d > /etc/pki/sr/{stem}.crt
printf '%s' '{k}' | base64 -d > /etc/pki/sr/{stem}.key
chmod 600 /etc/pki/sr/{stem}.key"""


def _write_ca_step(ca: str) -> str:
    import base64 as _b64
    c = _b64.b64encode(ca.encode()).decode()
    return f"""
install -d -m 755 /etc/pki/sr
printf '%s' '{c}' | base64 -d > /etc/pki/sr/ca.crt
chmod 644 /etc/pki/sr/ca.crt"""


@handler(ServiceId.NOPCOMMERCE)
def nopcommerce_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The store's CONTENT (a seeded catalogue page). The HTTPS front end is
    the `nginx` service's job; this handler only guarantees that the catalogue
    exists and is what the check reads."""
    page = STORE_PAGE.replace("'", "'\\''")
    return (
        Step("store-content",
             linux(f"""
install -d -m 755 /var/www/store
cat > /var/www/store/index.html <<'HTML'
{STORE_PAGE}HTML
if command -v chcon >/dev/null 2>&1; then chcon -R -t httpd_sys_content_t /var/www/store 2>/dev/null || true; fi""",
                   timeout_s=60),
             timeout_s=60),
        Step("store-content-verify",
             linux(f"grep -q 'Underpressure Water Authority Store' "
                   "/var/www/store/index.html"),
             timeout_s=30),
    )


@handler(ServiceId.NGINX)
def nginx_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """HTTPS for `shop.<domain>` on THIS guest's address, signed by the
    replica CA, served by whichever front end the golden carries (nginx or
    httpd — both are accepted; a missing one fails the verify, never a
    silent success)."""
    host = "shop." + ctx.domain
    cert, key = ctx.certificate(host)
    ca = ctx.ca_pem()
    conf = f"""
if command -v nginx >/dev/null 2>&1; then
  cat > /etc/nginx/conf.d/sr-store.conf <<'CONF'
server {{
  listen 80;
  server_name {host};
  return 301 https://$host$request_uri;
}}
server {{
  listen 443 ssl;
  server_name {host};
  root /var/www/store;
  index index.html;
  ssl_certificate /etc/pki/sr/shop.crt;
  ssl_certificate_key /etc/pki/sr/shop.key;
}}
CONF
  nginx -t && systemctl enable --now nginx && systemctl reload nginx
elif command -v apache2 >/dev/null 2>&1; then
  # Debian/Ubuntu apache2: site files, a2enmod ssl. The ecomm golden is the
  # Ubuntu 24.04 build with apache2 2.4 (no httpd, no nginx); asking for
  # httpd exited 127 and abandoned the rest of the guest.
  a2enmod ssl >/dev/null 2>&1 || true
  cat > /etc/apache2/sites-available/sr-store.conf <<'CONF'
<VirtualHost *:80>
  ServerName {host}
  Redirect permanent / https://{host}/
</VirtualHost>
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /etc/pki/sr/shop.crt
  SSLCertificateKeyFile /etc/pki/sr/shop.key
  ServerName {host}
  DocumentRoot /var/www/store
  <Directory /var/www/store>
    Require all granted
  </Directory>
</VirtualHost>
CONF
  a2ensite sr-store >/dev/null 2>&1 || true
  apache2ctl -t && systemctl enable --now apache2 && systemctl reload apache2
else
  cat > /etc/httpd/conf.d/sr-store.conf <<'CONF'
Listen 80
<VirtualHost *:80>
  ServerName {host}
  Redirect permanent / https://{host}/
</VirtualHost>
Listen 443
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /etc/pki/sr/shop.crt
  SSLCertificateKeyFile /etc/pki/sr/shop.key
  ServerName {host}
  DocumentRoot /var/www/store
  <Directory /var/www/store>
    Require all granted
  </Directory>
</VirtualHost>
CONF
  httpd -t && systemctl enable --now httpd && systemctl reload httpd
fi"""
    verify = f"""
curl -sS --silent --fail --cacert /etc/pki/sr/ca.crt \
  --resolve {host}:443:127.0.0.1 https://{host}/ -o /dev/null"""
    return (
        Step("store-tls", linux(_write_pem_step("shop", cert, key) + "\n"
                                + _write_ca_step(ca)), timeout_s=60),
        Step("store-front", linux(conf, timeout_s=300), timeout_s=300),
        Step("store-tls-verify", linux(verify, timeout_s=60), timeout_s=60),
    )


# -------------------------------------------------------------- mail role


def _mail_users(ctx: ProvisionContext) -> list[tuple[str, str]]:
    """(local part, password) for the two practice mail identities the check
    sends/reads as — the SAME values the vantage receives as env vars."""
    out = []
    for ref in ("credential:prb-mail-sender", "credential:prb-mail-reader"):
        user, password = split_credential(ctx.cred(ref))
        out.append((user.split("@")[0], password))
    return out


@handler(ServiceId.POSTFIX)
def postfix_handler(ctx: ProvisionContext) -> Sequence[Step]:
    users = _mail_users(ctx)
    relaying = ",".join(sorted({u[0] for u in users}))
    return (
        Step("postfix-config",
             linux(f"""
postconf -e 'myhostname = mail.{ctx.domain}' \
  'mydomain = {ctx.domain}' 'myorigin = $mydomain' \
  'mydestination = {ctx.domain}, localhost' \
  'inet_interfaces = all' 'inet_protocols = ipv4' \
  'home_mailbox = Maildir/' 'mynetworks = 127.0.0.0/8, {ctx.own_address()}/24' \
  'local_recipient_maps ='
for u in {relaying}; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/sh "$u"
done
postfix check && systemctl enable --now postfix
systemctl reload postfix""", timeout_s=300),
             timeout_s=300),
        Step("postfix-verify",
             linux("ss -ltn | grep -q ':25 ' && postfix status >/dev/null"),
             timeout_s=60),
    )


@handler(ServiceId.DOVECOT)
def dovecot_handler(ctx: ProvisionContext) -> Sequence[Step]:
    users = _mail_users(ctx)
    lines = "\n".join(f"{u}:{{PLAIN}}{p}" for u, p in users)
    host = "mail." + ctx.domain
    cert, key = ctx.certificate(host)
    ca = ctx.ca_pem()
    #: Opening state as reported: plaintext auth allowed; the public path is
    #: the published secure ports (993/995) the blueprint DNATs, so Dovecot
    #: terminates TLS there with the replica CA.
    return (
        Step("dovecot-tls",
             linux(_write_pem_step("mail", cert, key) + "\n"
                   + _write_ca_step(ca)
                   + """
if ! getent group dovecot >/dev/null 2>&1; then
  groupadd -r dovecot 2>/dev/null || true
fi
chown dovecot:dovecot /etc/pki/sr/mail.key 2>/dev/null || true
chmod 640 /etc/pki/sr/mail.key""", timeout_s=60),
             timeout_s=60),
        Step("dovecot-users",
             linux(f"""
install -d -m 755 /etc/dovecot
cat > /etc/dovecot/sr-users <<'USERS'
{lines}
USERS
chown root:www-data /etc/dovecot/sr-users && chmod 640 /etc/dovecot/sr-users
if ! grep -q 'sr-users' /etc/dovecot/conf.d/10-auth.conf 2>/dev/null; then
  printf '!include auth-passwd-file.conf\\n' >> /etc/dovecot/conf.d/10-auth.conf
fi
cat > /etc/dovecot/conf.d/99-sr.conf <<'CONF'
disable_plaintext_auth = no
auth_mechanisms = plain login
ssl = yes
ssl_cert = </etc/pki/sr/mail.crt
ssl_key = </etc/pki/sr/mail.key
mail_location = maildir:/var/mail/%u/Maildir
passdb {{
  driver = passwd-file
  args = /etc/dovecot/sr-users
}}
userdb {{
  driver = passwd-file
  args = /etc/dovecot/sr-users
  default_fields = uid=1000 gid=1000 home=/var/mail/%u
}}
protocols = imap pop3
CONF
for u in {' '.join(u for u, _ in users)}; do
  mkdir -p /var/mail/$u/Maildir/cur /var/mail/$u/Maildir/new /var/mail/$u/Maildir/tmp
  chown -R 1000:1000 /var/mail/$u
done
doveconf -n >/dev/null && systemctl enable --now dovecot && systemctl restart dovecot""",
                   timeout_s=300),
             timeout_s=300),
        Step("dovecot-verify",
             linux("ss -ltn | grep -q ':993 ' && ss -ltn | grep -q ':995 '"),
             timeout_s=60),
    )


#: Roundcube is NOT in the offline Ubuntu image (its sqlsrv driver comes from
#: an MS repo), so the webmail UI is a minimal PHP substitute that authenticates
#: against the same Dovecot passwd-file and lists the Maildir. Recorded as
#: substituted in fidelity.yaml.
ROUNDCUBE_APP = r"""<?php
$users = array();
foreach (file('/etc/dovecot/sr-users', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    if (strpos($line, ':') === false) continue;
    list($u, $p) = explode(':', $line, 2);
    $users[$u] = preg_replace('/^\{PLAIN\}/', '', $p);
}
$user = isset($_POST['_user']) ? $_POST['_user'] : '';
$user = preg_replace('/@.*$/', '', $user);   // the check posts the full address
$pass = isset($_POST['_pass']) ? $_POST['_pass'] : '';
if ($user === '' || !isset($users[$user]) || !hash_equals($users[$user], $pass)) {
    echo '<html><body><h2>Webmail login</h2>';
    echo '<form method="post"><input name="_user"><input name="_pass" type="password"><button>Login</button></form>';
    echo '</body></html>';
    exit;
}
$dir = '/var/mail/' . $user . '/Maildir/new';
$mails = is_dir($dir) ? glob($dir . '/*') : array();
echo '<html><body><h2>Inbox</h2><p>' . count($mails) . ' message(s)</p><ul>';
foreach ($mails as $m) {
    $fh = fopen($m, 'r');
    $subject = '';
    foreach (explode("\n", fread($fh, 2048)) as $h) {
        if (stripos($h, 'Subject:') === 0) { $subject = trim(substr($h, 8)); break; }
        if (trim($h) === '') break;
    }
    fclose($fh);
    echo '<li>' . htmlspecialchars($subject) . '</li>';
}
echo '</ul></body></html>';
"""


@handler(ServiceId.ROUNDCUBE)
def roundcube_handler(ctx: ProvisionContext) -> Sequence[Step]:
    host = "mail." + ctx.domain
    cert, key = ctx.certificate(host)
    ca = ctx.ca_pem()
    app = ROUNDCUBE_APP.replace("\\", "\\\\").replace("'", "'\\''")
    return (
        Step("roundcube-tls",
             linux(_write_pem_step("mail", cert, key) + "\n"
                   + _write_ca_step(ca)
                   + f"""
install -d -m 755 /var/www/webmail
chown -R www-data:www-data /var/www/webmail 2>/dev/null || true""",
                   timeout_s=60),
             timeout_s=60),
        Step("roundcube-app",
             linux(f"""
cat > /var/www/webmail/index.php <<'PHP'
{ROUNDCUBE_APP}PHP
cat > /etc/apache2/sites-available/sr-webmail.conf <<'CONF'
<VirtualHost *:80>
  ServerName {host}
  Redirect permanent / https://{host}/
</VirtualHost>
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /etc/pki/sr/mail.crt
  SSLCertificateKeyFile /etc/pki/sr/mail.key
  ServerName {host}
  DocumentRoot /var/www/webmail
  <Directory /var/www/webmail>
    Require all granted
  </Directory>
</VirtualHost>
CONF
a2enmod ssl >/dev/null 2>&1 || true
a2ensite sr-webmail >/dev/null 2>&1 || true
apache2ctl configtest && systemctl enable --now apache2 && systemctl reload apache2""",
                   timeout_s=300),
             timeout_s=300),
        Step("roundcube-verify",
             linux(f"""
curl -sS --silent --fail --cacert /etc/pki/sr/ca.crt \
  --resolve {host}:443:127.0.0.1 \
  -d '_user=prb-roundcube&_pass=x&_action=login&_task=login' \
  https://{host}/ -o /dev/null
ss -ltn | grep -q ':443 '""", timeout_s=60),
             timeout_s=60),
    )


@handler(ServiceId.SPLUNK_FORWARDER)
def splunk_forwarder_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The workstation's telemetry ship: rsyslog forwards to the replica's
    declared syslog input (5514/udp).

    The reported stack is the Splunk Universal Forwarder to 9997; the desktop
    golden carries no forwarder (its vendor deb is not in the offline image),
    so the substitution is labelled in fidelity.yaml. The verify is a real
    transmission, not a config file check.
    """
    sink = ctx.address("splunk")
    return (
        Step("forwarder-config",
             linux(f"""
cat > /etc/rsyslog.d/50-sr-splunk.conf <<'CONF'
*.* action(type="omfwd" target="{sink}" port="5514" protocol="udp"
          template="RSYSLOG_SyslogProtocol23Format")
CONF
systemctl enable --now rsyslog && systemctl restart rsyslog""",
                   timeout_s=180),
             timeout_s=180),
        Step("forwarder-verify",
             linux("logger -p user.info 'SRPRB-forwarder-probe' && "
                   "systemctl is-active rsyslog >/dev/null"),
             timeout_s=60),
    )


@handler(ServiceId.CHRONY)
def chrony_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Time service, reported offline-simulated: chrony may never reach a
    real upstream (egress is denied) — the requirement is a RUNNING,
    disciplined clock daemon, not an NTP response."""
    return (
        Step("chrony-enable",
             linux("systemctl disable --now systemd-timesyncd 2>/dev/null || true; "
                   "systemctl enable --now chrony 2>/dev/null || "
                   "systemctl enable --now chronyd 2>/dev/null"),
             timeout_s=120),
        Step("chrony-verify",
             linux("systemctl is-active chrony >/dev/null 2>&1 || "
                   "systemctl is-active chronyd >/dev/null 2>&1"),
             timeout_s=60),
    )


@handler(ServiceId.CUPS)
def cups_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Print service (reported in the workstation's service list): the CUPS
    listener must answer on 631, not just be enabled at boot."""
    return (
        Step("cups-enable",
             linux("systemctl enable --now cups 2>/dev/null || "
                   "systemctl enable --now cups-browsed 2>/dev/null || true"),
             timeout_s=120),
        Step("cups-verify",
             linux("ss -ltn | grep -q ':631 '"),
             timeout_s=60),
    )


@handler(ServiceId.AVAHI)
def avahi_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """mDNS (reported): daemon running and the 5353 UDP socket bound."""
    return (
        Step("avahi-enable",
             linux("systemctl enable --now avahi-daemon"),
             timeout_s=120),
        Step("avahi-verify",
             linux("ss -lun | grep -q ':5353 '"),
             timeout_s=60),
    )


@handler(ServiceId.CA_FILESHARE)
def ca_fileshare_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The exposed certificate services the entry-path task grades: an
    Enterprise Root CA with its PUBLIC certificate on an SMB share.

    The install runs non-interactively as SYSTEM (the guest agent's
    identity); the share is read-only for Everyone, which is the reported
    exposure and is disclosed as a synthetic reconstruction.
    """
    return (
        Step("ca-role",
             windows("Install-WindowsFeature -Name AD-Certificate "
                     "-IncludeManagementTools | Out-Null", timeout_s=600),
             timeout_s=600),
        Step("ca-install",
             windows("""
if (-not (Get-CertificationAuthority -ErrorAction SilentlyContinue)) {
  $p = @{
    CAtype = 'EnterpriseRootCA'
    CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
    KeyLength = 2048
    HashAlgorithmName = 'SHA256'
    ValidityPeriod = 'Years'
    ValidityPeriodUnits = 5
    Force = $true
  }
  Install-AdcsCertificationAuthority @p -ErrorAction Stop
}""", timeout_s=900),
             timeout_s=900),
        Step("ca-share",
             windows("""
$dir = 'C:\\CA'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
certutil.exe -ca.cert "$dir\\root.cer" | Out-Null
if (-not (Get-SmbShare -Name 'CA' -ErrorAction SilentlyContinue)) {
  New-SmbShare -Name 'CA' -Path $dir -ReadAccess 'Everyone' |
    Out-Null
}""", timeout_s=300),
             timeout_s=300),
        Step("ca-verify",
             windows("""
if (-not (Test-Path 'C:\\CA\\root.cer')) { throw 'CA cert missing' }
if (-not (Get-SmbShare -Name 'CA' -ErrorAction SilentlyContinue)) {
  throw 'CA share missing'
}""", timeout_s=120),
             timeout_s=120),
    )


# --------------------------------------------------------- edge behaviour
#
# The placeholder edge images are bare Debian-family copies; the REAL VyOS /
# OPNsense images are separate builds (infra/images/run_vyos_build.py). Until
# those land, the same TYPED contracts (public_forwards, routes, syslog edges)
# are executed on the placeholder through this handler set and the substitute
# is recorded in fidelity.yaml. A real VyOS implementation would register the
# same service ids with its own commands; nothing above this line changes.


def _guest_iface_plan(bp, guest_name: str) -> list[tuple[str, str, int]]:
    """[(segment, address/prefix, prefixlen)] in the guest's NIC order."""
    out: list[tuple[str, str, int]] = []
    for iface in bp.guest(guest_name).interfaces:
        seg = next(s for s in bp.segments if s.name == iface.segment)
        prefix = int(str(seg.cidr).split("/")[1])
        out.append((iface.segment, f"{iface.ipv4.address}/{prefix}", prefix))
    return out


def _wan_index(bp, guest_name: str) -> int:
    """Index of the simulated-WAN interface in NIC order (never guessed)."""
    for i, iface in enumerate(bp.guest(guest_name).interfaces):
        for seg in bp.segments:
            if seg.name == iface.segment and \
                    str(getattr(seg.purpose, "value", seg.purpose)) == \
                    "simulated-wan":
                return i
    raise ProvisionError(
        f"edge {guest_name!r} has no interface on the simulated-wan segment")


def _linux_configure_addresses(ifaces: list[tuple[str, str, int]]) -> str:
    specs = " ".join(f'"{addr}"' for _seg, addr, _p in ifaces)
    return f"""
i=0
for spec in {specs}; do
  dev=$(ip -o link show | awk -F': ' '{{print $2}}' | grep -v lo | sed -n "$((i+1))p")
  ip addr replace "$spec" dev "$dev" 2>/dev/null || true
  ip link set "$dev" up
  i=$((i+1))
done
ip -br a"""


def _forwarding_on() -> str:
    return """
sysctl -q -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward' /etc/sysctl.d/99-sr-range.conf 2>/dev/null || \
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-sr-range.conf"""


@handler(ServiceId.EDGE_NAT)
def edge_nat_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """Edge DNAT + masquerade + routes + syslog, from the typed contracts."""
    if ctx.bp is None:
        raise ProvisionError("edge-nat needs the blueprint")
    bp = ctx.bp
    ifaces = _guest_iface_plan(bp, ctx.guest)
    wan = f"$WANDEV"
    forwards = [f for f in bp.public_forwards if f.on_guest == ctx.guest]
    routes = [r for r in bp.routes if r.guest == ctx.guest]
    sinks = []
    for e in getattr(bp, "edges", []):
        if str(getattr(e.kind, "value", e.kind)) != "syslog" or e.src != ctx.guest:
            continue
        host = next((str(i.ipv4.address) for g in bp.guests if g.name == e.dst
                     for i in g.interfaces if i.ipv4), None)
        if host:
            sinks.append((host, int(e.port or 514),
                          str(getattr(e.protocol, "value", e.protocol) or "udp")))
    nat = []
    for f in forwards:
        target = next(str(i.ipv4.address) for g in bp.guests
                      if g.name == f.target_guest for i in g.interfaces
                      if i.ipv4)
        rule = (f"-t nat -C PREROUTING -i {wan} -d {f.vip} -p {f.protocol} "
                f"--dport {f.vip_port}")
        add = (f"-t nat -A PREROUTING -i {wan} -d {f.vip} -p {f.protocol} "
               f"--dport {f.vip_port} -j DNAT --to-destination "
               f"{target}:{f.target_port}")
        nat.append(f"iptables {rule} 2>/dev/null || iptables {add}")
    masq = (f"iptables -t nat -C POSTROUTING -s 172.16.0.0/12 -o {wan} "
            f"-j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING "
            f"-s 172.16.0.0/12 -o {wan} -j MASQUERADE")
    route_cmds = "\n".join(f"ip route replace {r.prefix} via {r.via}"
                           for r in routes)
    syslog_cmds = ""
    for host, port, proto in sinks:
        syslog_cmds += (f"""
cat >> /etc/rsyslog.d/50-sr-edge.conf <<'CONF' 2>/dev/null || true
*.* action(type="omfwd" target="{host}" port="{port}" protocol="{proto}")
CONF""")
    verify_forwards = "\n".join(
        f"iptables -t nat -S PREROUTING | grep -q '{f.vip}'" for f in forwards)
    verify_routes = "\n".join(
        f"ip route get {r.prefix.split('/')[0]} | grep -q 'via {r.via}'"
        for r in routes)
    return (
        Step("edge-addresses", linux(_linux_configure_addresses(ifaces)),
             timeout_s=120),
        Step("edge-nat", linux(f"""
WANDEV=$(ip -o link show | awk -F': ' '{{print $2}}' | grep -v lo | sed -n "{_wan_index(bp, ctx.guest) + 1}p"){_forwarding_on()}
{masq}
{chr(10).join(nat)}
{route_cmds}
{syslog_cmds}
systemctl restart rsyslog 2>/dev/null || true""", timeout_s=300),
             timeout_s=300),
        Step("edge-verify", linux(f"""
set -e
{verify_forwards}
{verify_routes}
sysctl -n net.ipv4.ip_forward | grep -qx 1""", timeout_s=120),
             timeout_s=120),
    )


@handler(ServiceId.EDGE_LAN)
def edge_lan_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The perimeter's forwarding + reported permissive opening policy."""
    if ctx.bp is None:
        raise ProvisionError("edge-lan needs the blueprint")
    bp = ctx.bp
    ifaces = _guest_iface_plan(bp, ctx.guest)
    lan = next((addr.split("/")[0] for seg, addr, _p in ifaces
                if seg == "inside-lan"), None)
    if lan is None:
        raise ProvisionError(f"{ctx.guest!r} has no inside-lan interface")
    return (
        Step("lan-addresses", linux(_linux_configure_addresses(ifaces)),
             timeout_s=120),
        Step("lan-permissive", linux(_forwarding_on() + """
iptables -P FORWARD ACCEPT
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT""", timeout_s=120),
             timeout_s=120),
        Step("lan-verify", linux(f"""
set -e
ip -4 addr show | grep -q '{lan}'
sysctl -n net.ipv4.ip_forward | grep -qx 1
iptables -S FORWARD | grep -qx -- '-P FORWARD ACCEPT'""",
                   timeout_s=60),
             timeout_s=60),
    )


@handler(ServiceId.STATIC_ROUTES)
def static_routes_handler(ctx: ProvisionContext) -> Sequence[Step]:
    """The guest's declared route table entries (vantages, team) — the typed
    `routes` contract executed, never a guessed default gateway."""
    if ctx.bp is None:
        raise ProvisionError("static-routes needs the blueprint")
    bp = ctx.bp
    routes = [r for r in bp.routes if r.guest == ctx.guest]
    if not routes:
        raise ProvisionError(
            f"{ctx.guest!r} declares static-routes but no routes target it")
    cmds = "\n".join(f"ip route replace {r.prefix} via {r.via}"
                     for r in routes)
    checks = "\n".join(
        f"ip route get {r.prefix.split('/')[0]} | grep -q 'via {r.via}'"
        for r in routes)
    return (
        Step("routes-add", linux(cmds, timeout_s=60), timeout_s=60),
        Step("routes-verify", linux(f"set -e\n{checks}", timeout_s=60),
             timeout_s=60),
    )
