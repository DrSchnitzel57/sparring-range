"""The managed-service installation contract (milestone 15).

The install gate renders the units and the environments; this module checks
that the SERVICES could actually run with what was rendered.  It is a static
contract check on the plan the installer writes, not a claim that systemd
ran: the managed-service half (starting the units, the real PostgreSQL, the
real TLS) stays the operator's step.

Every check here corresponds to a defect that a rendered-file check alone
would not catch:

* an identity that does not exist, or a unit that loads an environment the
  installer never writes;
* a credential the reading service cannot read (a 0600 file under a 0700
  directory), or a credential that an unrelated service CAN read;
* a private key path that nothing provisions;
* a public front door that routes /api to a prefix the API does not serve;
* a trust anchor or a certificate that the TLS bootstrap never creates.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
if str(REPO) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(REPO))

# The files the TLS bootstrap actually creates.
BOOTSTRAP_TLS_OUTPUTS = {
    "api-ca.crt", "api-ca.key", "api-client.crt", "api-client.key",
    "broker-server.crt", "broker-server.key", "ca.crt", "ca.key",
    "https.crt", "https.key", "ingest-server.crt", "ingest-server.key",
}

# The private key each service reads, and the identity that owns it.
KEY_OWNERS = {
    "SR_RUNNER_SSH_KEY_PATH": "srworker",
    "SR_VERIFIER_SSH_KEY_PATH": "srrange",
    "SR_BASTION_CLIENT_KEY_PATH": "srbastion",
}


def _parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def _unit_fields(text: str, field: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(field + "="):
            value = line.split("=", 1)[1].strip()
            if value:
                out.append(value)
    return out


def contract_problems(manifest: pathlib.Path) -> list[str]:
    """Return the contract violations of the rendered installation."""
    from deploy import appliance as installer
    from deploy.appliance_services import SERVICE_KEYS
    from infra.appliance.manifest import ApplianceManifest

    problems: list[str] = []
    m = ApplianceManifest.load(manifest)
    plan = installer.render_files(m)
    files = {str(f.path): f for f in plan.files}
    by_name = {f.path.name: f for f in plan.files}

    # --- the identities the units run as -----------------------------------
    for unit in plan.units:
        path = by_name.get(unit)
        if path is None:
            problems.append(f"the installer does not render {unit}")
            continue
        text = path.content
        users = _unit_fields(text, "User")
        groups = _unit_fields(text, "Group")
        if not users:
            problems.append(f"{unit} declares no User")
        for user in users:
            if user not in installer.USERS:
                problems.append(f"{unit} runs as the unknown identity {user}")
        for group in groups:
            if group not in installer.GROUPS:
                problems.append(f"{unit} uses the unknown group {group}")
        # every non-optional environment the unit loads must be rendered
        for env in _unit_fields(text, "EnvironmentFile"):
            optional = env.startswith("-")
            path_str = env.lstrip("-")
            if optional:
                continue
            if path_str not in files:
                problems.append(f"{unit} loads {path_str}, which the installer "
                                "does not write")

    # --- the environments and their readers ---------------------------------
    env_expectations = {
        "control-plane.derived.env": ("srrange", 0o640),
        "broker.env": ("sr-broker-clients", 0o640),
        "worker-supervisor.env": ("srworker", 0o640),
    }
    for name, (group, mode) in env_expectations.items():
        rendered = by_name.get(name)
        if rendered is None:
            problems.append(f"the installer does not render {name}")
            continue
        if rendered.group != group:
            problems.append(f"{name} is group {rendered.group}, so {group} "
                            "cannot read it")
        if rendered.mode != mode:
            problems.append(f"{name} has mode {oct(rendered.mode)}, expected "
                            f"{oct(mode)}")

    # --- the credentials each service reads ---------------------------------
    derived = by_name.get("control-plane.derived.env")
    supervisor_env = by_name.get("worker-supervisor.env")
    if derived is not None:
        values = _parse_env(derived.content)
        token_path = values.get("SR_WORKER_SUPERVISOR_TOKEN_FILE", "")
        if not token_path:
            problems.append("the derived environment names no supervisor "
                            "capability file")
        elif pathlib.Path(token_path).name != "worker-supervisor.token":
            problems.append(f"the API reads {token_path}, which is not the "
                            "API's own copy of the capability")
        for key, owner in KEY_OWNERS.items():
            path = values.get(key, "")
            if not path:
                problems.append(f"the derived environment names no {key}")
                continue
            expected = [rel for _name, rel, own, _g, _c in SERVICE_KEYS
                        if own == owner]
            if not any(path.endswith(rel) for rel in expected):
                problems.append(f"{key} names {path}, which no service "
                                f"provisions for {owner}")
        # the trust anchor must be a certificate the bootstrap creates
        for key in ("SR_TELEMETRY_CA_FILE", "SR_API_TLS_CA_FILE"):
            path = values.get(key, "")
            if path and pathlib.Path(path).name not in BOOTSTRAP_TLS_OUTPUTS:
                problems.append(f"{key} names {path}, which the TLS bootstrap "
                                "never creates")
        # the capability file the supervisor reads must be its own copy
        if supervisor_env is not None:
            sup = _parse_env(supervisor_env.content)
            sup_token = sup.get("SR_WORKER_SUPERVISOR_TOKEN_FILE", "")
            if sup_token and sup_token == token_path:
                problems.append("the API and the supervisor read the SAME "
                                "capability file; a 0600 secret cannot be "
                                "shared, each needs its own copy")
    if supervisor_env is not None:
        sup = _parse_env(supervisor_env.content)
        sup_token = sup.get("SR_WORKER_SUPERVISOR_TOKEN_FILE", "")
        if sup_token and pathlib.Path(sup_token).name != \
                "worker-supervisor.token.srworker":
            problems.append(f"the supervisor reads {sup_token}, which is not "
                            "its own copy of the capability")

    # --- the shared-secret group -------------------------------------------
    members = {user for user, (_g, extras) in installer.USERS.items()
               if "sr-secrets" in extras}
    if members != {"srrange", "srworker"}:
        problems.append(f"the sr-secrets group holds {sorted(members)}; the "
                        "API (which validates the capability) and the "
                        "supervisor (which presents it) are the only "
                        "legitimate readers")
    if installer.SECRET_DIR_MODE & 0o007:
        problems.append("the secrets directory is world-traversable")
    if not installer.SECRET_DIR_MODE & 0o010:
        problems.append("the secrets directory is not traversable by its "
                        "group: the API and the supervisor could not reach "
                        "the credential they must read")
    if installer.SECRET_DIR_GROUP != "sr-secrets":
        problems.append("the secrets directory is not owned by sr-secrets")

    # --- the public front door ---------------------------------------------
    site = by_name.get("sparring-range.conf")
    if site is not None:
        text = site.content
        match = re.search(r"location\s+/api/\s*\{(.*?)\}", text, re.S)
        if not match:
            problems.append("the nginx site has no /api location")
        else:
            proxy = re.search(r"proxy_pass\s+([^;]+);", match.group(1))
            if not proxy:
                problems.append("the nginx /api location proxies nothing")
            elif proxy.group(1).rstrip().endswith("/api/"):
                problems.append(
                    "the nginx /api location keeps the /api prefix, but the "
                    "API's routes are unprefixed — the prefix must be "
                    "stripped")
    if derived is not None:
        values = _parse_env(derived.content)
        if values.get("SR_API_ROUTE_PREFIX") != "/api":
            problems.append("the derived environment does not name the /api "
                            "prefix the clients use")
    web_unit = by_name.get("sr-web.service")
    if web_unit is not None and "127.0.0.1" not in web_unit.content:
        problems.append("the frontend does not bind to loopback only")

    # --- the ingest listener ------------------------------------------------
    ingest = by_name.get("sr-appliance-ingest.service")
    if ingest is not None:
        text = ingest.content
        for needed in ("ingest-server.crt", "ingest-server.key"):
            if needed not in text:
                problems.append(f"the ingest listener does not use {needed}")
    return problems


def check(manifest: pathlib.Path) -> dict:
    problems = contract_problems(manifest)
    return {"ok": not problems, "problems": problems}
