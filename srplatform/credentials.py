"""Protected environment credentials, resolved only where a check runs.

The check registry references credentials by LOGICAL NAME
(`credential:store-app-sql`) and never carries a value; a plan carries only
the variable NAME (`SR_CRED_STORE_APP_SQL`). This module is the last hop: a
root-owned, mode-0600 file on the appliance maps each environment's variable
names to their values, and the vantage executor resolves them at run time.

Why a separate file and not the database: the lab aggregate is read by
members, and a secret that a member can read is not a secret. Why not the
environment document: versioned, shared, reviewed, and non-secret by
construction. The file is the single place a value exists, and it is never
logged — the executor hands it to the vantage as an environment variable.

A missing file is not an error: every credentialed check then reports
`unknown` (scorer material unavailable), never a defender failure.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Callable

_VAR_RE = re.compile(r"^SR_CRED_[A-Z0-9_]{1,64}$")
_ENV_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
DEFAULT_PATH = "/etc/sparring-range/environment-credentials.json"

#: `resolver(name)` -> value or None; the shape the runner expects.
CredentialResolver = Callable[[str], "str | None"]


class CredentialError(Exception):
    """The store exists but cannot be trusted (wrong owner/mode/shape)."""


def _check_secret_file(p: pathlib.Path) -> None:
    """A world- or group-readable file is not a secret store. Refusing is the
    point: a silently accepted 0644 file would leak every guest credential."""
    st = p.stat()
    if st.st_mode & 0o077:
        raise CredentialError(
            f"{p} is {oct(st.st_mode & 0o777)}: a credential store must not be "
            "group/world readable (expected 0600)")


def load(path: str | pathlib.Path = DEFAULT_PATH, *,
         require_secure: bool = True) -> dict[str, dict[str, str]]:
    """Read the store: `{environment: {SR_CRED_NAME: value}}`.

    Shape is validated strictly (a typo must fail loud, not silently resolve
    to a wrong or absent credential mid-exercise) and secrets are never
    returned to a caller that prints them by accident — this returns the
    mapping, and only the executor decides who sees what.
    """
    p = pathlib.Path(path)
    if not p.is_file():
        return {}
    if require_secure:
        _check_secret_file(p)
    try:
        raw = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise CredentialError(f"{p} is not valid JSON: {exc}") from exc
    envs = raw.get("environments") if isinstance(raw, dict) else None
    if not isinstance(envs, dict):
        raise CredentialError(f"{p}: top level must be "
                              '{"environments": {...}}')
    out: dict[str, dict[str, str]] = {}
    for environment, values in envs.items():
        if not isinstance(environment, str) or not _ENV_RE.fullmatch(environment):
            raise CredentialError(f"{p}: bad environment key {environment!r}")
        if not isinstance(values, dict):
            raise CredentialError(f"{p}: {environment} must map names to values")
        clean: dict[str, str] = {}
        for name, value in values.items():
            if not isinstance(name, str) or not _VAR_RE.fullmatch(name):
                raise CredentialError(
                    f"{p}: {environment} has a bad variable name {name!r} "
                    "(expected SR_CRED_*)")
            if not isinstance(value, str) or not value:
                raise CredentialError(
                    f"{p}: {environment}.{name} must be a non-empty string")
            clean[name] = value
        out[environment] = clean
    return out


def resolver(path: str | pathlib.Path = DEFAULT_PATH,
             environment_id: str = "underpressure-range", *,
             require_secure: bool = True) -> CredentialResolver:
    """A resolver for ONE environment. Values stay in this closure; the
    executor passes them to the vantage as environment variables and never
    writes them into evidence."""
    material = load(path, require_secure=require_secure).get(environment_id, {})

    def resolve(name: str) -> str | None:
        return material.get(name)

    return resolve
