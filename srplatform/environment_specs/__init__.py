"""Versioned environment contracts (Underpressure plan — step 1).

An ENVIRONMENT is the durable replica: typed segments, guests with role
specific multi-NIC attachments, executable routing contracts (public
service paths, typed prefix routes, appliance deny rules), resource
reservations, service/dependency edges and a fidelity ledger that labels
every reconstructed value. An EXERCISE scenario references an environment
(frozen settings) instead of repeating addresses; older flat-topology
scenarios carry no environment reference and validate exactly as before.

Everything here is PURE DATA + validation: no provisioning, no I/O beyond
reading the repository-owned environment directory. The broker, installer
and API consume these validated objects; none of them may widen the closed
vocabularies defined here.
"""
from .attack import AttackGuide
from .blueprint import (
    AccessDeny,
    EnvironmentBlueprint,
    EnvironmentError,
    Guest,
    GuestRoute,
    PublicForward,
    Segment,
    ServiceEdge,
)
from .checks import ServiceCheck, load_checks
from .fidelity import FidelityEntry, FidelityLedger
from .loader import (
    LoadedEnvironment,
    environment_ids,
    environments_dir,
    load_environment,
)
from .routing import PathResult, public_service_path, resolve

__all__ = [
    "AccessDeny",
    "AttackGuide",
    "EnvironmentBlueprint",
    "EnvironmentError",
    "Guest",
    "GuestRoute",
    "PathResult",
    "PublicForward",
    "Segment",
    "ServiceCheck",
    "ServiceEdge",
    "load_checks",
    "FidelityEntry",
    "FidelityLedger",
    "LoadedEnvironment",
    "environment_ids",
    "environments_dir",
    "load_environment",
    "public_service_path",
    "resolve",
]
