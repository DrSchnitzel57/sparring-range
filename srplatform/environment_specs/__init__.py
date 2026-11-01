"""Versioned environment contracts (Underpressure plan — step 1).

An ENVIRONMENT is the durable replica: typed segments, guests with role
specific multi-NIC attachments, resource reservations, service/dependency
edges and a fidelity ledger that labels every reconstructed value. An
EXERCISE scenario references an environment (frozen settings) instead of
repeating addresses; older flat-topology scenarios carry no environment
reference and validate exactly as before.

Everything here is PURE DATA + validation: no provisioning, no I/O beyond
reading the repository-owned environment directory. The broker, installer
and API consume these validated objects; none of them may widen the closed
vocabularies defined here.
"""
from .attack import AttackGuide
from .blueprint import (
    EnvironmentBlueprint,
    EnvironmentError,
    Guest,
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

__all__ = [
    "AttackGuide",
    "EnvironmentBlueprint",
    "EnvironmentError",
    "Guest",
    "Segment",
    "ServiceEdge",
    "ServiceCheck",
    "load_checks",
    "FidelityEntry",
    "FidelityLedger",
    "LoadedEnvironment",
    "environment_ids",
    "environments_dir",
    "load_environment",
]
