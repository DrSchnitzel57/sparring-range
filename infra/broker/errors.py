"""Typed broker failures.

The distinction is load-bearing for safety:

  BrokerRefused  — the broker is healthy and DETERMINISTICALLY rejected the
                   operation (policy violation, latched, bad auth, conflict).
                   Retrying the same call is pointless; the caller must not
                   assume any side effect happened.
  BrokerUnavailable — the outcome is UNCERTAIN (transport down, timeout).
                   The caller must retain obligations and reservations and
                   reconcile later — never assume success OR absence.
  BrokerLatched  — cessation is engaged; only stop/status/lease operations
                   proceed.
"""
from __future__ import annotations


class BrokerError(RuntimeError):
    pass


class BrokerRefused(BrokerError):
    """Deterministic rejection by a reachable broker."""


class BrokerLatched(BrokerRefused):
    """Cessation latch is engaged — mutating operations are refused."""


class PolicyViolation(BrokerRefused):
    """The request is outside the operator policy (path, template, VMID,
    NIC, fields, or aggregate limits)."""


class BrokerConflict(BrokerRefused):
    """Idempotency key reused with different arguments, or the ledger says
    the resource is in a state that forbids this operation."""


class BrokerUnavailable(BrokerError):
    """Outcome unknown: transport/peer failure. Obligations are retained."""
