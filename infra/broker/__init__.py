"""Private deployment broker (milestone 02 — host-safe authority).

The ONLY component that may hold hypervisor authority. The API talks to
this package through typed, boundary-authenticated calls; it never sees a
backend credential, an arbitrary backend path, or a raw config payload.
Everything the broker accepts is checked against an operator policy
(nodes, templates, bounded VMID range, storage, clone mode, exact NIC/
segment lane, provisioning fields, aggregate CPU/RAM/disk limits) and
recorded in a durable ledger BEFORE the external side effect happens —
restart reconciles the ledger, it never blindly replays.

Modules:
  errors    typed failure taxonomy (refused vs uncertain vs latched)
  policy    operator policy file: the allowlist boundary
  ledger    protected SQLite durable state (claims/intents/lease/latch)
  service   typed operations + fail-closed cessation + lease watchdog
  client    API-side typed client (Unix socket or mutual-TLS, no fallback)
  server    mutual-TLS HTTPS front door for the service
  tools     offline operator CLI (status/stop/enroll/release/resolve)
  testing   isolated synthetic fixtures for acceptance layers only
"""
