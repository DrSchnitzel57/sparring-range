"""Private deployment broker (milestone 02 — host-safe authority).

The ONLY component that may hold Proxmox credentials. The API talks to this
package through typed, mutually-authenticated calls; it never sees a PVE
token, an arbitrary PVE path, or a raw config payload. Everything the broker
accepts is checked against an operator policy (nodes, templates, bounded
VMID range, storage, clone mode, exact NIC/VLAN, provisioning fields,
aggregate CPU/RAM/disk limits) and recorded in a durable ledger BEFORE the
external side effect happens — restart reconciles the ledger, it never
blindly replays.

Modules:
  errors    typed failure taxonomy (refused vs uncertain vs latched)
  policy    operator policy file: the allowlist boundary
  ledger    protected SQLite durable state (claims/intents/lease/latch)
  service   typed operations + fail-closed cessation + lease watchdog
  client    API-side typed client (mutual-TLS transport, no fallback)
  server    mutual-TLS HTTPS front door for the service
  tools     offline operator CLI (enroll/status/stop/reconcile/release)
  testing   isolated synthetic fixtures for acceptance layers only
"""
