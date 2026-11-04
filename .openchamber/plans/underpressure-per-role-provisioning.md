# Underpressure — per-role provisioning (the machines must BE the competition machines)

> Opened 2026-11-04 night, after the appliance recovery. Owner: this session.
> The images boot and the lab deploys; nothing configures the SOFTWARE roles.
> That single missing step is why `directory-auth` failed while DNS answered and
> the store returned a TLS error. This plan finishes the replica.

## Steps
- [x] 1. Engine: pure `build_plan` over `ServiceId`, broker `guest_exec` transport
      with the deploy's generation, fail-closed states, secret-free evidence.
- [x] 2. Directory + SQL handlers: AD forest `underpressure.local` (idempotent
      promote + reboot + seeded account), DNS A/MX/SRV records, both SQL
      databases with app logins and seeds (verify authenticates AS the app).
- [ ] 3. Linux domain join (`sssd-ad`) and Splunk (`splunk`, `splunk-forwarder`,
      `syslog-receiver`) handlers; wire provisioning into deploy/reset with a
      flag, and record evidence on the deployment rows.
- [ ] 4. Lab PKI: one per-appliance lab CA (root-owned), service certificates
      for `shop.`/`mail.` hosts, trust installed into the scoring vantage, so
      `verify_tls_against_lab_ca` is real. New: the vantage is not a serviced
      guest, so the executor must ship the CA to it (path/env contract).
- [ ] 5. Store role: nopCommerce (.NET publish) + nginx + TLS on ecomm, store
      database seeded by the SQL slice.
- [ ] 6. Mail role: Postfix + Dovecot + Roundcube (+ TLS) on webmail, sqlsrv
      DSN to mssql — the reported vulnerable opening state.
- [ ] 7. Router/firewall: VyOS `config.boot` (DNAT/VIPs, static routes,
      masquerade, syslog 5514) and OPNsense `config.xml` (rules, DHCP
      reservations) seeded at IMAGE BUILD (serial-seed), not at deploy.
- [ ] 8. Workstations: Ubuntu (join + forwarder) and Windows 11 (join).
- [ ] 9. Availability registry green from the real vantage (all 8 checks).
- [ ] 10. Integrated proof gate + findings/release review.

## Change map (producer -> consumer)

| Producer | Consumer(s) | Contract that must not drift |
| --- | --- | --- |
| `environment_specs/blueprint.py` `services`, addresses, `domain` | `scenario_engine/env_provision.build_plan` | addresses come from the blueprint only; a dependency address missing is a plan error |
| `scenario_engine/env_provision` | deployment resource rows (`provisioning`, `provisioning_ready`), lab UI/API | unimplemented is never `ready`; a service is ready only when every step exited 0 |
| `credentials.py` store (root:0600) | provisioning resolver, availability plan env vars | one place a value exists; evidence carries variable names only |
| broker `guest_exec` | env_provision transport | ownership + generation checked before AND after; agent absent = failed evidence |
| checks.yaml refs (`credential:...`) | availability_plan env vars | provisioning creates the SAME accounts the checks authenticate as |
| lab PKI (step 4) | ecomm/webmail certs + vantage trust | TLS verify is against the lab CA, never "verify off" |

## Observed vs assumed

- OBSERVED (live, 2026-11-04): `dns-authoritative` ok / `directory-auth` failed;
  store check errors on TLS; services are baked packages only.
- OBSERVED: every Linux golden carries `qemu-guest-agent`; Windows goldens get
  it via `start /wait msiexec` in the unattend (fix landed before the current
  ws2019 build).
- ASSUMED: `verify_tls_against_lab_ca` uses the DEFAULT trust store on the
  vantage, so the lab CA must be installed there (or shipped by the executor).
  Decide in step 4; do not weaken the check to "no verify".
- ASSUMED: router/firewall config is image-build content (blueprint declares
  `bootstrap: serial-seed`), not runtime provisioning.

## Non-goals

- No official competition weights, checker accounts or ports claimed.
- No fabricated service success: a role whose software cannot install fails
  loudly (`failed` evidence) rather than being marked ready.
- Fresh-replacement rules stay: no upgrade path to preserve.

## Gates

1. Engine + handlers: infra-free suite green (912 now).
2. Every handler lands with (a) a plan test pinning blueprint-derived values,
   (b) an idempotence test, (c) a live proof on the appliance before scoring.
3. Registry green = all 8 checks pass from the scoring vantage on real guests.
4. Proof gate runs only after 1–3, with two members and a mid-exercise reset.
