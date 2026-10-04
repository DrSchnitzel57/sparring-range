# Windows golden image + Sysmon checklist (F09/F21 — operator work, honest scope)

Windows template creation, licensing, and OOBE remain **operator hands-on
work**; nothing here claims Windows acceptance was automated or performed.
This is the checklist to run when the hardware step happens.

## Golden image (DC and Win10 members)
1. Install from licensed media; complete OOBE with built-in admin; `sconfig` →
   set compname `WIN-DC00` / `WIN-PC00`; enable WinRM over HTTPS or SSH
   (OpenSSH feature) for the verifier management channel.
2. **Defender baseline ON** (this is scored: `av_enabled` verifier expects
   RealTimeProtectionEnabled True on the clean baseline).
3. Install **Sysmon** with the shipped config:
   `Sysmon64.exe -accepteula -i C:\sparring\sysmonconfig.xml`
4. Baseline capture (feeds scenario verifier baselines):
   - `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
     → record values → scenario `persistence_run_key.baseline`
   - `schtasks /query /fo LIST` → keep the export with the image notes
5. Snapshot as Proxmox template; record VMIDs in `.env`
   (`TEMPLATE_VMID_WIN_DC`, `TEMPLATE_VMID_WIN10`).

## Sysmon → platform ingest (fixture-tested, live gate pending)
- Forward Microsoft-Windows-Sysmon/Operational via Windows Event Forwarding
  to a collector on the control plane (range has no egress — the collector
  pulls), then convert to `detection` events POSTed to `/ingest/auditd`
  with a `telemetry` capability token bound to that host.
- The event mapping the platform expects (see
  `telemetry/fixtures/sysmon-detection-sample.json`):
  `kind=detection`, `audit_key=sysmon-<EventID>`, `comm`, `argv` (Image +
  CommandLine), `source_id` (EventRecordID), `boot_id` (machine identity).
- Test fixture is validated by `tests/test_e_telemetry.py`; the LIVE
  subscription + collector are an operator gate — mark unaccepted until run.

## Acceptance (only closable by the operator)
- [ ] Command on a range Windows VM produces a Sysmon event that reaches the
      correct session as a `detection` with the right host + time.
- [ ] `av_enabled` passes on the golden baseline and fails after disabling.
- [ ] `persistence_run_key` awards only with declared-baseline semantics.
