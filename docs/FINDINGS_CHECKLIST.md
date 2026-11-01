# Current findings and validation evidence

The dated entries below are evidence at their recorded revisions, not standing
workflow instructions or fresh test runs. Native OpenChamber Todos hold the
actionable backlog. Receipts recorded before 2026-11-01 — the milestone-01..13
evidence and the dated plan-18..22 review-round ledgers — are preserved in Git
history (`git log -- docs/FINDINGS_CHECKLIST.md`); those dated results are
historical, not fresh runs.

## Work frozen at user request — 2026-11-01

The user requested integration and push **as-is**, with no further repair/review
loop. This is an unfinished development checkpoint, not release acceptance.

- Latest source: `c398eab870c855ade8d0ba4a647aac6c5723ac44`. It claims fixes
  for mirror-sequence validation, durable outage reconciliation (including
  API/CLI recovery), and no-replace forced-build rollback. **No completed
  independent review or final test receipt exists for this latest commit.**
- Last completed independent review: **VERDICT: FIX** at `da735cc`, source
  `2c9cad4`. Three demonstrated defects remained: a nonexistent mirror sequence
  could override authoritative failure; an outage-only failure remained blocked
  after the prescribed fresh successful check; forced rollback replaced a newly
  appeared foreign empty directory. These require independent re-verification
  against `c398eab`; implementation claims do not close them.
- That older source independently passed the infrastructure-free pytest command
  documented in `AGENTS.md`: **741 passed, 529 deselected, 13 warnings**, exit 0,
  136.36 s; practice passed **12 + 28**, zero skipped, 14.5 s. Focused disposable
  DB checks passed **23**, 20 deselected, 28.98 s. These are historical results,
  not fresh results for the frozen HEAD or its integration with `master`.
- Last independently inspected candidate: local cache
  `.cache/bundle/sparring-range-appliance-22f`, revision `2c9cad4`, MANIFEST
  SHA256 `0aeecdaa5948abe12044e5b65a1b5109b621c9d7891e2d502157e0722f87d6d2`.
  Its 395 listed files, four images and 248 runtime files were inspected;
  full verification exited 0 in 43.05 s. It is **not bound to the latest fixes**
  and was not accepted as a release. Cached artifacts/images are not Git payload.
- Installed appliance remains on the operator-upgraded release
  `59fb5442fede8814c879d29c61fb88748cabc5b2`, schema `0027`; plan-22 source
  has not been installed. Reported operator workarounds were model-key access
  permissions, rebuilding the frontend with its public API URL, and enrolling
  the current account's public key. No appliance action accompanies this freeze.
- Milestones 18/19 had prior software acceptance; milestone 21 had local
  upgrade/artifact acceptance for supervised installed testing. Plan 22 remains
  unaccepted. Installed provider/systemd/isolation/nested-KVM/member-journey
  qualification and sustained useful/adversarial AI behavior are not established
  by the local fixture results. Preserve earlier scoped commissioning receipts.
- Only the user-approved obsolete `-22`, `-22b`, `-22c` bundles were removed;
  approximately 19 GiB remained free. Original and newer candidates were retained.
  The implementation endpoint failed with connection refused when asked to
  acknowledge the freeze; no restart was requested. No test/build worker was
  visible in the user-process inventory during checkpointing.

Resume by independently checking the three findings against the frozen source,
refreshing affected acceptance evidence and building a source-bound candidate.
Do not deploy merely because this checkpoint is on the default branch.

## Underpressure implementation slice — 2026-11-01 (branch `underpressure-range`, base `9b31635`)

- **Plan-22 three-finding recheck against HEAD `9b31635`** (the frozen merge
  of the claimed fixes): all three mechanisms are present in the integrated
  source — every mirror envelope carries the authoritative `seq` and
  unreconciled lines never override committed authority
  (`srplatform/safety/__init__.py`); outage recovery is a NEW committed pass
  with the audited `POST /safety/reconcile-outage` +
  `rangectl safety reconcile-outage` (`app.py:2672`, `safety/__init__.py:777`);
  activation/forced rollback renames use `renameat2(RENAME_NOREPLACE)`
  (`deploy/bundle.py:254-284`). The round-5 AND round-6 regression suites
  pass at HEAD (7 passed, 13 deselected, 9.5 s). Infrastructure-free full
  suite at this base: **744 passed, 0 failed, 535 deselected** (113 s) —
  refreshed baseline replacing the historical 741. This is source +
  infrastructure-free-test evidence; independent review of the frozen
  integration and every installed/live gate REMAIN open (unchanged freeze).
- **New contract layer (validated, not release-accepted):**
  `srplatform/environment_specs` + `environments/underpressure-range`
  (blueprint/fidelity/checks/attack/defender, 12 guests, 8 real-transaction
  availability checks, labeled practice rubric), scenario schema v2 with
  environment pins, orchestrator refusal of flat environment deploys,
  Windows-path verifier args, durable lab aggregate (migration 0029 —
  forward, additive) with dependency-aware reset planner, and the closed
  segment/NIC lane in both broker policies (v1 policies unchanged and
  regression-proven). New tests: 27 environment + 9 lab + 7 NIC-lane;
  infra-free suite green at the slice head; DB lanes (fresh-migration +
  round-trip) run against a disposable containerized Postgres; authority
  lane 35 passed after the policy change.
- **Still pending (not faked):** multi-interface domain XML/seed backend
  wiring behind the segment policy, guest image builds (operator media),
  lab API/CLI + console gateway, red-agent environment binding + attacker
  tooling payload, packet-level segment isolation on real nft/libvirt, and
  every installed-appliance / real-model qualification gate.

## Supervised installed-upgrade findings — 2026-10-29 (plan 22 authorized)

User authorized consolidated repair and autonomous Qwen-high implementation /
independent review after planning. Binding scope:
[plan 22](../.openchamber/plans/22-installed-practice-repairs.md), including the
retained plan-20 F5–F9. Historical observations/workarounds below are evidence,
not claims that permanent repairs already landed. The proposed seven-day manual
policy override below was not confirmed applied; plan 22 supersedes it with
explicit qualification versus admission-health semantics.

Fresh planning baseline at `1083f22`, after disk/RAM/process checks:
`env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m pytest -q -ra -p no:cacheprovider` — exit 0,
**678 passed, 480 deselected, zero failed/skipped, six warnings, 95.97s**.
No DB, VM, model, firewall or deployed-appliance operation was run for planning.
Existing unrelated processes were not cleaned or terminated.

Operator testing is in progress. Keep one running list here and batch permanent
source fixes after testing, as requested by the user. Only minimal, explicitly
reported operator recovery steps are used meanwhile; security, containment or
data-loss concerns stop testing. Do not alter the sealed release being tested.

### LIVE-01 — API cannot read the preserved legacy model credential

- **Observed:** upgrade from schema 0019 reached service restart, then readiness
  returned HTTP 500. Production settings validation reported permission denied
  reading the existing model-key file. The attempt remains unfinished and fenced;
  no successful release stamp was reported.
- **Metadata evidence:** API runs as `srrange` without supplementary groups; the
  secrets directory is root-owned, group `sr-secrets`, mode 0750, without named
  ACLs; the model-key file is root-owned, mode 0600, without named ACLs. Both
  directory traversal and file read are therefore unavailable to the API.
- **Recovery instructions supplied:** grant only `srrange` traversal on the
  secrets directory and read access on this specific key through named ACLs;
  verify access without displaying the credential, then resume the existing
  attempt. Never make secrets world-readable, rotate the key, discard obligations
  or remove the maintenance fence to bypass readiness.
- **Permanent fix to batch:** fresh-install and preserving-upgrade provisioning
  must establish and verify API-only access to configured legacy credential
  files, preserve credential bytes/private ownership, and refuse unsafe or failed
  permission changes. Add actual identity/ACL tests, including refusal of access
  by ingest, worker, bastion and web identities and an idempotent upgrade check.
- **Operator result:** the existing attempt resumed successfully on 2026-10-29;
  output reports `status: done`, schema 0027, provisioning complete and all six
  services restarted, at release revision `59fb5442fede`. This confirms successful
  upgrade recovery, not independent verification of every ACL command or the
  subsequent browser/SSH/practice journey. Permanent provisioning repair remains
  pending the consolidated batch. The prematurely dispatched Qwen session ended
  without a text handoff; Git inspection found no changes from it.

### LIVE-02 — Successful retry retains a stale stage error

- **Observed:** the completed upgrade's restart stage reports `status: done` and
  a new completion time but still includes the previous readiness HTTP-500 error.
- **Impact:** confusing recovery diagnostics; the stale text must not be read as
  a new failed restart when the attempt reports completion. No additional service
  mutation or retry is warranted solely from this retained field.
- **Permanent fix to batch:** distinguish historical failed attempts from the
  current stage outcome, retaining failure evidence without presenting it as an
  unresolved error after successful recovery. Add failure/resume/success output
  regression coverage.
- **Status:** batched; post-upgrade readiness and functional checks pending.

### LIVE-03 — Post-upgrade doctor reports broker unreachable

- **Observed:** operator `/readyz` reports ready, schema 0027, controller held,
  runner configured, recordings writable and no issues; maintenance fence is
  absent and all six units are active. `doctor` nevertheless reports broker
  unreachable without explaining the failure.
- **Follow-up evidence:** root-run `status` reports inventory HTTP 403, peer UID
  not allowed. Broker startup reconciliation reports no pending intents, and its
  listener is active with a restricted UID allowlist. This identifies the failed
  root diagnostic as peer-identity rejection, not a demonstrated broker outage.
- **Confirmed:** operator's read-only inventory request as the actual API user
  succeeded. That user's UID matches the broker allowlist. No inventory contents
  were disclosed, and no broker permission change was needed.
- **Status:** broker connectivity confirmed for the API identity; root-run
  doctor/status reporting remains a diagnostic usability fix for the batch, not
  a broker-outage repair. Keep root outside the allowlist.

### LIVE-04 — Installed verifier reports five content drifts after upgrade

- **Observed:** content drift in the appliance nftables fragment, derived and
  bastion environment files, and API/broker unit definitions. Actual differences
  and whether they are preserved operator configuration are not yet established.
- **Confirmed:** operator compared all five installed files byte-for-byte with
  the current release's manifest-derived render; every file matches. No file
  contents were exposed and no configuration/firewall mutation was performed.
  `verify_install` compares against `install-receipt.json`; its old receipt is
  therefore not an adequate post-upgrade baseline for these changed files.
- **Permanent fix to batch:** update/version the verified installation receipt
  through successful upgrade finalization, preserving prior receipts and honest
  failure semantics. Add populated-upgrade followed by `verify` coverage; do not
  manually replace the receipt just to suppress warnings.
- **Status:** reported configuration drift classified as stale-baseline
  diagnostics, not an outstanding on-disk configuration mismatch. This comparison
  does not validate loaded firewall behavior. Readiness also reports older
  isolation receipts as stale; that is not a fresh isolation test or proof of
  changed isolation. Prior commissioning remains historical evidence, not
  permission to bypass current live safety gates.

### LIVE-05 — Browser login reports a fetch/network failure

- **Observed:** operator reaches the sign-in page, but submitting credentials
  displays `Failed to fetch`. Account identity is not yet confirmed.
- **Interpretation:** this message is not evidence of an invalid username or
  password; browser/API reachability, compiled public API URL, proxy routing,
  TLS, mixed-content blocking and CORS must be distinguished from authentication.
- **Next diagnostic:** capture only the browser page origin and failed login
  request URL/status or console error; never request passwords, authorization
  headers, tokens, request bodies or an unredacted HAR export.
- **Status:** unresolved; no account reset, credential changes or source-fix
  dispatch. Add any confirmed cause and minimum safe recovery to this batch.
- **Source lead:** `run_upgrade` calls `provision_release` without its
  `public_url` argument; its default is empty. `ensure_web_build` then supplies
  no `NEXT_PUBLIC_API_URL`, while `web/lib/api.js` defaults to the browser's
  localhost port 8000. This can produce a healthy appliance API and frontend
  HTTP response but a browser that cannot submit login to the appliance.
  Confirm the installed provision receipt and public proxy route before repair;
  this is not yet a measured browser request destination.
- **Confirmed operator checks:** the public `/api/readyz` route reports healthy
  schema 0027, while the completed attempt's frontend provision receipt reports
  no `next_public_api_url`. Combined with the inspected build/client defaults,
  this confirms missing browser API configuration in the upgrade build. No
  credential rejection or invalid-account conclusion is established.
- **Recovery plan:** resource-check, then rebuild the installed frontend with
  the existing manifest's public URL and the selected appliance Node runtime;
  restart only the web service and confirm browser login connectivity. Keep the
  sealed payload unchanged. Recovery execution/result not yet confirmed.
- **Operator recovery result:** capacity checks showed adequate disk and RAM;
  operator loaded the existing manifest public URL, stopped only the web service,
  rebuilt the installed frontend using its selected Node binary and the correct
  `NEXT_PUBLIC_API_URL`, then restarted the web service. Build succeeded and the
  service reports active. No dependency reinstall or sealed-payload edit was
  involved. Browser hard-refresh/login result remains pending.
- **Confirmed functional result:** operator subsequently reported successful
  browser login. The fetch failure is recovered; the permanent upgrade-build URL
  fix remains queued for the consolidated batch. No account reset was needed.
- **Further UI check:** operator can open Admin Models. No finished sessions or
  old recordings are available for the proposed history checks; operator chose
  not to pursue those checks. Historical preservation is therefore not newly
  qualified by this installed test, and absence alone is not classified as
  upgrade data loss. Continue with current model connectivity and new-run tests.
- **Model check:** operator reported that the active model profile's explicit
  probe succeeded. This confirms that particular admitted provider request, not
  sustained agent usefulness, complete provider compatibility or range isolation.
  New-run testing still requires the installed release-stage/safety gates.
- **Safety UI observation:** operator reports install-ready, lab-ready and
  attack-authorized all yes, supervisor latch clear and broker cessation latch
  not engaged. This records the displayed state, not a new packet-isolation or
  emergency-stop test; earlier stale-receipt details remain part of the evidence.
- **New-run observation:** one existing web-practice lab reached `ready`; UI
  presents separate attacker/defender bastion connections and a manual Begin
  control. The match has not yet begun. Uptime is correctly displayed unscored
  before valid checks. No connection-capability usernames or session identifiers
  are recorded here. Defender SSH, active agent progress, coaching, cleanup and
  replay are not yet qualified by this run.
- **Permanent fix to batch:** pass the manifest public URL through the real
  upgrade provision stage and require an authenticated browser login regression
  after an upgrade, not only frontend HTTP-200 readiness.

### LIVE-06 — Defender bastion rejects desktop public-key authentication

- **Observed:** operator used the defender connection instruction from a second
  desktop terminal; bastion answered `Permission denied (publickey)`.
- **Scope:** this establishes reachable SSH and failed authentication, not a
  guest-readiness failure or a proven upgrade regression. Offered desktop key,
  agent availability and enrollment for the owning application account have not
  yet been compared. Connection capability usernames are intentionally omitted.
- **Next diagnostic:** inspect desktop agent fingerprints/public-key filenames
  and account-bound enrollment without disclosing private keys or weakening
  bastion authentication. Do not copy appliance management/runner private keys
  to the desktop or enable password login as a workaround.
- **Status:** unresolved diagnostic; no permanent fix dispatched.
- **Follow-up:** desktop agent initially contained no identities. Operator
  loaded the intended key into the agent with a bounded lifetime and removed
  the temporary private-key file; SSH still refused while the lab was ready.
  Appliance inspection found zero enrolled keys for the current browser account.
  Historical commissioning used a different member account. This points to
  account-bound onboarding, not an established upgrade key-loss regression;
  compare enrolled account names before adding the intended public key. No
  private key or key fingerprint is recorded here.
- **Confirmed enrollment mismatch:** only the historical member account has
  enrolled keys, and one of those fingerprints matches the desktop agent's
  loaded key. The current browser account has none. Recovery can reuse that
  existing public key for the current account without exporting a private key,
  removing old entries or changing bastion authentication. Enrollment/reload and
  successful defender SSH are still pending operator confirmation.
- **Recovery confirmed:** operator reached the defender guest through the
  recorded bastion and `whoami` returned the expected defender identity after
  adding only the matching existing public key for the current browser account
  and reloading the bastion. No private-key redistribution was needed. Treat
  this as account onboarding, not an established upgrade key-loss defect.

### LIVE-07 — Begin correctly refuses expired safety evidence; UI is unclear

- **Observed:** new lab is ready and defender SSH works, but Begin refuses
  baseline verification, datapath proof and killswitch-test receipts older than
  the configured 24-hour lifetime. Earlier Safety page release stages all showed
  yes, with both latches clear.
- **Interpretation:** expired evidence is not evidence of newly broken isolation
  or cancellation. Begin's freshness refusal is fail-closed and must not be
  bypassed by extending TTLs, editing timestamps or submitting unobserved passed
  attestations. Historical commissioning remains completed, but does not refresh
  these time-bounded records.
- **Next operator work:** collect fresh actual isolation and stop-test evidence
  in the disposable lab, then record only observed outcomes through supported
  operator flows. Do not start model-driven attacks before the required gates.
- **Permanent batch item:** expose current Begin blockers/freshness clearly in
  the session and safety UI, distinct from commissioning/release-stage state.
- **Status:** match not begun; renewed evidence and active-run checks pending.
- **Operator usability requirement:** user explicitly rejects repeating manual
  commissioning/SSH/network/stop procedures for ordinary use. The expired-record
  renewal workflow is a practical deployment blocker, not merely UI polish.
  Stop repeating ad hoc manual checks. Include a supported, evidence-producing
  automatic validation/renewal workflow in the consolidated repair proposal;
  preserve fail-closed behavior for failed/unknown checks and require operator
  action for genuine configuration changes or failures. Do not satisfy this by
  silently increasing TTLs, copying old attestations, fabricating outcomes or giving model
  workers host credentials/firewall authority. Exact design and any privileged
  operator installation changes require explicit review before implementation.
- **Fresh defender observations:** external ICMP attempt reported network
  unreachable; bounded DNS lookup returned no addresses with exit code 2; a
  repeated IPv6-default-route query returned no routes and exit code 0. An
  earlier interrupted IPv6 query was inconclusive and is superseded by that
  successful repeat. These observations cover this defender guest only, not
  attacker egress, management/same-bridge isolation or emergency-stop behavior.
- **Current-lab repeat:** operator again confirmed defender identity, noninteractive
  sudo, unreachable external ICMP, DNS no-resolution exit 2 and no IPv6 default
  route with exit 0. Do not keep repeating these observations while the same
  lab/configuration remains in scope. Operator correctly questioned repeated
  commissioning steps: distinguish completed historical qualification, fresh
  observations already collected, and the specific expired records blocking
  Begin. No additional model-driven run or fresh stop-test pass is claimed.

### LIVE-08 — Apparent idle expiry followed by unresponsive web UI

- **Observed:** before Begin succeeded, operator reported SSH stopped responding
  after the displayed lab idle-expiry time, then the web page also stopped
  responding. Expiry/cleanup completion and the affected services are not yet
  confirmed. No model-driven match was started in this test.
- **Interpretation:** normal idle expiry could close guest SSH, but must not be
  assumed to explain an unresponsive appliance website. Distinguish browser,
  frontend, API, cleanup and host resource failures before intervention.
- **Next diagnostic:** read-only appliance uptime/resource/service checks and
  bounded local API/frontend HTTP probes from the appliance administrative SSH
  session, not the expiring guest sessions. Preserve logs; no blind reboot,
  cleanup deletion or service restart before capturing evidence.
- **Status:** unresolved incident; add findings to the consolidated batch, not
  individual speculative source-fix dispatches.
- **Operator follow-up:** operator reported the broader hypervisor connectivity
  problem resolved and unrelated to this work. No host command or live
  intervention was performed by the assistant. Do not classify the outage as an
  application defect without further evidence; appliance readiness, website
  responsiveness and expired-lab cleanup still need confirmation after recovery.
- **Recovery observations:** appliance readiness again reports ready, schema
  0027, no issues and controller held. Operator reports the original session
  state is complete. A subsequent operator `recovery status` check confirmed
  zero pending intents, active claims and open obligations. These are observed
  broker-ledger counts, not proof that every live libvirt object or model-job
  obligation has been independently enumerated.

### LIVE-09 — UI offers an attacker bastion connection outside key policy

- **Observed:** desktop's persisted member key matches the enrolled account;
  attacker connection now passes initial bastion authentication but fails the
  target hop with `PermissionDenied`. This is distinct from the earlier missing
  desktop identity and account-enrollment problems.
- **Source classification:** guest role policy places the member bastion key
  only in defender guests; attacker accepts the scoped runner principal instead.
  Bastion target dialing uses the defender user. Recommending the displayed
  attacker connection for member SSH was therefore an operator-guidance error,
  not a reason to broaden attacker key policy or redistribute service keys.
- **Permanent batch item:** do not advertise member SSH connections that cannot
  authenticate under the role contract; clearly distinguish attacker telemetry
  from defender interactive access. Add UI/API role-policy compatibility tests.
- **Next action:** use only the current defender connection for member SSH.
  Attacker safety observations need the supported operator diagnostic channel;
  do not improvise privileged access or mark them passed from this refused hop.
- **Status:** recorded for batch; no key-policy change or source-fix dispatch.

### LIVE-10 — Coach misattributes operator setup to attacker activity

- **Observed:** before a model-driven match could begin, coach described the
  operator's SSH identity/sudo/connectivity checks as suspicious reconnaissance.
  When corrected by the operator, it doubled down and described audit events as
  attacker entries rather than acknowledging uncertain attribution.
- **Impact:** misleading guidance and poor handling of explicit user correction.
  Event citations and a host label do not establish authenticated actor identity;
  host telemetry is not independent proof of attacker activity or intent.
- **Permanent batch fix:** provide phase/run state and reliable command provenance
  in coaching context, distinguish member bastion activity from agent operations
  and background telemetry, preserve unknown attribution, and acknowledge user
  corrections without treating them as independently verified evidence. Add
  ready-before-Begin and member-setup/telemetry counterexamples. Subjective
  coaching must not alter deterministic scoring or verified outcomes.
- **Status:** batched; no new model-worker invocation or speculative source patch.

### Operator policy proposal — safety-evidence validity interval

- User requested an actionable policy correction after clarifying that elapsed
  time alone does not falsify earlier observations. A bounded seven-day (168 h)
  operator validity interval is proposed for supervised practice, explicitly
  retaining original record timestamps and all configuration-change, failed
  evidence, latch and unknown-cessation checks. It is not automatic validation or
  a claim that the old observations were rerun.
- Local settings parsing confirmed `SR_SAFETY_EVIDENCE_MAX_AGE_H=168` resolves
  to 168. Operator application/result is pending; no live configuration changed
  by the assistant. The longer interval does not establish unchanged isolation
  and is not a substitute for investigating an actual network/control change.
- Long-term evidence-producing renewal and clearer freshness UI remain batched;
  do not silently change global defaults or fabricate new passed attestations.

## Recording new acceptance evidence

For every gate record: date, evidence Git revision and dirty status, exact command
and non-secret environment, runtime/fixture versions, exit code and all
pass/fail/skip/deselect totals, boundary actually exercised, prerequisite blockers,
and observable live outcomes where applicable. Never record plaintext credentials,
real admin terminal casts or mutable generated files as proof in Git.

Only close a blocker after independently executing its agreed milestone criteria.
No implementation milestone is closed by this documentation pass.
