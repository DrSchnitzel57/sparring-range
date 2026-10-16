"""proxmoxer wrapper (Part 2/3): rangectl drives Proxmox with an API token, not root.

Everything host-level goes through this module so there is one place to audit.

F05 repairs:
  * correct documented PVE endpoints and HTTP verbs (resource DELETE for
    destroy; `newvmid` for clone; concrete node paths — no literal braces),
  * asynchronous UPID tasks are WAITED on with bounded polling and the task's
    exit status is checked — callers may no longer proceed on an unfinished
    clone/start/delete,
  * TLS: verify against a configured CA by default; the insecure mode is an
    explicit, logged lab override (never silent),
  * `FakePVEHttp` simulates the API at the proxmoxer BOUNDARY (below this
    adapter) so production call ordering and task states are actually tested.
"""
from __future__ import annotations

import re
import time
from typing import Protocol


class ProxmoxError(RuntimeError):
    pass


class ProxmoxTaskError(ProxmoxError):
    pass


class PveHttpError(ProxmoxError):
    """An HTTP-level PVE error with its status code (mirrors proxmoxer's
    UnknownStatusCode contract: `.status_code` is the HTTP response)."""

    def __init__(self, status_code: int, message: str = ""):
        self.status_code = int(status_code)
        super().__init__(f"PVE HTTP {status_code}: {message}")


class PveNotFound(PveHttpError):
    """CONFIRMED absence: the PVE API answered 404 for this exact resource."""

    def __init__(self, message: str = ""):
        super().__init__(404, message or "resource does not exist")


class PveUnavailable(ProxmoxError):
    """UNCERTAIN state: transport/timeout/auth/permission/server failure.

    This is NOT absence. Callers must retain the resource and its reservation
    (audit N01: an outage must never authorize a delete or complete teardown).
    """


# Exact per-guest-config-absence wording PVE 9.2 returns for a nonexistent
# VMID (live capture 2026-10-14). Deliberately narrow: node name, the
# qemu-server directory, digits, .conf, and the literal wording must all
# match before any 500 is treated as confirmed absence.
_PVE_ABSENT_CONFIG_RE = re.compile(
    r"Configuration file 'nodes/[^/']+/qemu-server/\d+\.conf' does not exist"
)


def classify_pve_error(exc: Exception) -> ProxmoxError:
    """Map ANY adapter-layer exception to a typed outcome.

    Absence is ONLY ever confirmed by: an explicit HTTP 404, or PVE 9.2's
    per-guest-config-absence 500 wording (_PVE_ABSENT_CONFIG_RE below).
    Everything else carrying a PVE status (401/403/5xx...) or a transport
    signature is UNCERTAIN — never silently 'missing'. In particular 500
    "no such file '<path>'" is NOT absence: source-wise it is emitted only
    by the API router's static-file fallback when the request matches no
    API route at all (PVE::APIServer::AnyEvent `die "no such file '$path'"`),
    i.e. it is the signature of a URL-prefix bug (the db01932 class). An
    earlier revision classified it as absence — audit A1 (docs/audits/
    pve92-alignment.md) shows that turns any routing bug into silent false
    absence (free-looking VMIDs, 'already-absent' teardowns of live VMs).
    Plain exceptions WITHOUT a PVE/transport signature (e.g. test-injected
    failures) pass through unclassified so injected failures stay as loud
    and as typed as the injector wrote them."""
    if isinstance(exc, (PveHttpError, PveUnavailable)):
        return exc
    status = getattr(exc, "status_code", None)
    if status is not None:
        try:
            status = int(status)
        except (TypeError, ValueError):
            return PveUnavailable(f"unparseable PVE status {status!r}: {exc}")
        if status == 404:
            return PveNotFound(str(exc))
        if status == 500 and _PVE_ABSENT_CONFIG_RE.search(str(exc)):
            # Second absence dialect seen live (PVE 9.2.21, 2026-10-14):
            # 500 "Configuration file 'nodes/<node>/qemu-server/<vmid>.conf'
            # does not exist". The guest config file IS the VM definition,
            # so PVE naming that exact file is deterministic confirmation
            # the VMID is free — not an outage. The regex is anchored to
            # that per-guest shape so no other 500 can be swallowed.
            return PveNotFound(str(exc))
        return PveUnavailable(f"PVE status {status}: {exc}")
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return PveUnavailable(f"transport failure: {exc}")
    return exc


class _ProxmoxerPathAdapter:
    """proxmoxer joins path segments onto its /api2/json base with
    posixpath.join — a segment with a LEADING SLASH replaces the base
    entirely, so api.get("/nodes/x") silently requests "/nodes/x" and PVE
    answers 500 "no such file" (live-deploy find, 2026-10-14: every real
    proxmoxer call from this client lost its /api2/json prefix). The whole
    codebase passes '/nodes/...' paths, so normalize here, at the single
    boundary. Injected fakes (api=...) are NOT wrapped: they emulate this
    boundary and receive exactly what the wrapper sends."""

    def __init__(self, api):
        self._api = api

    def get(self, path, **kw):
        return self._api.get(path.lstrip("/"), **kw)

    def post(self, path, **kw):
        return self._api.post(path.lstrip("/"), **kw)

    def delete(self, path, **kw):
        return self._api.delete(path.lstrip("/"), **kw)

    def __getattr__(self, name):
        return getattr(self._api, name)


class ProxmoxLike(Protocol):
    def version(self) -> dict: ...
    def get(self, path: str) -> dict | list: ...
    def post(self, path: str, **kwargs) -> dict | list | None: ...
    def delete(self, path: str) -> dict | list | None: ...


class ProxmoxClient:
    """Thin, transparent wrapper over proxmoxer (token auth) + task waiting."""

    def __init__(self, host: str | None = None, token_id: str | None = None,
                 token_secret: str | None = None, api=None):
        from srplatform.settings import get_settings
        s = get_settings()
        if api is None:
            host = host or s.proxmox_host
            token_id = token_id or s.proxmox_token_id
            token_secret = token_secret or s.proxmox_token_secret
            if not token_id or not token_secret:
                raise ProxmoxError(
                    "Proxmox API token not configured (PROXMOX_TOKEN_ID / PROXMOX_TOKEN_SECRET). "
                    "Drew: create the token in Datacenter → Permissions → API Tokens.")
            from proxmoxer import ProxmoxAPI

            insecure = s.proxmox_insecure_lab_override
            verify: object = True
            if s.proxmox_tls_ca_file:
                verify = s.proxmox_tls_ca_file
            if insecure:
                verify = False
                print("WARNING: Proxmox TLS verification DISABLED by explicit lab override")
            # Audit A5: a malformed PROXMOX_TOKEN_ID (missing '!', wrong
            # realm form) otherwise surfaces as a confusing 401 from PVE
            # (live incident 2026-10-14: stray hyphen in the user name).
            # Fail fast, at construction, with the expected shape.
            user, sep, name = token_id.partition("!")
            if not sep or not user or not name or "@" not in user \
                    or "!" in name:
                raise ProxmoxError(
                    f"PROXMOX_TOKEN_ID {token_id!r} is malformed: expected "
                    "'<user>@<realm>!<tokenname>' (e.g. sr-broker@pve!range)"
                    " — the user part must match the realm user EXACTLY")
            api = _ProxmoxerPathAdapter(
                ProxmoxAPI(host, user=user, token_name=name,
                           token_value=token_secret, verify_ssl=verify,
                           timeout=s.proxmox_http_timeout_s))
        self.api = api
        self.task_timeout = s.proxmox_task_timeout_s

    # --- raw pass-through ------------------------------------------------------
    def version(self) -> dict:
        """GET /version (PVE::API2 'version', user => 'all').

        Audit A3: NOT `self.api.version()` — with the real proxmoxer that
        is attribute routing to a resource OBJECT, and calling it with no
        verb returns the resource itself (proxmoxer core __call__ returns
        self), so real PVE was never queried; only the fake made it look
        like a dict. The verb call is the only shape that issues HTTP."""
        return self.api.get("/version")

    def get(self, path: str) -> dict | list:
        return self.api.get(path)

    def post(self, path: str, **kwargs) -> dict | list | None:
        return self.api.post(path, **kwargs)

    def delete(self, path: str) -> dict | list | None:
        return self.api.delete(path)

    # --- async tasks (F05) ------------------------------------------------------
    def wait_for_task(self, node: str, upid: str, timeout: int | None = None,
                      poll_s: float = 1.0) -> dict:
        """Poll a UPID until stopped; raise on error exit status or timeout."""
        if not upid:
            raise ProxmoxTaskError(f"no UPID returned for task on {node}")
        deadline = time.monotonic() + (timeout or self.task_timeout)
        while True:
            try:
                status = self.get(f"/nodes/{node}/tasks/{upid}/status")
            except Exception as e:  # noqa: BLE001 — the task may still be RUNNING
                raise classify_pve_error(e) from e
            if isinstance(status, dict) and status.get("status") == "stopped":
                exit_status = status.get("exitstatus")
                if exit_status == "OK":
                    return status
                raise ProxmoxTaskError(f"task {upid} on {node} failed: exitstatus={exit_status}")
            if time.monotonic() > deadline:
                raise ProxmoxTaskError(f"task {upid} on {node} timed out after "
                                       f"{timeout or self.task_timeout}s")
            time.sleep(poll_s)

    # --- operations used by the deploy layer (concrete node, correct verbs) -----
    def resources(self) -> list[dict]:
        return self.get("/cluster/resources")

    def next_vmid(self, start: int) -> int:
        """Prefer `start` if PVE confirms it free, else scan for the next
        free VMID >= start. Concurrency is NOT solved here — callers race
        by design and must treat clone failures as subject to concurrent
        races (the broker serialises via its ledger + per-candidate probes).

        Audit A4 (source PVE::API2::Cluster 'nextid'): `?vmid=N` is an
        ASSERTION, not an allocator — PVE returns N when free and 400
        "VM N already exists" when taken; without `vmid` it scans from the
        datacenter next-id.lower (100), never from `start`. So the
        "next free >= start" behaviour below comes from the resources()
        scan fallback, and that scan only lists VMIDs this token may see
        (permission-filtered) — a further reason the caller must handle
        clone collisions. Any non-400 failure (401/403/5xx/transport)
        also lands in the fallback, where resources() will fail loudly
        with the real error if the endpoint itself is down."""
        try:
            nid = self.get(f"/cluster/nextid?vmid={start}")
            return int(nid)
        except Exception:
            existing = {int(r["vmid"]) for r in self.resources() if r.get("vmid")}
            cand = start
            while cand in existing:
                cand += 1
            return cand

    def clone_template(self, node: str, template_vmid: int, new_vmid: int, name: str,
                       full: bool = False, storage: str | None = None) -> str:
        """Linked clone (full=False). Returns the UPID — CALLER MUST wait_for_task.

        The documented PVE parameter for the destination id is `newid`
        (https://pve.proxmox.com/pve-docs/api-viewer POST /nodes/{node}/qemu/{vmid}/clone);
        `newvmid` is NOT a parameter and real PVE rejects it."""
        kwargs: dict = {"newid": new_vmid, "name": name, "full": 1 if full else 0}
        if storage:
            kwargs["storage"] = storage
        return self.post(f"/nodes/{node}/qemu/{template_vmid}/clone", **kwargs)

    def set_config(self, node: str, vmid: int, **cfg) -> None:
        self.post(f"/nodes/{node}/qemu/{vmid}/config", **cfg)

    # --- typed resource lookups (audit N01) ------------------------------------
    # Contract: return None ONLY on a confirmed 404 from PVE; raise
    # PveUnavailable on every other failure. "Could not ask" is never "absent".
    def lookup_vm(self, node: str, vmid: int) -> str | None:
        """VM status string ('running', 'stopped', ...) or None if PVE
        CONFIRMS the resource does not exist. Uncertain reads RAISE."""
        try:
            st = self.get(f"/nodes/{node}/qemu/{vmid}/status/current")
        except Exception as e:  # noqa: BLE001 — classified, never swallowed
            err = classify_pve_error(e)
            if isinstance(err, PveNotFound):
                return None
            raise err from e
        if not isinstance(st, dict):
            raise PveUnavailable(f"malformed status response for vmid {vmid}: {st!r}")
        status = st.get("status")
        if not status:
            raise PveUnavailable(f"status response for vmid {vmid} has no status field")
        return str(status)

    def lookup_config(self, node: str, vmid: int) -> dict | None:
        """VM config dict, or None on CONFIRMED absence; uncertain reads RAISE.

        Injected test failures (plain exceptions without a PVE status code)
        surface as PveUnavailable so production code paths stay honest."""
        try:
            cfg = self.get(f"/nodes/{node}/qemu/{vmid}/config")
        except Exception as e:  # noqa: BLE001
            err = classify_pve_error(e)
            if isinstance(err, PveNotFound):
                return None
            raise err from e
        if not isinstance(cfg, dict):
            raise PveUnavailable(f"malformed config response for vmid {vmid}: {cfg!r}")
        return cfg

    def try_lookup_config(self, node: str, vmid: int) -> dict | None:
        """Best-effort identity read for RESUME reconciliation: returns the
        config, None on confirmed absence, or {'_unavailable': str(err)} when
        the read failed for ANY reason (injected transport failure, 403,
        timeout). The caller must treat '_unavailable' as UNCERTAIN — never
        as absence or ownership."""
        try:
            return self.lookup_config(node, vmid)
        except Exception as e:  # noqa: BLE001 — classified uncertainty, not absence
            return {"_unavailable": str(e)[:300]}

    def vm_status(self, node: str, vmid: int) -> str:
        """Back-compat wrapper: 'absent' means CONFIRMED 404; uncertainty
        raises instead of masquerading as 'unknown'."""
        st = self.lookup_vm(node, vmid)
        return "absent" if st is None else st

    def start(self, node: str, vmid: int) -> str:
        return self.post(f"/nodes/{node}/qemu/{vmid}/status/start")

    def stop(self, node: str, vmid: int, force: bool = False) -> str:
        action = "stop" if force else "shutdown"
        return self.post(f"/nodes/{node}/qemu/{vmid}/status/{action}")

    def delete_vm(self, node: str, vmid: int) -> str:
        """Resource DELETE (the documented operation), returns UPID."""
        return self.delete(f"/nodes/{node}/qemu/{vmid}")

    # --- typed guest-agent file read (paired 03+04, step 3) -------------------
    # The ONLY guest-agent operation the release uses: read the fresh clone's
    # PUBLIC SSH host key during initial provisioning. Fixed path, bounded
    # response, ownership verified by the broker before AND after the read.
    # No arbitrary paths, no guest exec, no host shell. Requires the scoped
    # `VM.GuestAgent.FileRead` privilege on approved lab resources in
    # production; broad `VM.Monitor` / `VM.GuestAgent.Unrestricted` fallback
    # is forbidden and fails closed.
    GUEST_HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"
    # First-boot completion marker (live find 2026-10-16): host keys may
    # regenerate AFTER one successful read on slow first boots (cloud-init
    # still in modules-final), stranding the pinned generation. The marker
    # file exists only once first boot completes, so waiting for it before
    # the stability reads pins post-regen keys. Second fixed path — still
    # no arbitrary reads, no exec, same FileRead privilege.
    GUEST_BOOT_MARKER_PATH = "/var/lib/cloud/instance/boot-finished"

    def read_guest_file(self, node: str, vmid: int, path: str) -> str:
        """Read ONE allowlisted guest-agent path. Returns the file content.

        Only `GUEST_HOST_KEY_PATH` is representable; anything else raises
        ProxmoxError before any HTTP call. Response must be a dict with a
        `content` string that parses as a single-line `ssh-ed25519` public
        key — anything else raises PveUnavailable (uncertain, retain).
        """
        if path != self.GUEST_HOST_KEY_PATH:
            raise ProxmoxError(
                f"guest-agent read refused: {path!r} is not the allowlisted "
                f"host-key path {self.GUEST_HOST_KEY_PATH!r} (no arbitrary "
                "paths, no exec, no host shell)")
        import urllib.parse
        query = urllib.parse.urlencode({"file": path})
        try:
            resp = self.get(f"/nodes/{node}/qemu/{vmid}/agent/file-read?{query}")
        except Exception as e:  # noqa: BLE001 — classified uncertainty
            raise classify_pve_error(e) from e
        if not isinstance(resp, dict) or not isinstance(resp.get("content"), str):
            raise PveUnavailable(
                f"malformed guest-agent file-read response for vmid {vmid}: "
                f"{resp!r}")
        content = resp["content"].strip()
        parts = content.split()
        # Live find 2026-10-14: cloud-init's ssh module appends a
        # `root@hostname` COMMENT to generated host keys — a perfectly
        # valid 3-field .pub line. The key material is parts[:2]; the
        # comment is dropped, because the pin feeds known_hosts lines,
        # which carry no comment and must match what sshd presents.
        if len(parts) not in (2, 3) or parts[0] != "ssh-ed25519" \
                or len(parts[1]) < 32:
            raise PveUnavailable(
                f"guest-agent host-key response for vmid {vmid} is not a "
                "bounded ssh-ed25519 public key")
        content = " ".join(parts[:2])
        if len(content) > 1024 or "\n" in content:
            raise PveUnavailable(
                f"guest-agent host-key response for vmid {vmid} exceeds bounds")
        return content

    def read_boot_marker(self, node: str, vmid: int, timeout_s: float = 120.0,
                         poll_s: float = 2.0) -> bool:
        """True once the guest's first boot completed (marker file present;
        it is empty by convention — presence, not content, is the signal).
        False when the window expires. Only not-ready dialects wait; VM
        absence, permission errors, and anything else raise immediately,
        and a timeout is PveUnavailable — uncertain, never success."""
        import urllib.parse
        query = urllib.parse.urlencode({"file": self.GUEST_BOOT_MARKER_PATH})
        deadline = time.monotonic() + timeout_s
        last: Exception | None = None
        while True:
            try:
                resp = self.get(
                    f"/nodes/{node}/qemu/{vmid}/agent/file-read?{query}")
            except Exception as e:  # noqa: BLE001 — classified below
                err = classify_pve_error(e)
                if isinstance(err, PveNotFound):
                    raise  # the VM itself is gone — waiting cannot help
                if not any(sig in str(err).lower()
                           for sig in self._KEY_NOT_READY_SIGNATURES):
                    raise err from e
                last = err
            else:
                if isinstance(resp, dict) and isinstance(resp.get("content"), str):
                    return True
                last = PveUnavailable(
                    f"malformed boot-marker response for vmid {vmid}: {resp!r}")
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(poll_s, deadline - time.monotonic()))

    # First-boot "key not materialized yet" dialects for the guest-agent
    # read (live finds 2026-10-14): the agent daemon may still be booting,
    # and the host key itself is regenerated by cloud-init during first
    # boot — the template deliberately ships with keys REMOVED. All of
    # these mean "retry within the bounded window"; anything else raises
    # immediately. Confirmed VM absence (PveNotFound) is checked BEFORE
    # these and never retries.
    #
    # Audit A2 (docs/audits/pve92-alignment.md): signatures must NOT
    # overlap the two "cannot know" dialects. The router's routing-bug 500
    # ("no such file '<api path>'") is matched by the qga strerror wording
    # only ("no such file or directory" — the guest-side file-open error
    # while the key is absent), never by the bare "no such file" prefix.
    # "does not exist" was removed: that wording is PVE's per-guest-CONFIG
    # absence (VM gone), which raises above, not a key-not-ready signal.
    _KEY_NOT_READY_SIGNATURES = (
        "guest agent is not running",
        "not a bounded ssh-ed25519 public key",
        "malformed guest-agent file-read response",
        "file not found",
        "no such file or directory",
    )

    def read_guest_file_when_ready(self, node: str, vmid: int, path: str,
                                   timeout_s: float = 120.0,
                                   poll_s: float = 2.0) -> str:
        """`read_guest_file`, tolerating the first-boot agent+key window.

        Live finds 2026-10-14: right after a clone starts, PVE answers
        guest-agent calls with 500 "QEMU guest agent is not running" until
        the in-guest agent connects, AND the host key file itself only
        materializes when cloud-init's ssh module regenerates it during
        first boot (templates ship with keys removed). There is NO status
        endpoint (GET .../agent/status answers 501 "Not Implemented"), so
        readiness is probed by retrying the real allowlisted read itself —
        same endpoint, same privilege, no new surface. Only the
        not-materialized-yet dialects retry; confirmed absence or any
        other error raises immediately, and a timeout stays
        PveUnavailable — uncertain, never success."""
        deadline = time.monotonic() + timeout_s
        last: Exception | None = None
        while True:
            try:
                return self.read_guest_file(node, vmid, path)
            except Exception as e:  # noqa: BLE001 — classified below
                err = classify_pve_error(e)
                if isinstance(err, PveNotFound):
                    raise  # the VM itself is gone — waiting cannot help
                if not any(sig in str(err).lower()
                           for sig in self._KEY_NOT_READY_SIGNATURES):
                    raise err from e
                last = err
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PveUnavailable(
                    f"guest agent for vmid {vmid} not ready within "
                    f"{timeout_s}s: {last}")
            time.sleep(min(poll_s, remaining))

    # --- high-level sequences used by the orchestrator ---------------------------
    def clone_and_wait(self, node, template_vmid, new_vmid, name, full=False) -> None:
        upid = self.clone_template(node, template_vmid, new_vmid, name, full=full)
        self.wait_for_task(node, upid)

    def start_and_wait(self, node, vmid, timeout: int = 90) -> None:
        if self.vm_status(node, vmid) == "running":
            return
        upid = self.start(node, vmid)
        self.wait_for_task(node, upid, timeout=timeout)

    def destroy_and_wait(self, node, vmid, force_stop_timeout: int = 60) -> str:
        """Confirmed-outcome destroy (audit N01):

        * returns 'already-absent' WITHOUT issuing a delete when PVE confirms
          the resource does not exist (idempotent);
        * returns 'destroyed' only after the delete task completed OK;
        * RAISES PveUnavailable when the pre-delete read is uncertain — the
          caller must retain the resource and its reservation. An outage is
          never a successful no-op teardown.
        """
        st = self.lookup_vm(node, vmid)   # raises PveUnavailable when uncertain
        if st is None:
            return "already-absent"
        if st == "running":
            upid = self.stop(node, vmid, force=True)
            self.wait_for_task(node, upid, timeout=force_stop_timeout)
        upid = self.delete_vm(node, vmid)
        self.wait_for_task(node, upid, timeout=force_stop_timeout)
        return "destroyed"


class FakePVEHttp:
    """A fake of the proxmoxer HTTP BOUNDARY (get/post/delete + task queue), so
    ProxmoxClient's REAL code paths — URLs, verbs, UPID polling, error
    propagation — are exercised in tests (F05). Configure task behaviour per
    path fragment; default tasks complete OK immediately.

    ``pve_no_such_file=True`` (audit A9/A10, plan 13 AC#4) replays the REAL
    PVE 9.2 absence dialect instead of the fake's historical 404: per-guest
    paths for a missing VMID answer 500 "Configuration file
    'nodes/<node>/qemu-server/<vmid>.conf' does not exist" (source:
    PVE::QemuConfig->load_config via cfs; live-confirmed 2026-10-14), and a
    clone onto a used VMID answers 500 "unable to create VM N: config file
    already exists" (plain die in the clone code — 500, not 400). The 404
    mode stays the default so existing fixtures keep their current shape."""

    def __init__(self, pve_no_such_file: bool = False):
        self.vms: dict[int, dict] = {}
        self.tasks: dict[str, dict] = {}
        self._upid = 0
        self.requests: list[tuple[str, str, dict]] = []
        self.pve_no_such_file = bool(pve_no_such_file)
        # behaviour hooks
        self.task_polls_needed = 0          # how long tasks stay "running"
        self.agent_not_ready_polls = 0      # /agent/status 500s before ready
        self.empty_key_polls = 0            # empty host-key reads (cloud-init
        #                                       not regenerated yet) before key
        self.qga_missing_file_polls = 0     # 500 "No such file or directory"
        #                                       guest-file-open errors (audit
        #                                       A2 first-boot key-absent dialect)
        self.fail_task_fragments = ()       # URL fragments whose tasks fail
        self.fail_request_fragments = ()    # raise immediately
        # audit N01: DISTINCT failure responses per URL fragment — value is an
        # int (PVE HTTP status) or a ready-made exception instance, e.g.
        #   http.fail_requests = {"/config": TimeoutError("management outage"),
        #                         "/status/current": 403}
        self.fail_requests: dict[str, object] = {}
        self._poll_count: dict[str, int] = {}

    def version(self):
        return {"version": "fake-pve"}

    def _absent(self, vmid: int) -> Exception:
        """Absence exception for a per-guest path of a missing VMID: the
        real 9.2 500 dialect in pve_no_such_file mode, else the fake's
        historical 404 (both classify to PveNotFound — audit A1/A10)."""
        if self.pve_no_such_file:
            return PveHttpError(
                500, f"Configuration file 'nodes/fake/qemu-server/{vmid}.conf'"
                     " does not exist")
        return PveNotFound(f"no VM {vmid}")

    def _maybe_fail(self, path: str) -> None:
        for frag, failure in self.fail_requests.items():
            if frag in path:
                if isinstance(failure, BaseException):
                    raise failure
                raise PveHttpError(int(failure), f"injected {path}")
        if any(f in path for f in self.fail_request_fragments):
            raise RuntimeError(f"injected request failure for {path}")

    def _new_upid(self, path: str) -> str:
        self._upid += 1
        upid = f"UPID:fake:{self._upid:08d}:0:0:{self._upid:08d}:qemu:{path}::"
        failed = any(f in path for f in self.fail_task_fragments)
        self.tasks[upid] = {"node": "fake", "status": "running", "_failed": failed,
                            "_path": path}
        return upid

    def get(self, path, **kw):
        self.requests.append(("GET", path, kw))
        self._maybe_fail(path)
        if path.strip("/") == "version":
            # GET /version (user => 'all' in PVE::API2) — served so the
            # client's version() probe is exercised (audit A3).
            return {"version": "fake-pve", "release": "9.2", "repoid": "fake"}
        if "/agent/file-read" in path:
            # First-boot window (live find 2026-10-14): real PVE answers
            # 500 "QEMU guest agent is not running" until the in-guest
            # agent connects; agent_not_ready_polls replays that here.
            if self.agent_not_ready_polls > 0:
                self.agent_not_ready_polls -= 1
                raise PveHttpError(500, "QEMU guest agent is not running")
            if self.qga_missing_file_polls > 0:
                # Audit A2 dialect: agent answers, guest key file not
                # regenerated yet — qga file-open strerror (retryable).
                self.qga_missing_file_polls -= 1
                raise PveHttpError(500, "Agent error: open failed with error"
                                        " code 2: No such file or directory")
            if self.empty_key_polls > 0:
                # Live find 2026-10-14: during first boot the agent answers
                # while cloud-init's ssh module has not regenerated the
                # (template-scrubbed) host key yet — empty content.
                self.empty_key_polls -= 1
                return {"content": ""}
            # Typed guest-agent FileRead (paired 03+04, step 3): the fake
            # models the documented GET /nodes/{node}/qemu/{vmid}/agent/
            # file-read?file=... endpoint. ONLY allowlisted paths are served
            # (host key + first-boot marker); anything else is a 400 (like
            # real PVE parameter validation). The key is FRESH per clone
            # (VMID + name bound), modeling scrubbed-template + first-boot
            # regeneration. The marker appears only when boot_completed is
            # set (live find 2026-10-16: keys may regenerate after readable
            # but before first boot completes).
            import hashlib
            import urllib.parse
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise self._absent(vmid)
            qs = urllib.parse.urlparse(path).query
            file_param = urllib.parse.parse_qs(qs).get("file", [""])[0]
            if file_param == "/var/lib/cloud/instance/boot-finished":
                if v.get("boot_completed", True):
                    return {"content": ""}
                raise PveHttpError(500, "Agent error: open failed with error"
                                        " code 2: No such file or directory")
            if file_param != "/etc/ssh/ssh_host_ed25519_key.pub":
                raise PveHttpError(400, f"file-read refused for {file_param!r}")
            digest = hashlib.sha256(
                f"{vmid}:{v.get('name', '')}".encode()).hexdigest()[:32]
            # Synthetic but well-formed ed25519 public key body (base64-ish).
            import base64
            raw = hashlib.sha256(f"hostkey:{vmid}:{v.get('name', '')}".encode()).digest()
            b64 = base64.b64encode(raw + raw).decode()[:68]
            override = v.get("guest_host_key")
            if override is not None:
                return {"content": override}
            return {"content": f"ssh-ed25519 {b64}"}
        if path.startswith("/cluster/resources"):
            return [{"vmid": vmid, "name": v["name"], "node": "fake", "type": "qemu",
                     "status": v["status"]} for vmid, v in self.vms.items()]
        if path.startswith("/cluster/nextid"):
            start = int(path.split("vmid=")[1]) if "vmid=" in path else 200
            existing = set(self.vms)
            cand = start
            while cand in existing:
                cand += 1
            return str(cand)
        if "/tasks/" in path and path.endswith("/status"):
            upid = path.split("/tasks/")[1].rsplit("/status", 1)[0]
            t = self.tasks.get(upid)
            if not t:
                raise KeyError(f"no such task {upid}")
            self._poll_count[upid] = self._poll_count.get(upid, 0) + 1
            if self._poll_count[upid] > self.task_polls_needed:
                t["status"] = "stopped"
                t["exitstatus"] = "ERROR: injected failure" if t["_failed"] else "OK"
                if t["exitstatus"] == "OK" and "_done_cb" in t:
                    t["_done_cb"]()
            return {"status": t["status"], "exitstatus": t.get("exitstatus")}
        if path.endswith("/config"):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise self._absent(vmid)  # 404 mode, or real 500 dialect
            # real PVE config includes the VM's NAME (creation identity);
            # the fake must model that or identity checks test nothing
            cfg = dict(v.get("config", {}))
            cfg.setdefault("name", v.get("name", ""))
            return cfg
        if "/status/current" in path:
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise self._absent(vmid)  # 404 mode, or real 500 dialect
            return {"status": v["status"], "vmid": vmid}
        return {}

    #: documented POST /nodes/{node}/qemu/{vmid}/clone parameters (PVE API viewer).
    #: The fake REJECTS anything else so adapter tests cannot agree with an
    #: invented parameter name (audit R06: `newvmid` vs documented `newid`).
    CLONE_PARAMS = {"newid", "name", "description", "full", "storage", "target",
                    "format", "snapname"}

    #: PVE pve-tag-list schema: tags are ';'-separated and each tag matches
    #: [A-Za-z0-9_.+-]+  (characters like '=' are REJECTED by real PVE).
    TAG_LIST_RE = re.compile(r"^[A-Za-z0-9_.+\-]+(;[A-Za-z0-9_.+\-]+)*$")

    def post(self, path, **kw):
        self.requests.append(("POST", path, kw))
        self._maybe_fail(path)
        if "/clone" in path:
            unknown = set(kw) - self.CLONE_PARAMS
            if unknown:
                # real PVE answers 400 with "unrecognized parameter"
                raise PveHttpError(400, f"unrecognized parameter(s): {sorted(unknown)}")
            if "newid" not in kw:
                raise PveHttpError(400, "missing required parameter 'newid'")
            tpl = int(path.split("/qemu/")[1].split("/")[0])
            new = int(kw["newid"])
            if new in self.vms:
                if self.pve_no_such_file:
                    # Audit A9: real PVE plain-dies here -> 500, not 400.
                    raise PveHttpError(
                        500, f"unable to create VM {new}: config file "
                             "already exists")
                raise PveHttpError(400, f"VMID {new} in use")
            if tpl not in self.vms:
                raise PveHttpError(400, f"template {tpl} not found")
            # the clone only materializes when the task COMPLETES (async semantics)
            upid = self._new_upid(path)
            def _finish_clone(new=new, kw=kw, tpl=tpl):
                # Fresh clone identity: first-boot host keys are regenerated
                # (the template's keys are scrubbed), so every clone gets a
                # FRESH synthetic host key — never the template's, never reused.
                import base64
                import hashlib
                import uuid as _uuid
                raw = hashlib.sha256(
                    f"hostkey:{new}:{kw['name']}:{_uuid.uuid4().hex}".encode()
                ).digest()
                fresh_key = "ssh-ed25519 " + base64.b64encode(raw + raw).decode()[:68]
                self.vms.setdefault(
                    new, {"name": kw["name"], "template": tpl, "status": "stopped",
                          "guest_host_key": fresh_key})
            self.tasks[upid]["_done_cb"] = _finish_clone
            return upid
        if path.endswith("/status/start"):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise self._absent(vmid)
            upid = self._new_upid(path)
            self.tasks[upid]["_done_cb"] = lambda: v.update(status="running")
            return upid
        if path.endswith(("/status/shutdown", "/status/stop")):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise self._absent(vmid)
            upid = self._new_upid(path)
            self.tasks[upid]["_done_cb"] = lambda: v.update(status="stopped")
            return upid
        if path.endswith("/config"):
            vmid = int(path.split("/qemu/")[1].split("/")[0])
            v = self.vms.get(vmid)
            if not v:
                raise self._absent(vmid)
            if "tags" in kw and not self.TAG_LIST_RE.match(str(kw["tags"])):
                # real PVE validates pve-tag-list on PUT (audit N01: validate
                # request schemas against the supported PVE version)
                raise PveHttpError(400, f"invalid tags {kw['tags']!r} (pve-tag-list rejected)")
            v.setdefault("config", {}).update(kw)
            return None
        return None

    def delete(self, path, **kw):
        self.requests.append(("DELETE", path, kw))
        self._maybe_fail(path)
        vmid = int(path.rsplit("/", 1)[1])
        if vmid not in self.vms:
            raise self._absent(vmid)  # 404 mode, or real 500 dialect
        upid = self._new_upid(path)
        self.tasks[upid]["_done_cb"] = lambda: self.vms.pop(vmid, None)
        return upid
