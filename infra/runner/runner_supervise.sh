#!/bin/bash
# runner-supervisor — runner-side supervised containment for the sparring
# range isolated runner (audit N05, hardened for audits T01, T-04 and the
# fifth-follow-up F1/F5 findings).
#
# Installed on the ISOLATED RUNNER ONLY (the single configured SSH target of
# the worker; see docs/OPERATOR_RUNBOOK.md). The worker talks to it with a
# stable operation identity:
#
#   runner-supervisor start <op_id> -- <command...>   start tracked job, stream output
#   runner-supervisor status <op_id>                  running | gone | unknown | not-found
#   runner-supervisor cancel <op_id>                  kill the job + ALL descendants
#   runner-supervisor list                            all tracked op ids
#
# Exit codes: 0 ok | 1 cancel-unconfirmed | 2 usage | 3 refused (tombstone)
#             4 containment/boundary unavailable (unsupported execution mode) | 5 lock timeout
#
# FIFTH-FOLLOW-UP HARDENING (audit F1/F5 — cgroup membership was not yet
# authoritative containment):
#   * TRUSTED COMMAND BOUNDARY: model-selected commands are arbitrary and run
#     under the SAME uid that owns a delegated cgroup, so a redirected child
#     could previously migrate into the PARENT cgroup (escape), hide in a
#     nested cgroup from a direct-membership read, or rewrite the supervisor's
#     bookkeeping. Every command now executes inside a kernel-enforced
#     boundary created by the trusted launcher: a fresh USER + MOUNT + CGROUP
#     + PID namespace (unshare). Inside it the real cgroup hierarchy above the
#     operation is INVISIBLE (the cgroup namespace roots the operation tree
#     and /sys/fs/cgroup is re-mounted from that namespace), other processes
#     are invisible (fresh PID namespace + fresh /proc), and the supervisor's
#     state directory is masked by a tmpfs. If the host cannot supply this
#     boundary, start REFUSES (exit 4) BEFORE executing anything. The
#     installation/privilege model is documented in docs/OPERATOR_RUNBOOK.md
#     §6 (prefer a separate unprivileged command uid where available; the
#     namespace boundary is enforced regardless).
#   * RECURSIVE LIVENESS: liveness is the operation tree's populated state
#     (cgroup.events includes descendants), not the direct cgroup.procs list
#     a nested child can vacate.
#   * FAIL-CLOSED AUTHORITY: a failed/missing/unreadable state read is
#     reported as `unknown` — never `gone`. Records are NOT cleaned up
#     because a read failed, cancellation never confirms over an unknown,
#     and a missing control file with a live recorded leader is not proof of
#     cessation.
#   * KERNEL-SCOPED CESSATION: the KILL pass is cgroup.kill over the
#     protected operation tree (no scan-to-signal PID window). The graceful
#     TERM pass is the identity-guarded process-group signal ONLY. The
#     SR_OP_ID environment marker is never signalled — bare-PID/marker
#     fallback signalling is eliminated (a marker may be diagnostic, never
#     authority).
#
# T-04 HARDENING retained:
#   * Every job runs inside its OWN cgroup (RUNNER_CGROUP_ROOT, a delegated
#     cgroup v2 directory). If no usable cgroup root exists, start REFUSES
#     (exit 4, unsupported execution mode) rather than run uncontained work.
#   * PGID SIGNAL IDENTITY GUARD: the pidfile records <pid>:<starttime>.
#     A process-group signal is sent only when the recorded leader is alive
#     AND its start time still matches — a recycled PGID is never signalled.
#   * ATOMIC START/CANCEL COORDINATION: start and cancel serialize on a
#     per-operation flock. A cancel can no longer observe "no process"
#     between start's tombstone check and its spawn, and a start racing an
#     acknowledged cancel is refused by the tombstone. Successful
#     registration into the containment boundary (leader moved + pidfile
#     recorded) is acknowledged BEFORE start releases the coordination lock.
#   * CLEAN CONTROL CHANNEL: every verb answers with exactly one token on
#     stdout; unreadable files are skipped WITHOUT leaking shell errors into
#     the channel.
#   * TEST SEAM (documented, inert unless set): RUNNER_SUPERVISOR_TEST_HOOK
#     runs a command while start holds the operation lock (after the
#     tombstone check, before spawn) so barrier-driven race tests can pin the
#     exact interleaving. Production never sets it.
#
# Earlier T01 hardening retained: cancellation tombstones refuse delayed
# starts; cancel answers 'gone' ONLY when nothing inside the containment
# tree remains; an SSH disconnect of the START connection never cancels
# anything.
set -u

STATE_DIR="${RUNNER_SUPERVISOR_STATE:-$HOME/.sparring_runner/jobs}"
TOMBSTONE_TTL="${RUNNER_SUPERVISOR_TOMBSTONE_TTL:-86400}"
mkdir -p "$STATE_DIR"

die() { echo "$@" >&2; exit 2; }

valid_op() { case "$1" in (*[!a-zA-Z0-9_-]*|'') return 1;; (*) return 0;; esac; }

gc_tombstones() {
  local now cutoff f t
  now=$(date +%s); cutoff=$((now - TOMBSTONE_TTL))
  for f in "$STATE_DIR"/*.cancelled; do
    [ -e "$f" ] || continue
    t=$(stat -c %Y "$f" 2>/dev/null || echo "$now")
    [ "$t" -lt "$cutoff" ] && rm -f "$f"
  done
  return 0
}

# ---------------------------------------------------------------- containment
# Resolve the delegated cgroup v2 root: explicit RUNNER_CGROUP_ROOT, else the
# caller's own systemd user-slice path when it is writable (delegated).
_resolve_cgroup_root() {
  if [ -n "${RUNNER_CGROUP_ROOT:-}" ]; then
    echo "$RUNNER_CGROUP_ROOT"; return 0
  fi
  local path cand
  path=$(awk -F:: '$1=="0"{print $2}' /proc/self/cgroup 2>/dev/null)
  cand="/sys/fs/cgroup${path}"
  if [ -d "$cand" ] && [ -w "$cand" ]; then echo "$cand"; return 0; fi
  return 1
}

CG_ROOT=$(_resolve_cgroup_root || true)

# The trusted launcher: user+mount+cgroup+pid namespaces. The command cannot
# see or reach the cgroup hierarchy above its operation, other processes, or
# the supervisor's state directory (masked inside the mount namespace).
BOUNDARY_CMD="unshare --user --map-root-user --mount --cgroup --pid --fork --mount-proc"

boundary_available() { # 0 when the trusted boundary can actually be created
  command -v unshare >/dev/null 2>&1 || return 1
  $BOUNDARY_CMD /bin/true >/dev/null 2>&1
}

cg_path() { # the per-op cgroup directory
  [ -n "$CG_ROOT" ] || return 1
  echo "$CG_ROOT/sr-$1"
}

cg_usable() { # 0 when the root exists on cgroup2 and a probe dir can be made
  # with the kernel facilities the authority depends on (cgroup.kill +
  # cgroup.events) — a root without them cannot host trusted containment.
  [ -n "$CG_ROOT" ] && [ -d "$CG_ROOT" ] && [ -w "$CG_ROOT" ] || return 1
  [ "$(stat -fc %T "$CG_ROOT" 2>/dev/null)" = "cgroup2fs" ] || return 1
  local probe="$CG_ROOT/.sr-probe.$$" rc=0
  mkdir "$probe" 2>/dev/null || return 1
  [ -f "$probe/cgroup.events" ] || rc=1
  [ -w "$probe/cgroup.kill" ] || rc=1
  rmdir "$probe" 2>/dev/null
  return $rc
}

# AUTHORITATIVE liveness of the operation tree. Echoes exactly one of:
#   running   — the tree is populated (kernel-generated, includes descendants)
#   gone      — confirmed empty (or the recorded leader is verifiably dead)
#   unknown   — the authority FAILED (unreadable/missing state): NEVER gone
#   not-found — nothing was ever recorded for this operation
op_liveness() {
  local op="$1" cg ev
  cg=$(cg_path "$op") || { echo unknown; return; }
  if [ ! -d "$cg" ]; then
    # containment tree missing: previously dispatched work is NOT presumed
    # gone — fall back to the recorded leader identity.
    if [ -f "$STATE_DIR/$op.pid" ]; then
      if job_identity_matches "$op"; then echo running; else echo gone; fi
    elif [ -f "$STATE_DIR/$op.cancelled" ]; then
      echo gone
    else
      echo not-found
    fi
    return
  fi
  ev=$(cat "$cg/cgroup.events" 2>/dev/null) || {
    # A failed read is UNKNOWN — never gone — UNLESS the tree was removed
    # concurrently (the start connection's confirmed-gone cleanup races this
    # read). The kernel only permits rmdir of an EMPTY cgroup, so a tree
    # that no longer exists is confirmed cessation, not a failed authority.
    [ -d "$cg" ] || { echo gone; return; }
    echo unknown; return; }
  case "$ev" in
    *"populated 1"*) echo running ;;
    *"populated 0"*) echo gone ;;
    *) echo unknown ;;
  esac
}

cg_kill() { # one signal pass over the operation tree
  local op="$1" sig="${2:-TERM}" cg
  cg=$(cg_path "$op") || return 0
  [ -d "$cg" ] || return 0
  if [ "$sig" = KILL ]; then
    # kernel-scoped: reaches every descendant with no scan-to-signal window
    echo 1 > "$cg/cgroup.kill" 2>/dev/null || return 1
  else
    # graceful pass: identity-guarded process-group signal ONLY (leader ==
    # pgid via setsid). Never bare PIDs, never environment markers.
    if job_identity_matches "$op"; then
      kill -TERM -"$(job_leader "$op")" 2>/dev/null
    fi
  fi
  return 0
}

cg_cleanup() { # remove the operation tree bottom-up (nested descendants
  # included); a directory with live members refuses removal, which keeps
  # the authority honest
  local cg; cg=$(cg_path "$1") || return 0
  [ -d "$cg" ] || return 0
  find "$cg" -mindepth 1 -depth -type d -exec rmdir {} \; 2>/dev/null
  rmdir "$cg" 2>/dev/null
  return 0
}

# pidfile records "<pid>:<starttime>" (field 22 of /proc/pid/stat). Echoes the
# recorded leader pid when the job is RECORDED (not a liveness statement).
job_pgid() {
  local pidfile="$STATE_DIR/$1.pid"
  [ -f "$pidfile" ] || return 1
  local rec; rec=$(cat "$pidfile" 2>/dev/null) || return 1
  case "$rec" in (*[0-9]*:[0-9]*) ;; (*) return 1;; esac
  echo "$rec"
}

job_leader() { job_pgid "$1" | cut -d: -f1; }
job_startticks() { job_pgid "$1" | cut -d: -f2; }

# The recorded leader is alive AND is the same process that was recorded —
# never signal a recycled pid/pgid (audit T-04).
job_identity_matches() {
  local op="$1" pid st cur
  pid=$(job_leader "$op") || return 1
  st=$(job_startticks "$op") || return 1
  cur=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  [ "$cur" = "$st" ]
}

job_alive() { # 0 when the operation is CONFIRMED still live
  [ "$(op_liveness "$1")" = running ]
}

kill_job() { # one signal pass + verification; 0 = tree confirmed gone
  local sig="$1" op="$2" lv i
  cg_kill "$op" "$sig" || true
  for i in 1 2 3 4 5 6 7 8 9 10; do
    lv=$(op_liveness "$op")
    [ "$lv" = gone ] && return 0
    [ "$lv" = not-found ] && return 0
    sleep 0.2
  done
  lv=$(op_liveness "$op")
  [ "$lv" = gone ] || [ "$lv" = not-found ]
}

op_lock() { # per-operation flock held on fd 9 by the caller
  flock -w 10 9 || die "could not acquire operation lock (stale holder?)"
}

cmd="${1:-}"; op="${2:-}"
[ -n "$cmd" ] || die "usage: runner-supervisor start|status|cancel|list <op_id> [-- cmd...]"
valid_op "$op" || die "invalid op id"
gc_tombstones

case "$cmd" in
  start)
    shift 2
    [ "${1:-}" = "--" ] || die "expected -- before the command"
    shift
    [ $# -gt 0 ] || die "empty command"
    cg_usable || {
      echo "refused: authoritative containment unavailable — RUNNER_CGROUP_ROOT is not a writable cgroup v2 directory with cgroup.kill/cgroup.events; refusing to run uncontained work" >&2
      exit 4; }
    boundary_available || {
      echo "refused: trusted command boundary unavailable — the runner cannot create user/mount/cgroup/pid namespaces (unshare), through which the operation's containment is made non-escapable; refusing to execute model commands without it" >&2
      exit 4; }
    exec 9>"$STATE_DIR/$op.lock"
    op_lock
    # TOMBSTONE: cancellation was acknowledged for this operation — a
    # late/delayed start must NEVER execute it.
    if [ -f "$STATE_DIR/$op.cancelled" ]; then
      echo "refused: op $op was cancelled — start after cancellation is forbidden" >&2
      exit 3
    fi
    if job_alive "$op"; then die "op $op already running"; fi
    CG_OP=$(cg_path "$op")
    mkdir "$CG_OP" 2>/dev/null || {
      echo "refused: could not create containment cgroup for $op" >&2; exit 4; }
    # Documented test seam: runs WHILE THE LOCK IS HELD, after the tombstone
    # check and before the spawn, so tests can pin the start/cancel race.
    if [ -n "${RUNNER_SUPERVISOR_TEST_HOOK:-}" ]; then sh -c "$RUNNER_SUPERVISOR_TEST_HOOK"; fi
    # The group leader moves ITSELF into the containment cgroup and records
    # its own pid + start time BEFORE exec — closing the spawn/register
    # window for cancel (which needs the lock and sees the pidfile). It then
    # execs the TRUSTED LAUNCHER: fresh user/mount/cgroup/pid namespaces,
    # /sys/fs/cgroup re-rooted onto the operation's own cgroup directory
    # (BIND — the real hierarchy above the operation becomes unreachable;
    # a fresh cgroup2 SUPERBLOCK mount is NOT used because kernels before
    # the 6.13-era kernfs userns rework refuse it from a non-init user
    # namespace with EBUSY, e.g. Ubuntu 24.04), a fresh /proc (other
    # processes invisible), and the supervisor's bookkeeping masked by
    # tmpfs. Registration into the boundary is acknowledged (pidfile
    # recorded) before the lock is released.
    SR_OP_ID="$op" SR_PIDFILE="$STATE_DIR/$op.pid" SR_CG_PROCS="$CG_OP/cgroup.procs" \
      SR_CG_DIR="$CG_OP" SR_STATE_DIR="$STATE_DIR" \
      setsid -w bash -c '
        echo $$ > "$SR_CG_PROCS" 2>/dev/null || exit 97
        st=$(awk "{print \$22}" "/proc/$$/stat" 2>/dev/null) || st=0
        echo "$$:$st" > "$SR_PIDFILE"
        exec '"$BOUNDARY_CMD"' bash -c "
          mount --bind \"\$SR_CG_DIR\" /sys/fs/cgroup 2>/dev/null || exit 96
          mount -t tmpfs tmpfs \"\$SR_STATE_DIR\" 2>/dev/null || exit 96
          exec \"\$@\"" _ "$@"' _ "$@" &
    job=$!
    # Registration is complete once the leader recorded itself; only then may
    # cancel take the lock (it must find either the tombstone or the job).
    for _ in $(seq 1 50); do
      [ -f "$STATE_DIR/$op.pid" ] && break
      if ! kill -0 "$job" 2>/dev/null; then break; fi
      sleep 0.1
    done
    flock -u 9 2>/dev/null || exec 9>&-
    # stream output on THIS connection until the job ends. If the connection
    # drops the job KEEPS RUNNING (new session) and stays cancellable by
    # op_id — disconnect is never treated as cessation.
    wait "$job" 2>/dev/null; rc=$?
    if [ "$rc" = 97 ] || [ "$rc" = 96 ]; then
      rm -f "$STATE_DIR/$op.pid"; cg_cleanup "$op"
      if [ "$rc" = 96 ]; then
        echo "refused: command boundary setup failed (cgroup re-root / state mask)" >&2
      else
        echo "refused: job could not enter its containment cgroup" >&2
      fi
      exit 4
    fi
    # the pidfile is removed only once the tree is CONFIRMED gone — never
    # because a state read failed
    lv=$(op_liveness "$op")
    if [ "$lv" = gone ]; then
      rm -f "$STATE_DIR/$op.pid"; cg_cleanup "$op"
    fi
    exit $rc
    ;;
  status)
    lv=$(op_liveness "$op")
    case "$lv" in
      running) echo running; exit 0 ;;
      gone)
        echo gone
        rm -f "$STATE_DIR/$op.pid"; cg_cleanup "$op"
        exit 0 ;;
      unknown)
        # failed/missing authority: visible, retained, NEVER gone
        echo unknown; exit 0 ;;
      *) echo not-found; exit 0 ;;
    esac
    ;;
  cancel)
    exec 9>"$STATE_DIR/$op.lock"
    op_lock
    # TOMBSTONE FIRST: record the cancellation BEFORE answering, so a start
    # racing this cancel is refused and a cancel-before-start leaves durable
    # evidence. The lock makes "check tombstone → spawn" (start) and
    # "tombstone → kill → verify" (cancel) mutually exclusive.
    touch "$STATE_DIR/$op.cancelled"
    kill_job TERM "$op" || true
    kill_job KILL "$op" || true
    lv=$(op_liveness "$op")
    if [ "$lv" = running ] || [ "$lv" = unknown ]; then
      # live work, or an authority whose state cannot be read — an
      # acknowledged cancellation must never leave survivors or hide one
      echo "cancel-unconfirmed" >&2; exit 1
    fi
    rm -f "$STATE_DIR/$op.pid"
    cg_cleanup "$op"
    echo gone
    exit 0
    ;;
  list)
    for f in "$STATE_DIR"/*.pid; do
      [ -e "$f" ] || continue
      op_id=$(basename "$f" .pid)
      job_alive "$op_id" && echo "$op_id"
    done
    exit 0
    ;;
  *)
    die "unknown verb '$cmd'"
    ;;
esac
