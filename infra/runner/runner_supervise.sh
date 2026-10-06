#!/bin/bash
# runner-supervisor — runner-side supervised containment for the sparring
# range isolated runner (audit N05, hardened for audits T01 and T-04).
#
# Installed on the ISOLATED RUNNER ONLY (the single configured SSH target of
# the worker; see docs/OPERATOR_RUNBOOK.md). The worker talks to it with a
# stable operation identity:
#
#   runner-supervisor start <op_id> -- <command...>   start tracked job, stream output
#   runner-supervisor status <op_id>                  running | gone | not-found
#   runner-supervisor cancel <op_id>                  kill the job + ALL descendants
#   runner-supervisor list                            all tracked op ids
#
# Exit codes: 0 ok | 1 cancel-unconfirmed | 2 usage | 3 refused (tombstone)
#             4 containment unavailable (unsupported execution mode) | 5 lock timeout
#
# T-04 HARDENING (fourth review — the acceptance blockers):
#   * AUTHORITATIVE CONTAINMENT VIA CGROUP v2: environment-marker tracking
#     was escapable — a descendant that execs with a CLEARED environment is
#     invisible to a /proc/*/environ scan, so 'gone' could hide live work.
#     Every job now runs inside its OWN cgroup (RUNNER_CGROUP_ROOT, a
#     delegated cgroup v2 directory — see OPERATOR_RUNBOOK). Liveness is
#     "the cgroup still has members", which a child CANNOT escape by editing
#     its environment. If no usable cgroup root exists, start REFUSES (exit
#     4, unsupported execution mode) rather than run uncontained work.
#     The SR_OP_ID environment scan is retained as a SECONDARY signal (belt
#     and suspenders), never as the sole authority.
#   * PGID SIGNAL IDENTITY GUARD: the pidfile records <pid>:<starttime>.
#     A process-group signal is sent only when the recorded leader is alive
#     AND its start time still matches — a recycled PGID is never signalled.
#   * ATOMIC START/CANCEL COORDINATION: start and cancel serialize on a
#     per-operation flock. Start holds it from the tombstone check through
#     spawn+pidfile registration; cancel holds it from tombstone creation
#     through kill+verification. A cancel can no longer observe "no process"
#     between start's tombstone check and its spawn, and a start racing an
#     acknowledged cancel is refused by the tombstone.
#   * CLEAN CONTROL CHANNEL: every verb answers with exactly one token on
#     stdout; unreadable /proc entries are skipped WITHOUT leaking shell
#     errors into the channel (a merged-stderr channel whose verdict line is
#     polluted is indistinguishable from an unreachable supervisor).
#   * TEST SEAM (documented, inert unless set): RUNNER_SUPERVISOR_TEST_HOOK
#     runs a command while start holds the operation lock (after the
#     tombstone check, before spawn) so barrier-driven race tests can pin
#     the exact interleaving. Production never sets it.
#
# Earlier T01 hardening retained: cancellation tombstones refuse delayed
# starts; cancel answers 0 ('gone') ONLY when nothing carrying the operation
# remains; an SSH disconnect of the START connection never cancels anything.
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

cg_path() { # the per-op cgroup directory
  [ -n "$CG_ROOT" ] || return 1
  echo "$CG_ROOT/sr-$1"
}

cg_usable() { # 0 when the root exists on cgroup2 and a probe dir can be made
  [ -n "$CG_ROOT" ] && [ -d "$CG_ROOT" ] && [ -w "$CG_ROOT" ] || return 1
  [ "$(stat -fc %T "$CG_ROOT" 2>/dev/null)" = "cgroup2fs" ] || return 1
  local probe="$CG_ROOT/.sr-probe.$$"
  mkdir "$probe" 2>/dev/null || return 1
  rmdir "$probe" 2>/dev/null
  return 0
}

cg_alive() { # 0 when the op's cgroup still has member processes
  # NOTE: cgroup virtual files stat with size 0 — `[ -s ]` would ALWAYS be
  # false here; the membership must be READ.
  local cg; cg=$(cg_path "$1") || return 1
  [ -f "$cg/cgroup.procs" ] || return 1
  [ -n "$(cat "$cg/cgroup.procs" 2>/dev/null)" ]
}

cg_kill() { # one signal pass over the whole cgroup; kernel cgroup.kill first
  local op="$1" cg procs
  cg=$(cg_path "$op") || return 0
  [ -d "$cg" ] || return 0
  if [ "${2:-TERM}" = KILL ] && [ -w "$cg/cgroup.kill" ]; then
    echo 1 > "$cg/cgroup.kill" 2>/dev/null || true
  fi
  procs=$(cat "$cg/cgroup.procs" 2>/dev/null) || return 0
  for p in $procs; do kill "-${2:-TERM}" "$p" 2>/dev/null; done
}

cg_cleanup() {
  local cg; cg=$(cg_path "$1") || return 0
  [ -d "$cg" ] || return 0
  rmdir "$cg" 2>/dev/null
  return 0
}

# Secondary (non-authoritative) signal: processes still carrying the op id.
# `cat 2>/dev/null` — a bash redirection failure would print to the SHELL's
# stderr, which the SSH control channel merges into stdout and which would
# corrupt the one-token verdict (audit T-04).
op_pids() {
  local op="$1" pid envf
  for pid in /proc/[0-9]*; do
    pid=${pid#/proc/}
    envf="/proc/$pid/environ"
    [ -r "$envf" ] || continue
    if cat "$envf" 2>/dev/null | tr '\0' '\n' | grep -qx "SR_OP_ID=$op"; then
      echo "$pid"
    fi
  done
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

job_alive() { # 0 when the operation still has ANY live process
  cg_alive "$1" && return 0
  [ -n "$(op_pids "$1")" ]
}

kill_job() { # one signal pass: cgroup (authoritative) + guarded pgid + markers
  local sig="$1" op="$2" pid
  cg_kill "$op" "$sig"
  if job_identity_matches "$op"; then
    kill "-$sig" -"$(job_leader "$op")" 2>/dev/null   # leader == pgid (setsid)
  fi
  for pid in $(op_pids "$op"); do kill "-$sig" "$pid" 2>/dev/null; done
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    job_alive "$op" || return 0
    sleep 0.2
  done
  return 1
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
      echo "refused: authoritative containment unavailable — RUNNER_CGROUP_ROOT is not a writable cgroup v2 directory; refusing to run uncontained work" >&2
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
    # window for cancel (which needs the lock and sees the pidfile).
    SR_OP_ID="$op" SR_PIDFILE="$STATE_DIR/$op.pid" SR_CG_PROCS="$CG_OP/cgroup.procs" \
      setsid -w bash -c '
        echo $$ > "$SR_CG_PROCS" 2>/dev/null || exit 97
        st=$(awk "{print \$22}" "/proc/$$/stat" 2>/dev/null) || st=0
        echo "$$:$st" > "$SR_PIDFILE"
        exec "$@"' _ "$@" &
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
    if [ "$rc" = 97 ]; then
      rm -f "$STATE_DIR/$op.pid"; cg_cleanup "$op"
      echo "refused: job could not enter its containment cgroup" >&2
      exit 4
    fi
    # the pidfile is removed only once NO process carries the identity
    if ! job_alive "$op"; then
      rm -f "$STATE_DIR/$op.pid"; cg_cleanup "$op"
    fi
    exit $rc
    ;;
  status)
    if job_alive "$op"; then echo running; exit 0; fi
    if [ -f "$STATE_DIR/$op.pid" ] || [ -d "$(cg_path "$op" 2>/dev/null)" ] \
       || [ -f "$STATE_DIR/$op.cancelled" ]; then
      echo gone; rm -f "$STATE_DIR/$op.pid"; cg_cleanup "$op"; exit 0
    fi
    echo not-found
    exit 0
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
    if job_alive "$op"; then
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
