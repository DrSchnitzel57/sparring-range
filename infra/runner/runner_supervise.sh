#!/bin/bash
# runner-supervisor — runner-side supervised containment for the sparring
# range isolated runner (audit N05, hardened for audit T01).
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
# T01 HARDENING (each was a review finding):
#   * DESCENDANT TRACKING: leader-PID-only checks let a background descendant
#     outlive its leader while status reported 'gone'. Every job runs with
#     SR_OP_ID exported, so liveness is "any process still carries this
#     operation identity in its environment" — descendants included, and
#     immune to PID reuse (a recycled PID cannot carry our environment).
#     Trust limit: a descendant that execs with a CLEARED environment escapes
#     tracking; the documented range commands do not, and cancel reports
#     'cancel-unconfirmed' rather than a false 'gone' whenever anything with
#     the identity remains.
#   * START REGISTRATION RACE CLOSED: the pidfile is written BY THE GROUP
#     LEADER ITSELF before exec, and cancel additionally targets every pid
#     carrying the identity directly — a cancel between "spawned" and
#     "recorded" always finds the job.
#   * CANCELLATION TOMBSTONES: cancel records a tombstone BEFORE answering;
#     a start for a cancelled op is REFUSED — a delayed start request can
#     never execute after cancellation was acknowledged. Tombstones older
#     than TOMBSTONE_TTL are garbage-collected on any verb.
#   * cancel answers 0 ('gone') ONLY when no process carrying the identity
#     remains; otherwise it exits 1 ('cancel-unconfirmed'). An SSH disconnect
#     of the START connection never cancels anything by itself.
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

op_pids() { # every live pid whose environment carries SR_OP_ID=<op>
  local op="$1" pid envf
  for pid in /proc/[0-9]*; do
    pid=${pid#/proc/}
    envf="/proc/$pid/environ"
    [ -r "$envf" ] || continue
    if tr '\0' '\n' < "$envf" 2>/dev/null | grep -qx "SR_OP_ID=$op"; then
      echo "$pid"
    fi
  done
}

job_pgid() { # echoes the recorded pgid when the job is RECORDED (not liveness)
  local pidfile="$STATE_DIR/$1.pid"
  [ -f "$pidfile" ] || return 1
  local rec; rec=$(cat "$pidfile" 2>/dev/null) || return 1
  case "$rec" in (*[!0-9]*|'') return 1;; esac
  echo "$rec"
}

job_alive() { # 0 when ANY process still carries the operation identity
  [ -n "$(op_pids "$1")" ]
}

kill_job() { # one signal pass over the recorded group AND every identity-carrying pid
  local sig="$1" op="$2" pgid pid
  pgid=$(job_pgid "$op") || pgid=""
  [ -n "$pgid" ] && kill "-$sig" -"$pgid" 2>/dev/null
  for pid in $(op_pids "$op"); do kill "-$sig" "$pid" 2>/dev/null; done
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    job_alive "$op" || return 0
    sleep 0.2
  done
  return 1
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
    # TOMBSTONE (audit T01): cancellation was acknowledged for this operation
    # — a late/delayed start must NEVER execute it.
    if [ -f "$STATE_DIR/$op.cancelled" ]; then
      echo "refused: op $op was cancelled — start after cancellation is forbidden" >&2
      exit 3
    fi
    if job_alive "$op"; then die "op $op already running"; fi
    # The group leader records its OWN pid (== pgid after setsid) BEFORE exec,
    # closing the spawn/register window for cancel. `-w` keeps the stream
    # connection tied to the job's exit status.
    SR_OP_ID="$op" SR_PIDFILE="$STATE_DIR/$op.pid" \
      setsid -w bash -c 'echo $$ > "$SR_PIDFILE"; exec "$@"' _ "$@" &
    job=$!
    # stream output on THIS connection until the job ends. If the connection
    # drops the job KEEPS RUNNING (new session) and stays cancellable by
    # op_id — disconnect is never treated as cessation.
    wait "$job" 2>/dev/null; rc=$?
    # the pidfile is removed only once NO process carries the identity
    if ! job_alive "$op"; then rm -f "$STATE_DIR/$op.pid"; fi
    exit $rc
    ;;
  status)
    if job_alive "$op"; then echo running; exit 0; fi
    if [ -f "$STATE_DIR/$op.pid" ] || [ -f "$STATE_DIR/$op.cancelled" ]; then
      echo gone; rm -f "$STATE_DIR/$op.pid"; exit 0
    fi
    echo not-found
    exit 0
    ;;
  cancel)
    # TOMBSTONE FIRST (audit T01): record the cancellation BEFORE answering,
    # so a start racing this cancel is refused and a cancel-before-start
    # leaves durable evidence.
    touch "$STATE_DIR/$op.cancelled"
    kill_job TERM "$op" || true
    kill_job KILL "$op" || true
    if job_alive "$op"; then
      echo "cancel-unconfirmed" >&2; exit 1
    fi
    rm -f "$STATE_DIR/$op.pid"
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
