#!/bin/bash
# runner-supervisor — runner-side supervised containment for the sparring
# range isolated runner (audit N05).
#
# Installed on the ISOLATED RUNNER ONLY (the single configured SSH target of
# the worker; see docs/OPERATOR_RUNBOOK.md). The worker talks to it with a
# stable operation identity:
#
#   runner-supervisor start <op_id> -- <command...>   start tracked job, stream output
#   runner-supervisor status <op_id>                  running | gone | not-found
#   runner-supervisor cancel <op_id>                  kill the job's process group
#   runner-supervisor list                            all tracked op ids
#
# Each job runs in its OWN process group (setsid) with a pidfile under the
# state dir. Cancellation is confirmed by the group actually disappearing —
# an SSH disconnect of the START connection never cancels anything by
# itself, and cancel only answers 0 once cessation is confirmed.
set -u

STATE_DIR="${RUNNER_SUPERVISOR_STATE:-$HOME/.sparring_runner/jobs}"
mkdir -p "$STATE_DIR"

die() { echo "$@" >&2; exit 2; }

valid_op() { case "$1" in (*[!a-zA-Z0-9_-]*|'') return 1;; (*) return 0;; esac; }

job_pgid() { # echoes pgid or nothing
  local pidfile="$STATE_DIR/$1.pid"
  [ -f "$pidfile" ] || return 1
  local pid; pid=$(cat "$pidfile" 2>/dev/null) || return 1
  case "$pid" in (*[!0-9]*|'') return 1;; esac
  # identity: the pid must still be a session leader (we started it via setsid)
  ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' | grep -qx "$pid" && echo "$pid"
}

cmd="${1:-}"; op="${2:-}"
[ -n "$cmd" ] || die "usage: runner-supervisor start|status|cancel|list <op_id> [-- cmd...]"

case "$cmd" in
  start)
    valid_op "$op" || die "invalid op id"
    shift 2
    [ "${1:-}" = "--" ] || die "expected -- before the command"
    shift
    [ $# -gt 0 ] || die "empty command"
    if job_pgid "$op" >/dev/null; then die "op $op already running"; fi
    # start the job as its own process-group leader; record the pid
    setsid "$@" &
    job=$!
    echo "$job" > "$STATE_DIR/$op.pid"
    # stream output on THIS connection until the job ends
    wait "$job"; rc=$?
    rm -f "$STATE_DIR/$op.pid"
    exit $rc
    ;;
  status)
    valid_op "$op" || die "invalid op id"
    if [ ! -f "$STATE_DIR/$op.pid" ]; then echo not-found; exit 0; fi
    if pgid=$(job_pgid "$op"); then echo running; else echo gone; rm -f "$STATE_DIR/$op.pid"; fi
    exit 0
    ;;
  cancel)
    valid_op "$op" || die "invalid op id"
    if [ ! -f "$STATE_DIR/$op.pid" ]; then echo gone; exit 0; fi
    if pgid=$(job_pgid "$op"); then
      kill -TERM -"$pgid" 2>/dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 -"$pgid" 2>/dev/null || break
        sleep 0.5
      done
      kill -0 -"$pgid" 2>/dev/null && kill -KILL -"$pgid" 2>/dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 -"$pgid" 2>/dev/null || break
        sleep 0.2
      done
      if kill -0 -"$pgid" 2>/dev/null; then
        echo "cancel-unconfirmed" >&2; exit 1
      fi
    fi
    rm -f "$STATE_DIR/$op.pid"
    echo gone
    exit 0
    ;;
  list)
    for f in "$STATE_DIR"/*.pid; do
      [ -e "$f" ] || continue
      op_id=$(basename "$f" .pid)
      job_pgid "$op_id" >/dev/null && echo "$op_id"
    done
    exit 0
    ;;
  *)
    die "unknown verb '$cmd'"
    ;;
esac
