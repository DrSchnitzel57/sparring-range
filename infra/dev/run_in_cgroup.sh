#!/usr/bin/env bash
# Run a command UNPRIVILEGED inside a delegated cgroup v2 subtree.
#
# Why this exists (audit B10, review P1): the CI runner's own cgroup is
# root-owned, so an unprivileged process cannot migrate its children OUT of
# it — and chowning only the delegated DIRECTORY leaves its cgroup.procs
# root-owned, so even migrations INSIDE the subtree would be refused by the
# kernel's permission check. Root therefore performs the single privileged
# move (this shell into the subtree) and verifies it; the command then runs
# as the unprivileged user, but only after an UNPRIVILEGED migration probe
# proves the delegated file permissions really permit moving processes
# between child cgroups. If any part of that chain is misconfigured, this
# wrapper fails before the gate ever runs.
#
# usage: sudo run_in_cgroup.sh <cgroup-root> <user> <cmd> [args...]
set -euo pipefail

if [ "${1:-}" = "--dropped" ]; then
  # ---- unprivileged phase: prove REAL migration permission in the subtree
  root="$2"; shift 2
  probe="$root/sr-wrap-probe-$$"
  mkdir "$probe"
  if [ ! -w "$probe/cgroup.procs" ]; then
    echo "$root is not a writable cgroup (new child lacks a writable cgroup.procs)" >&2
    rmdir "$probe" 2>/dev/null || true
    exit 1
  fi
  status=1
  sleep 30 & pid=$!
  if echo "$pid" > "$probe/cgroup.procs" 2>/dev/null; then
    status=0
    deadline=$((SECONDS + 10))
    until grep -qx "$pid" "$probe/cgroup.procs"; do
      [ "$SECONDS" -lt "$deadline" ] || { status=1; break; }
      sleep 0.2
    done
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  removed=0
  for _ in $(seq 20); do  # cgroup rmdir only succeeds once fully empty
    rmdir "$probe" 2>/dev/null && { removed=1; break; }
    sleep 0.1
  done
  if [ "$removed" -ne 1 ]; then
    echo "probe cgroup $probe could not be removed (leak)" >&2
    exit 1
  fi
  if [ "$status" -ne 0 ]; then
    echo "unprivileged migration inside $root failed — delegation needs the" \
         "control FILES (cgroup.procs) owned by the delegatee, not just the" \
         "directory (audit B10)" >&2
    exit 1
  fi
  exec "$@"
fi

# ---- privileged phase (root): the single allowed migration
root="${1:?usage: run_in_cgroup.sh <cgroup-root> <user> <cmd>...}"
user="${2:?}"
shift 2
test "$(id -u)" -eq 0 || { echo "must be invoked via sudo" >&2; exit 1; }
test "$(stat -fc %T "$root")" = cgroup2fs || {
  echo "$root is not a cgroup v2 directory" >&2; exit 1; }

echo $$ > "$root/cgroup.procs"
# verify the move took effect before dropping privileges — a silent failure
# would run the whole layer outside the boundary and make the tests useless
deadline=$((SECONDS + 10))
until grep -q "$(basename "$root")" "/proc/$$/cgroup"; do
  [ "$SECONDS" -lt "$deadline" ] || {
    echo "process never appeared inside $root (/proc/self/cgroup: $(cat "/proc/$$/cgroup"))" >&2
    exit 1; }
  sleep 0.2
done

exec runuser -u "$user" -- env \
  PATH="$PATH" HOME="$HOME" RUNNER_CGROUP_ROOT="$root" \
  "$0" --dropped "$root" "$@"
