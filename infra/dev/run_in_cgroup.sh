#!/usr/bin/env bash
# Run a command UNPRIVILEGED inside a delegated cgroup v2 subtree.
#
# Why this exists (audit B10, review P1): the CI runner's own cgroup is
# root-owned, so an unprivileged process cannot migrate its children OUT of
# it — chowning a newly created destination directory is not migration
# permission. Here root performs the one privileged move (this shell into
# the delegated subtree), VERIFIES it took effect, and only then drops to
# the unprivileged user. Every later migration happens strictly within the
# user-owned subtree, where both endpoints are writable by the tests.
#
# usage: sudo run_in_cgroup.sh <cgroup-root> <user> <cmd> [args...]
set -euo pipefail

root="${1:?usage: run_in_cgroup.sh <cgroup-root> <user> <cmd>...}"
user="${2:?}"
shift 2

test "$(id -u)" -eq 0 || { echo "must be invoked via sudo" >&2; exit 1; }
test "$(stat -fc %T "$root")" = cgroup2fs || {
  echo "$root is not a cgroup v2 directory" >&2; exit 1; }

# the single privileged step: move this shell into the delegated subtree
echo $$ > "$root/cgroup.procs"
# POSITIVE CONTROL: verify the move actually took effect before dropping
# privileges — a silent failure here would run the whole layer outside the
# boundary and make the tests meaningless
deadline=$((SECONDS + 10))
until grep -q "$(basename "$root")" "/proc/$$/cgroup"; do
  [ "$SECONDS" -lt "$deadline" ] || {
    echo "process never appeared inside $root (/proc/self/cgroup: $(cat "/proc/$$/cgroup"))" >&2
    exit 1; }
  sleep 0.2
done

exec runuser -u "$user" -- env \
  PATH="$PATH" HOME="$HOME" RUNNER_CGROUP_ROOT="$root" "$@"
