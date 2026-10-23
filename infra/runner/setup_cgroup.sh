#!/bin/bash
# Guest-only boot provisioning. Never delegate the global cgroup ancestor.
set -euo pipefail
uid=$(id -u attacker)
[ "$uid" -ge 1000 ] || { echo "refused: unexpected attacker UID" >&2; exit 1; }
loginctl enable-linger attacker
systemctl start "user@$uid.service"
relative=$(systemctl show "user-$uid.slice" -p ControlGroup --value)
[ "$relative" = "/user.slice/user-$uid.slice" ] || {
    echo "refused: unexpected attacker slice: $relative" >&2; exit 1;
}
parent="/sys/fs/cgroup$relative"
[ "$(stat -fc %T "$parent")" = cgroup2fs ]
d="$parent/sr-runner"
mkdir -p "$d"
# Migration checks BOTH the destination and the common ancestor. Only the
# attacker's own slice is delegated; the root cgroup and other users stay root.
chown attacker:attacker "$parent/cgroup.procs" "$d" \
    "$d/cgroup.procs" "$d/cgroup.subtree_control"
chmod 0700 "$d"
# PAM reads this for each new runner SSH connection. Preserve all other entries.
sed -i '/^RUNNER_CGROUP_ROOT=/d' /etc/environment
printf 'RUNNER_CGROUP_ROOT=%s\n' "$d" >> /etc/environment
