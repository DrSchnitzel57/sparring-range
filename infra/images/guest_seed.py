#!/usr/bin/env python3
"""NoCloud seed-ISO builder for isolated Ubuntu-guest gates (03+04 rework).

Builds a CIDATA-labeled ISO carrying exactly two files (`user-data`,
`meta-data`) from local inputs — no network, no root, pure Python
(`pycdlib`). The ISO is attached as a cdrom alongside the run-owned guest
disk; cloud-init's NoCloud datasource consumes it on first boot with a fresh
`instance-id`. Per-boot identity (hostname, checks, serial markers) is baked
per run — never a live secret.

The guest reports exclusively over the serial console (`/dev/ttyS0`, mapped
by QEMU to a run-owned log): lines of the form `SR-GUEST-<check>-PASS` or
`SR-GUEST-<check>-FAIL:<reason>`, terminated by `SR-GUEST-DONE rc=<n>` before
`poweroff`. The host asserts on those bytes — never on a mocked callback.
"""
from __future__ import annotations

import io
import pathlib
import uuid

import pycdlib


def build_seed_iso(path: pathlib.Path, user_data: str, meta_data: str,
                   network_config: str | None = None) -> pathlib.Path:
    """Write a CIDATA seed ISO. ISO9660 names are d1-charset (A-Z/0-9/_), so
    Rock Ridge carries the lowercase `user-data`/`meta-data` names cloud-init
    expects; the volume label is CIDATA either way."""
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, sys_ident="LINUX", vol_ident="CIDATA",
            vol_set_ident="CIDATA", rock_ridge="1.09")
    files = [("USERDATA", "user-data", user_data),
             ("METADATA", "meta-data", meta_data)]
    if network_config is not None:
        # NoCloud's network-config is consumed by cloud-init's network stage,
        # BEFORE systemd-networkd-wait-online.  Writing netplan only from
        # write_files/runcmd delays DHCP until after that wait and can add
        # minutes to every first boot (and make QGA/SSH appear "never ready").
        files.append(("NETCFG", "network-config", network_config))
    for iso_name, rr_name, text in files:
        data = text.encode("utf-8")
        iso.add_fp(io.BytesIO(data), len(data), f"/{iso_name}.;1",
                   rr_name=rr_name)
    iso.write_fp(open(path, "wb"))
    iso.close()
    return path


def meta_data(instance_id: str, hostname: str) -> str:
    return (f"instance-id: {instance_id}\n"
            f"local-hostname: {hostname}\n")


def fresh_instance_id(role: str) -> str:
    return f"sr-{role}-{uuid.uuid4().hex[:8]}"
