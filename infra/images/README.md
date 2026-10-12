# Image manifests — paired 03+04 plan step 1.
#
# `manifest.json` is the pinned build record: Ubuntu 24.04 LTS (noble)
# cloud-image URL + SHA256, pinned guest package set, per-guest budgets
# (2 vCPU / 2 GiB; disks attacker 16 / web 12 / DB 16 GiB), capture bounds
# (64 MiB spool, 32 MiB cast), and the retained build-input list.
#
# Build discipline:
# - The build phase MAY fetch exactly the pinned base image (URL + SHA256
#   verified before use). The builder refuses a mismatch or an absent
#   checksum file — never proceed on an unverified base image.
# - Practice and negative-path tests run with NO general egress; only narrow
#   synthetic control paths are allowed.
# - Bake ONLY operator public access keys into protected build inputs, never
#   private keys/live tokens. Scrub secrets/logs/spools/host keys/machine IDs
#   from the finished artifact.
# - No runtime package fetching on clones: the template carries everything.
# - QEMU serial-console bootstrap is a test-only trusted transport, not proof
#   of real PVE guest-agent permissions.
#
# Packer is RETIRED: `golden-linux.pkr.hcl` remains in the tree for history
# only and must not be used for release builds. The supported path is
# `infra/images/build.py` from these pinned inputs.
