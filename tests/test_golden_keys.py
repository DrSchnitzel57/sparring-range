"""Golden-image key installation: ownership comes from the image, not a guess.

The gate that failed live (2026-11-04) was an injected `authorized_keys`
chowned to a hardcoded 1000:1000 while `sr` was 1001; sshd StrictModes
refused it for every key. These tests hold the rule that fixes it: the uid
is read from /etc/passwd, merging is idempotent, and an audit reports a
wrong owner instead of trusting the file's presence.
"""
from __future__ import annotations

import pathlib

import pytest

from infra.images.golden_keys import check_image_root, install_keys, \
    merge_keys, passwd_ids

KEY_A = "ssh-ed25519 AAAABASTION bastion@appliance"
KEY_B = "ssh-ed25519 AAAARUNNER runner@appliance"
PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
          "sr:x:1001:1001::/home/sr:/bin/bash\n")


def _root(tmp_path, passwd=PASSWD):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/passwd").write_text(passwd)
    return root


def test_the_uid_comes_from_the_images_own_passwd_not_a_guess():
    """ubuntu=1000, sr=1001: the injected file must belong to 1001 or sshd
    refuses it for every key."""
    assert passwd_ids(PASSWD, "sr") == (1001, 1001)
    assert passwd_ids(PASSWD, "ubuntu") == (1000, 1000)


def test_a_missing_account_is_an_error_not_a_default():
    with pytest.raises(KeyError, match="no 'sr' account"):
        passwd_ids(PASSWD, "sr") if "sr:" not in PASSWD else passwd_ids(
            "root:x:0:0::/:/bin/sh\n", "sr")


def test_merge_is_line_compared_and_idempotent():
    merged = merge_keys(f"{KEY_A}\n", [KEY_A, KEY_B])
    assert merged.splitlines() == [KEY_A, KEY_B]
    assert merge_keys(merged, [KEY_A, KEY_B]) == merged
    assert merge_keys("", []) == ""


def test_install_creates_the_file_with_the_OWNER_uid(tmp_path):
    root = _root(tmp_path)
    chowned = []
    result = install_keys(root, [KEY_A, KEY_B],
                          chown=lambda p, u, g: chowned.append((pathlib.Path(p).name, u, g)))
    assert result["uid"] == 1001 and result["gid"] == 1001
    assert result["added"] == 2 and result["keys"] == 2
    target = root / "home/sr/.ssh/authorized_keys"
    assert target.read_text().splitlines() == [KEY_A, KEY_B]
    assert target.stat().st_mode & 0o777 == 0o600
    assert (root / "home/sr/.ssh").stat().st_mode & 0o777 == 0o700
    owners = {name: (u, g) for name, u, g in chowned}
    assert owners[".ssh"] == (1001, 1001)
    assert owners["authorized_keys"] == (1001, 1001)
    assert owners["sr"] == (1001, 1001)


def test_reinstall_adds_only_the_new_key(tmp_path):
    root = _root(tmp_path)
    install_keys(root, [KEY_A], chown=lambda *a: None)
    again = install_keys(root, [KEY_A, KEY_B], chown=lambda *a: None)
    assert again["added"] == 1 and again["keys"] == 2


@pytest.mark.skipif(__import__("os").getuid() != 0,
                    reason="chown to a foreign uid needs root")
def test_audit_catches_the_live_failure_wrong_owner(tmp_path):
    """Reproduce the exact live defect: the right keys, owned by 1000."""
    import os

    root = _root(tmp_path)
    install_keys(root, [KEY_A], chown=lambda p, u, g: os.chown(p, u, g))
    os.chown(root / "home/sr/.ssh/authorized_keys", 1000, 1000)
    audit = check_image_root(root, [KEY_A])
    assert audit["ok"] is False
    assert any("StrictModes" in p for p in audit["problems"])


def test_audit_reports_a_missing_key(tmp_path):
    root = _root(tmp_path)
    install_keys(root, [KEY_A], chown=lambda *a: None)
    audit = check_image_root(root, [KEY_A, KEY_B])
    assert audit["ok"] is False
    assert any("missing key" in p for p in audit["problems"])


def test_audit_flags_group_readable_keys(tmp_path):
    root = _root(tmp_path)
    install_keys(root, [KEY_A], chown=lambda *a: None)
    (root / "home/sr/.ssh/authorized_keys").chmod(0o644)
    audit = check_image_root(root, [KEY_A])
    assert audit["ok"] is False
    assert any("group/world readable" in p for p in audit["problems"])
