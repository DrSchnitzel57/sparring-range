"""Plan 22 LIVE-01 (unit half): the POSIX ACL codec and merge logic.

The kernel enforces these bytes; here we prove the ENCODER, the ORDER the
kernel demands, the MERGE that preserves foreign entries, and the fail-closed
verifier. The real DAC decisions across UIDs are exercised in the practice
gate fixture (tests/test_plan22_key_access_dac.py), not mocked away here.
"""
from __future__ import annotations

import errno
import struct

import pytest

from deploy.posixacl import (AclError, _GROUP, _GROUP_OBJ, _MASK, _OTHER,
                             _USER, _USER_OBJ, base_from_mode, canonical,
                             decode, desired_entries, encode,
                             ensure_named_read_access, verify_named_access)

U_OBJ, U, G_OBJ, G, M, O = _USER_OBJ, _USER, _GROUP_OBJ, _GROUP, _MASK, _OTHER


def base_acl(user=0o7, group=0o0, other=0o0):
    """What a plain `chmod 700`/`600` file has: the three base entries."""
    return [(U_OBJ, user, 0xFFFFFFFF), (G_OBJ, group, 0xFFFFFFFF),
            (O, other, 0xFFFFFFFF)]


# ------------------------------------------------------------------ codec -- #
def test_round_trip_matches_the_kernel_xattr_layout():
    entries = canonical(base_acl() + [(U, 0o4, 4242), (M, 0o4, 0xFFFFFFFF)])
    blob = encode(entries)
    assert struct.unpack("<I", blob[:4])[0] == 2
    assert len(blob) == 4 + 8 * len(entries)
    assert decode(blob) == entries


def test_decode_refuses_garbage():
    with pytest.raises(AclError):
        decode(b"\x02\x00\x00\x00\x01\x02")           # ragged length
    with pytest.raises(AclError):
        decode(struct.pack("<I", 1) + b"\x00" * 8)    # wrong version


# ---------------------------------------------------------------- ordering -- #
def test_canonical_order_is_the_strict_kernel_order():
    entries = canonical([(O, 0, 0xFFFFFFFF), (M, 0o4, 0xFFFFFFFF),
                         (U, 0o1, 9), (G_OBJ, 0, 0xFFFFFFFF), (U, 0o4, 1),
                         (U_OBJ, 0o6, 0xFFFFFFFF)])
    tags = [t for t, _, _ in entries]
    assert tags == [U_OBJ, U, U, G_OBJ, M, O]
    user_ids = [i for t, _, i in entries if t == U]
    assert user_ids == sorted(user_ids)
    assert entries[-1][0] == O                        # exactly one, last


def t_ok(t):
    return True


def test_canonical_refuses_malformed_sets():
    with pytest.raises(AclError):
        canonical([(U_OBJ, 0o6, 0xFFFFFFFF), (U, 0o4, 1)])       # no OTHER
    with pytest.raises(AclError):
        canonical([(U_OBJ, 0o6, 0xFFFFFFFF), (U_OBJ, 0o4, 0xFFFFFFFF),
                   (G_OBJ, 0, 0xFFFFFFFF), (O, 0, 0xFFFFFFFF)])  # dup obj


# ------------------------------------------------------------------ merge -- #
def test_merge_adds_the_grant_and_recomputes_the_mask():
    got = desired_entries(base_acl(user=0o6), named_users={1001: 0o4})
    by = {(t, i): p for t, p, i in got}
    assert by[(U, 1001)] == 0o4
    assert by[(M, 0xFFFFFFFF)] == 0o4                 # union over named+group
    assert by[(G_OBJ, 0xFFFFFFFF)] == 0o0             # owning group untouched
    assert by[(U_OBJ, 0xFFFFFFFF)] == 0o6             # owner untouched


def test_merge_preserves_foreign_entries_and_updates_only_our_uid():
    current = canonical(base_acl() + [(U, 0o5, 777), (G, 0o4, 55),
                                      (M, 0o5, 0xFFFFFFFF)])
    got = desired_entries(current, named_users={1001: 0o4})
    by = {(t, i): p for t, p, i in got}
    assert by[(U, 777)] == 0o5                        # operator's own grant
    assert by[(G, 55)] == 0o4                         # foreign group kept
    assert by[(U, 1001)] == 0o4
    assert by[(M, 0xFFFFFFFF)] == 0o5 | 0o4           # never shrinks
    # idempotent: re-merging the result changes nothing
    assert canonical(desired_entries(got, named_users={1001: 0o4})) == \
        canonical(got)


# -------------------------------------------------- injectable xattr glue -- #
class FakeXattr:
    def __init__(self, store=None, fail_set=()):
        self.store = store or {}
        self.fail_set = fail_set

    def get(self, path, name, *, follow_symlinks=True):
        if name != "system.posix_acl_access" or path not in self.store:
            raise OSError(errno.ENODATA, "no data")
        return self.store[path]

    def set(self, path, name, value, *, follow_symlinks=True):
        if path in self.fail_set:
            raise OSError(errno.EOPNOTSUPP, "operation not supported")
        self.store[path] = value

    def decode(self, path):
        return decode(self.store[path])


def test_ensure_grants_verifies_and_is_idempotent(tmp_path):
    d = tmp_path / "secrets"
    f = d / "model.key"
    d.mkdir()
    f.write_bytes(b"SECRET\n")
    d.chmod(0o750)                     # the production secrets-directory mode
    f.chmod(0o600)                     # the operator's credential mode
    fx = FakeXattr()
    first = ensure_named_read_access(d, f, uid=1001,
                                     getxattr=fx.get, setxattr=fx.set)
    assert first["directory"]["granted"] == "1" and first["file"]["granted"] == "4"
    assert fx.decode(str(f)) == canonical(desired_entries(
        base_from_mode(0o600), named_users={1001: 0o4}))
    assert fx.decode(str(d)) == canonical(desired_entries(
        base_from_mode(0o750), named_users={1001: 0o1}))
    again = ensure_named_read_access(d, f, uid=1001,
                                     getxattr=fx.get, setxattr=fx.set)
    assert again == first
    assert f.read_bytes() == b"SECRET\n"               # bytes never touched


def test_ensure_fails_closed_when_the_filesystem_refuses(tmp_path):
    d = tmp_path / "secrets"
    f = d / "model.key"
    d.mkdir()
    f.write_bytes(b"SECRET\n")
    fx = FakeXattr(fail_set={str(f)})
    with pytest.raises(AclError, match="POSIX ACLs"):
        ensure_named_read_access(d, f, uid=1001,
                                 getxattr=fx.get, setxattr=fx.set)
    # a refused write leaves NO half state pretending to be a grant
    assert verify_named_access(f, {1001: 0o4}, getxattr=fx.get)["ok"] is False


def test_verify_reports_the_missing_grant(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir()
    fx = FakeXattr({str(d): encode(base_acl(user=0o7))})
    check = verify_named_access(d, {1001: 0o1}, getxattr=fx.get)
    assert check["ok"] is False and 1001 in check["missing"]
