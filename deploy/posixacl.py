"""Minimal POSIX ACL codec and provisioning helper (plan 22 LIVE-01).

The appliance must let ONE named identity (the API service user) traverse
the root-owned secrets directory and read exactly one credential — without
rotating the operator's secret, widening the file mode, changing the file's
group, or granting a whole service group. That is a named POSIX ACL entry,
nothing else.

``setfacl`` is not guaranteed on a minimal appliance (this repository's own
test container lacks the binary), so entries are encoded directly into the
``system.posix_acl_access`` extended attribute in the on-disk kernel format
(``<le32 version 2>`` followed by ``<u16 tag, u16 perm, u32 id>`` entries in
canonical order). Encoding and merging are pure functions so the risky part
is unit-testable without privileges; everything fails CLOSED: an absent
filesystem ACL feature, an unparsable existing ACL, or a refusal to store
the attribute raises rather than silently leaving the API unable to start.

The only production entry point is :func:`ensure_named_read_access`, called
while root from ``apply`` and from upgrade provisioning. It is idempotent
(re-running with the same grants rewrites identical bytes) and never touches
file ownership, mode bits outside the ACL mask, or the secret bytes.
"""
from __future__ import annotations

import errno
import os
import pathlib
import struct

XATTR_NAME = "system.posix_acl_access"
_VERSION = 2
# Linux reports a missing xattr as ENODATA; ENOATTR is the portable alias.
_MISSING_XATTR = {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}

# xattr tags (linux/posix_acl_xattr.h)
_USER_OBJ, _USER, _GROUP_OBJ, _GROUP, _MASK, _OTHER = 1, 2, 4, 8, 16, 32
# e_id for entries with no identity
_UNDEFINED = 0xFFFFFFFF


class AclError(RuntimeError):
    """Any ACL operation that could not be proven — never guess."""


def encode(entries: list[tuple[int, int, int]]) -> bytes:
    """Serialise (tag, perm, id) triples into the xattr format."""
    body = struct.pack("<I", _VERSION)
    for tag, perm, ident in entries:
        body += struct.pack("<HHI", tag, perm, ident)
    return body


def decode(blob: bytes) -> list[tuple[int, int, int]]:
    if len(blob) < 4 or (len(blob) - 4) % 8:
        raise AclError("posix ACL blob has an unexpected length")
    if struct.unpack("<I", blob[:4])[0] != _VERSION:
        raise AclError("unsupported posix ACL version")
    out = []
    for off in range(4, len(blob), 8):
        tag, perm, ident = struct.unpack("<HHI", blob[off:off + 8])
        out.append((tag, perm, ident))
    return out


def canonical(entries: list[tuple[int, int, int]]
              ) -> list[tuple[int, int, int]]:
    """Sort into the strict order the kernel requires.

    The kernel rejects (EINVAL) any blob whose entries are not ordered
    USER_OBJ, named USERS ascending, GROUP_OBJ, named GROUPS ascending,
    MASK?, OTHER — building canonically is cheaper than debugging a
    refusal on a live appliance.
    """
    by_tag: dict[int, list[tuple[int, int, int]]] = {}
    for tag, perm, ident in entries:
        by_tag.setdefault(tag, []).append((tag, perm, ident))
    unknown = set(by_tag) - {_USER_OBJ, _USER, _GROUP_OBJ, _GROUP, _MASK,
                             _OTHER}
    if unknown:
        raise AclError(f"unknown ACL tags: {sorted(unknown)}")
    for tag in (_USER_OBJ, _GROUP_OBJ, _MASK, _OTHER):
        if len(by_tag.get(tag, [])) > 1:
            raise AclError(f"ACL has more than one entry for tag {tag}")
    for required in (_USER_OBJ, _GROUP_OBJ, _OTHER):
        if required not in by_tag:
            raise AclError(f"ACL is missing required tag {required}")
    out = [by_tag[_USER_OBJ][0]]
    out += sorted(by_tag.get(_USER, []), key=lambda e: e[2])
    out.append(by_tag[_GROUP_OBJ][0])
    out += sorted(by_tag.get(_GROUP, []), key=lambda e: e[2])
    if _MASK in by_tag:
        out.append(by_tag[_MASK][0])
    out.append(by_tag[_OTHER][0])
    return out


def desired_entries(current: list[tuple[int, int, int]], *,
                    named_users: dict[int, int]) -> list[tuple[int, int, int]]:
    """Merge the wanted named-user grants into the decoded current ACL.

    Only USER entries with ids in ``named_users`` are added or updated;
    every other entry — including foreign named users and groups an
    operator added by hand — is preserved untouched. The mask is recomputed
    as the union of everything the named entries and the owning group may
    grant (setfacl's rule), so grants never silently shrink.
    """
    out: list[tuple[int, int, int]] = []
    for tag, perm, ident in current:
        if tag == _USER and ident in named_users:
            continue
        if tag == _MASK:
            continue           # recomputed below
        out.append((tag, perm, ident))
    out += [(_USER, perm, uid) for uid, perm in named_users.items()]
    named = [e for e in out if e[0] in (_USER, _GROUP)]
    if named:
        mask = 0
        for _, perm, _ in named:
            mask |= perm
        group_obj = next(p for t, p, _ in out if t == _GROUP_OBJ)
        mask |= group_obj
        out.append((_MASK, mask & 0o7, _UNDEFINED))
    return canonical(out)


def base_from_mode(mode: int) -> list[tuple[int, int, int]]:
    """The ACL the kernel derives for a file WITHOUT the xattr: exactly the
    three mode bits (setfacl shows the same as no-ACL)."""
    return [(_USER_OBJ, (mode >> 6) & 0o7, _UNDEFINED),
            (_GROUP_OBJ, (mode >> 3) & 0o7, _UNDEFINED),
            (_OTHER, mode & 0o7, _UNDEFINED)]


def get_acl(path: pathlib.Path, *,
            getxattr=os.getxattr,
            stat=os.stat) -> list[tuple[int, int, int]]:
    """The effective ACL: the stored one, or the mode-derived base."""
    try:
        blob = getxattr(str(path), XATTR_NAME, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in _MISSING_XATTR:
            return base_from_mode(stat(str(path)).st_mode & 0o777)
        raise AclError(f"cannot read the ACL of {path}: {exc}") from exc
    return decode(blob)


def set_acl(path: pathlib.Path, entries: list[tuple[int, int, int]], *,
            setxattr=os.setxattr) -> None:
    try:
        setxattr(str(path), XATTR_NAME, encode(canonical(entries)),
                 follow_symlinks=False)
    except OSError as exc:
        raise AclError(
            f"cannot set the ACL of {path}: {exc} — the filesystem must "
            "support POSIX ACLs (ZFS: posixacl feature); refusing to "
            "continue with an unverifiable credential grant") from exc


def verify_named_access(
        path: pathlib.Path, named_users: dict[int, int], *,
        getxattr=os.getxattr) -> dict:
    """Report (never mutate) whether the wanted grants are in effect."""
    try:
        current = get_acl(path, getxattr=getxattr)
    except AclError as exc:
        return {"path": str(path), "ok": False, "problem": str(exc)}
    by_tag = {(t, i): p for t, p, i in current}
    missing = {uid: f"want {perm:o}, have "
                    f"{by_tag.get((_USER, uid), None) and format(by_tag[(_USER, uid)], 'o') or 'none'}"
               for uid, perm in named_users.items()
               if by_tag.get((_USER, uid), 0) & perm != perm}
    return {"path": str(path), "ok": not missing,
            **({"missing": missing} if missing else {})}


def ensure_named_read_access(
        directory: pathlib.Path, file: pathlib.Path, *,
        uid: int, dir_perm: int = 0o1, file_perm: int = 0o4,
        getxattr=os.getxattr, setxattr=os.setxattr) -> dict:
    """Provision: ``uid`` may traverse ``directory`` and read ``file``.

    root ownership and the secret bytes are never touched; the file keeps
    its 0600-style owner-only mode (the visible group bits are the ACL
    mask, which grants nothing to the owning group). Idempotent: rewriting
    identical entries is a no-op at the byte level. Raises
    :class:`AclError` if anything cannot be proven — the caller fails the
    provisioning stage rather than leaving the API facing a 500 readiness.
    """
    actions: dict = {"uid": uid, "mode": "named-posix-acl"}
    for target, perm, label in ((directory, dir_perm, "directory"),
                                (file, file_perm, "file")):
        target = pathlib.Path(target)
        if not target.exists():
            raise AclError(f"{label} {target} does not exist")
        current = get_acl(target, getxattr=getxattr)
        entries = desired_entries(current, named_users={uid: perm})
        set_acl(target, entries, setxattr=setxattr)
        check = verify_named_access(target, {uid: perm},
                                    getxattr=getxattr)
        if not check["ok"]:
            raise AclError(f"{label} {target}: ACL grant not in effect: "
                           f"{check}")
        actions[label] = {"path": str(target),
                          "granted": format(perm, "o")}
    return actions
