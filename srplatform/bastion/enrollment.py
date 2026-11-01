"""Account-bound bastion public-key enrollment (plan 22 LIVE-06).

The defender's bastion refused a desktop key that existed and was loaded
into the agent — because the CURRENT browser account simply had no enrolled
key: enrollment lived only in an operator-editable file, with no way to ask
"which accounts can authenticate?" and no supported way to add a public key
for an account. This module is the permanent store next to that file:

* the operator-provisioned ``bastion_authorized_keys_file`` stays the
  commissioning source of truth and is NEVER rewritten here;
* enrolled keys live in one ``user <pubkey>`` file under the STATE
  directory, written atomically by the API only, holding PUBLIC keys only
  (a private-key blob is refused before anything is stored);
* every operation preserves other accounts' entries — enrollment mistakes
  must not evict a working desktop;
* the bastion merges both sources and hot-reloads the enrollment file by
  mtime, so enrollment takes effect on the next authentication with no
  service restart and no privileged signal.

Public-key FINGERPRINTS (``SHA256:...``) are what the API surfaces; the
material is not secret, but the interface keeps it minimal anyway.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import os
import pathlib
import tempfile

_KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
              "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
              "sk-ssh-ed25519@openssh.com",
              "sk-ecdsa-sha2-nistp256@openssh.com")
MAX_KEY_BYTES = 2000


def enrolled_keys_path(settings) -> pathlib.Path | None:
    """The enrollment path the API and the bastion each derive from THEIR
    OWN settings. On an installed appliance BOTH service environments
    render the same explicit ``SR_BASTION_ENROLLED_KEYS_FILE`` — that
    render is the writer/reader contract (plan 22 review: the state-tree
    fallback below is shared only when the state file itself is shared,
    and the API's controller subtree is deliberately untraversable by the
    bastion, so an installed system MUST carry the explicit path). The
    beside-the-state fallback remains for dev/fixture single-process use.
    Returns None only when NEITHER knob exists (synthetic settings):
    enrollment is then simply off, never a crash for a bystander."""
    s = str(getattr(settings, "bastion_enrolled_keys_file", "") or "")
    if s:
        return pathlib.Path(s)
    state = str(getattr(settings, "safety_state_file", "") or "")
    if not state:
        return None
    return pathlib.Path(state).parent / "bastion" / "enrolled_keys"


def fingerprint(key_line: str) -> str:
    blob = key_line.split(" ")[1].strip()
    raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(raw).digest()).decode().rstrip("=")


def validate_public_key(text: str) -> str:
    """Return the canonical single line, or raise ValueError. Public keys
    ONLY: the private-key marker is refused loudly, an empty or multi-key
    paste never half-succeeds, and the key must be importable."""
    if "PRIVATE KEY" in text.upper():
        raise ValueError("that is a PRIVATE key — only the public half is "
                         "ever enrolled or transmitted")
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if len(lines) != 1:
        raise ValueError("expected exactly one public-key line")
    line = lines[0]
    if len(line) > MAX_KEY_BYTES:
        raise ValueError(f"public key line exceeds {MAX_KEY_BYTES} bytes")
    fields = line.split(" ")
    if len(fields) < 2 or fields[0] not in _KEY_TYPES:
        raise ValueError("not an OpenSSH public key line "
                         "(ssh-ed25519/ssh-rsa/ecdsa-… <base64> [comment])")
    try:
        raw = base64.b64decode(fields[1] + "=" * (-len(fields[1]) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("key body is not valid base64") from exc
    if len(raw) < 32:
        raise ValueError("key body too short to be real")
    try:
        import asyncssh
        asyncssh.import_public_key(line)
    except Exception as exc:  # noqa: BLE001 — asyncssh raises several types
        raise ValueError(f"key rejected by the SSH layer: {exc}") from exc
    return line


def parse(path: pathlib.Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        user, _, key = line.partition(" ")
        if key.strip():
            out.setdefault(user, []).append(key.strip())
    return out


def _write(path: pathlib.Path, users: dict[str, list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "# account-bound bastion public-key enrollment (API-managed; " \
           "public keys only)\n"
    for user in sorted(users):
        for key in users[user]:
            body += f"{user} {key}\n"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".enrolled-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)     # PUBLIC keys; the bastion identity reads it
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def _locked(path: pathlib.Path):
    """Serialize read-modify-write ACROSS PROCESSES (plan 22 review): the
    atomic REPLACE protects readers, but two writers that read the same
    base silently lose one update. The lock is taken on a STABLE sidecar
    file — never on the enrollment inode itself, which os.replace swaps —
    so an exclusive holder is honoured for the whole parse-write-replace
    window. Only public keys ever live in the directory, so a 0644 lock
    file leaks nothing."""
    lock = path.with_name(path.name + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)          # closing the descriptor releases the lock


def enroll(path: pathlib.Path, username: str, public_key: str
           ) -> tuple[bool, list[str]]:
    """Idempotent: an already-enrolled identical key changes nothing.
    Returns (created, fingerprints-of-account). Concurrent enrollments for
    OTHER accounts both persist — a lost update here once evicted a working
    desktop's key."""
    key = validate_public_key(public_key)
    with _locked(path):
        users = parse(path)
        entries = users.get(username, [])
        created = key not in entries
        if created:
            entries = entries + [key]
            users[username] = entries
            _write(path, users)
    return created, [fingerprint(k) for k in users[username]]


def revoke(path: pathlib.Path, username: str, want_fp: str) -> bool:
    with _locked(path):
        users = parse(path)
        entries = users.get(username, [])
        keep = [k for k in entries if fingerprint(k) != want_fp]
        if len(keep) == len(entries):
            return False
        if keep:
            users[username] = keep
        else:
            users.pop(username, None)
        _write(path, users)
    return True


def status(path: pathlib.Path) -> dict[str, list[str]]:
    return {u: [fingerprint(k) for k in ks]
            for u, ks in sorted(parse(path).items())}


def has_any(path: pathlib.Path, username: str) -> bool:
    return bool(parse(path).get(username))
