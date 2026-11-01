"""One bounded SSH channel policy for every non-interactive management call.

Live practice 2026-10-23: a diagnostic command against a wedged guest (TCP
established, daemon stuck) hung the caller forever — OpenSSH sends no
keepalives by default, so a black-holed connection never errors, and an
inherited stdin lets a remote shell block on input that will never arrive.
Every platform-initiated ssh call therefore carries BOTH bounds:

* ``ServerAliveInterval``/``ServerAliveCountMax`` — a dead peer is detected
  in seconds and ssh exits with 255 (the verifier maps that to `unknown`,
  never to a pass);
* ``stdin=DEVNULL`` — nothing can wait on input (callers pass this to
  subprocess alongside these options; see ``DEVNULL_STDIN``).

The outer per-call timeout stays in force as well: keepalives bound the
*connection*, the timeout bounds the *command*.
"""
from __future__ import annotations

#: spliced into every platform ssh command line
SSH_ALIVE_OPTS: list[str] = [
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=3",
]
