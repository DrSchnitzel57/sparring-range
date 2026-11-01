"""plan 19 review ROUND 4 — fence reconciliation for pre-0023 chains.

Migration 0023 added the durable cancellation fence (``cancel_intent``)
and the chain identity (``chain_root``), but it could only set intent
to FALSE on rows that already existed — the defect it guards against
had, in older releases, ALREADY produced its escaped state: a
``cancelled`` logical root with a live ``queued`` retry child (or
grandchild). After 0023 that child still carries no intent, its own
flags are clean, and admission happily dispatches the attempt of a
request its root cancelled. Upgrading must not revive a cancelled
engagement.

This migration reconciles exactly that, as data (no schema change —
hence applied 0020..0023 stay byte-unchanged and this is pure
forward):

* every row whose logical chain contains a CANCELLED row is stamped
  with the durable cancellation intent, so no future writer can treat
  it as unfenced;
* ``queued`` rows in such a chain become ``cancelled`` with an honest
  reconciliation note — the logical request WAS cancelled;
* ``running`` / ``cessation_unknown`` rows KEEP their state: an
  uncertain cessation is an obligation, not a success, and the slot
  stays held for the operator regardless of the fence.

An ordinary FAILED parent with a queued retry child is deliberately
untouched: a failed attempt is not a cancelled logical request, and
its bounded retry must survive the upgrade. Cancelled rows only ever
came from the chain-wide cancellation protocol (or the one-row
deadline-at-admission shape), so "chain contains a cancelled row"
means exactly "this logical request was cancelled".

``downgrade`` cannot and does not attempt to un-reconcile: erasing the
fence would RE-ARM the escaped dispatch this migration closes, and a
cancellation intent is a historical fact, not a reversible setting.
"""
from __future__ import annotations

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

_FENCED_CHAINS = (
    "SELECT chain_root FROM model_jobs "
    "WHERE state = 'cancelled' AND chain_root IS NOT NULL"
)


def upgrade() -> None:
    op.execute(
        "UPDATE model_jobs SET cancel_intent = true "
        f"WHERE chain_root IN ({_FENCED_CHAINS}) "
        "AND cancel_intent = false")
    op.execute(
        "UPDATE model_jobs SET state = 'cancelled', "
        "error = 'cancelled with its logical request (fence "
        "reconciliation: this chain contains a cancelled row; upgrade "
        "repair from pre-0023 state)', finished_at = now() "
        "WHERE state = 'queued' "
        f"AND chain_root IN ({_FENCED_CHAINS})")


def downgrade() -> None:
    # Deliberately a no-op. The reconciliation records what the
    # cancellation protocol had already decided; "undoing" it would
    # hand a cancelled logical request back a dispatchable attempt —
    # the exact defect this migration closes. Schema is unchanged, so
    # the chain simply stays consistent with its history.
    pass
