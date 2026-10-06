"""Third-follow-up regressions — Stage 4: crash-safe telemetry spool
(audit T08).

Uses the REAL Spooler (real flock, real files) with injected crashes at the
exact windows the probe exploited: counter truncate/write, record write, and
acknowledgement. Proves: no ID reuse after interruption, new unsent events
survive, torn tails are quarantined BEFORE any append, and physical loss is
counted exactly once.
"""
from __future__ import annotations

import json
import os

import pytest

from telemetry.shipper import Spooler


def _ids(sp: Spooler) -> list[int]:
    return [i for i, _ in sp.pending()]


def test_t08_empty_counter_after_crash_never_reuses_ids(tmp_path):
    """Crash between the counter's truncate and write left the OLD code at
    zero — two events could receive ID 1, and acking the old in-flight ID
    removed the newer unsent event."""
    sp = Spooler(str(tmp_path))
    assert sp.append({"id": "e1"}) == 1
    assert sp.append({"id": "e2"}) == 2

    # simulate the crash the probe injected: counter truncated, never rewritten
    open(sp.seq_path, "w").write("")

    sp2 = Spooler(str(tmp_path))                      # fresh process
    s3 = sp2.append({"id": "e3"})
    assert s3 == 3, f"ID REUSE after lost counter: got {s3} (must recover from spool)"
    assert _ids(sp2) == [1, 2, 3]

    # acking the OLD in-flight id must not consume newer unsent events
    sp2.ack({1})
    assert [e["id"] for _, e in sp2.pending()] == ["e2", "e3"]


def test_t08_garbage_counter_recovers_from_outstanding_ids(tmp_path):
    sp = Spooler(str(tmp_path))
    sp.append({"id": "a"})
    sp.append({"id": "b"})
    with open(sp.seq_path, "w") as f:
        f.write("not-a-number")                       # corrupted counter
    sp2 = Spooler(str(tmp_path))
    assert sp2.append({"id": "c"}) == 3
    assert len(set(_ids(sp2))) == 3


def test_t08_crash_during_counter_update_cannot_duplicate_ids(tmp_path, monkeypatch):
    """The counter update is tmp+rename+fsync: a crash mid-update leaves the
    counter at the PREVIOUS durable value — and since the record append
    happens after, no persisted record can share an ID."""
    sp = Spooler(str(tmp_path))
    assert sp.append({"id": "e1"}) == 1

    real_replace = os.replace

    def crash_replace(a, b, *args, **kw):
        raise OSError("injected crash during counter rename")

    os.replace = crash_replace
    try:
        with pytest.raises(OSError):
            sp.append({"id": "e2"})                    # crash mid seq update
    finally:
        os.replace = real_replace

    sp2 = Spooler(str(tmp_path))                       # restart
    assert sp2.append({"id": "e3"}) == 2               # counter still durable at 1
    ids = _ids(sp2)
    assert len(ids) == len(set(ids)) == 2, ids         # no duplicate IDs ever


def test_t08_crash_after_counter_write_before_record_keeps_ids_unique(tmp_path,
                                                                      monkeypatch):
    """Crash between the durable counter increment and the record append:
    the consumed ID becomes a GAP (never reused), and every unsent record
    survives."""
    sp = Spooler(str(tmp_path))
    sp.append({"id": "e1"})

    real_read = Spooler._read_lines
    boom = {"on": True}

    def crash_after_seq(self):
        if boom["on"]:
            raise OSError("injected crash after seq write, before append")
        return real_read(self)

    Spooler._read_lines = crash_after_seq
    try:
        with pytest.raises(OSError):
            sp.append({"id": "e2"})                    # seq consumed, record lost
    finally:
        Spooler._read_lines = real_read

    sp2 = Spooler(str(tmp_path))
    s = sp2.append({"id": "e3"})
    assert s == 3, "the consumed ID must NOT be reused"
    assert [e["id"] for _, e in sp2.pending()] == ["e1", "e3"]


def test_t08_torn_tail_is_quarantined_before_the_next_append(tmp_path):
    """The probe's reproduction: with an interrupted `{"interrupted":` tail,
    the OLD code JOINED the next valid append onto that physical line — the
    new event existed in the file but never reached the pending queue."""
    sp = Spooler(str(tmp_path))
    sp.append({"id": "e1"})
    with open(sp.path, "a") as f:
        f.write('{"interrupted":')                     # torn tail, no newline

    s2 = sp.append({"id": "e2"})                       # repair must run FIRST
    got = [e["id"] for _, e in sp.pending()]
    assert got == ["e1", "e2"], f"new event joined onto the torn tail: {got}"

    # the fragment is QUARANTINED (recoverable), not silently deleted
    q = (tmp_path / "malformed.ndjson").read_text()
    assert '{"interrupted":' in q

    # physical loss counted EXACTLY ONCE — repeated reads do not re-count
    gaps = (tmp_path / "gaps").read_text()
    assert gaps.count("quarantined-malformed") == 1
    total = sp.dropped
    sp.pending(); sp.pending(); sp.append({"id": "e3"})
    assert sp.dropped == total, "same bad line counted repeatedly"
    assert (tmp_path / "gaps").read_text().count("quarantined-malformed") == 1


def test_t08_malformed_middle_line_counted_once_across_reads(tmp_path):
    sp = Spooler(str(tmp_path))
    sp.append({"id": "g1"})
    with open(sp.path, "a") as f:
        f.write("GARBAGE-NOT-JSON\n")
    sp.append({"id": "g2"})

    assert [e["id"] for _, e in sp.pending()] == ["g1", "g2"]
    first = sp.dropped
    sp.pending(); sp.pending()
    assert sp.dropped == first == 1


def test_t08_unsent_events_survive_crash_between_send_and_ack(tmp_path):
    """Acknowledgement is BY STABLE ID across restarts: events that were
    sent-but-not-acked stay queued, and acking them removes exactly those."""
    sp = Spooler(str(tmp_path))
    sp.append({"id": "s1"})
    sp.append({"id": "s2"})
    batch = sp.pending()

    sp2 = Spooler(str(tmp_path))                       # crash + restart
    assert [i for i, _ in sp2.pending()] == [i for i, _ in batch]
    sp2.ack({batch[0][0]})
    assert [e["id"] for _, e in sp2.pending()] == ["s2"]

    # the spool file stays valid JSON lines throughout
    for line in open(sp2.path):
        if line.strip():
            json.loads(line)
