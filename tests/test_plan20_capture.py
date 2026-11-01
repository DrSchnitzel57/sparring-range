"""Plan 20 timed output capture — chunking, quotas, drain and failure.

Real subprocess streams through the real reader: the capture is fed
what the command really writes. Proven: bounded chunks with an honest
tail, a byte quota with EXACTLY ONE truncated marker and counted
drops, persistence failures counted as gaps without ever breaking the
command or the drain, the separate capture quota independent of the
model-context output bound (large output still drains, result still
bounded), and a cut-off stream recorded as an honest gap, never as
"the program printed nothing".

Review-fix round (findings 2/9/10) additionally pins: ``feed`` NEVER
blocks on a slow, hanging or overflowing persistence path (bounded
queue + one consumer thread + bounded join budget); a lost
acknowledgement can never renumber or poison the sequence (retries
keep seq+content, conflicts are counted, sequences are never reused);
and writes separated by real pauses carry their own observed READ
timestamps while merged bursts honestly declare their precision.
"""
from __future__ import annotations

import threading
import time

import pytest

from srplatform.red_agent.capture import OutputCapture
from srplatform.red_agent.runner import LocalDevRunner
from srplatform.settings import Settings

pytestmark = pytest.mark.containment


def _collect(**kw):
    rows = []

    def emit(seq, kind, text, dropped, read_ts=None):
        rows.append((seq, kind, text, dropped, read_ts))
        return "stored"
    return OutputCapture(emit, **kw), rows


# --- pure capture semantics -------------------------------------------------
def test_chunks_are_bounded_with_honest_tail():
    cap, rows = _collect(chunk_bytes=10, quota_bytes=1000)
    cap.feed(b"a" * 25, at=time.time())
    summary = cap.finish()
    assert [(r[0], r[1], len(r[2])) for r in rows] == [
        (0, "output", 10), (1, "output", 10), (2, "output", 5)]
    assert summary["chunks"] == 3 and summary["bytes_captured"] == 25
    assert summary["complete"] is True and summary["truncated"] is False


def test_quota_closes_capture_with_exactly_one_marker():
    cap, rows = _collect(chunk_bytes=8, quota_bytes=20)
    cap.feed(b"z" * 100, at=time.time())
    cap.feed(b"more", at=time.time())       # past quota: counted only
    summary = cap.finish()
    kinds = [r[1] for r in rows]
    assert kinds.count("truncated") == 1
    stored = sum(len(r[2]) for r in rows if r[1] == "output")
    assert stored == 20                    # quota is exact, never exceeded
    assert summary["truncated"] is True
    # 104 fed, 20 stored → everything else is counted, including the
    # bytes that had been buffered when the quota line split a chunk
    assert summary["dropped_after_quota"] == 104 - 20
    assert summary["complete"] is False    # honest: this capture is partial


def test_persistence_failures_are_counted_never_raised():
    def dead(seq, kind, text, dropped, read_ts=None):
        return "error"
    cap = OutputCapture(dead, chunk_bytes=4, quota_bytes=1000,
                        retries=0)
    cap.feed(b"some output", at=time.time())   # must not raise
    summary = cap.finish(error="stream aborted")
    assert summary["chunks"] == 0
    assert summary["chunks_failed"] >= 2   # data chunks + gap attempt
    assert summary["gaps"] >= 1
    assert summary["complete"] is False


def test_finish_is_idempotent():
    cap, rows = _collect(chunk_bytes=8, quota_bytes=1000)
    cap.feed(b"tail-overflow-", at=time.time())
    s1 = cap.finish()
    s2 = cap.finish(error="again")
    assert s1 == s2
    assert [r for r in rows if r[1] == "gap"] == []  # single honest close


# --- review finding 2: persistence never touches the drain path --------------
def test_feed_never_blocks_and_finish_bails_out_within_budget():
    """A hanging capture endpoint (the reviewer's 1.5 s-delay repro taken
    to the limit): ``feed`` is a pure hand-off and ``finish`` joins with
    an EXPLICIT budget — the stop path proceeds and the summary says,
    truthfully, that persistence did not finish."""
    hang = threading.Event()

    def emit(seq, kind, text, dropped, read_ts=None):
        hang.wait(60)
        return "stored"

    cap = OutputCapture(emit, chunk_bytes=8, quota_bytes=1_000_000,
                        flush_budget_s=0.3, retries=0)
    try:
        t0 = time.monotonic()
        for i in range(50):
            cap.feed(f"chunk{i} ".encode(), at=time.time())
        assert time.monotonic() - t0 < 0.5     # hand-off only, network-free

        t0 = time.monotonic()
        summary = cap.finish()
        waited = time.monotonic() - t0
        assert waited < 2.0                    # BOUNDED join, not the endpoint
        assert summary["persist_budget_exceeded"] is True
        assert summary["complete"] is False
    finally:
        hang.set()


def test_queue_overflow_drops_honestly_without_blocking():
    """Bounded memory beats bounded fidelity: with a wedged consumer the
    queue overflows into counted drops instead of a growing backlog or
    a blocked reader."""
    hang = threading.Event()

    def emit(seq, kind, text, dropped, read_ts=None):
        hang.wait(60)
        return "stored"

    cap = OutputCapture(emit, chunk_bytes=8, quota_bytes=10_000_000,
                        queue_size=2, flush_budget_s=0.2, retries=0)
    try:
        t0 = time.monotonic()
        for i in range(100):
            cap.feed(b"x" * 40, at=time.time())
        assert time.monotonic() - t0 < 0.5
        summary = cap.finish()
        assert summary["queue_dropped_bytes"] > 0
        assert summary["complete"] is False
    finally:
        hang.set()


def test_command_deadline_is_independent_of_a_hung_capture_endpoint():
    """REAL subprocess: a 1-second command deadline must not be stretched
    by a capture endpoint that never answers (the reviewer measured
    3.02 s for a 1 s timeout when the POST blocked the pipe reader)."""
    hang = threading.Event()

    def emit(seq, kind, text, dropped, read_ts=None):
        hang.wait(60)
        return "stored"

    runner = _local_runner()
    cap = OutputCapture(emit, chunk_bytes=64, quota_bytes=10_000,
                        flush_budget_s=0.2, retries=0)
    try:
        t0 = time.monotonic()
        res = runner.run("echo noise; sleep 30", timeout=1,
                         op_id="p20-deadline", output_sink=cap)
        elapsed = time.monotonic() - t0
    finally:
        hang.set()
    assert res.timed_out is True
    # deadline (1s) + bounded join (0.2s) + kill/cessation work — never
    # the endpoint's 60 s hang
    assert elapsed < 4.0, f"deadline stretched by capture: {elapsed:.3f}s"
    assert cap.summary()["persist_budget_exceeded"] is True


# --- review finding 9: ack handling can never poison the sequence -------------
def test_lost_ack_cannot_renumber_or_poison_the_sequence():
    """Server stores chunk #0, the acknowledgement is lost: the retry
    must resend the SAME seq and content (answered ``duplicate``) and
    later chunks must NEVER reuse seq 0 — the reviewer's [0,0,0] byte
    loss is impossible by construction."""
    store: dict[int, str] = {}

    def flaky_emit(seq, kind, text, dropped, read_ts=None):
        if seq in store:
            return "duplicate" if store[seq] == text else "conflict"
        store[seq] = text
        if seq == 0:
            return "error"      # stored, but the ack never arrives
        return "stored"

    cap = OutputCapture(flaky_emit, chunk_bytes=4, quota_bytes=1000,
                        retries=2, retry_backoff_s=0.01)
    cap.feed(b"AAAA", at=1.0)
    cap.feed(b"BBBB", at=2.0)
    cap.feed(b"CCCC", at=3.0)
    summary = cap.finish()
    assert summary["complete"] is True
    assert sorted(store) == [0, 1, 2]
    assert [store[0], store[1], store[2]] == ["AAAA", "BBBB", "CCCC"]


def test_content_conflict_is_a_counted_gap_never_a_rewrite():
    seen = []

    def emit(seq, kind, text, dropped, read_ts=None):
        seen.append((seq, text))
        return "conflict" if seq == 0 else "stored"

    cap = OutputCapture(emit, chunk_bytes=4, quota_bytes=1000, retries=0)
    cap.feed(b"AAbB", at=1.0)
    cap.feed(b"CCCC", at=2.0)
    summary = cap.finish()
    assert summary["chunks_failed"] == 1       # the conflict, counted
    assert summary["complete"] is False
    assert [s for s, _ in seen] == [0, 1]      # seq never reused


def test_server_quota_status_stops_further_output_sends():
    sent = []

    def emit(seq, kind, text, dropped, read_ts=None):
        sent.append((seq, kind))
        return "quota" if kind == "output" else "stored"

    cap = OutputCapture(emit, chunk_bytes=4, quota_bytes=1_000_000, retries=0)
    cap.feed(b"A" * 12, at=1.0)
    summary = cap.finish()
    assert summary["server_quota"] is True and summary["truncated"] is True
    assert summary["complete"] is False
    # only ONE output attempt reaches the server after the quota answer
    assert len([k for _s, k in sent if k == "output"]) == 1


# --- review finding 10: real read times, honest precision --------------------
def test_burst_within_window_merges_and_declares_precision():
    rows = []

    def emit(seq, kind, text, dropped, read_ts=None):
        rows.append((kind, text, read_ts))
        return "stored"

    cap = OutputCapture(emit, chunk_bytes=4096, quota_bytes=1000,
                        merge_window_s=0.25, retries=0)
    t0 = time.time()
    cap.feed(b"alpha ", at=t0)
    cap.feed(b"beta ", at=t0 + 0.05)
    cap.feed(b"gamma", at=t0 + 0.10)
    summary = cap.finish()
    outs = [r for r in rows if r[0] == "output"]
    assert len(outs) == 1 and outs[0][2] == t0   # one merged read window
    assert summary["timing_precision_s"] == 0.25
    assert summary["read_timed"] is True


def test_separated_writes_keep_separate_observed_read_times():
    """REAL subprocess: prints, pauses 1.2 s, prints again. The OLD
    capture merged both writes at one persist time and still claimed
    complete timing; now the rows carry their pipe-read instants and the
    gap between them is visible."""
    rows = []

    def emit(seq, kind, text, dropped, read_ts=None):
        rows.append((kind, text, read_ts))
        return "stored"

    runner = _local_runner()
    cap = OutputCapture(emit, chunk_bytes=4096, quota_bytes=100_000,
                        merge_window_s=0.25, retries=0)
    res = runner.run("echo one; sleep 1.2; echo two", timeout=15,
                     op_id="p20-timesplit", output_sink=cap)
    assert res.exit_code == 0
    outs = [(t, ts) for (k, t, ts) in rows if k == "output"]
    assert len(outs) == 2, f"writes merged despite a 1.2 s pause: {outs!r}"
    first, second = outs[0], outs[1]
    assert "one" in first[0] and "two" in second[0]
    assert first[1] is not None and second[1] is not None
    assert second[1] - first[1] >= 1.0     # REAL separation, not persist time
    assert res.capture["read_timed"] is True
    assert res.capture["timing_precision_s"] == 0.25
    assert res.capture["complete"] is True


# --- real streams through the local-dev runner -------------------------------
def _local_runner(**updates):
    s = Settings(sr_env="dev", runner_transport="local-dev", **updates)
    return LocalDevRunner(s)


def test_runner_feeds_every_byte_independent_of_the_result_bound():
    """A 50 KB command output: the RESULT buffer stays at its hard bound
    (model context), the TIMED CAPTURE keeps the whole stream (its own,
    larger quota) — two consumers, two fences, neither one silently
    shrinking the other."""
    rows = []

    def emit(seq, kind, text, dropped, read_ts=None):
        rows.append((seq, kind, text))
        return "stored"
    runner = _local_runner(runner_max_output_bytes=1000,
                           runner_op_capture_bytes=200_000,
                           runner_output_chunk_bytes=4096)
    cap = OutputCapture(emit, chunk_bytes=4096, quota_bytes=200_000)
    res = runner.run("head -c 50000 /dev/zero | tr '\\0' 'x'",
                     timeout=30, op_id="p20cap-big", output_sink=cap)
    assert res.exit_code == 0, res.output
    assert len(res.output) <= 1000          # model-context bound respected
    captured = sum(len(r[2]) for r in rows if r[1] == "output")
    assert captured >= 49000                # timed capture saw the stream
    assert res.capture["complete"] is True
    assert res.capture["bytes_captured"] >= 49000
    assert res.capture["chunks"] == len(
        [r for r in rows if r[1] == "output"])


def test_runner_capture_quota_truncates_but_facts_stay():
    rows = []

    def emit(seq, kind, text, dropped, read_ts=None):
        rows.append((seq, kind, text))
        return "stored"
    runner = _local_runner(runner_op_capture_bytes=100,
                           runner_output_chunk_bytes=48)
    cap = OutputCapture(emit, chunk_bytes=48, quota_bytes=100)
    res = runner.run("head -c 5000 /dev/zero | tr '\\0' 'y'",
                     timeout=30, op_id="p20cap-quota", output_sink=cap)
    assert res.exit_code == 0
    assert res.capture["truncated"] is True
    assert res.capture["dropped_after_quota"] > 4000
    assert [r for r in rows if r[1] == "truncated"].__len__() == 1
    # the final facts are unaffected by capture truncation:
    assert res.timed_out is False and res.capture is not None


def test_killed_stream_records_an_honest_gap_not_silence():
    rows = []

    def emit(seq, kind, text, dropped, read_ts=None):
        rows.append((seq, kind, text))
        return "stored"
    runner = _local_runner()
    cap = OutputCapture(emit, chunk_bytes=64, quota_bytes=10_000)
    # prints, THEN outlives its deadline — capture must end at the cutoff
    res = runner.run("echo early; sleep 5", timeout=1,
                     op_id="p20cap-timeout", output_sink=cap)
    assert res.timed_out is True
    assert res.capture["gaps"] >= 1          # stream cut off = gap, said so
    assert res.capture["complete"] is False
    assert any("early" in (r[2] or "") for r in rows)
    gap_rows = [r for r in rows if r[1] == "gap"]
    assert gap_rows and "timed out" in gap_rows[-1][2]
