"""Plan 20 timed output capture — chunking, quotas, drain and failure.

Real subprocess streams through the real reader: the capture is fed
what the command really writes. Proven: bounded chunks with an honest
tail, a byte quota with EXACTLY ONE truncated marker and counted
drops, persistence failures counted as gaps without ever breaking the
command or the drain, the separate capture quota independent of the
model-context output bound (large output still drains, result still
bounded), and a cut-off stream recorded as an honest gap, never as
"the program printed nothing"."""
from __future__ import annotations

import pytest

from srplatform.red_agent.capture import OutputCapture
from srplatform.red_agent.runner import LocalDevRunner
from srplatform.settings import Settings

pytestmark = pytest.mark.containment


def _collect(**kw):
    rows = []

    def emit(seq, kind, text, dropped):
        rows.append((seq, kind, text, dropped))
        return True
    return OutputCapture(emit, **kw), rows


# --- pure capture semantics -------------------------------------------------
def test_chunks_are_bounded_with_honest_tail():
    cap, rows = _collect(chunk_bytes=10, quota_bytes=1000)
    cap.feed(b"a" * 25)
    summary = cap.finish()
    assert [(r[0], r[1], len(r[2])) for r in rows] == [
        (0, "output", 10), (1, "output", 10), (2, "output", 5)]
    assert summary["chunks"] == 3 and summary["bytes_captured"] == 25
    assert summary["complete"] is True and summary["truncated"] is False


def test_quota_closes_capture_with_exactly_one_marker():
    cap, rows = _collect(chunk_bytes=8, quota_bytes=20)
    cap.feed(b"z" * 100)
    cap.feed(b"more")                     # past quota: counted only
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
    def dead(seq, kind, text, dropped):
        return False
    cap = OutputCapture(dead, chunk_bytes=4, quota_bytes=1000)
    cap.feed(b"some output")               # must not raise
    summary = cap.finish(error="stream aborted")
    assert summary["chunks"] == 0
    assert summary["chunks_failed"] >= 2   # data chunks + gap attempt
    assert summary["gaps"] >= 1
    assert summary["complete"] is False


def test_finish_is_idempotent():
    cap, rows = _collect(chunk_bytes=8, quota_bytes=1000)
    cap.feed(b"tail-overflow-")
    s1 = cap.finish()
    s2 = cap.finish(error="again")
    assert s1 == s2
    assert [r for r in rows if r[1] == "gap"] == []  # single honest close


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

    def emit(seq, kind, text, dropped):
        rows.append((seq, kind, text))
        return True
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

    def emit(seq, kind, text, dropped):
        rows.append((seq, kind, text))
        return True
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

    def emit(seq, kind, text, dropped):
        rows.append((seq, kind, text))
        return True
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
