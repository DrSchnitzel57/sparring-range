"""Plan 22 LIVE-02: a successful retry must not present the stale stage
error as a current failure, while the failure evidence itself is retained.

Reproduced defect (installed upgrade 2026-10-29): after the readiness-500
failure, the resumed attempt completed and `journal.load()` reported the
restart stage as `status: done` WITH A NEW TIME — but the dict still
carried the previous `error`, so recovery diagnostics read a finished
upgrade as an unresolved failure (docs/FINDINGS_CHECKLIST.md LIVE-02).
"""
from __future__ import annotations

import deploy.upgrade as up


def _journal(tmp_path):
    return up.Journal(tmp_path / "etc")


def test_resume_moves_the_stale_error_to_prior_history(tmp_path):
    j = _journal(tmp_path)
    attempt = j.create(meta={"release": "x"})
    j.mark(attempt, "restart", "started")
    j.mark(attempt, "restart", "failed", error="readiness returned HTTP 500")
    # resume re-runs the unfinished stage and succeeds
    j.mark(attempt, "restart", "started")
    data = j.mark(attempt, "restart", "done", units="6")

    stage = data["stages"]["restart"]
    assert stage["status"] == "done"
    assert "error" not in stage, (
        "the completed stage entry must not present the historical error "
        "as a current failure")
    assert stage.get("units") == "6"
    # the failure evidence is retained, never deleted
    prior = [p for p in stage.get("prior", []) if p.get("status") == "failed"]
    assert prior, "the failed attempt must remain visible as history"
    assert "HTTP 500" in prior[-1]["error"]


def test_single_pass_stage_has_no_invented_history(tmp_path):
    j = _journal(tmp_path)
    attempt = j.create(meta={"release": "x"})
    j.mark(attempt, "backup", "started")
    stage = j.mark(attempt, "backup", "done", files=3)["stages"]["backup"]
    assert stage["status"] == "done" and stage["files"] == 3
    assert "prior" not in stage, (
        "a stage that never failed gets no invented history")


def test_interrupted_start_is_also_recorded_as_history(tmp_path):
    # A SIGKILL between the start mark and any outcome is still evidence:
    # resume must show the interrupted start as prior, not hide it.
    j = _journal(tmp_path)
    attempt = j.create(meta={"release": "x"})
    j.mark(attempt, "provision", "started")           # crash point
    j.mark(attempt, "provision", "started")           # resume re-enters
    stage = j.mark(attempt, "provision", "done")["stages"]["provision"]
    assert stage["status"] == "done"
    assert [p["status"] for p in stage["prior"]] == ["started"]


def test_top_level_completion_separates_attempts_not_overwrites(tmp_path):
    j = _journal(tmp_path)
    attempt = j.create(meta={"release": "x"})
    j.mark(attempt, "restart", "failed", error="boom")
    # a DIFFERENT attempt (started fresh after a manual resolve) keeps the
    # failed one's whole record intact; the new one shows only its own
    data = j.finish(attempt, revision="r1")
    assert data["status"] == "done" and data["revision"] == "r1"
    assert data["stages"]["restart"]["status"] == "failed", (
        "finish() never rewrites stage history of a never-retried stage")
