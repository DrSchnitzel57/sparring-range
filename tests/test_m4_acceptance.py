"""M4 acceptance tests — Part 5/M4 'Accept when':

  * a scenario defined ENTIRELY in YAML (no code changes) deploys, runs, and
    produces a score — proven by the quick-win-01 file that only exists as YAML
  * adding a new objective is a YAML edit reusing an existing verifier
Plus the M4 deliverables: library metadata for the launcher, strict validation,
and verifier semantics shared by red AND blue (polarity, unknown, provenance).
"""
import pytest

from srplatform import verification_service
from verifiers.base import Context
from verifiers import registry
from tests.conftest import launch_and_wait


# db layer membership derives from the fixture closure (milestone 01)


# --- criterion 1: YAML-only scenario, end to end through the API --------------
def test_m4_yaml_only_scenario_deploys_verifies_scores(client, users, fake_pve):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    def host_exec(host, command):
        if command.startswith("cat "):
            return 0, "FLAG{quick-win}\n"
        if "awk" in command and "/etc/passwd" in command:
            return 0, ""                       # no rogue uid-0
        if "list-unit-files" in command:
            return 0, "sshd.service enabled enabled\n"
        return 127, "no route"
    verification_service.set_verifier_exec(host_exec)

    # red objective confirmed by the BACKEND verifier, not a claim
    r = client.post(f"/sessions/{sid}/verifier_checks",
                    json={"objective_id": "flaggrab"}, headers=users["member"])
    assert r.status_code == 200 and r.json()["passed"] is True
    assert r.json()["status"] == "passed" and r.json()["event_id"]

    card = client.post(f"/sessions/{sid}/score", headers=users["member"]).json()
    assert card["status"] == "scored"
    assert card["earned"] == card["total"] == 15
    assert {i["domain"] for i in card["items"]} == {"identify", "protect"}

    # score snapshot persisted; the progress view can see it (owner DB connection)
    snap = client.get(f"/sessions/{sid}/score", headers=users["member"]).json()
    assert snap["event_id"] == card["event_id"]


def test_m4_unreachable_state_is_unknown_not_fabricated(client, users):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    def dead_exec(host, command):
        raise TimeoutError("host unreachable")
    verification_service.set_verifier_exec(dead_exec)

    card = client.post(f"/sessions/{sid}/score", headers=users["member"]).json()
    # documented policy: unknown scores 0 but REMAINS VISIBLE as partial —
    # no fabricated passes, no silent all-F scorecard
    assert card["status"] == "partial"
    assert card["earned"] == 0 and card["total"] == 15
    assert all(i["status"] == "unknown" for i in card["items"])
    assert all(i["error"] for i in card["items"])

    # and an UNKNOWN red objective never counts as compromised
    r = client.post(f"/sessions/{sid}/verifier_checks",
                    json={"objective_id": "flaggrab"}, headers=users["member"])
    assert r.json()["status"] == "unknown" and r.json()["passed"] is False


# --- criterion 2: YAML validation is strict and offline ------------------------
def test_m4_loader_rejects_bad_scenarios(tmp_path, monkeypatch):
    import shutil

    from srplatform.scenario_engine import loader

    # copy the real library so cross-references (verifier ids) resolve
    shutil.copytree("scenarios", tmp_path, dirs_exist_ok=True)
    good = (tmp_path / "quick-win-01.yaml").read_text()
    monkeypatch.setattr(loader, "scenarios_dir", lambda: tmp_path)

    # targeted mutations, each individually unacceptable
    mutations = {
        "negative points": good.replace("points: 10", "points: -5"),
        "unknown verifier": good.replace("verifier: flag_file_present", "verifier: magic_wand"),
        "missing required arg": good.replace("path: /root/flag_quickwin.txt", "xhost: nope"),
        "bad ip": good.replace("10.66.0.10", "999.1.1.1"),
    }
    monkeypatch.setattr(loader, "scenarios_dir", lambda: tmp_path)
    for label, mutated in mutations.items():
        (tmp_path / "bad-01.yaml").write_text(mutated)
        with pytest.raises(loader.ScenarioError):
            loader.load_scenario("bad-01")
        assert label  # readability

    # list_scenarios surfaces invalid entries instead of hiding them
    (tmp_path / "bad-02.yaml").write_text(good.replace("points: 10", "points: -1"))
    rows = loader.list_scenarios(tmp_path)
    bad_rows = [r for r in rows if r.get("_valid") is False]
    assert any(r["id"] == "bad-02" for r in bad_rows)


def test_m4_library_metadata_for_launcher(client):
    rows = client.get("/scenarios").json()
    wf = next(r for r in rows if r["id"] == "web-foothold-01")
    # fields the M7 browser filters on
    assert {"difficulty", "focus", "est_minutes", "techniques"} <= set(wf)
    assert all(r.get("_valid") is not False for r in rows), "library must be fully valid"


# --- verifier library semantics (no DB): shared red/blue contract --------------
def test_verifier_polarity_serves_red_and_blue():
    import hashlib
    import json
    from verifiers.library.flag_file import CronPersistencePresent

    cron = CronPersistencePresent()
    digest = hashlib.sha256(b"clean distro fixture").hexdigest()
    baseline = {"uid": 0, "gid": 0, "mode": 0o644, "sha256": digest}
    pins = {"baseline_file_sha256": {"e2scrub_all": digest}}
    dirty = json.dumps({"files": {"e2scrub_all": baseline, "backdoor": baseline}, "crontab": ""})
    ctx = Context(exec=lambda h, c: (0, dirty))
    red = cron.evaluate(ctx, host="web01", **pins)
    assert red.status == "passed"                       # red: persistence exists
    blue = cron.evaluate(ctx, host="web01", expect="absent", **pins)
    assert blue.status == "failed"                      # blue: NOT allowed to award
    clean = Context(exec=lambda h, c: (0, json.dumps({"files": {"e2scrub_all": baseline}, "crontab": ""})))
    blue_clean = cron.evaluate(clean, host="web01", expect="absent", **pins)
    assert blue_clean.status == "passed"
    # baseline-only state must NOT count as red persistence (F10)
    red_clean = cron.evaluate(clean, host="web01", **pins)
    assert red_clean.status == "failed"


def test_verifier_unknown_never_passes_and_typed_args_reject_garbage():
    from verifiers.library.flag_file import FlagFilePresent
    from verifiers.library.ccdc import DataIntegrity

    flag = FlagFilePresent()
    dead = Context(exec=lambda h, c: (_ for _ in ()).throw(OSError("ssh down")))
    assert flag.evaluate(dead, host="h", path="/x").status == "unknown"

    # wrong type for path (int) is an argument error, not a crash or a pass
    ok_ctx = Context(exec=lambda h, c: (0, "FLAG{x}"))
    assert flag.evaluate(ok_ctx, host="h", path=12345).status == "unknown"

    # integrity hash typo in the SCENARIO is caught statically by the loader path
    di = DataIntegrity()
    assert di.validate_static({"host": "h", "path": "/x", "expected_sha256": "deadbeef"})
    assert di.validate_static({"host": "h", "path": "/x",
                               "expected_sha256": "0" * 64}) is None


def test_verifier_flag_provenance_mismatch_is_not_a_pass():
    from verifiers.library.flag_file import FlagFilePresent
    ctx = Context(exec=lambda h, c: (0, "someone-elses-file"))
    out = FlagFilePresent().evaluate(ctx, host="h", path="/root/flag_foothold.txt",
                                     expected_content="FLAG{web01-root}")
    assert out.status == "failed"
    assert out.evidence["provenance"] == "mismatch"


def test_verifier_commands_are_shell_quoted():
    """No injection through scenario-provided paths into the management channel."""
    from verifiers.library.flag_file import FlagFilePresent
    seen = []

    def spy(h, c):
        seen.append(c)
        return 0, "x"
    FlagFilePresent().evaluate(Context(exec=spy), host="h", path="/x; rm -rf /",
                               expected_content="x")
    assert seen and "rm -rf" in seen[0] and ";" in seen[0]
    # the metacharacters exist only INSIDE a single-quoted argument
    assert seen[0].split("cat ")[1].startswith("'/x;")
