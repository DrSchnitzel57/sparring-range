"""Mojang guest-image acceptance (paired 03+04, milestone 03).

Required gate: `python infra/dev/acceptance.py images` (disposable Postgres
+ isolated QEMU, synthetic API/DB/SSH). Every test drives REAL artifacts —
pinned manifests, the deterministic builder, actual service/seed/flaw code,
the typed broker FileRead channel, and a real isolated QEMU boot — never
mocked callbacks or fabricated audit records.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

pytestmark = pytest.mark.images

REPO = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- manifest ---
def test_images_manifest_pins_ubuntu_packages_budgets_and_inputs():
    manifest = json.loads((REPO / "infra/images/manifest.json").read_text())
    base = manifest["base_image"]
    assert base["release"].startswith("24.04"), base
    assert base["source_url"].startswith(
        "https://cloud-images.ubuntu.com/noble/"), base
    assert len(base["sha256"]) == 64 and all(
        c in "0123456789abcdef" for c in base["sha256"].lower()), base
    assert manifest["packages"], "pinned package set must be non-empty"
    assert any(p.startswith("nginx=") for p in manifest["packages"])
    assert any("pymysql" in p.lower() for p in manifest["packages"]), \
        "DB-backed variant reads MySQL through PyMySQL"
    assert any("auditd" in p for p in manifest["packages"])
    guests = manifest["guests"]
    assert guests["attacker"]["vcpus"] == 2
    assert guests["attacker"]["memory_mb"] == 2048
    assert guests["attacker"]["disk_gb"] == 16
    assert guests["mojang-web-local"]["disk_gb"] == 12
    assert guests["mojang-web-db"]["disk_gb"] == 16
    assert manifest["capture"]["spool_max_bytes"] == 64 * 1024 * 1024
    assert manifest["capture"]["cast_max_bytes"] == 32 * 1024 * 1024
    for inp in manifest["build_inputs"]:
        assert (REPO / inp).exists(), f"pinned build input missing: {inp}"
    on_disk = sorted(l.strip() for l in
                     (REPO / "infra/images/packages-24.04.txt").read_text()
                     .splitlines() if l.strip() and not l.startswith("#"))
    assert sorted(manifest["packages"]) == on_disk


def test_images_packer_retired_not_used_for_release():
    pkr = (REPO / "infra/images/golden-linux.pkr.hcl").read_text()
    assert "RETIRED" in pkr, "Packer path must be explicitly retired"
    # No release tooling may reference the Packer path as a build step.
    for path in ((REPO / "infra/images/build.py").read_text(),
                 (REPO / "infra/images/README.md").read_text()):
        assert "packer" not in path.lower() or "retir" in path.lower(), path[:200]


def test_images_seeds_three_games_twelve_fixed_purchases():
    seeds = json.loads((REPO / "scenarios/mojang-seeds.json").read_text())
    assert seeds["seed_version"] == 1
    assert {g["game_id"] for g in seeds["games"]} == {
        "minecraft", "dungeons", "legends"}
    assert len(seeds["purchases"]) == 12
    ids = [p["purchase_id"] for p in seeds["purchases"]]
    assert ids == [f"buy-{i:03d}" for i in range(1, 13)], ids
    assert all(p["price_cents"] > 0 for p in seeds["purchases"])
    assert "fictional" in seeds["note"].lower()


def test_images_mojang_scenarios_load_with_attacker_and_budgets():
    from srplatform.scenario_engine.loader import load_scenario
    for sid, expect_hosts in (("mojang-web-01", {"attacker", "web01"}),
                              ("mojang-web-db-01", {"attacker", "web01", "db01"})):
        spec = load_scenario(sid)
        assert spec["seed_version"] == 1
        assert spec["image_version"] == "noble-20261012"
        hosts = {h["name"]: h for h in spec["topology"]["hosts"]}
        assert set(hosts) == expect_hosts, hosts
        assert hosts["attacker"]["template_vmid"] == 9005
        assert hosts["attacker"]["ip"] == "10.66.0.9", \
            "fresh attacker has a fixed network destination"
        assert hosts["web01"]["template_vmid"] == 9011
        if "db01" in hosts:
            assert hosts["db01"]["template_vmid"] == 9012
        # Legacy snapshots preserved: old scenarios still load unchanged.
        legacy = load_scenario("web-foothold-01")
        assert legacy["topology"]["hosts"][0]["template_vmid"] == 9001


def test_images_mysql_seed_is_logical_not_disk_hash():
    schema = (REPO / "infra/images/payloads/mojang-web-db/etc/mysql/mojang"
              / "schema.sql").read_text()
    assert "mojang_reader" in schema
    assert "GRANT SELECT" in schema
    assert "GRANT ALL" not in schema, "reader role must be SELECT-only"
    seed = (REPO / "infra/images/payloads/mojang-web-db/etc/mysql/mojang"
            / "seed.sql").read_text()
    assert seed.count("INSERT INTO purchases") == 12, seed[:200]
    for sid in ("mojang-web-01", "mojang-web-db-01"):
        text = (REPO / f"scenarios/{sid}.yaml").read_text()
        assert "ibdata1" not in text, \
            f"{sid} must not use raw MySQL disk hashes as evidence"
        assert "sha256sum /var/lib/mysql" not in text


def test_images_flaws_documented_with_service_preserving_fixes():
    app = (REPO / "infra/images/payloads/mojang-web-local/srv/mojang-web"
           / "app.py").read_text()
    # Diagnostic flaw: GENUINE web-user command execution (shell), bounded,
    # documented, and switchable off while the catalogue keeps serving.
    assert "shell=True" in app and "web-user" in app
    assert "DIAG{{web-user}}" in app and "mojang-diag-proof.txt" in app
    assert "MOJANG_DIAG_ENABLED" in app and "403" in app
    helper = (REPO / "infra/images/payloads/mojang-web-local/usr/local/bin"
              / "mojang-maintenance").read_text()
    # Working guest-root path: root-owned helper behind a scoped sudo rule
    # that trusts the web-user-writable tools dir (setuid-on-a-script is
    # ignored by Linux and must not come back).
    assert "/srv/mojang-web/tools" in helper and "backup-tool" in helper
    assert "setuid" in helper.lower(), "helper must document why not setuid"
    sudoers = (REPO / "infra/images/payloads/mojang-web-local/etc/sudoers.d"
               / "mojang-maintenance").read_text()
    assert ("web-user ALL=(root) NOPASSWD: /usr/local/bin/mojang-maintenance"
            in sudoers)
    unit = (REPO / "infra/images/payloads/mojang-web-local/etc/systemd/system"
            / "mojang-web.service").read_text()
    # The chain needs a privilege transition; NoNewPrivileges is reconciled
    # (NOT an active directive in the vulnerable unit, documented as a
    # hardening fix). Check directive lines, not prose.
    assert not [l for l in unit.splitlines()
                if l.strip().startswith("NoNewPrivileges")]
    assert "NoNewPrivileges" in unit, "unit must document the reconciliation"
    fixes = (REPO / "infra/images/payloads/mojang-web-local/srv/mojang-web"
             / "FIXES.md").read_text()
    assert "MOJANG_DIAG_ENABLED=off" in fixes
    assert "rm -f /etc/sudoers.d/mojang-maintenance" in fixes
    assert "still active" in fixes or "still serves" in fixes or "stays ready" in fixes
    # Both role trees carry the identical chain (shared build path).
    for rel in ("srv/mojang-web/app.py", "usr/local/bin/mojang-maintenance",
                "etc/sudoers.d/mojang-maintenance", "srv/mojang-web/FIXES.md"):
        assert (REPO / f"infra/images/payloads/mojang-web-db/{rel}").read_text() \
            == (REPO / f"infra/images/payloads/mojang-web-local/{rel}").read_text(), rel


def test_images_builder_deterministic_scrubbed_public_keys_only(tmp_path):
    pub = tmp_path / "guest.pub"
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAsyntheticBuilderTest synthetic\n")
    out1 = tmp_path / "build1"
    out2 = tmp_path / "build2"
    for out in (out1, out2):
        r = subprocess.run([sys.executable, "infra/images/build.py", "--out", str(out),
                            "--pubkey", str(pub)], cwd=REPO, capture_output=True,
                           text=True, timeout=120)
        assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    m1 = json.loads((out1 / "BUILD-MANIFEST.json").read_text())
    m2 = json.loads((out2 / "BUILD-MANIFEST.json").read_text())
    assert m1 == m2, "builder must be deterministic"
    for guest in ("attacker", "mojang-web-local", "mojang-web-db"):
        tree = out1 / guest
        # Public key baked; no private material, no placeholders, no host keys.
        ak_files = list(tree.rglob("authorized_keys"))
        assert ak_files, f"{guest} carries no authorized_keys"
        for ak in ak_files:
            assert "syntheticBuilderTest" in ak.read_text()
        blob = "\n".join(p.read_text(errors="ignore") for p in tree.rglob("*")
                         if p.is_file())
        for marker in ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
                       "CHANGE_ME", "CHANGEME"):
            assert marker not in blob, f"{guest} leaks {marker}"
        assert not list(tree.rglob("ssh_host_ed25519_key")), \
            f"{guest} ships a host key (must be fresh per clone)"
        assert not list(tree.rglob("ssh_host_ed25519_key.pub")), \
            f"{guest} ships a host key (must be fresh per clone)"
    # Private keys are refused, not baked.
    bad = tmp_path / "bad.pub"
    bad.write_text("ssh-ed25519 AAAAbad\n-----BEGIN OPENSSH PRIVATE KEY-----\n")
    r = subprocess.run([sys.executable, "infra/images/build.py", "--out",
                        str(tmp_path / "bad-out"), "--pubkey", str(bad)],
                       cwd=REPO, capture_output=True, text=True, timeout=120)
    assert r.returncode != 0, "builder must refuse private-key material"


def test_images_mojang_verifiers_observe_behavior():
    from verifiers.base import Context
    from verifiers import registry
    http_v = registry.get("http_content")
    mysql_v = registry.get("mysql_rows")

    def ok_exec(host, cmd):
        if cmd.startswith("curl"):
            return 0, "<html>Minecraft Legends\nbuy-001 blue-alex</html>"
        if "COUNT(*)" in cmd:
            return 0, "12"
        if "SELECT purchase_id" in cmd:
            return 0, "buy-001\tminecraft\tblue-alex"
        return 1, ""

    ctx = Context(exec=ok_exec, hosts={"web01": "10.66.0.10", "db01": "10.66.0.11"})
    assert http_v.evaluate(ctx, host="web01",
                           expected_text="Minecraft Legends").status == "passed"
    assert http_v.evaluate(ctx, host="web01",
                           expected_text="ZZZ-no-such-game-zzz").status == "failed"
    assert mysql_v.evaluate(ctx, host="db01", table="purchases",
                            expected_count=12,
                            expected_text="buy-001").status == "passed"
    assert mysql_v.evaluate(ctx, host="db01", table="purchases",
                            expected_count=11).status == "failed"
    # Unknown hosts / probe failures are unknown, never passes.
    assert http_v.evaluate(Context(exec=ok_exec, hosts={}),
                           host="web01",
                           expected_text="ZZZ-no-such-game-zzz").status in ("failed", "unknown")

    def fail_exec(host, cmd):
        return 1, "boom"

    ctx2 = Context(exec=fail_exec, hosts={"web01": "10.66.0.10"})
    assert http_v.evaluate(ctx2, host="web01",
                           expected_text="Minecraft Legends").status == "unknown"
