"""Plan 22 LIVE-06 + LIVE-09: bastion key enrollment and role-correct
connection instructions.

LIVE-06: a desktop key was refused because the CURRENT account had no
enrolled public key — the store is now API-managed (public keys only,
fingerprints surfaced, idempotent, other accounts preserved), merged with
the untouched operator commissioning file, and hot-reloaded by the bastion
so enrollment needs no restart.

LIVE-09: connections must not advertise a member SSH login the platform
itself refuses to use: the attacker host is runner-principal territory, so
its entry carries no `ssh` string and an honest note instead.
"""
from __future__ import annotations

import os
import pathlib

import pytest


def _pubkey():
    import asyncssh
    k = asyncssh.generate_private_key("ssh-ed25519")
    return k, k.export_public_key().decode().strip()


# ------------------------------------------------ enrollment store (unit) ---
def test_validate_accepts_real_public_key_and_refuses_the_rest(tmp_path):
    from srplatform.bastion import enrollment as en
    _, line = _pubkey()
    assert en.validate_public_key(line + "\n") == line
    for bad, why in (
            ("-----BEGIN OPENSSH PRIVATE KEY-----\nbAAAA\n", "private"),
            ("", "one"),
            ("ssh-ed25519 AAAA\nssh-ed25519 BBBB", "one"),
            ("not-a-key body", "openssh"),
            ("ssh-ed25519 ####bad-base64####", "base64|rejected|short"),
    ):
        with pytest.raises(ValueError) as e:
            en.validate_public_key(bad)
        assert any(w in str(e.value).lower() for w in why.split("|")), (bad, e.value)


def test_enroll_is_idempotent_and_never_evicts_other_accounts(tmp_path):
    from srplatform.bastion import enrollment as en
    path = tmp_path / "enrolled_keys"
    _, a = _pubkey()
    _, b = _pubkey()
    created, fps = en.enroll(path, "alice", a)
    assert created and len(fps) == 1 and fps[0].startswith("SHA256:")
    created2, fps2 = en.enroll(path, "alice", a)          # same key again
    assert not created2 and fps2 == fps
    en.enroll(path, "bob", b)                              # other account
    _, fps_a = en.enroll(path, "alice", a)
    assert fps_a == fps                                    # preserved
    st = en.status(path)
    assert set(st) == {"alice", "bob"}
    assert en.revoke(path, "bob", en.fingerprint(b)) is True
    assert en.revoke(path, "bob", "SHA256:whatever") is False
    assert set(en.status(path)) == {"alice"}
    # file stays PUBLIC-key-only, one entry per line
    text = path.read_text()
    assert "PRIVATE" not in text and text.count("alice") == 1


def test_enrolled_keys_path_explicit_setting_wins_over_derivation(tmp_path):
    from types import SimpleNamespace
    from srplatform.bastion import enrollment as en
    s = SimpleNamespace(bastion_enrolled_keys_file="",
                        safety_state_file=str(tmp_path / "state" / "s.json"))
    assert en.enrolled_keys_path(s) == tmp_path / "state" / "bastion" / "enrolled_keys"
    s.bastion_enrolled_keys_file = str(tmp_path / "elsewhere")
    assert str(en.enrolled_keys_path(s)) == str(tmp_path / "elsewhere")
    # synthetic settings without either knob: enrollment is OFF, not broken
    assert en.enrolled_keys_path(SimpleNamespace()) is None


# --------------------------------- the installed writer/reader contract ---- #
def _appliance_manifest(tmp_path):
    from tests.test_appliance_contract import _manifest
    from infra.appliance.manifest import ApplianceManifest
    return ApplianceManifest.from_dict(_manifest(tmp_path),
                                       verify_images=False)


def _env_value(rendered: str, key: str) -> str:
    lines = [ln for ln in rendered.splitlines() if ln.startswith(key + "=")]
    assert len(lines) == 1, (key, lines)
    return lines[0].split("=", 1)[1]


def test_service_envs_render_one_shared_enrollment_path(tmp_path):
    """Review item 3: BOTH service environments must name the SAME
    absolute, state-tree location — outside the API's 0700 controller
    subtree, which the bastion may not traverse. The rendered env is the
    contract; divergence here is what silently un-enrolled every member
    on the installed appliance."""
    import pathlib

    import deploy.appliance as ap
    m = _appliance_manifest(tmp_path)
    etc, prefix = tmp_path / "etc", tmp_path / "prefix"
    control = ap.render_control_env(m, etc=etc, prefix=prefix)
    bastion = ap.render_bastion_env(m, etc=etc, prefix=prefix)
    w = _env_value(control, "SR_BASTION_ENROLLED_KEYS_FILE")
    r = _env_value(bastion, "SR_BASTION_ENROLLED_KEYS_FILE")
    assert w == r, "writer and reader rendered DIFFERENT enrollment paths"
    p = pathlib.Path(w)
    assert p.is_absolute() and w == ap.enrolled_keys_file(m)
    assert p.parent.parent == pathlib.Path(m.state_dir)
    assert p.parent.name == ap.ENROLLMENT_DIR_NAME
    assert "controller" not in p.parts


def test_enrollment_dir_provisioned_fresh_and_on_populated_upgrade(tmp_path):
    """Fresh AND populated-upgrade apply both provision the shared
    location (mode 0775 srrange:root); an existing enrollment file
    survives re-provisioning untouched — the upgrade must not un-enroll
    anyone, and mode drift is repaired."""
    import pathlib

    import deploy.appliance as ap
    m = _appliance_manifest(tmp_path)
    run = ap.Runner(dry_run=False)
    lay = ap.default_layout(root=tmp_path / "root",
                            etc=tmp_path / "root/etc")
    d = pathlib.Path(m.state_dir) / ap.ENROLLMENT_DIR_NAME
    ap._ensure_dirs(m, run, lay)                      # fresh
    assert d.is_dir() and d.stat().st_mode & 0o777 == 0o775
    f = d / ap.ENROLLMENT_FILE_NAME
    f.write_text("alice ssh-ed25519 AAAAC3NzaC1lZDI1 test\n")
    f.chmod(0o644)
    d.chmod(0o700)                                     # operator drift
    ap._ensure_dirs(m, run, lay)                      # populated upgrade
    assert f.read_text().startswith("alice ")
    assert d.stat().st_mode & 0o777 == 0o775


def test_rendered_path_is_the_shared_reader_writer_location(tmp_path):
    """With EXACTLY the env values the installer renders, an enrollment
    written through the API-side settings is immediately visible through
    the bastion-side settings — and the file the API creates is 0644 even
    under a private umask (public keys; the bastion identity must be able
    to open it)."""
    import os

    from srplatform.settings import Settings
    from srplatform.bastion import enrollment as en

    import deploy.appliance as ap
    m = _appliance_manifest(tmp_path)
    rendered = ap.enrolled_keys_file(m)
    api_s = Settings(sr_env="production",
                     safety_state_file=str(pathlib.Path(m.state_dir)
                                           / "controller"
                                           / "safety_state.json"),
                     bastion_enrolled_keys_file=rendered)
    bastion_s = Settings(sr_env="production",
                         bastion_enrolled_keys_file=rendered)
    assert en.enrolled_keys_path(api_s) == en.enrolled_keys_path(bastion_s)
    _, line = _pubkey()
    old = os.umask(0o077)               # hostile umask for the writer
    try:
        created, _fps = en.enroll(en.enrolled_keys_path(api_s), "alice",
                                  line)
    finally:
        os.umask(old)
    assert created
    read_path = en.enrolled_keys_path(bastion_s)
    assert en.has_any(read_path, "alice")
    assert read_path.stat().st_mode & 0o777 == 0o644


# -------------------------------------- concurrent enrollments (item 4) --- #
def test_cross_process_enrollments_never_lose_an_update(tmp_path):
    """Review item 4: atomic REPLACE protects READERS, but two writer
    processes that read the same base used to silently lose one update —
    both enrollments reported created=True and only one account survived.
    The flock on the stable sidecar serializes them: a first process that
    HOLDS the lock forces the second to WAIT (deterministic), and a
    concurrent burst of distinct enrollments all persist."""
    import multiprocessing as mp
    import os
    import time

    from srplatform.bastion import enrollment as en
    ctx = mp.get_context("fork")
    path = tmp_path / "enrolled_keys"

    def child(i, barrier, n=3):
        keys = []
        for j in range(n):
            _, line = _pubkey()
            keys.append(line)
            barrier.wait(timeout=30) if j == 0 else None
            created, _ = en.enroll(path, f"user{i}-j{j}", line)
            assert created, f"lost update for user{i}-j{j}"

    barrier = ctx.Barrier(6)
    procs = [ctx.Process(target=child, args=(i, barrier)) for i in range(6)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0, f"child exit {p.exitcode}"
    st = en.status(path)
    assert len(st) == 18, sorted(st)

    # deterministic serialization: while one process holds the lock, an
    # enrollment from ANOTHER process must block, then succeed on release
    lock_fd = os.open(path.with_name(path.name + ".lock"),
                      os.O_CREAT | os.O_RDWR, 0o644)
    import fcntl
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    _, line = _pubkey()

    def late():
        created, _ = en.enroll(path, "late-user", line)
        assert created

    p = ctx.Process(target=late)
    p.start()
    time.sleep(0.4)
    assert p.is_alive(), "the second writer overtook the lock holder"
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    p.join(30)
    assert p.exitcode == 0
    os.close(lock_fd)
    assert en.has_any(path, "late-user")


# ------------------------------------------------- bastion merge + reload ---
def test_bastion_merges_operator_file_and_hot_reloads_enrollment(tmp_path,
                                                                  monkeypatch):
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("SR_RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("SR_BASTION_HOST_KEY_PATH", str(tmp_path / "hostkey"))
    op_file = tmp_path / "authorized_keys"
    priv_alice, op_key = _pubkey()
    op_file.write_text(f"alice {op_key}\n")
    monkeypatch.setenv("SR_BASTION_AUTHORIZED_KEYS_FILE", str(op_file))
    enroll_file = tmp_path / "enrolled_keys"
    monkeypatch.setenv("SR_BASTION_ENROLLED_KEYS_FILE", str(enroll_file))
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        from srplatform.bastion.proxy import BastionProxy
        priv_bob, bob_line = _pubkey()

        async def _none(_t):
            return None
        bp = BastionProxy(resolve_token=_none, event_sink=_none)

        def ok(user, priv):
            return bp.authorized_keys(user, priv.convert_to_public())

        assert ok("alice", priv_alice)                    # operator file
        assert not ok("bob", priv_bob)                    # not yet enrolled
        # enrollment happens WHILE the bastion runs: mtime reload only
        enroll_file.parent.mkdir(parents=True, exist_ok=True)
        enroll_file.write_text(f"bob {bob_line}\n")
        st = enroll_file.stat()
        os.utime(enroll_file, ns=(st.st_atime_ns + 10**9, st.st_mtime_ns + 10**9))
        assert ok("bob", priv_bob), "enrollment did not hot-reload"
        assert ok("alice", priv_alice), "merge broke the operator key"
        enroll_file.unlink()                              # removal reloads too
        assert not ok("bob", priv_bob)
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------- role policy (unit) ----
def test_host_role_policy_and_annotate():
    from srplatform import host_roles as hr
    assert hr.host_role("attacker", None) == "attacker"
    assert hr.host_role("attacker", 9005) == "attacker"     # spec wins, same
    assert hr.host_role("web01", 9001) == "target"          # legacy template
    assert hr.host_role("web01", 9011) == "mojang-web-local"
    e = {"host": "attacker", "template_vmid": 9005, "ssh": "ssh ... -l tok",
         "login_token": "tok"}
    hr.annotate(e)
    assert e["role"] == "attacker" and e["member_ssh"] is False
    assert "ssh" not in e and "member SSH" in e["note"]
    assert "runner" in e["note"]
    d = {"host": "web01", "template_vmid": 9001, "ssh": "ssh ... -l tok"}
    hr.annotate(d)
    assert d["member_ssh"] is True and d["ssh"].startswith("ssh ")


# ------------------------------------------------------------- API (db) -----
def _priv_pem() -> tuple[str, str]:
    import asyncssh
    k = asyncssh.generate_private_key("ssh-ed25519")
    return (k.export_public_key().decode().strip(),
            k.export_private_key().decode().strip())


def test_enrollment_api_roundtrip_privacy_and_honesty(client, users):
    pub, pem = _priv_pem()
    op = users["op"]
    # operator enrolls for the member's account
    r = client.post("/admin/bastion/enrollment",
                    json={"username": "blue", "public_key": pub}, headers=op)
    assert r.status_code == 201, r.text
    fp = r.json()["fingerprints"][-1]
    assert r.json()["created"] is True and fp.startswith("SHA256:")
    # idempotent: the identical key changes nothing
    r2 = client.post("/admin/bastion/enrollment",
                     json={"username": "blue", "public_key": pub}, headers=op)
    assert r2.json()["created"] is False and r2.json()["fingerprints"][-1] == fp
    # a PRIVATE key is refused before anything is stored — and loudly
    r3 = client.post("/admin/bastion/enrollment",
                     json={"username": "blue", "public_key": pem}, headers=op)
    assert r3.status_code == 400 and "PRIVATE" in r3.json()["detail"]
    # member self-diagnosis sees only their own account
    me = client.get("/bastion/enrollment/me", headers=users["member"])
    assert me.status_code == 200
    body = me.json()
    assert body["enrolled"] is True and body["fingerprints"] == [fp]
    # operator view lists fingerprints, never key material
    lst = client.get("/admin/bastion/enrollment", headers=op).json()
    assert lst["enrolled"]["blue"] == [fp]
    assert base64_absent(str(lst), pub)
    # revoke, then honest absence
    d = client.delete("/admin/bastion/enrollment",
                      params={"username": "blue", "fingerprint": fp}, headers=op)
    assert d.status_code == 200
    assert client.get("/bastion/enrollment/me",
                      headers=users["member"]).json()["enrolled"] is False
    assert client.delete("/admin/bastion/enrollment",
                         params={"username": "blue", "fingerprint": fp},
                         headers=op).status_code == 404
    # member cannot administer the store
    assert client.get("/admin/bastion/enrollment",
                      headers=users["member"]).status_code == 403


def base64_absent(rendered: str, pub_line: str) -> bool:
    blob = pub_line.split(" ")[1]
    return blob[:20] not in rendered


def test_connections_carry_role_policy_and_enrollment_truth(client, users,
                                                            fake_pve):
    from tests.conftest import launch_and_wait
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    out = launch_and_wait(client, users["member"], sid)["result"]
    # launch instructions carry the role verdict for every host
    for entry in out["connections"]:
        assert entry["role"] and isinstance(entry["member_ssh"], bool)
    r = client.get(f"/sessions/{sid}/connections", headers=users["member"]).json()
    conn = r["connections"][0]
    # web01 (legacy template, defender-side): member SSH stays advertised
    assert conn["host"] == "web01" and conn["member_ssh"] is True
    assert conn["ssh"].startswith("ssh ")
    # enrollment truth: the account has NO key yet — the LIVE-06 failure
    # mode must be visible BEFORE the member tries to SSH
    ke = r["key_enrollment"]
    assert ke["enrolled"] is False and ke["fingerprints"] == []
    client.post("/admin/bastion/enrollment",
                json={"username": "blue", "public_key": _priv_pem()[0]},
                headers=users["op"])
    r2 = client.get(f"/sessions/{sid}/connections", headers=users["member"]).json()
    assert r2["key_enrollment"]["enrolled"] is True
