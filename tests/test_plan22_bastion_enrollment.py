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
