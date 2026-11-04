"""Protected environment credentials: shape, permissions, and honest absence.

A credential store that is group-readable is not a secret store; a store that
is silently unparsable resolves nobody mid-exercise. Both fail LOUD here, and
a missing store is not an error at all - every credentialed check then reports
`unknown`, which is what the decision table already promises.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from srplatform.credentials import CredentialError, load, resolver

GOOD = {"environments": {"underpressure-range": {
    "SR_CRED_STORE_APP_SQL": "store:pass",
    "SR_CRED_PRB_MAIL_READER": "reader@lab:pass"}}}


def _write(tmp_path, body, mode=0o600):
    p = tmp_path / "creds.json"
    p.write_text(json.dumps(body) if not isinstance(body, str) else body)
    p.chmod(mode)
    return p


def test_values_resolve_by_variable_name_only(tmp_path):
    p = _write(tmp_path, GOOD)
    resolve = resolver(p)
    assert resolve("SR_CRED_STORE_APP_SQL") == "store:pass"
    assert resolve("SR_CRED_NOT_THERE") is None


def test_a_missing_store_resolves_nothing_and_is_not_an_error(tmp_path):
    resolve = resolver(tmp_path / "absent.json")
    assert resolve("SR_CRED_STORE_APP_SQL") is None


def test_a_group_readable_store_is_refused(tmp_path):
    """The whole point is that members cannot read a secret; 0644 is a leak
    that already happened, not a warning."""
    p = _write(tmp_path, GOOD, mode=0o644)
    with pytest.raises(CredentialError, match="group/world readable"):
        load(p)
    # tests/dev may opt out explicitly; production must not
    assert load(p, require_secure=False)["underpressure-range"]


def test_a_malformed_variable_name_fails_loud(tmp_path):
    bad = {"environments": {"underpressure-range": {"STORE_SQL": "x"}}}
    with pytest.raises(CredentialError, match="bad variable name"):
        load(_write(tmp_path, bad))


def test_an_empty_value_fails_loud(tmp_path):
    bad = {"environments": {"underpressure-range": {"SR_CRED_X": ""}}}
    with pytest.raises(CredentialError, match="non-empty"):
        load(_write(tmp_path, bad))


def test_invalid_json_fails_loud(tmp_path):
    with pytest.raises(CredentialError, match="not valid JSON"):
        load(_write(tmp_path, "{not json"))


def test_one_environment_never_sees_anothers_credentials(tmp_path):
    body = {"environments": {
        "underpressure-range": {"SR_CRED_SHARED": "mine"},
        "other-range": {"SR_CRED_SHARED": "theirs"}}}
    p = _write(tmp_path, body)
    assert resolver(p, "underpressure-range")("SR_CRED_SHARED") == "mine"
    assert resolver(p, "other-range")("SR_CRED_SHARED") == "theirs"
    assert resolver(p, "no-such-range")("SR_CRED_SHARED") is None
