"""Versioned service-check registry — availability as REAL transactions.

Availability stops being "is the HTTP/MySQL port answering": each check is
a typed transaction executed FROM THE TRUSTED SCORING VANTAGE against a
named guest (never from an attacker-controlled machine, never a bare port
scan dressed up as health). Infrastructure failure yields UNKNOWN evidence,
never downtime and never free points, and every check declares the guests
whose failure makes it an infrastructure problem instead of a defense
problem.

Credentials are referenced by logical name (`credential:<name>`), resolved
only by the protected captain/verifier path at run time. This document
never contains a secret value, and a secret-looking value is a load error.
"""
from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

CRED_REF_RE = re.compile(r"^credential:[a-z][a-z0-9._-]{1,63}$")
CHECK_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CheckKind(str, Enum):
    HTTPS_CONTENT = "https-content"
    MAIL_ROUNDTRIP = "mail-roundtrip"
    WEB_LOGIN = "web-login"
    DNS_RECORDS = "dns-records"
    DIRECTORY_AUTH = "directory-auth"
    SQL_SEED_READ = "sql-seed-read"
    SPLUNK_SEARCH = "splunk-search"


# ---- typed params (closed per kind) -----------------------------------------
class HttpsContentParams(Strict):
    url_path: str = Field(default="/", pattern=r"^/[^\s]*$")
    expected_text: str = Field(min_length=1, max_length=200)
    host_header: str | None = Field(default=None, max_length=253)
    # TLS trust is validated against the LAB CA material the environment
    # publishes; a mismatch is a real availability/security signal.
    verify_tls_against_lab_ca: bool = True


class MailRoundtripParams(Strict):
    sender_ref: str = Field(pattern=CRED_REF_RE.pattern)
    recipient_ref: str = Field(pattern=CRED_REF_RE.pattern)
    protocols: list[str] = ["imap"]
    subject_prefix: str = Field(default="SRPRB", pattern=r"^[A-Za-z0-9._-]{1,16}$")

    @model_validator(mode="after")
    def _protocols(self) -> "MailRoundtripParams":
        bad = [p for p in self.protocols if p not in ("imap", "pop3")]
        if bad:
            raise ValueError(f"mail protocols must be imap/pop3, got {bad}")
        if not self.protocols:
            raise ValueError("at least one retrieval protocol required")
        return self


class WebLoginParams(Strict):
    url_path: str = Field(pattern=r"^/[^\s]*$")
    account_ref: str = Field(pattern=CRED_REF_RE.pattern)
    success_text: str = Field(min_length=1, max_length=200)
    verify_tls_against_lab_ca: bool = True


class DnsRecordsParams(Strict):
    # name -> record types the authoritative answer must contain
    records: dict[str, list[str]] = Field(min_length=1)

    @model_validator(mode="after")
    def _types(self) -> "DnsRecordsParams":
        for name, types in self.records.items():
            bad = [t for t in types if t not in ("A", "AAAA", "MX", "SRV", "CNAME")]
            if bad or not types:
                raise ValueError(f"dns record {name!r}: types must be a non-empty "
                                 f"subset of A/AAAA/MX/SRV/CNAME, got {types}")
        return self


class DirectoryAuthParams(Strict):
    account_ref: str = Field(pattern=CRED_REF_RE.pattern)
    # Authentication success (simple bind / Kerberos AS-REQ) is the check;
    # group membership is a SECURITY check elsewhere, never availability.
    method: str = Field(default="simple-bind", pattern=r"^(simple-bind|kerberos-asreq)$")


class SqlSeedReadParams(Strict):
    database: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    # A seeded read transaction: the named seed expectation id (synthetic
    # fixture), never user input and never a raw query string.
    seed_expectation: str = Field(min_length=1, max_length=128,
                                  pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    app_account_ref: str = Field(pattern=CRED_REF_RE.pattern)


class SplunkSearchParams(Strict):
    index: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_:-]+$")
    search_expectation: str = Field(min_length=1, max_length=128,
                                    pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    ingest_account_ref: str = Field(pattern=CRED_REF_RE.pattern)


PARAM_MODELS: dict[CheckKind, type[BaseModel]] = {
    CheckKind.HTTPS_CONTENT: HttpsContentParams,
    CheckKind.MAIL_ROUNDTRIP: MailRoundtripParams,
    CheckKind.WEB_LOGIN: WebLoginParams,
    CheckKind.DNS_RECORDS: DnsRecordsParams,
    CheckKind.DIRECTORY_AUTH: DirectoryAuthParams,
    CheckKind.SQL_SEED_READ: SqlSeedReadParams,
    CheckKind.SPLUNK_SEARCH: SplunkSearchParams,
}


class ServiceCheck(Strict):
    """One availability transaction. `guest`/`depends_on_guests` are checked
    against the blueprint by the environment loader; `interval_class` maps to
    a server-owned sampling cadence (scheduled samples bind to service,
    exercise, generation and slot at run time — never here)."""
    id: str = Field(pattern=CHECK_ID_RE.pattern)
    kind: CheckKind
    guest: str = Field(min_length=1, max_length=31)
    title: str = Field(min_length=1, max_length=120)
    params: dict
    # Guests whose outage makes this check's failure INFRASTRUCTURE:
    # evidence is then UNKNOWN, never downtime, never attacker credit.
    depends_on_guests: list[str] = []
    interval_class: str = Field(default="fast", pattern=r"^(fast|steady)$")
    practice_note: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _params(self) -> "ServiceCheck":
        model = PARAM_MODELS[self.kind]
        try:
            validated = model.model_validate(self.params)
        except Exception as exc:  # pydantic or value error
            raise ValueError(f"check {self.id} ({self.kind.value}): params "
                             f"invalid: {exc}") from exc
        # keep the normalized params for downstream consumers
        self.params = validated.model_dump(mode="json")
        return self


class PracticeTask(Strict):
    """One clearly-labeled PRACTICE rubric task. No official competition
    weights, checker accounts or scoring ports are claimed anywhere."""
    id: str = Field(pattern=CHECK_ID_RE.pattern)
    title: str = Field(min_length=1, max_length=160)
    # Which availability transactions, if any, this task observes.
    service_checks: list[str] = []
    points: int = Field(gt=0, le=100)
    domain: str = Field(default="general", max_length=40)
    description: str = Field(min_length=1, max_length=1000)


class ServiceCheckRegistry(Strict):
    schema_version: int = 1
    environment: str = Field(min_length=1, max_length=64)
    version: int = Field(ge=1)
    practice_only: bool = True  # underpressure ships practice semantics
    checks: list[ServiceCheck] = Field(min_length=1)
    tasks: list[PracticeTask] = []

    @model_validator(mode="after")
    def _unique(self) -> "ServiceCheckRegistry":
        issues: list[str] = []
        ids = [c.id for c in self.checks]
        if len(ids) != len(set(ids)):
            issues.append("checks: duplicate service check ids")
        tids = [t.id for t in self.tasks]
        if len(tids) != len(set(tids)):
            issues.append("tasks: duplicate practice task ids")
        for t in self.tasks:
            for cid in t.service_checks:
                if cid not in ids:
                    issues.append(f"task {t.id}: unknown service check {cid!r}")
        if not self.practice_only:
            issues.append("official (non-practice) scoring requires an approved "
                          "rubric source; this registry may not declare it")
        if issues:
            raise ValueError("\n".join(issues))
        return self

    def check(self, check_id: str) -> ServiceCheck:
        for c in self.checks:
            if c.id == check_id:
                return c
        raise ValueError(f"unknown service check {check_id!r}")


def load_checks(raw: dict) -> ServiceCheckRegistry:
    """Parse + validate a checks document (secrets already rejected upstream
    by the environment loader's secret scan)."""
    return ServiceCheckRegistry.model_validate(raw)
