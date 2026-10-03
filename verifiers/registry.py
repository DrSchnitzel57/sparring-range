"""Verifier registry — scenario YAML references verifiers by id."""
from __future__ import annotations

from verifiers.base import Verifier
from verifiers.library.flag_file import FlagFilePresent, CronPersistencePresent
from verifiers.library.ccdc import (
    NoRogueAdmin, RogueAccount, FirewallEnabled, AvEnabled, ServicePresent,
    ScheduledTaskPresent, PersistenceRunKey, UnpatchedService, DataIntegrity, ExfilFlag,
)

REGISTRY: dict[str, Verifier] = {}


def register(v: Verifier) -> None:
    REGISTRY[v.id] = v


def get(verifier_id: str) -> Verifier:
    if verifier_id not in REGISTRY:
        raise KeyError(f"no verifier '{verifier_id}' — registered: {sorted(REGISTRY)}")
    return REGISTRY[verifier_id]


for _v in (FlagFilePresent(), CronPersistencePresent(), NoRogueAdmin(), RogueAccount(),
           FirewallEnabled(), AvEnabled(), ServicePresent(), ScheduledTaskPresent(),
           PersistenceRunKey(), UnpatchedService(), DataIntegrity(), ExfilFlag()):
    register(_v)
