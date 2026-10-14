"""classify_pve_error: real-PVE absence signatures (live + source audit).

PVE 9.2 confirms a free VMID on per-guest paths with 500 "Configuration
file 'nodes/<node>/qemu-server/<vmid>.conf' does not exist" (live capture
2026-10-14; PVE::QemuConfig->load_config via cfs). 404 also stays absence.

Audit A1 (docs/audits/pve92-alignment.md): 500 "no such file '<path>'"
is NOT absence — source-wise it is the API router's static-file fallback
(PVE::APIServer::AnyEvent) answering a request that matched NO API route,
exactly what the pre-db01932 missing-/api2/json-prefix URLs produced.
Treating it as absence turns any URL bug into silent false absence
(free-looking VMIDs, 'already-absent' teardowns of running VMs), so it
must stay UNCERTAIN and loud.
"""
from infra.proxmox_client import (PveNotFound, PveUnavailable,
                                  classify_pve_error)


class _Http500(Exception):
    status_code = 500


class _Http404(Exception):
    status_code = 404


def test_missing_guest_config_500_is_confirmed_absence():
    exc = _Http500("500 Internal Server Error: Configuration file "
                   "'nodes/pve/qemu-server/9100.conf' does not exist")
    assert isinstance(classify_pve_error(exc), PveNotFound)


def test_plain_404_stays_absence():
    assert isinstance(classify_pve_error(_Http404("gone")), PveNotFound)


def test_routing_bug_no_such_file_500_stays_uncertain():
    # The router's route-not-found wording (also the exact signature the
    # leading-slash prefix bug produced): UNCERTAIN, never absence.
    exc = _Http500("500 Internal Server Error: no such file "
                   "'/nodes/pve/qemu/9100/status/current'")
    err = classify_pve_error(exc)
    assert isinstance(err, PveUnavailable)


def test_qga_missing_file_500_stays_uncertain():
    # Guest-agent file-open error while the host key is not regenerated
    # yet: the VM EXISTS, so this must never classify as absence either.
    exc = _Http500("500 Internal Server Error: Agent error: open failed "
                   "with error code 2: No such file or directory")
    assert isinstance(classify_pve_error(exc), PveUnavailable)


def test_other_500_stays_uncertain():
    exc = _Http500("500 Internal Server Error: cluster filesystem down")
    assert isinstance(classify_pve_error(exc), PveUnavailable)


def test_absence_regex_requires_exact_shape():
    # Same words without the per-guest config shape stay uncertain.
    exc = _Http500("500 Internal Server Error: does not exist")
    assert isinstance(classify_pve_error(exc), PveUnavailable)
