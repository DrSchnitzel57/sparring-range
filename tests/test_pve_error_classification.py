"""classify_pve_error: real-PVE absence signatures (live-deploy find).

PVE answers per-guest paths for a nonexistent VMID with 500 "no such
file", not 404; the fake PVE used by every automated test returned 404,
so the first real next_vmid probe classified confirmed absence as
uncertain and refused the deploy.
"""
from infra.proxmox_client import PveNotFound, PveUnavailable, classify_pve_error


class _Http500(Exception):
    status_code = 500


class _Http404(Exception):
    status_code = 404


def test_no_such_file_500_is_confirmed_absence():
    exc = _Http500("500 Internal Server Error: no such file "
                   "'/nodes/pve/qemu/9100/status/current'")
    assert isinstance(classify_pve_error(exc), PveNotFound)


def test_plain_404_stays_absence():
    assert isinstance(classify_pve_error(_Http404("gone")), PveNotFound)


def test_other_500_stays_uncertain():
    exc = _Http500("500 Internal Server Error: cluster filesystem down")
    assert isinstance(classify_pve_error(exc), PveUnavailable)
