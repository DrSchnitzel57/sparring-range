"""VyOS golden builder: the config ISO and the rendered plan it carries."""
from __future__ import annotations

import pathlib

import pycdlib

from infra.images.run_vyos_build import build_config_iso


def test_config_iso_carries_the_rendered_config_under_the_mapped_name(
        tmp_path):
    iso_path = tmp_path / "config.iso"
    build_config_iso("set system host-name 'vyos-edge'\n", iso_path)
    iso = pycdlib.PyCdlib()
    iso.open(str(iso_path))
    try:
        files = [rec.file_identifier().decode().split(";")[0]
                 for rec in iso.list_children(iso_path="/") if rec.is_file()]
        assert "CONFIG.BOOT" in files
    finally:
        iso.close()


def test_the_default_config_is_the_edge_config_the_blueprint_declares():
    from srplatform.environment_specs import load_environment
    from srplatform.environment_specs.router_config import render_vyos

    bp = load_environment("underpressure-range").blueprint
    text = render_vyos(bp)
    # the ISO step would carry exactly this plan: every public path is a DNAT
    for fwd in bp.public_forwards:
        assert fwd.vip in text and str(fwd.vip_port) in text
    assert "translation address" in text
