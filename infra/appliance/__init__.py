"""Single-appliance deployment boundary (milestone 14 foundation).

The appliance is ONE Ubuntu host running the product and KVM/libvirt for the
inner full VMs.  No outer-host credential exists here: the deterministic
local broker owns the only libvirt connection, and the API/model/bastion/
ingest processes never see it.

Modules are intentionally small and independently loadable so the installer
can validate a manifest without importing the VM backend, and the broker can
run without importing the API.
"""

from .errors import ApplianceError, ManifestError

__all__ = ["ApplianceError", "ManifestError"]
