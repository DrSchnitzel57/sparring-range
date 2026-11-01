"""Appliance-local error types.

They deliberately do not inherit the broker's transport-era error cousins: an
appliance backend can never be mistaken for a remote-broker path, and the
typed server maps each one to a stable wire code.
"""

from __future__ import annotations


class ApplianceError(RuntimeError):
    """Base class for appliance failures that must be visible/fail closed."""

    code = "appliance_error"


class ManifestError(ApplianceError):
    code = "manifest_invalid"


class BackendUnavailable(ApplianceError):
    code = "backend_unavailable"


class BackendReadBackFailed(ApplianceError):
    code = "read_back_failed"


class ImageIntegrityError(ApplianceError):
    code = "image_integrity"


class FixtureOnlyBackend(ApplianceError):
    code = "fixture_backend"
