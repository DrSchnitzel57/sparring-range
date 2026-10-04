"""Priority request queue — now a thin compatibility shim over the single
model gateway (F18). Red-loop traffic shares the SAME gateway as coach
traffic within a process; interactive hints are scheduled first.
"""
from srplatform.model_gateway import (  # noqa: F401
    ModelGateway,
    PRIORITY_AAR,
    PRIORITY_HINT,
    PRIORITY_RED,
    QueueFull,
    get_model_gateway,
    set_model_gateway,
)

coach_queue = get_model_gateway()
