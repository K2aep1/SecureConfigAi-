"""API v1 router assembly.

Feature routers and the documented metadata endpoint are mounted under ``/api/v1``.
The legacy service-wide ``/health`` and ``/meta`` paths remain available at the root
for health probes and backward compatibility.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import admin, ai, auth, devices, meta, policies, scans
from app.core.config import settings
from app.schemas import MetaOut

#: Feature routers, all mounted under the versioned prefix.
api_router = APIRouter(prefix=settings.API_PREFIX)
api_router.include_router(auth.router)
api_router.include_router(devices.router)
api_router.include_router(scans.router)
api_router.include_router(policies.router)
api_router.include_router(admin.router)
api_router.include_router(ai.router)
# Keep the documented versioned metadata route; /meta remains for backwards compatibility.
api_router.add_api_route(
    "/meta",
    meta.meta,
    methods=["GET"],
    response_model=MetaOut,
    tags=["meta"],
    name="meta_v1",
)

#: Service endpoints that stay at the application root (health probes, metadata).
root_router = APIRouter()
root_router.include_router(meta.router)
