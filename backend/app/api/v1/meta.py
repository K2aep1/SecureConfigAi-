"""Meta endpoints: health and platform/baseline identity."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import settings
from app.core.database import healthcheck
from app.schemas import HealthOut, MetaOut
from app.services.baseline import load_baseline
from app.services.scoring import SCORING_MODEL_VERSION

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    baseline = load_baseline()
    database = healthcheck()
    return HealthOut(
        status="healthy" if database.get("reachable", False) else "degraded",
        service=settings.APP_NAME,
        environment=settings.APP_ENV,
        version=settings.APP_VERSION,
        baseline_version=baseline.version,
        scoring_model_version=SCORING_MODEL_VERSION,
        database=database,
    )


@router.get("/meta", response_model=MetaOut)
def meta() -> MetaOut:
    baseline = load_baseline()
    return MetaOut(
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        scoring_model_version=SCORING_MODEL_VERSION,
        baseline={
            "baseline_id": baseline.baseline_id,
            "version": baseline.version,
            "title": baseline.title,
            "description": baseline.description,
            "published_at": baseline.published_at,
            "reference_policy": baseline.reference_policy,
            "references": list(baseline.references),
            "thresholds": dict(baseline.thresholds),
        },
        control_count=len(baseline.controls),
        control_weight_total=baseline.total_weight,
        environment=settings.APP_ENV,
    )
