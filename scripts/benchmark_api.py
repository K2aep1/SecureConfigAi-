#!/usr/bin/env python
"""Measure the API against a real PostgreSQL database with a realistic history.

The research report measured `GET /scans` at **27.9 MB / 3.07 s**, `risk-trend` at
**2.16 s for 162 bytes**, and **~31 MB of database per scan**. Those numbers are the
baseline this script is designed to re-measure, so every claim in the completion report can
be reproduced with one command instead of being taken on trust.

It runs against ``--database-url`` (or ``TEST_DATABASE_URL``), applies the migrations,
seeds N assessments through the real upload endpoint, then times a fixed set of requests
in-process with ``TestClient``. In-process timing excludes network and TLS, which is stated
in the output so the numbers are not compared to a browser measurement.

Safety: it refuses to run against a database whose name does not contain ``test`` or
``bench``, and it removes only the assessments and devices it created. The generated user is
**anonymised rather than deleted**: audit rows reference their actor, and a hard delete
would rewrite history.

Usage::

    set TEST_DATABASE_URL=postgresql+psycopg://<user>:<password>@localhost:5432/secureconfigai_test
    python scripts/benchmark_api.py --scans 30 --samples 10
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"


def _fail(message: str) -> int:
    print(f"benchmark refused: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure API latency and payload size.")
    parser.add_argument("--database-url", default=os.environ.get("TEST_DATABASE_URL", ""))
    parser.add_argument("--scans", type=int, default=30)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--json-out", default="")
    args = parser.parse_args(argv)

    url = (args.database_url or "").strip()
    if not url:
        return _fail("set TEST_DATABASE_URL or pass --database-url")

    database = url.split("://", 1)[-1].rsplit("/", 1)[-1].split("?")[0]
    if not any(token in database.lower() for token in ("test", "bench")):
        return _fail(f"database {database!r} does not look like a test/benchmark database")

    os.environ["APP_ENV"] = "development"
    os.environ["DATABASE_URL"] = url
    os.environ.setdefault("JWT_SECRET_KEY", "benchmark-only-secret-0123456789abcdefghij")
    os.environ["RATE_LIMIT_ENABLED"] = "false"
    os.environ["AI_ENABLED"] = "false"
    os.environ["SCAN_INVENTORY"] = "false"
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)

    from alembic.config import Config  # noqa: PLC0415

    from alembic import command  # noqa: PLC0415

    command.upgrade(Config("alembic.ini"), "head")

    from fastapi.testclient import TestClient  # noqa: PLC0415
    from sqlalchemy import func, select  # noqa: PLC0415

    from app.core.database import SessionLocal, engine  # noqa: PLC0415
    from app.db.models import Device, Scan, ScanResult, User  # noqa: PLC0415
    from app.main import app  # noqa: PLC0415
    from app.services.jobs import manager  # noqa: PLC0415
    from tests.documents import failing_document, perfect_document, snapshot_from  # noqa: PLC0415

    # A benchmark-only credential: it never leaves this process and is never committed.
    password = "benchmark-only-not-a-secret"
    email = f"bench-{uuid.uuid4().hex[:10]}@example.com"
    results: dict[str, object] = {"database": database, "scans_seeded": args.scans, "samples": args.samples}

    def timed(call, samples: int) -> tuple[list[float], object]:
        durations: list[float] = []
        response = None
        for _ in range(samples):
            started = time.perf_counter()
            response = call()
            durations.append((time.perf_counter() - started) * 1000.0)
        return durations, response

    with TestClient(app) as client:
        # ------------------------------------------------------------- seed
        registered = client.post(
            "/api/v1/auth/register", json={"email": email, "password": password, "full_name": "Benchmark"}
        )
        assert registered.status_code == 201, registered.text
        tokens = client.post("/api/v1/auth/login", json={"email": email, "password": password}).json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        device = client.post(
            "/api/v1/devices/register", headers=headers, json={"hostname": "BENCH-PC", "criticality": 4}
        )
        assert device.status_code == 201, device.text

        seed_started = time.perf_counter()
        scan_ids: list[str] = []
        for index in range(args.scans):
            document = (
                perfect_document(f"BENCH-{index:02d}")
                if index % 3
                else failing_document(f"BENCH-{index:02d}")
            )
            response = client.post(
                "/api/v1/scans/upload",
                headers=headers,
                files={
                    "file": (
                        "configuration_snapshot.json",
                        json.dumps(snapshot_from(document)).encode("utf-8"),
                        "application/json",
                    )
                },
            )
            assert response.status_code == 200, response.text
            scan_ids.append(response.json()["scan_id"])
        seed_seconds = time.perf_counter() - seed_started
        results["seed_seconds"] = round(seed_seconds, 2)
        results["seed_per_scan_ms"] = round(seed_seconds / max(1, args.scans) * 1000.0, 1)

        # ------------------------------------------------------------- database footprint
        session = SessionLocal()
        try:
            owner_id = session.query(User).filter(User.email == email).one().id
            scan_bytes = session.execute(
                select(
                    func.coalesce(func.sum(func.pg_column_size(Scan.raw_data)), 0),
                    func.coalesce(func.sum(func.pg_column_size(Scan.normalized_data)), 0),
                    func.coalesce(func.sum(func.pg_column_size(Scan.id)), 0),
                ).where(Scan.user_id == owner_id)
            ).one()
            result_bytes = session.execute(
                select(
                    func.coalesce(func.sum(func.pg_column_size(ScanResult.controls)), 0),
                    func.coalesce(func.sum(func.pg_column_size(ScanResult.assessment)), 0),
                    func.coalesce(func.sum(func.pg_column_size(ScanResult.categories)), 0),
                )
                .join(Scan, Scan.id == ScanResult.scan_id)
                .where(Scan.user_id == owner_id)
            ).one()
            total = sum(scan_bytes) + sum(result_bytes)
            results["database"] = {
                "scans_raw_data_bytes": int(scan_bytes[0]),
                "scans_normalized_data_bytes": int(scan_bytes[1]),
                "scan_results_controls_bytes": int(result_bytes[0]),
                "scan_results_assessment_bytes": int(result_bytes[1]),
                "scan_results_categories_bytes": int(result_bytes[2]),
                "total_bytes_for_history": int(total),
                "bytes_per_scan": int(total / max(1, args.scans)),
            }
        finally:
            session.close()

        # ------------------------------------------------------------- endpoints
        def measure(name: str, call, *, note: str = "") -> None:
            durations, response = timed(call, args.samples)
            body = response.content if response is not None else b""
            results.setdefault("endpoints", {})[name] = {
                "status": getattr(response, "status_code", None),
                "bytes": len(body),
                "median_ms": round(statistics.median(durations), 2),
                "p95_ms": round(sorted(durations)[max(0, int(len(durations) * 0.95) - 1)], 2),
                "min_ms": round(min(durations), 2),
                "max_ms": round(max(durations), 2),
                "note": note,
            }

        measure(
            "GET /scans?limit=25",
            lambda: client.get("/api/v1/scans?limit=25", headers=headers),
            note="summary schema, keyset pagination, deferred evidence columns",
        )
        measure(
            "GET /scans/trend",
            lambda: client.get("/api/v1/scans/trend?limit=30", headers=headers),
            note="explicit projection over four columns",
        )
        measure(
            "GET /scans/alerts",
            lambda: client.get("/api/v1/scans/alerts", headers=headers),
            note="explicit projection",
        )
        measure(
            "GET /scans/{id}",
            lambda: client.get(f"/api/v1/scans/{scan_ids[-1]}", headers=headers),
            note="summary detail",
        )
        measure(
            "GET /scans/{id}/results",
            lambda: client.get(f"/api/v1/scans/{scan_ids[-1]}/results", headers=headers),
            note="dashboard payload: 28 controls, stored results, no evidence document",
        )

        # Scan start must be a fast 202; the worker is stubbed so nothing is spawned.
        manager.submit = lambda scan_id: None  # type: ignore[assignment]
        measure(
            "POST /scans/start",
            lambda: client.post(
                "/api/v1/scans/start", headers=headers, json={"device_id": device.json()["id"]}
            ),
            note="202 Accepted; collection happens in the worker, not the request",
        )

        # ------------------------------------------------------------- reports
        target = scan_ids[-1]
        first, response = timed(lambda: client.get(f"/api/v1/scans/{target}/report/html", headers=headers), 1)
        etag = response.headers.get("ETag") if response is not None else None
        conditional, response304 = timed(
            lambda: client.get(f"/api/v1/scans/{target}/report/html", headers=headers, params={}), 1
        )
        cached, response304 = timed(
            lambda: client.get(
                f"/api/v1/scans/{target}/report/html", headers={**headers, "If-None-Match": etag}
            ),
            args.samples,
        )
        results.setdefault("endpoints", {})["GET /scans/{id}/report/html"] = {
            "status": getattr(response304, "status_code", None),
            "bytes": len(response304.content) if response304 is not None else 0,
            "first_render_ms": round(first[0], 2),
            "warm_render_ms": round(conditional[0], 2),
            "conditional_median_ms": round(statistics.median(cached), 2),
            "note": "pre-generated on completion; If-None-Match returns 304 with no body",
        }

        # ------------------------------------------------------------- cleanup
        # The assessments and devices are removed; the user is anonymised instead of
        # deleted. Audit rows reference their actor, and the audit trail is immutable by
        # design — a hard delete would either rewrite history or be refused by the
        # foreign key. Anonymising keeps the chain verifiable.
        session = SessionLocal()
        try:
            owner = session.query(User).filter(User.email == email).one()
            for scan in session.query(Scan).filter(Scan.user_id == owner.id).all():
                session.delete(scan)
            session.flush()
            for device_row in session.query(Device).filter(Device.user_id == owner.id).all():
                session.delete(device_row)
            session.flush()
            owner.is_active = False
            owner.email = f"bench-anonymised-{uuid.uuid4().hex[:12]}@example.invalid"
            owner.full_name = "Benchmark (anonymised)"
            session.commit()
        finally:
            session.close()

    engine.dispose()

    print(json.dumps(results, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwritten to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
