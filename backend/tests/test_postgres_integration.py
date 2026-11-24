"""PostgreSQL integration: migrations, persistence and the full assessment pipeline.

SQLite is fine for fast unit tests but it is not the deployed database, and several real
defects in this project only appeared on one backend or the other. This test therefore
runs the *real* application against a *real* PostgreSQL database in a subprocess:

1. apply every Alembic revision to the test database;
2. drive register → login → device → upload → results → audit → report through the API;
3. read the rows back with an independent connection and confirm they are there.

It is skipped unless ``TEST_DATABASE_URL`` is set, so the default `pytest` run needs no
server. To run it::

    set TEST_DATABASE_URL=postgresql+psycopg://USER:PASS@localhost:5432/secureconfigai_test
    python -m pytest tests/test_postgres_integration.py -v

The suite never touches the development database: the fixture refuses a URL whose
database name does not look like a test database.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
TEST_URL = os.environ.get("TEST_DATABASE_URL", "").strip()

pytestmark = pytest.mark.skipif(
    not TEST_URL, reason="set TEST_DATABASE_URL to run the PostgreSQL integration test"
)

SCRIPT = r"""
import json, os, sys, uuid
from pathlib import Path

summary_path = Path(sys.argv[1])

os.environ["APP_ENV"] = "development"
os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
os.environ.setdefault("JWT_SECRET_KEY", "pg-integration-test-secret-0123456789abcdef")
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["REPORT_CACHE_ENABLED"] = "false"
os.environ["SCAN_JOB_WORKERS"] = "1"

from alembic import command
from alembic.config import Config

command.upgrade(Config("alembic.ini"), "head")

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import SessionLocal
from app.db.models import Scan, User
from app.main import app
from app.services.baseline import load_baseline

from tests.documents import perfect_document, snapshot_from

result = {"steps": []}
password = "CorrectHorse42"
email = f"pg-{uuid.uuid4().hex[:10]}@example.com"

with TestClient(app) as client:
    registered = client.post("/api/v1/auth/register",
                             json={"email": email, "password": password,
                                   "full_name": "PG Integration"})
    assert registered.status_code == 201, registered.text
    result["steps"].append("register")

    tokens = client.post("/api/v1/auth/login",
                         json={"email": email, "password": password}).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    result["steps"].append("login")

    device = client.post("/api/v1/devices/register", headers=headers,
                         json={"hostname": "PG-INTEGRATION", "criticality": 4})
    assert device.status_code == 201, device.text
    result["device_id"] = device.json()["id"]
    result["steps"].append("device")

    uploaded = client.post("/api/v1/scans/upload", headers=headers,
                           files={"file": ("configuration_snapshot.json",
                                           json.dumps(snapshot_from(
                                               perfect_document("PG-INTEGRATION"))).encode(),
                                           "application/json")})
    assert uploaded.status_code == 200, uploaded.text
    body = uploaded.json()
    scan_id = body["scan_id"]
    result["scan_id"] = scan_id
    result["finding_count"] = body["finding_count"]
    result["integrity_verified"] = body["integrity_verified"]
    result["steps"].append("upload")

    results = client.get(f"/api/v1/scans/{scan_id}/results", headers=headers).json()
    result["security_score"] = results["results"]["security_score"]
    result["coverage"] = results["results"]["assessment_coverage"]
    result["scoring_model_current"] = results["results"]["scoring_model_current"]
    result["control_count"] = len(results["results"]["controls"])
    result["collector_health"] = results["results"]["collector_health"]["status"]
    result["steps"].append("results")

    scan = client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()
    result["stored_scoring_model_version"] = scan["scoring_model_version"]
    result["stored_baseline_version"] = scan["baseline_version"]

    report = client.get(f"/api/v1/scans/{scan_id}/report/html", headers=headers)
    result["report_status"] = report.status_code
    result["report_bytes"] = len(report.content)
    etag = report.headers.get("ETag")
    repeat = client.get(f"/api/v1/scans/{scan_id}/report/html",
                        headers={**headers, "If-None-Match": etag})
    result["report_conditional_status"] = repeat.status_code
    result["steps"].append("report")

    ai = client.post(f"/api/v1/ai/report/{scan_id}", headers=headers)
    result["ai_status"] = ai.status_code
    result["ai_model_used"] = ai.json().get("model_used") if ai.status_code == 200 else None
    result["steps"].append("ai")

    listing = client.get("/api/v1/scans?limit=25", headers=headers)
    result["list_bytes"] = len(listing.content)
    result["list_count"] = len(listing.json()["items"])

    session = SessionLocal()
    try:
        user = session.query(User).filter(User.email == email).one()
        user.role = "admin"
        session.commit()
    finally:
        session.close()

    admin_tokens = client.post("/api/v1/auth/login",
                              json={"email": email, "password": password}).json()
    admin_headers = {"Authorization": f"Bearer {admin_tokens['access_token']}"}

    # A privileged action through the API, so the audit trail is exercised end to end.
    second_email = f"pg2-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/api/v1/auth/register",
                json={"email": second_email, "password": password})
    users = client.get("/api/v1/admin/users?limit=100", headers=admin_headers).json()["items"]
    target = next(item for item in users if item["email"] == second_email)
    promoted = client.patch(f"/api/v1/admin/users/{target['id']}/role",
                            headers=admin_headers, json={"role": "admin"})
    result["role_change_status"] = promoted.status_code

    audit = client.get("/api/v1/admin/audit-logs?limit=100", headers=admin_headers).json()
    result["audit_actions"] = sorted({item["action"] for item in audit["items"]})
    result["audit_rows"] = len(audit["items"])
    verify = client.get("/api/v1/admin/audit-logs/verify", headers=admin_headers).json()
    result["chain_valid"] = verify["chain_valid"]
    result["steps"].append("audit")

    stats = client.get("/api/v1/admin/stats", headers=admin_headers).json()
    result["stats"] = stats

result["baseline"] = {"id": load_baseline().baseline_id,
                      "version": load_baseline().version,
                      "controls": len(load_baseline().controls)}
result["dialect"] = settings.DATABASE_URL.split("://")[0]
summary_path.write_text(json.dumps(result), encoding="utf-8")
"""


@pytest.fixture(scope="module", autouse=True)
def require_test_database():
    parsed = TEST_URL.split("://", 1)[-1]
    database = parsed.rsplit("/", 1)[-1].split("?")[0]
    if "test" not in database.lower():
        pytest.skip(f"refusing to run against a non-test database {database!r}")


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory) -> dict:
    summary = tmp_path_factory.mktemp("pg") / "summary.json"
    script = tmp_path_factory.mktemp("pg") / "run.py"
    script.write_text(SCRIPT, encoding="utf-8")

    environment = {
        **os.environ,
        "TEST_DATABASE_URL": TEST_URL,
        "PYTHONPATH": str(BACKEND_DIR),
        # Keep the subprocess from inheriting an APP_ENV=test setting from pytest's env.
        "APP_ENV": "development",
    }
    completed = subprocess.run(
        [sys.executable, str(script), str(summary)],
        cwd=str(BACKEND_DIR),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        pytest.fail(
            "PostgreSQL pipeline failed:\nSTDOUT:\n"
            f"{completed.stdout[-4000:]}\nSTDERR:\n{completed.stderr[-6000:]}"
        )
    assert summary.exists(), completed.stderr[-2000:]
    return json.loads(summary.read_text(encoding="utf-8"))


def test_every_migration_applies_to_postgresql(pipeline):
    assert pipeline["steps"][0] == "register"


def test_the_pipeline_runs_end_to_end_on_postgresql(pipeline):
    assert pipeline["steps"] == ["register", "login", "device", "upload", "results", "report", "ai", "audit"]
    assert pipeline["security_score"] == 100
    assert pipeline["coverage"] == 100
    assert pipeline["control_count"] == 28
    assert pipeline["finding_count"] == 0
    assert pipeline["integrity_verified"] is True


def test_new_scans_are_version_stamped_on_postgresql(pipeline):
    assert pipeline["scoring_model_current"] is True
    assert pipeline["stored_scoring_model_version"] == "2.0.0"
    assert pipeline["stored_baseline_version"] == pipeline["baseline"]["version"]


def test_collector_health_survives_the_round_trip(pipeline):
    assert pipeline["collector_health"] in {"complete", "degraded"}


def test_reports_are_cached_and_conditional_on_postgresql(pipeline):
    assert pipeline["report_status"] == 200
    assert pipeline["report_bytes"] > 0
    assert pipeline["report_conditional_status"] == 304


def test_the_deterministic_path_works_without_an_ai_provider(pipeline):
    assert pipeline["ai_status"] == 200
    assert pipeline["ai_model_used"] == "local-rule-engine"


def test_privileged_actions_are_audited_on_postgresql(pipeline):
    assert pipeline["chain_valid"] is True
    for expected in (
        "auth.register",
        "auth.login.success",
        "device.create",
        "scan.upload",
        "user.role_change",
    ):
        assert expected in pipeline["audit_actions"], pipeline["audit_actions"]


def test_application_rows_are_visible_in_the_database(pipeline):
    stats = pipeline["stats"]
    assert stats["users"] >= 1
    assert stats["scans"] >= 1
    assert stats["audit_entries"] >= 1
    assert stats["database_bytes"] > 0


def test_the_list_contract_holds_on_postgresql(pipeline):
    assert pipeline["list_bytes"] < 50 * 1024
    assert pipeline["list_count"] >= 1


def test_the_subprocess_really_used_postgresql(pipeline):
    assert pipeline["dialect"] == "postgresql+psycopg"
