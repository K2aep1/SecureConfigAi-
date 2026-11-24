"""Scan job runner.

The scan takes tens of seconds to minutes. Running it inside the request would hold a
database session and a worker thread for the whole duration, so it runs here instead:

* ``POST /scans/start`` inserts a ``queued`` row and submits it to a bounded pool; the
  request returns immediately with ``202``.
* The worker streams the scanner's JSON progress lines, updating ``stage``/``progress``
  and a heartbeat, so the API can report live progress without a message broker.
* On startup, scans that were ``queued``/``running`` when the process died are marked
  ``failed`` Ã¢â‚¬â€ an interrupted scan must never masquerade as a running one.

Deliberately in-process: the deployment is a single node and this keeps setup to
"install and run". The interface (submit/cancel/recover) is the same one a Celery or RQ
implementation would expose, so moving to a broker later is a local change.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import SCANNER_DIR, settings
from app.core.database import session_scope
from app.core.timeutil import elapsed_ms
from app.db.models import Device, Scan, User
from app.services.scan_service import ingest_document

logger = logging.getLogger("secureconfigai.jobs")

SCANNER_MODULE = "scanner.cli"
PROGRESS_GRACE_SECONDS = 20


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ScanJobManager:
    def __init__(self, max_workers: int | None = None) -> None:
        self.max_workers = max_workers or settings.SCAN_JOB_WORKERS
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="scan-worker")
        self._running: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        self._queued = 0

    # ------------------------------------------------------------------ public API
    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._running)

    def submit(self, scan_id: uuid.UUID) -> None:
        self._pool.submit(self._run_scan, scan_id)

    def cancel(self, scan_id: uuid.UUID | str) -> bool:
        key = str(scan_id)
        with self._lock:
            process = self._running.get(key)
        if process is None:
            return False
        try:
            process.terminate()
        except Exception:  # pragma: no cover - best effort
            logger.warning("could not terminate scan process %s", key, exc_info=True)
            return False
        return True

    def shutdown(self, wait: bool = False) -> None:
        with self._lock:
            processes = list(self._running.values())
        for process in processes:
            try:
                process.terminate()
            except Exception:  # noqa: S110 - best effort during shutdown
                pass
        self._pool.shutdown(wait=wait, cancel_futures=True)

    def recover_stale(self, db: Session) -> int:
        """Fail scans that were interrupted (queued/running with no fresh heartbeat)."""
        if not settings.STARTUP_RECOVER_SCANS:
            return 0
        cutoff = _utcnow() - timedelta(seconds=settings.SCAN_STALE_AFTER_SECONDS)
        stale = [
            scan
            for scan in db.query(Scan).filter(Scan.status.in_(["queued", "running"])).all()
            if (scan.heartbeat_at or scan.started_at) is None
            or (scan.heartbeat_at or scan.started_at) < cutoff
        ]
        for scan in stale:
            scan.status = "failed"
            scan.stage = "Interrupted"
            scan.completed_at = _utcnow()
            scan.error_message = (
                "The service stopped while this assessment was running. Start a new assessment."
            )
        if stale:
            db.commit()
            logger.warning("marked %d interrupted scan(s) as failed", len(stale))
        return len(stale)

    # ------------------------------------------------------------------ internals
    def _command(self, output_dir: Path, inventory: bool, collectors: list[str] | None) -> list[str]:
        command = [
            sys.executable,
            "-m",
            SCANNER_MODULE,
            "--output",
            str(output_dir),
            "--progress-json",
            "--budget-seconds",
            str(settings.SCAN_BUDGET_SECONDS),
            "--parallel",
            str(settings.SCAN_PARALLEL),
        ]
        command.append("--inventory" if inventory else "--no-inventory")
        command.append("--elevate" if settings.SCANNER_ELEVATE else "--no-elevate")
        if collectors:
            command += ["--collectors", ",".join(collectors)]
        return command

    def _run_scan(self, scan_id: uuid.UUID) -> None:
        output_dir = Path(tempfile.mkdtemp(prefix="secureconfigai_scan_"))
        process: subprocess.Popen | None = None
        try:
            with session_scope() as db:
                scan = db.get(Scan, scan_id)
                if scan is None:
                    logger.warning("scan %s disappeared before it started", scan_id)
                    return
                if scan.status == "cancelled":
                    return
                inventory = settings.SCAN_INVENTORY
                collectors = None
                raw_params = (scan.raw_data or {}) if isinstance(scan.raw_data, dict) else {}
                if isinstance(raw_params.get("inventory"), bool):
                    inventory = raw_params["inventory"]
                if isinstance(raw_params.get("collectors"), list):
                    collectors = [str(c) for c in raw_params["collectors"]]

                scan.status = "running"
                scan.stage = "Starting collector"
                scan.progress = 1
                scan.heartbeat_at = _utcnow()
                scan.worker_id = f"worker-{os.getpid()}"
                db.commit()

            command = self._command(output_dir, inventory, collectors)
            logger.info("scan %s: %s", scan_id, " ".join(command[1:]))
            creation_flags = 0
            if platform.system().lower() == "windows":
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            process = subprocess.Popen(
                command,
                cwd=str(SCANNER_DIR.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creation_flags,
            )
            with self._lock:
                self._running[str(scan_id)] = process

            # A cancellation that arrives between the status write and process creation
            # would otherwise be lost, leaving an orphaned child for the whole budget.
            with session_scope() as db:
                current = db.get(Scan, scan_id)
                if current is not None and current.status == "cancelled":
                    process.terminate()

            self._pump_progress(scan_id, process)
            return_code = process.wait(timeout=PROGRESS_GRACE_SECONDS)
            stderr_tail = ""
            if process.stderr is not None:
                stderr_tail = (process.stderr.read() or "")[-2000:]

            if return_code != 0:
                self._fail(
                    scan_id,
                    f"scanner exited with code {return_code}"
                    + (f": {stderr_tail.strip()}" if stderr_tail.strip() else ""),
                )
                return

            result_file = output_dir / "scan_result.json"
            if not result_file.exists():
                self._fail(scan_id, "scanner produced no scan_result.json")
                return

            document = json.loads(result_file.read_text(encoding="utf-8"))
            self._finish(scan_id, document, result_file)

        except subprocess.TimeoutExpired:
            self._fail(scan_id, "scanner did not exit after producing its result")
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan %s failed", scan_id)
            self._fail(scan_id, f"{type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                self._running.pop(str(scan_id), None)
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except Exception:  # noqa: S110 - best effort after the budget expired
                    pass
            shutil.rmtree(output_dir, ignore_errors=True)

    def _pump_progress(self, scan_id: uuid.UUID, process: subprocess.Popen) -> None:
        """Read the scanner's JSON progress lines and mirror them into the scan row."""
        if process.stdout is None:
            return
        last_write = 0.0
        import time

        for line in process.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            percent = event.get("percent")
            stage = str(event.get("stage") or "")[:120]
            now = time.monotonic()
            if now - last_write < 0.4 and event.get("event") not in {"done", "error"}:
                continue
            last_write = now
            try:
                with session_scope() as db:
                    scan = db.get(Scan, scan_id)
                    if scan is None or scan.status == "cancelled":
                        continue
                    if isinstance(percent, (int, float)):
                        scan.progress = max(scan.progress or 0, min(100, int(percent)))
                    if stage:
                        scan.stage = stage
                    scan.heartbeat_at = _utcnow()
            except Exception:  # pragma: no cover - progress must never break the scan
                logger.warning("could not persist progress for scan %s", scan_id, exc_info=True)

    def _resolve_scan_device(
        self, db: Session, scan: Scan, document: dict[str, Any], user: User | None
    ) -> Device | None:
        """Resolve the scanned host to a user-owned device record.

        A live scan may start without ``device_id``. In that case the scanner's
        ``device.hostname`` is the source of truth for associating the completed
        assessment with an existing (or newly registered) device.
        """
        if scan.device_id is not None:
            return db.get(Device, scan.device_id)

        device_info = document.get("device") if isinstance(document.get("device"), dict) else {}
        hostname = str(device_info.get("hostname") or "").strip()
        if not hostname or hostname.lower() in {"unknown-host", "unknown host"}:
            logger.warning("scan %s has no usable hostname in scanner output; leaving it unlinked", scan.id)
            return None

        device = (
            db.query(Device).filter(Device.user_id == scan.user_id, Device.hostname == hostname).one_or_none()
        )
        os_type = str(device_info.get("os") or "windows")[:32]
        os_version = str(device_info.get("version") or "")[:64] or None
        os_build = str(device_info.get("build") or "")[:64] or None

        if device is None:
            device = Device(
                user_id=scan.user_id,
                hostname=hostname[:255],
                os_type=os_type,
                os_version=os_version,
                os_build=os_build,
                criticality=settings.SCAN_DEFAULT_CRITICALITY,
            )
            db.add(device)
            db.flush()
            audit.record(
                db,
                "device.create",
                actor=user,
                entity_type="device",
                entity_id=device.id,
                details={
                    "hostname": device.hostname,
                    "source": "local_agent_scan",
                    "scan_id": str(scan.id),
                },
                commit=False,
            )
        else:
            if os_type:
                device.os_type = os_type
            if os_version:
                device.os_version = os_version
            if os_build:
                device.os_build = os_build

        scan.device_id = device.id
        logger.info("linked scan %s to device %s (hostname=%s)", scan.id, device.id, device.hostname)
        return device

    def _finish(self, scan_id: uuid.UUID, document: dict[str, Any], result_file: Path) -> None:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status == "cancelled":
                return
            user = db.get(User, scan.user_id)
            device = self._resolve_scan_device(db, scan, document, user)

            scanner_meta = document.get("scanner") if isinstance(document.get("scanner"), dict) else {}
            scan.scanner_version = str(scanner_meta.get("version") or "")[:32] or None
            scan.evidence_bytes = result_file.stat().st_size
            scan.status = "running"
            scan.stage = "Scoring evidence"
            scan.progress = 95
            db.commit()

            ingest_document(db, scan, document, device=device, user=user)

            scan.completed_at = _utcnow()
            scan.duration_ms = elapsed_ms(scan.started_at, scan.completed_at)
            scan.progress = 100
            scanner_status = str(scanner_meta.get("status") or "completed")
            if scanner_status == "failed":
                scan.status = "failed"
                scan.stage = "Scanner failed"
                scan.error_message = str(scanner_meta.get("error") or "scanner reported failure")[:2000]
            else:
                scan.status = "completed"
                partial = scanner_status == "completed_with_errors"
                scan.stage = "Completed with degraded evidence" if partial else "Completed"
                if partial:
                    scan.error_message = (
                        f"{scanner_meta.get('errors', 0)} collector error(s), "
                        f"{scanner_meta.get('timeouts', 0)} timeout(s), "
                        f"{scanner_meta.get('skipped', 0)} skipped"
                    )
            scan.heartbeat_at = scan.completed_at
            db.commit()

            audit.record(
                db,
                "scan.complete" if scan.status == "completed" else "scan.fail",
                actor=user,
                entity_type="scan",
                entity_id=scan.id,
                outcome=scan.status,
                details={
                    "duration_ms": scan.duration_ms,
                    "scanner_status": scanner_status,
                    "evidence_bytes": scan.evidence_bytes,
                },
            )
        self._maybe_generate_reports(scan_id)

    def _maybe_generate_reports(self, scan_id: uuid.UUID) -> None:
        """Pre-generate HTML and PDF so repeat views are a cache hit."""
        if not settings.REPORT_CACHE_ENABLED:
            return
        try:
            from app.services.report_service import ensure_reports

            with session_scope() as db:
                scan = db.get(Scan, scan_id)
                if scan is not None and scan.status == "completed":
                    ensure_reports(db, scan)
        except Exception:  # pragma: no cover - reports must not fail a scan
            logger.warning("report pre-generation failed for scan %s", scan_id, exc_info=True)

    def _fail(self, scan_id: uuid.UUID, message: str) -> None:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status == "cancelled":
                return
            scan.status = "failed"
            scan.stage = "Failed"
            scan.completed_at = _utcnow()
            scan.heartbeat_at = scan.completed_at
            scan.error_message = message[:2000]
            scan.duration_ms = elapsed_ms(scan.started_at, scan.completed_at)
            user = db.get(User, scan.user_id)
            db.commit()
            audit.record(
                db,
                "scan.fail",
                actor=user,
                entity_type="scan",
                entity_id=scan.id,
                outcome="failure",
                details={"error": message[:500]},
            )


manager = ScanJobManager()
