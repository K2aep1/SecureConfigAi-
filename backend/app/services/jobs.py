"""Scan job runner.

A live assessment takes tens of seconds to minutes. Running it inside the request would
hold a database session and a worker thread for that whole time, so it runs here:

* ``POST /scans/start`` inserts a ``queued`` row and submits it to a bounded pool. The
  request returns immediately with ``202``.
* The worker streams the scanner's JSON progress lines into ``stage``, ``progress`` and
  a heartbeat, so the API can report live progress without a message broker.
* A watchdog enforces a hard wall-clock deadline, so a scanner that stops writing
  output cannot hold a worker forever.
* On startup, scans that were ``queued`` or ``running`` when the process died are marked
  ``failed``. An interrupted scan must never look like a running one.

Cancellation and completion are serialised on the scan row with ``SELECT ... FOR UPDATE``
(where the database supports it), so a late worker write cannot overwrite a cancellation.

The module runs in-process on purpose: the deployment is a single node, and this keeps
setup to "install and run". The interface (submit, cancel, recover) is the one a Celery
or RQ implementation would expose, so moving to a broker later is a local change.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import EVIDENCE_DIR, SCANNER_DIR, settings
from app.core.database import session_scope
from app.core.timeutil import elapsed_ms
from app.db.models import Device, Scan, User
from app.services.scan_service import (
    document_evidence_bytes,
    effective_for_device,
    ingest_document,
    project_document,
)

logger = logging.getLogger("secureconfigai.jobs")

SCANNER_MODULE = "scanner.cli"
PROGRESS_GRACE_SECONDS = 20
HARD_DEADLINE_MARGIN_SECONDS = 60
PROGRESS_WRITE_INTERVAL_SECONDS = 0.4
STDERR_TAIL_CHARS = 2000
ACTIVE_STATUSES = ("queued", "running")
UNLINKED_HOSTNAMES = frozenset({"unknown-host", "unknown host"})


# --------------------------------------------------------------------------- helpers
def _utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes. Treat them as UTC before comparing."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _hard_deadline_seconds() -> float:
    """Upper bound on one scanner process, including its own budget and exit grace."""
    return float(settings.SCAN_BUDGET_SECONDS + PROGRESS_GRACE_SECONDS + HARD_DEADLINE_MARGIN_SECONDS)


def _creation_flags() -> int:
    if platform.system().lower() != "windows":
        return 0
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _read_tail(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-STDERR_TAIL_CHARS:].strip()
    except OSError:
        return ""


def _store_raw_evidence(scan_id: uuid.UUID, document: dict[str, Any]) -> str:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"{scan_id}.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(document, handle, default=str, separators=(",", ":"))
    return str(path)


def _close_quietly(handle: TextIO | None) -> None:
    if handle is None:
        return
    try:
        handle.close()
    except OSError:
        pass


def _kill_quietly(process: subprocess.Popen) -> None:
    try:
        if process.poll() is None:
            process.kill()
    except OSError:
        pass


# --------------------------------------------------------------------------- manager
class ScanJobManager:
    def __init__(self, max_workers: int | None = None) -> None:
        self.max_workers = max_workers or settings.SCAN_JOB_WORKERS
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="scan-worker")
        self._running: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ public API
    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._running)

    def submit(self, scan_id: uuid.UUID) -> None:
        self._pool.submit(self._run_scan, scan_id)

    def cancel(self, scan_id: uuid.UUID | str) -> bool:
        """Terminate the scanner process for a scan, if one is running.

        The caller is responsible for writing the ``cancelled`` status. The worker
        re-reads that status before it writes anything, so a late result cannot
        overwrite it.
        """
        key = str(scan_id)
        with self._lock:
            process = self._running.get(key)
        if process is None:
            return False
        try:
            process.terminate()
        except OSError:
            logger.warning("could not terminate scan process %s", key, exc_info=True)
            return False
        return True

    def shutdown(self, wait: bool = False) -> None:
        with self._lock:
            processes = list(self._running.values())
        for process in processes:
            try:
                process.terminate()
            except OSError:
                pass
        self._pool.shutdown(wait=wait, cancel_futures=True)

    def recover_stale(self, db: Session) -> int:
        """Fail scans that were interrupted: queued or running with no recent heartbeat."""
        if not settings.STARTUP_RECOVER_SCANS:
            return 0

        now = _utcnow()
        cutoff = now - timedelta(seconds=settings.SCAN_STALE_AFTER_SECONDS)
        active = db.execute(select(Scan).where(Scan.status.in_(ACTIVE_STATUSES))).scalars()
        stale: list[Scan] = []
        for scan in active:
            last_seen = _aware(scan.heartbeat_at or scan.started_at)
            if last_seen is None or last_seen < cutoff:
                stale.append(scan)

        for scan in stale:
            scan.status = "failed"
            scan.stage = "Interrupted"
            scan.completed_at = now
            scan.heartbeat_at = now
            scan.error_message = (
                "The service stopped while this assessment was running. Start a new assessment."
            )
        if stale:
            db.commit()
            logger.warning("marked %d interrupted scan(s) as failed", len(stale))
        return len(stale)

    # ------------------------------------------------------------------ command
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
            "--inventory" if inventory else "--no-inventory",
            "--elevate" if settings.SCANNER_ELEVATE else "--no-elevate",
        ]
        if collectors:
            command += ["--collectors", ",".join(collectors)]
        return command

    # ------------------------------------------------------------------ run
    def _run_scan(self, scan_id: uuid.UUID) -> None:
        key = str(scan_id)
        output_dir = Path(tempfile.mkdtemp(prefix="secureconfigai_scan_"))
        stderr_path = output_dir / "scanner.stderr.log"
        process: subprocess.Popen | None = None
        stderr_handle: TextIO | None = None
        watchdog: threading.Timer | None = None
        expired = threading.Event()

        try:
            claimed = self._claim(scan_id)
            if claimed is None:
                return
            inventory, collectors = claimed

            # Stderr goes to a file, not a pipe. A pipe nobody drains can fill up, block
            # the scanner, and deadlock the stdout loop that is waiting for it to finish.
            stderr_handle = stderr_path.open("w", encoding="utf-8", errors="replace")
            process = subprocess.Popen(
                self._command(output_dir, inventory, collectors),
                cwd=str(SCANNER_DIR.parent),
                stdout=subprocess.PIPE,
                stderr=stderr_handle,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=_creation_flags(),
            )
            with self._lock:
                self._running[key] = process

            watchdog = self._arm_watchdog(scan_id, process, expired)

            # Cancellation can arrive between the status write and the Popen call.
            # Without this check the child would run for its full budget.
            if self._status(scan_id) == "cancelled":
                process.terminate()

            self._pump_progress(scan_id, process)
            return_code = process.wait(timeout=PROGRESS_GRACE_SECONDS)
            _close_quietly(stderr_handle)
            stderr_handle = None

            if return_code != 0:
                if expired.is_set():
                    self._fail(scan_id, "The assessment exceeded its time limit and was stopped.")
                    return
                tail = _read_tail(stderr_path)
                message = f"scanner exited with code {return_code}"
                self._fail(scan_id, f"{message}: {tail}" if tail else message)
                return

            result_file = output_dir / "scan_result.json"
            if not result_file.exists():
                self._fail(scan_id, "scanner produced no scan_result.json")
                return

            document = json.loads(result_file.read_text(encoding="utf-8"))
            self._finish(scan_id, document, result_file)

        except subprocess.TimeoutExpired:
            self._fail(scan_id, "scanner did not exit after producing its result")
        except json.JSONDecodeError:
            self._fail(scan_id, "scanner produced invalid JSON")
        except Exception as exc:  # defensive: the worker must always reach a terminal state
            logger.exception("scan %s failed", scan_id)
            self._fail(scan_id, f"{type(exc).__name__}: {exc}")
        finally:
            if watchdog is not None:
                watchdog.cancel()
            with self._lock:
                self._running.pop(key, None)
            if process is not None:
                _kill_quietly(process)
                _close_quietly(process.stdout)
            _close_quietly(stderr_handle)
            shutil.rmtree(output_dir, ignore_errors=True)

    def _claim(self, scan_id: uuid.UUID) -> tuple[bool, list[str] | None] | None:
        """Move a queued scan to running. Returns its parameters, or None if it must not start.

        Only ``queued`` scans start. A scan that was cancelled while it waited in the pool,
        or failed during recovery, is skipped. The row lock keeps a concurrent cancel from
        interleaving with the transition.
        """
        with session_scope() as db:
            scan = db.get(Scan, scan_id, with_for_update=True)
            if scan is None:
                logger.warning("scan %s disappeared before it started", scan_id)
                return None
            if scan.status != "queued":
                logger.info("scan %s is %s; not starting it", scan_id, scan.status)
                return None

            params = scan.raw_data if isinstance(scan.raw_data, dict) else {}
            inventory = (
                params["inventory"] if isinstance(params.get("inventory"), bool) else settings.SCAN_INVENTORY
            )
            collectors = (
                [str(c) for c in params["collectors"]] if isinstance(params.get("collectors"), list) else None
            )

            now = _utcnow()
            scan.status = "running"
            scan.stage = "Starting collector"
            scan.progress = 1
            scan.started_at = scan.started_at or now
            scan.heartbeat_at = now
            scan.worker_id = f"worker-{os.getpid()}"
            db.commit()
            return inventory, collectors

    def _status(self, scan_id: uuid.UUID) -> str | None:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            return scan.status if scan is not None else None

    def _arm_watchdog(
        self, scan_id: uuid.UUID, process: subprocess.Popen, expired: threading.Event
    ) -> threading.Timer:
        """Kill the scanner if it outlives its hard deadline, whatever it is doing."""

        def expire() -> None:
            logger.warning("scan %s exceeded its hard deadline; stopping the scanner", scan_id)
            expired.set()
            _kill_quietly(process)

        timer = threading.Timer(_hard_deadline_seconds(), expire)
        timer.daemon = True
        timer.start()
        return timer

    # ------------------------------------------------------------------ progress
    def _pump_progress(self, scan_id: uuid.UUID, process: subprocess.Popen) -> None:
        """Read the scanner's JSON progress lines and mirror them into the scan row."""
        if process.stdout is None:
            return
        last_write = 0.0
        for raw_line in process.stdout:
            line = raw_line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue

            terminal = event.get("event") in {"done", "error"}
            now = time.monotonic()
            if not terminal and now - last_write < PROGRESS_WRITE_INTERVAL_SECONDS:
                continue
            last_write = now
            self._apply_progress(scan_id, event)

    def _apply_progress(self, scan_id: uuid.UUID, event: dict[str, Any]) -> None:
        percent = event.get("percent")
        stage = str(event.get("stage") or "")[:120]
        try:
            with session_scope() as db:
                scan = db.get(Scan, scan_id)
                if scan is None or scan.status != "running":
                    return
                if isinstance(percent, (int, float)) and not isinstance(percent, bool):
                    scan.progress = max(scan.progress or 0, min(100, int(percent)))
                if stage:
                    scan.stage = stage
                scan.heartbeat_at = _utcnow()
        except Exception:  # progress must never break the scan
            logger.warning("could not persist progress for scan %s", scan_id, exc_info=True)

    # ------------------------------------------------------------------ device link
    def _resolve_scan_device(
        self, db: Session, scan: Scan, document: dict[str, Any], user: User | None
    ) -> Device | None:
        """Link the completed assessment to a device owned by the scan's user.

        A live scan may start without ``device_id``. The scanner's hostname is then the
        source of truth, and a device is created for it if none exists.
        """
        if scan.device_id is not None:
            return db.get(Device, scan.device_id)

        device_info = document.get("device") if isinstance(document.get("device"), dict) else {}
        hostname = str(device_info.get("hostname") or "").strip()[:255]
        if not hostname or hostname.lower() in UNLINKED_HOSTNAMES:
            logger.warning("scan %s has no usable hostname in scanner output; leaving it unlinked", scan.id)
            return None

        os_type = str(device_info.get("os") or "windows")[:32]
        os_version = str(device_info.get("version") or "")[:64] or None
        os_build = str(device_info.get("build") or "")[:64] or None

        # Case-insensitive, matching the devices module. Windows hostnames are not case-sensitive.
        device = db.execute(
            select(Device).where(
                Device.user_id == scan.user_id,
                func.lower(Device.hostname) == hostname.lower(),
            )
        ).scalar_one_or_none()

        if device is None:
            device = Device(
                user_id=scan.user_id,
                hostname=hostname,
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
                details={"hostname": device.hostname, "source": "local_agent_scan", "scan_id": str(scan.id)},
                commit=False,
            )
        else:
            device.os_type = os_type or device.os_type
            device.os_version = os_version or device.os_version
            device.os_build = os_build or device.os_build

        scan.device_id = device.id
        logger.info("linked scan %s to device %s", scan.id, device.id)
        return device

    # ------------------------------------------------------------------ terminal states
    def _finish(self, scan_id: uuid.UUID, document: dict[str, Any], result_file: Path) -> None:
        with session_scope() as db:
            # The row lock serialises this write with a concurrent cancel.
            scan = db.get(Scan, scan_id, with_for_update=True)
            if scan is None or scan.status == "cancelled":
                return
            user = db.get(User, scan.user_id)
            device = self._resolve_scan_device(db, scan, document, user)

            scanner_meta = document.get("scanner") if isinstance(document.get("scanner"), dict) else {}
            scanner_status = str(scanner_meta.get("status") or "completed")
            scan.scanner_version = str(scanner_meta.get("version") or "")[:32] or None
            scan.evidence_bytes = result_file.stat().st_size

            # The same projection the upload path stores, so the document view and reassess
            # work the same way for live and offline scans.
            effective = effective_for_device(db, device)
            projection = project_document(document, effective)
            scan.normalized_data = projection
            if settings.STORE_RAW_EVIDENCE or document_evidence_bytes(projection) > settings.MAX_STORED_EVIDENCE_BYTES:
                scan.uploaded_file_path = _store_raw_evidence(scan.id, document)

            scan.status = "running"
            scan.stage = "Scoring evidence"
            scan.progress = 95
            db.commit()

            ingest_document(db, scan, document, device=device, user=user)

            now = _utcnow()
            scan.completed_at = now
            scan.duration_ms = elapsed_ms(scan.started_at, scan.completed_at)
            scan.heartbeat_at = now
            scan.progress = 100

            if scanner_status == "failed":
                scan.status = "failed"
                scan.stage = "Scanner failed"
                scan.error_message = str(scanner_meta.get("error") or "scanner reported failure")[:2000]
            else:
                scan.status = "completed"
                degraded = scanner_status == "completed_with_errors"
                scan.stage = "Completed with degraded evidence" if degraded else "Completed"
                if degraded:
                    scan.error_message = (
                        f"{scanner_meta.get('errors', 0)} collector error(s), "
                        f"{scanner_meta.get('timeouts', 0)} timeout(s), "
                        f"{scanner_meta.get('skipped', 0)} skipped"
                    )
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
            completed = scan.status == "completed"

        if completed:
            self._maybe_generate_reports(scan_id)

    def _maybe_generate_reports(self, scan_id: uuid.UUID) -> None:
        """Pre-generate HTML and PDF so the first report view is a cache hit."""
        if not settings.REPORT_CACHE_ENABLED:
            return
        try:
            from app.services.report_service import ensure_reports

            with session_scope() as db:
                scan = db.get(Scan, scan_id)
                if scan is not None and scan.status == "completed":
                    ensure_reports(db, scan)
        except Exception:  # reports must not fail a scan
            logger.warning("report pre-generation failed for scan %s", scan_id, exc_info=True)

    def _fail(self, scan_id: uuid.UUID, message: str) -> None:
        with session_scope() as db:
            scan = db.get(Scan, scan_id, with_for_update=True)
            if scan is None or scan.status == "cancelled":
                return
            now = _utcnow()
            scan.status = "failed"
            scan.stage = "Failed"
            scan.completed_at = now
            scan.heartbeat_at = now
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