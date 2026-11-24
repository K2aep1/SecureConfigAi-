"""Assembly of the ``scan_result.json`` document.

The result document is the producer side of the frozen contract: a single,
compact, non-duplicated JSON object whose every collector payload appears
exactly once under ``checks.<collector>``.

Schema shape (spec section 2)::

    schema_version, format, snapshot_id, created_at,
    scanner{...}, execution{...}, device{...}, checks{...},
    collector_status{...}

``collector_status`` is a compact status map.  It never embeds a payload and
there is no ``check_results`` section: the previous implementation duplicated
every payload up to four times, which is exactly what this module exists to
prevent.
"""

from __future__ import annotations

import platform
import socket
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from scanner.base.collector import BaseCollector, CollectorResult

__all__ = ["SCHEMA_VERSION", "ScanSummary", "build_result_document", "new_snapshot_id"]

#: Frozen output schema version implemented by this scanner.
SCHEMA_VERSION = "1.2"

FORMAT = "SecureConfigAI Configuration Snapshot"


def new_snapshot_id() -> str:
    """Snapshot identifier in the documented ``SCFG-yyyymmdd-<hex>`` form."""
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return f"SCFG-{stamp}-{uuid.uuid4().hex[:12].upper()}"


@dataclass
class ScanSummary:
    """Counts and timing rolled up over one scan."""

    collector_count: int = 0
    completed: int = 0
    unavailable: int = 0
    errors: int = 0
    timeouts: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    budget_seconds: float = 120.0
    inventory: bool = False

    @classmethod
    def from_results(cls, results: Mapping[str, CollectorResult]) -> ScanSummary:
        summary = cls(collector_count=len(results))
        for result in results.values():
            status = result.status
            if status == "completed":
                summary.completed += 1
            elif status == "skipped":
                summary.skipped += 1
            elif status == "timeout":
                summary.timeouts += 1
            elif status == "unavailable":
                summary.unavailable += 1
            else:
                summary.errors += 1
        return summary

    @property
    def status(self) -> str:
        """``completed`` unless a collector failed or was cut short."""
        if self.errors or self.timeouts or self.skipped or self.unavailable:
            return "completed_with_errors"
        if self.completed == 0 and self.collector_count:
            return "failed"
        return "completed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "collector_count": self.collector_count,
            "completed": self.completed,
            "errors": self.errors,
            "timeouts": self.timeouts,
            "skipped": self.skipped,
            "unavailable": self.unavailable,
            "duration_seconds": self.duration_seconds,
            "budget_seconds": self.budget_seconds,
            "inventory": self.inventory,
        }


def _execution_context() -> dict[str, Any]:
    """Best-effort description of the process that produced the scan."""
    import ctypes
    import getpass

    is_admin = False
    if platform.system().lower() == "windows":
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            is_admin = False
    try:
        user = getpass.getuser()
    except (OSError, KeyError):  # pragma: no cover - unusual service contexts
        user = None
    return {
        "user": user,
        "is_admin": is_admin,
        "integrity_level": "high" if is_admin else "medium",
        "elevation_requested": False,
        "platform": platform.platform(),
    }


def build_result_document(
    results: Mapping[str, CollectorResult],
    *,
    execution: Mapping[str, Any] | None = None,
    device: Mapping[str, Any] | None = None,
    summary: ScanSummary | None = None,
    started_at: str,
    completed_at: str,
    inventory: bool = False,
    budget_seconds: float = 120.0,
    collectors: list[BaseCollector] | None = None,
) -> dict[str, Any]:
    """Build the complete, compact result document.

    Args:
        results: Ordered mapping of collector name to its outcome.
        execution: Execution context (merged over the auto-detected one).
        device: Device evidence, normally ``results["device"]`` payload.
        summary: Pre-computed counts; derived from ``results`` when omitted.
        started_at / completed_at: ISO-8601 UTC timestamps.
        inventory: Whether inventory collectors were included.
        budget_seconds: The wall-clock budget the run was given.
        collectors: Collector objects, used for the stage label fallback.
    """
    summary = summary or ScanSummary.from_results(results)
    summary.duration_seconds = _duration_seconds(started_at, completed_at)
    summary.budget_seconds = float(budget_seconds)
    summary.inventory = bool(inventory)

    collected_device = dict(device or {})
    collected_device.setdefault("hostname", socket.gethostname())
    collected_device.setdefault("os", "windows")
    if not collected_device.get("version"):
        collected_device["version"] = platform.version() or None
    if not collected_device.get("build"):
        collected_device["build"] = platform.release() or None
    for key in (
        "name",
        "architecture",
        "install_date",
        "last_boot",
        "serial_number",
        "windows_directory",
        "computer_name",
    ):
        collected_device.setdefault(key, None)

    merged_execution = {**_execution_context(), **(execution or {})}
    merged_execution["started_at"] = started_at
    merged_execution["completed_at"] = completed_at

    checks: dict[str, Any] = {}
    collector_status: dict[str, Any] = {}
    for name, result in results.items():
        checks[name] = result.check_payload()
        collector_status[name] = result.status_entry()

    return {
        "schema_version": SCHEMA_VERSION,
        "format": FORMAT,
        "snapshot_id": new_snapshot_id(),
        "created_at": completed_at,
        "scanner": {
            "name": "SecureConfigAI Scanner",
            "version": SCHEMA_VERSION,
            "platform": platform.system().lower(),
            **summary.as_dict(),
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "execution": merged_execution,
        "device": collected_device,
        "checks": checks,
        "collector_status": collector_status,
    }


def _duration_seconds(started_at: str, completed_at: str) -> float:
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(completed_at)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, (end - start).total_seconds()), 3)
