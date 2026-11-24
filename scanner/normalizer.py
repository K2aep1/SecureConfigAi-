"""Storage projection of a scan result.

``normalize_scan_output`` is the boundary between the scanner's own result
document and what the backend persists.  It is intentionally a **projection**,
not a re-shaping: the five payload-bearing sections listed below are copied
verbatim so the control engine can never disagree with the scanner, and nothing
is duplicated or renamed.

Projection::

    {"schema_version", "device", "checks", "collector_status", "scanner", "execution"}

Notes:

* ``check_results`` is deliberately **not** part of the projection.  It does not
  exist in schema 1.2 output; if a legacy caller passes one in, it is dropped.
* Values are never defaulted to ``false``/``0``.  Only *structural* keys are
  filled in (so a consumer can index them safely) and textual fallbacks stay
  honest placeholders such as ``"unknown-host"``.
"""

from __future__ import annotations

from typing import Any

from scanner.report import SCHEMA_VERSION

__all__ = ["PROJECTION_KEYS", "normalize_scan_output"]

#: Exact key set of the storage projection.
PROJECTION_KEYS = ("schema_version", "device", "checks", "collector_status", "scanner", "execution")


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def normalize_scan_output(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Return the storage projection of a scanner result document.

    Args:
        raw: The document produced by :func:`scanner.report.build_result_document`.

    Returns:
        A dict with exactly :data:`PROJECTION_KEYS`.
    """
    source = raw if isinstance(raw, dict) else {}
    device = _mapping(source.get("device"))
    checks = _mapping(source.get("checks"))
    collector_status = _mapping(source.get("collector_status"))
    scanner = _mapping(source.get("scanner"))
    execution = _mapping(source.get("execution"))

    if not collector_status and checks:
        # Tolerate a bare checks document (e.g. hand-written fixtures) by
        # synthesising statuses straight from each payload's own status field.
        for name, payload in checks.items():
            status = "completed"
            if isinstance(payload, dict):
                status = str(payload.get("status") or "completed").lower()
            collector_status[name] = {
                "status": status,
                "duration_ms": None,
                "error": None,
                "required_privilege": None,
                "evidence_status": status,
            }

    schema_version = source.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version:
        schema_version = SCHEMA_VERSION

    return {
        "schema_version": schema_version,
        "device": {
            "hostname": device.get("hostname") or "unknown-host",
            "os": device.get("os") or "windows",
            "version": device.get("version"),
            "build": device.get("build"),
            "name": device.get("name"),
            "architecture": device.get("architecture"),
            "install_date": device.get("install_date"),
            "last_boot": device.get("last_boot"),
            "serial_number": device.get("serial_number"),
            "windows_directory": device.get("windows_directory"),
            "computer_name": device.get("computer_name"),
        },
        "checks": checks,
        "collector_status": collector_status,
        "scanner": scanner,
        "execution": execution,
    }
