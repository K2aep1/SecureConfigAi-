"""Strict value coercion and evidence-shaping helpers.

The whole point of this module is spec section 2 rule 3: *never substitute*
``false`` *for "unknown"*.  Exactly one helper decides truth, and it answers
``None`` whenever the input is not unambiguously boolean:

    >>> coerce_bool(True), coerce_bool("1"), coerce_bool("Off")
    (True, True, False)
    >>> coerce_bool("unknown"), coerce_bool(None), coerce_bool(2)
    (None, None, None)

Note the deliberate asymmetry with :func:`is_true`, which is only for *internal*
derivations where a sentinel already proves the value was read.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, TypeVar

__all__ = [
    "as_int",
    "as_str",
    "carry_status",
    "coerce_bool",
    "configured",
    "count_of",
    "first_dict",
    "is_true",
    "one_or_many",
    "reg_state",
]

#: Statuses a payload may report, per spec section 2 rule 4.
PAYLOAD_STATUSES = frozenset({"completed", "unavailable", "skipped", "timeout", "error"})

T = TypeVar("T")

_TRUE_WORDS = frozenset({"1", "true", "on", "yes", "enabled"})
_FALSE_WORDS = frozenset({"0", "false", "off", "no", "disabled"})


def coerce_bool(value: Any) -> bool | None:
    """Return ``True``/``False`` only for unambiguous truth, else ``None``.

    Accepted: real ``bool``, integers ``0``/``1``, floats ``0.0``/``1.0``, and
    the case-insensitive strings ``0/1/false/true/no/yes/off/on/disabled/enabled``
    with surrounding whitespace ignored.

    Everything else — including ``None``, ``""``, ``"unknown"``, ``"N/A"``,
    ``-1`` and any other number — yields ``None`` so the backend records the
    control as ``unknown`` instead of silently compliant/non-compliant.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, int):
        if value == 0:
            return False
        if value == 1:
            return True
        return None
    if isinstance(value, float):
        if value == 0.0:
            return False
        if value == 1.0:
            return True
        return None
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE_WORDS:
            return True
        if token in _FALSE_WORDS:
            return False
    return None


def is_true(value: Any) -> bool:
    """Internal derivation helper: ``coerce_bool(value) is True``.

    Use this where the surrounding code has *already* established that the
    evidence was readable; it never manufactures truth from ``None``.
    """
    return coerce_bool(value) is True


def as_int(value: Any) -> int | None:
    """Return an ``int`` for int-like input, else ``None``.

    Bool is rejected on purpose (a boolean is not a count).  Strings must parse
    cleanly as a base-10 integer; ``"12 days"`` yields ``None`` rather than 12.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        token = value.strip()
        try:
            return int(token)
        except ValueError:
            return None
    return None


def as_str(value: Any) -> str | None:
    """Return a stripped string, or ``None`` when there is nothing to report."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def configured(value: Any) -> bool:
    """``True`` when a value was actually read (not ``None``)."""
    return value is not None


def reg_state(observed: Any, name: str) -> dict[str, Any]:
    """Return a tri-state registry observation without confusing denied reads
    with absent values.

    ``readable=True, exists=False`` means the value was successfully checked
    and is not configured. ``readable=False`` means the query failed; in that
    case ``configured`` is ``None`` and the evidence must remain unknown.
    Legacy ``exists``-only observations remain supported.
    """
    if not isinstance(observed, dict):
        return {"readable": False, "configured": None, "value": None,
                "error": "registry observation missing"}
    readable = observed.get("readable")
    if readable is None:
        # Backward compatibility: old scripts only emitted exists.
        readable = isinstance(observed.get("exists"), bool)
    if readable is not True:
        return {"readable": False, "configured": None, "value": None,
                "error": as_str(observed.get("error")) or "registry value could not be read"}
    exists = observed.get("exists") is True
    return {"readable": True, "configured": exists,
            "value": observed.get("value") if exists else None, "error": None}


def one_or_many(value: Any) -> list[Any]:
    """Normalise PowerShell's object/array ambiguity into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_dict(values: Iterable[Any]) -> dict[str, Any]:
    """First mapping in ``values``, else an empty mapping."""
    for item in values:
        if isinstance(item, dict):
            return item
    return {}


def count_of(value: Any) -> int | None:
    """Length of a list value, or ``None`` when the value was not a list."""
    if isinstance(value, list):
        return len(value)
    return None


def carry_status(
    payload: dict[str, Any],
    raw: dict[str, Any],
    *,
    default_reason: str,
) -> dict[str, Any]:
    """Copy a non-``completed`` status (and its reason) from a raw PS result.

    Collectors rebuild their payload key by key, which would otherwise silently
    drop the ``status``/``error`` pair the PowerShell program reported.  Spec
    section 2 rule 6 requires that pair to survive whenever a collector cannot
    vouch for its evidence.
    """
    status = str(raw.get("status") or "completed").strip().lower()
    if status == "completed":
        return payload
    if status not in PAYLOAD_STATUSES:
        status = "error"
    payload["status"] = status
    payload["error"] = (as_str(raw.get("error")) or
                        as_str(raw.get("probe_error")) or default_reason)
    return payload
