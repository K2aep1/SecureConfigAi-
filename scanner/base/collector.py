"""Collector interface and bounded parallel orchestrator.

This module defines the two pieces of the scanner that every evidence source
depends on:

``BaseCollector``
    The frozen collector interface.  A collector owns exactly one Windows
    evidence domain, knows whether it needs administrator rights, whether it is
    inventory-only (and therefore excluded from a default scan), and which keys
    the backend control engine reads out of its payload.

``ScannerOrchestrator``
    Runs collectors in a bounded :class:`~concurrent.futures.ThreadPoolExecutor`
    under a shared wall-clock budget.  Collectors are subprocess-bound, so
    threads (not processes) are the right concurrency primitive; the GIL is
    released while the PowerShell child runs.

Two invariants matter to the consumer contract:

1. **Determinism.**  Results are merged in the fixed collector order that was
   supplied, never in completion order, so the written JSON is byte-stable for
   a given set of evidence values.
2. **Budget honesty.**  The orchestrator never lets the whole run overrun the
   budget by more than one collector timeout, and records everything it did not
   run as ``status: "skipped"`` with the reason attached.
"""

from __future__ import annotations

import queue
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import monotonic
from typing import Any

__all__ = [
    "BaseCollector",
    "CollectorError",
    "CollectorResult",
    "CollectorUnavailable",
    "ProgressEvent",
    "ScannerOrchestrator",
]

#: Statuses a collector result may carry, per spec section 2 rule 4.
VALID_STATUSES = frozenset({"completed", "unavailable", "skipped", "timeout", "error"})

#: Upper bound for a single collector's timeout.  Keeps one pathological
#: collector from eating an entire budget even when the pool is idle.
MAX_COLLECTOR_TIMEOUT = 60.0

#: Floor for a single collector's timeout; below this a PowerShell start-up
#: alone would guarantee a bogus timeout.
MIN_COLLECTOR_TIMEOUT = 2.0


class CollectorError(RuntimeError):
    """A collector could not produce evidence for a reason worth reporting."""

    def __init__(self, message: str, *, status: str = "error") -> None:
        super().__init__(message)
        self.status = status if status in VALID_STATUSES else "error"


class CollectorUnavailable(CollectorError):
    """Evidence exists in principle but is not readable in this context.

    Distinct from a hard error: ``unavailable`` means "we looked, we were
    denied, we will not guess".  The backend maps this straight to ``unknown``.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, status="unavailable")


class BaseCollector:
    """One independent Windows security evidence source.

    Subclasses implement :meth:`collect`.  They may raise:

    * :class:`CollectorUnavailable` â€” evidence denied/unreadable (honest null).
    * :class:`CollectorError` â€” the collection genuinely failed.
    * :class:`TimeoutError` â€” the subprocess exceeded its slice.
    * any other exception â€” recorded as ``status: "error"``.

    A successful ``collect`` returns a payload dict.  The orchestrator adds
    ``status`` (``completed``) and ``_meta``; the collector must not set them.
    """

    #: Stable collector key; also the key under ``checks`` in the result.
    category: str = "generic"

    #: Human readable stage label used by the progress protocol.
    stage: str = "generic"

    #: ``True`` when the collector needs an elevated token to return real
    #: evidence.  This is *metadata*: a non-elevated run still executes the
    #: collector and reports ``null``/``unavailable`` rather than ``false``.
    requires_admin: bool = False

    #: ``True`` for high-volume inventory that no control reads.  Inventory
    #: collectors are excluded unless the caller passes ``--inventory``.
    inventory_only: bool = False

    #: Keys the backend control engine reads from this payload (spec section 3).
    evidence_keys: tuple[str, ...] = ()

    #: Short description of where the evidence comes from.
    source_provider: str = "Microsoft Windows / PowerShell"

    def collect(self) -> dict[str, Any]:
        """Return this collector's typed, raw evidence payload."""
        raise NotImplementedError

    # -- orchestrator helpers -------------------------------------------------

    @property
    def required_privilege(self) -> str:
        return "administrator" if self.requires_admin else "standard_user"

    def display_stage(self) -> str:
        return self.stage or self.category


@dataclass(frozen=True)
class ProgressEvent:
    """One line of the ``--progress-json`` protocol (spec section 4)."""

    event: str
    stage: str
    percent: int
    collector: str | None = None
    status: str | None = None
    duration_ms: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "stage": self.stage,
            "percent": self.percent,
            "collector": self.collector,
            "status": self.status,
            "duration_ms": self.duration_ms,
        }


@dataclass
class CollectorResult:
    """Normalised outcome of running (or deliberately not running) a collector."""

    name: str
    status: str
    payload: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0
    required_privilege: str = "standard_user"
    evidence_status: str = "collected"
    stage: str = ""

    def check_payload(self) -> dict[str, Any]:
        """The dict stored under ``checks.<name>``.

        Never contains a nested copy of itself, never contains ``check_results``.
        """
        payload = dict(self.payload)
        payload["status"] = self.status
        if self.error is not None:
            payload["error"] = self.error
        elif self.status != "completed":
            payload["error"] = self.status
        return payload

    def status_entry(self) -> dict[str, Any]:
        """The compact entry stored under ``collector_status.<name>``.

        Deliberately carries no evidence â€” only status metadata.
        """
        return {
            "status": self.status,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "required_privilege": self.required_privilege,
            "evidence_status": self.evidence_status,
        }


class ScannerOrchestrator:
    """Run collectors in a bounded pool under a shared wall-clock budget."""

    def __init__(
        self,
        collectors: Sequence[BaseCollector] | None = None,
        *,
        parallel: int = 4,
        budget_seconds: float = 120.0,
        max_collector_timeout: float = MAX_COLLECTOR_TIMEOUT,
    ) -> None:
        self.collectors: list[BaseCollector] = list(collectors or [])
        self.parallel = max(1, int(parallel))
        self.budget_seconds = float(budget_seconds)
        self.max_collector_timeout = float(max_collector_timeout)

    def register(self, collector: BaseCollector) -> None:
        """Append a collector to the fixed execution order."""
        self.collectors.append(collector)

    # -- execution ------------------------------------------------------------

    def run(
        self,
        emit: Callable[[ProgressEvent], None] | None = None,
        *,
        started_at: str | None = None,
    ) -> dict[str, Any]:
        """Run every collector and return the merged result document skeleton.

        ``emit`` is invoked **only from the calling thread**, so the progress
        protocol can never interleave or reorder under concurrency.
        """
        clock = monotonic()
        deadline = clock + self.budget_seconds
        total = len(self.collectors)
        events: queue.Queue[ProgressEvent] = queue.Queue()

        def relay(event: ProgressEvent) -> None:
            events.put(event)

        order = [collector.category for collector in self.collectors]
        results: list[CollectorResult | None] = [None] * total
        completed = 0

        def percent_for(done: int) -> int:
            if total == 0:
                return 100
            return min(99, 1 + int(88 * done / total))

        if emit is not None and total:
            emit(ProgressEvent("start", "Detecting device", 0))

        pool_size = max(1, min(self.parallel, total)) if total else 1
        with ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="scanner") as pool:
            future_index: dict[Future[dict[str, Any]], int] = {}
            next_index = 0
            in_flight: set[Future[dict[str, Any]]] = set()

            def submit(index: int, now: float) -> None:
                remaining = deadline - now
                active = max(1, min(pool_size, len(in_flight) + 1))
                slice_seconds = max(MIN_COLLECTOR_TIMEOUT, remaining / active)
                timeout = min(slice_seconds, self.max_collector_timeout, max(remaining, 0.0))
                collector = self.collectors[index]
                future = pool.submit(self._collect_one, collector, max(timeout, 0.01), deadline, relay)
                future_index[future] = index
                in_flight.add(future)

            while next_index < total:
                now = monotonic()
                if now >= deadline:
                    break
                while next_index < total and len(in_flight) < pool_size:
                    submit(next_index, monotonic())
                    next_index += 1
                if not in_flight:
                    break
                done, in_flight = wait(in_flight, timeout=0.1, return_when=FIRST_COMPLETED)
                for future in done:
                    index = future_index.pop(future)
                    results[index] = future.result()
                    completed += 1
                    self._drain(events, emit, completed, total, percent_for)
                self._drain(events, emit, completed, total, percent_for)

            # Budget exhausted with work still in flight: wait out the slices
            # already granted (that is the single permitted overrun), then mark
            # anything untouched as skipped.
            if in_flight:
                done, still_running = wait(in_flight, return_when=FIRST_COMPLETED)
                while done or still_running:
                    for future in done:
                        index = future_index.pop(future)
                        results[index] = future.result()
                        completed += 1
                        self._drain(events, emit, completed, total, percent_for)
                    if not still_running:
                        break
                    done, still_running = wait(still_running, timeout=60.0, return_when=FIRST_COMPLETED)
                    self._drain(events, emit, completed, total, percent_for)
                self._drain(events, emit, completed, total, percent_for)

            for index in range(total):
                if results[index] is not None:
                    continue
                collector = self.collectors[index]
                results[index] = CollectorResult(
                    name=collector.category,
                    status="skipped",
                    error="wall-clock budget exhausted before this collector started",
                    duration_ms=0.0,
                    required_privilege=collector.required_privilege,
                    evidence_status="skipped",
                    stage=collector.display_stage(),
                )

            pool.shutdown(wait=True)

        self._drain(events, emit, completed, total, percent_for)

        checks: dict[str, Any] = {}
        statuses: dict[str, Any] = {}
        for name, result in zip(order, results, strict=False):
            assert result is not None
            checks[name] = result.check_payload()
            statuses[name] = result.status_entry()

        return {
            "order": order,
            "checks": checks,
            "collector_status": statuses,
            "results": {name: result for name, result in zip(order, results, strict=False) if result},
        }

    @staticmethod
    def _drain(
        events: queue.Queue[ProgressEvent],
        emit: Callable[[ProgressEvent], None] | None,
        completed: int,
        total: int,
        percent_for: Callable[[int], int],
    ) -> None:
        """Flush queued collector events to the caller's thread."""
        while True:
            try:
                event = events.get_nowait()
            except queue.Empty:
                return
            if emit is not None:
                emit(
                    ProgressEvent(
                        event="collector",
                        stage=event.stage,
                        percent=max(event.percent, percent_for(completed)),
                        collector=event.collector,
                        status=event.status,
                        duration_ms=event.duration_ms,
                    )
                )

    def _collect_one(
        self,
        collector: BaseCollector,
        timeout: float,
        deadline: float,
        relay: Callable[[ProgressEvent], None],
    ) -> CollectorResult:
        """Run one collector inside the pool, converting failures to statuses."""
        started = monotonic()
        stage = collector.display_stage()
        result: CollectorResult
        try:
            payload = collector.collect()
            if not isinstance(payload, dict):
                raise CollectorError("collector returned a non-dict payload")
            status = str(payload.pop("status", "completed") or "completed").lower()
            if status not in VALID_STATUSES:
                status = "completed"
            result = CollectorResult(
                name=collector.category,
                status=status,
                payload=payload,
                error=None if status == "completed" else str(payload.get("error") or status),
                duration_ms=round((monotonic() - started) * 1000, 1),
                required_privilege=collector.required_privilege,
                evidence_status=("collected" if status == "completed" else status),
                stage=stage,
            )
        except TimeoutError:
            result = CollectorResult(
                name=collector.category,
                status="timeout",
                error=f"collector exceeded its {timeout:.1f}s slice",
                duration_ms=round((monotonic() - started) * 1000, 1),
                required_privilege=collector.required_privilege,
                evidence_status="timeout",
                stage=stage,
            )
        except CollectorUnavailable as exc:
            result = CollectorResult(
                name=collector.category,
                status="unavailable",
                error=str(exc) or "evidence unavailable",
                duration_ms=round((monotonic() - started) * 1000, 1),
                required_privilege=collector.required_privilege,
                evidence_status="unavailable",
                stage=stage,
            )
        except Exception as exc:  # never let one source hide the others
            result = CollectorResult(
                name=collector.category,
                status=getattr(exc, "status", "error"),
                error=str(exc) or exc.__class__.__name__,
                duration_ms=round((monotonic() - started) * 1000, 1),
                required_privilege=collector.required_privilege,
                evidence_status="error",
                stage=stage,
            )
        relay(
            ProgressEvent(
                event="collector",
                stage=stage,
                percent=0,
                collector=collector.category,
                status=result.status,
                duration_ms=result.duration_ms,
            )
        )
        return result


def utcnow() -> str:
    """ISO-8601 UTC timestamp used throughout the result document."""
    return datetime.now(UTC).isoformat()


def select_collectors(
    collectors: Iterable[BaseCollector],
    *,
    names: Sequence[str] | None = None,
    inventory: bool = False,
) -> list[BaseCollector]:
    """Filter a collector sequence by name and inventory policy, keeping order."""
    wanted = {name.strip().lower() for name in names or () if name.strip()}
    selected: list[BaseCollector] = []
    for collector in collectors:
        if not inventory and collector.inventory_only:
            continue
        if wanted and collector.category.lower() not in wanted:
            continue
        selected.append(collector)
    return selected
