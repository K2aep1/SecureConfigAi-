"""Command line entry point for the SecureConfigAI Windows scanner.

Usage::

    python -m scanner.cli --output <dir> [--inventory] [--progress-json]
                          [--budget-seconds 120] [--collectors a,b,c]
                          [--elevate | --no-elevate] [--parallel 4]

Contract highlights (spec sections 1, 4 and 5):

* writes ``<output>/scan_result.json`` always and
  ``<output>/configuration_snapshot.json`` unless ``--no-snapshot`` is given,
  both compact UTF-8 without BOM and without ``indent``;
* ``--progress-json`` puts one JSON object per line on **stdout**; every other
  message goes to **stderr**;
* the whole run is bounded by ``--budget-seconds``; collectors that could not
  start are recorded ``status: "skipped"``;
* exit code 0 when a result was produced, 1 when it could not be produced.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from time import monotonic
from typing import Any

from scanner.base.collector import (
    BaseCollector,
    ProgressEvent,
    ScannerOrchestrator,
    select_collectors,
    utcnow,
)
from scanner.collectors import build_collectors
from scanner.normalizer import normalize_scan_output
from scanner.report import SCHEMA_VERSION, ScanSummary, build_result_document
from scanner.snapshot import build_configuration_snapshot

__all__ = ["build_parser", "dumps_compact", "main", "run_scan"]

DEFAULT_PARALLEL = 4
DEFAULT_BUDGET_SECONDS = 120.0


def dumps_compact(payload: Any) -> str:
    """Canonical compact JSON: no indent, no ASCII escaping, no NaN."""
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def write_text(path: Path, text: str) -> None:
    """Write UTF-8 **without** BOM and with ``\\n`` newlines."""
    path.write_text(text, encoding="utf-8", newline="\n")


class ProgressWriter:
    """Emits the spec section 4 protocol and keeps ``percent`` monotonic.

    Also mirrors the latest state to ``<output>/scan_progress.json`` so a
    sibling process can poll coarse progress without reading the full result.
    """

    def __init__(self, output_dir: Path, *, enabled: bool) -> None:
        self.enabled = enabled
        self.output_dir = output_dir
        self._percent = 0
        self._latest: ProgressEvent | None = None

    def __call__(self, event: ProgressEvent) -> None:
        percent = max(self._percent, min(100, int(event.percent)))
        self._percent = percent
        normalised = ProgressEvent(
            event=event.event,
            stage=event.stage,
            percent=percent,
            collector=event.collector,
            status=event.status,
            duration_ms=event.duration_ms,
        )
        self._latest = normalised
        if self.enabled:
            sys.stdout.write(dumps_compact(normalised.as_dict()) + "\n")
            sys.stdout.flush()
        self._mirror(normalised)

    def _mirror(self, event: ProgressEvent) -> None:
        try:
            write_text(
                self.output_dir / "scan_progress.json",
                dumps_compact({**event.as_dict(), "updated_at": utcnow()}),
            )
        except OSError:  # progress mirroring must never fail a scan
            pass


def run_scan(
    output_dir: Path,
    *,
    parallel: int = DEFAULT_PARALLEL,
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
    inventory: bool = False,
    collectors: Sequence[BaseCollector] | None = None,
    progress: ProgressWriter | None = None,
    elevation_requested: bool = False,
    signing_key: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the scan and return ``(result_document, snapshot_document)``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    progress = progress or ProgressWriter(output_dir, enabled=False)
    selected = (
        list(collectors)
        if collectors is not None
        else select_collectors(build_collectors(), inventory=inventory)
    )

    started_at = utcnow()
    started_clock = monotonic()
    orchestrator = ScannerOrchestrator(selected, parallel=parallel, budget_seconds=budget_seconds)
    merged = orchestrator.run(progress, started_at=started_at)
    completed_at = utcnow()
    duration = monotonic() - started_clock

    results = merged["results"]
    device_payload = {}
    device_result = results.get("device")
    if device_result is not None:
        device_payload = device_result.payload

    summary = ScanSummary.from_results(results)
    summary.duration_seconds = round(duration, 3)

    device = dict(device_payload)
    device["hostname"] = device.get("hostname") or _fallback_hostname()
    device["os"] = device.get("os") or "windows"

    result = build_result_document(
        results,
        execution={
            "elevation_requested": bool(elevation_requested),
            "inventory": bool(inventory),
            "parallel": int(parallel),
        },
        device=device,
        summary=summary,
        started_at=started_at,
        completed_at=completed_at,
        inventory=inventory,
        budget_seconds=budget_seconds,
        collectors=selected,
    )
    normalized = normalize_scan_output(result)
    snapshot = build_configuration_snapshot(
        normalized,
        scanner_version=SCHEMA_VERSION,
        scan_started_at=started_at,
        signing_key=signing_key or os.environ.get("EVIDENCE_SIGNING_KEY"),
    )
    progress(
        ProgressEvent("done", "Analyzing configuration", 100, None, summary.status, round(duration * 1000, 1))
    )
    return result, snapshot


def _fallback_hostname() -> str:
    import socket

    try:
        return socket.gethostname()
    except OSError:  # pragma: no cover - unusual network stacks
        return "unknown-host"


def build_parser() -> argparse.ArgumentParser:
    """Construct the documented command line interface."""
    parser = argparse.ArgumentParser(
        prog="scanner.cli",
        description="SecureConfigAI independent Windows security scanner",
    )
    parser.add_argument(
        "--output",
        default="./scan_output",
        help="directory that receives scan_result.json and configuration_snapshot.json",
    )
    inventory_group = parser.add_mutually_exclusive_group()
    inventory_group.add_argument(
        "--inventory",
        action="store_true",
        help="also run the inventory collectors (network_inventory, installed_software)",
    )
    inventory_group.add_argument(
        "--no-inventory",
        action="store_false",
        dest="inventory",
        help="skip the inventory collectors (the default)",
    )
    parser.set_defaults(inventory=False)
    parser.add_argument(
        "--progress-json",
        action="store_true",
        help="write one JSON progress object per line to stdout",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=DEFAULT_BUDGET_SECONDS,
        help="wall-clock budget for the whole run (default: %(default)s)",
    )
    parser.add_argument(
        "--collectors",
        default=None,
        help="comma separated subset of collector names to run",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=DEFAULT_PARALLEL,
        help="maximum collectors running at once (default: %(default)s)",
    )
    parser.add_argument(
        "--elevate",
        action="store_true",
        help="request UAC elevation before scanning",
    )
    parser.add_argument(
        "--no-elevate",
        action="store_true",
        help="never request UAC elevation (the service default)",
    )
    parser.add_argument(
        "--no-snapshot",
        action="store_true",
        help="skip writing configuration_snapshot.json",
    )
    parser.add_argument(
        "--signing-key",
        default=None,
        help=(
            "shared secret for the optional HMAC provenance envelope; defaults to the "
            "EVIDENCE_SIGNING_KEY environment variable. Without a key the snapshot is "
            "integrity-checked only, and the backend says so."
        ),
    )
    return parser


def _summarise(output_dir: Path, result: dict[str, Any], elapsed: float, result_bytes: int) -> str:
    scanner = result.get("scanner", {})
    lines = [
        f"scan complete in {elapsed:.1f}s -> {output_dir}",
        f"  schema_version : {result.get('schema_version')}",
        f"  scan_result.json: {result_bytes} bytes",
        f"  collectors     : {scanner.get('collector_count')} "
        f"(completed={scanner.get('completed')} unavailable={scanner.get('unavailable')} "
        f"errors={scanner.get('errors')} timeouts={scanner.get('timeouts')} "
        f"skipped={scanner.get('skipped')})",
        f"  status         : {scanner.get('status')}",
        f"  inventory      : {scanner.get('inventory')}",
        "  collector_status:",
    ]
    for name, entry in (result.get("collector_status") or {}).items():
        lines.append(
            f"    {name:<20} {str(entry.get('status')):<12} "
            f"{entry.get('duration_ms')} ms  {entry.get('error') or ''}".rstrip()
        )
    return "\n".join(lines)


def _request_uac_elevation(argv: list[str]) -> int:
    """Re-launch this scanner through Windows UAC and wait for the child."""
    import platform
    import subprocess

    if platform.system().lower() != "windows":
        return -1
    try:

        def ps_quote(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        exe = ps_quote(str(Path(sys.executable).resolve()))
        args = ",".join(ps_quote(str(item)) for item in argv)
        script = (
            "$args=@(" + args + "); "
            "$p=Start-Process -FilePath " + exe + " -ArgumentList $args -Verb RunAs -PassThru -Wait; "
            "exit $p.ExitCode"
        )
        completed = subprocess.run(
            ["powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
        )
        return completed.returncode
    except (OSError, subprocess.SubprocessError):
        return -1


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    import platform

    args = build_parser().parse_args(argv)
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    elevate = bool(args.elevate) and not bool(args.no_elevate)
    if elevate and platform.system().lower() == "windows":
        from scanner.report import _execution_context

        if not _execution_context()["is_admin"]:
            child = [
                "-m",
                "scanner.cli",
                "--output",
                str(output_dir),
                "--no-elevate",
            ]
            if args.inventory:
                child.append("--inventory")
            if args.progress_json:
                child.append("--progress-json")
            child += [
                "--budget-seconds",
                str(args.budget_seconds),
                "--parallel",
                str(args.parallel),
            ]
            if args.collectors:
                child += ["--collectors", args.collectors]
            if args.signing_key:
                # V4 fix (11.2): the signing key used to be forwarded as a plain
                # --signing-key argv element, visible in the process list of every
                # local user for the duration of the elevated run. The elevated
                # child inherits this environment, and build_configuration_snapshot
                # already falls back to EVIDENCE_SIGNING_KEY, so the secret now
                # travels through the environment instead of the command line.
                os.environ["EVIDENCE_SIGNING_KEY"] = args.signing_key
            code = _request_uac_elevation(child)
            if code == 0:
                return 0
            print(
                "UAC elevation was not completed; continuing with available privileges.",
                file=sys.stderr,
            )

    collector_names = (
        [name for name in args.collectors.split(",") if name.strip()] if args.collectors else None
    )
    selected = select_collectors(
        build_collectors(),
        names=collector_names,
        inventory=bool(args.inventory),
    )
    if not selected:
        print("no collectors selected", file=sys.stderr)
        return 1

    unknown = sorted(
        {
            name.strip().lower()
            for name in collector_names or []
            if name.strip().lower() not in {collector.category.lower() for collector in build_collectors()}
        }
    )
    if unknown:
        print(f"ignoring unknown collectors: {', '.join(unknown)}", file=sys.stderr)

    progress = ProgressWriter(output_dir, enabled=bool(args.progress_json))
    started = monotonic()
    try:
        result, snapshot = run_scan(
            output_dir,
            parallel=args.parallel,
            budget_seconds=args.budget_seconds,
            inventory=bool(args.inventory),
            collectors=selected,
            progress=progress,
            elevation_requested=elevate,
            signing_key=args.signing_key,
        )
    except Exception as exc:  # a scan that produces nothing is exit code 1
        print(f"scanner failed: {exc}", file=sys.stderr)
        return 1

    result_path = output_dir / "scan_result.json"
    payload = dumps_compact(result)
    write_text(result_path, payload)
    if not args.no_snapshot:
        write_text(
            output_dir / "configuration_snapshot.json",
            dumps_compact(snapshot),
        )
    elapsed = monotonic() - started
    print(_summarise(output_dir, result, elapsed, len(payload.encode("utf-8"))), file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
