"""Scanner command-line contract tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Imported after the path fix above, which is the whole point of this module.
from app.services.jobs import ScanJobManager  # noqa: E402
from scanner.cli import build_parser  # noqa: E402


def test_inventory_is_opt_in_and_worker_flag_is_accepted():
    parser = build_parser()

    assert parser.parse_args([]).inventory is False
    assert parser.parse_args(["--no-inventory", "--no-elevate"]).inventory is False
    assert parser.parse_args(["--inventory"]).inventory is True


def test_inventory_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--inventory", "--no-inventory"])


def test_scan_worker_command_matches_scanner_cli():
    manager = object.__new__(ScanJobManager)
    command = manager._command(Path("scan-output"), inventory=False, collectors=None)

    assert build_parser().parse_args(command[3:]).inventory is False
