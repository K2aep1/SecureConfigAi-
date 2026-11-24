"""Single-invocation PowerShell runner.

Every collector makes **exactly one** call to :func:`run_script`.  The script it
passes in must end with a statement that emits one JSON document; `run_script`
prepends a small prelude (UTF-8 pinned both ways, terminating errors) and
appends a compressed ``ConvertTo-Json`` epilogue.

Why ``-EncodedCommand``
    The script text is base64 encoded as UTF-16LE, so it survives any quoting,
    newline, or non-ASCII content without a temporary ``.ps1`` on disk and
    without the Windows console code page ever being consulted.

Why explicit encoding
    The specification forbids relying on the console code page.  stdout and
    stderr are decoded with ``encoding="utf-8", errors="replace"``, and the
    prelude forces ``[Console]::OutputEncoding`` so the child agrees.

Timeouts
    ``subprocess`` timeouts kill only the direct child.  PowerShell can leave
    grandchildren behind, so a timed-out run is additionally reaped with
    ``taskkill /T /F`` on the process id.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from typing import Any, Final

__all__ = [
    "PowerShellError",
    "PowerShellTimeout",
    "PS_EXECUTABLE",
    "PRELUDE",
    "epilogue",
    "run_script",
]

#: Evidence payloads nest at most four levels; a shallow depth keeps
#: ConvertTo-Json from descending into provider objects it should never touch.
DEFAULT_DEPTH: Final[int] = 4

PS_EXECUTABLE: Final[str] = "powershell"

PRELUDE: Final[str] = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$PSStyle = $null
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
try { $OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
"""

#: Extra time granted on top of the caller's slice so the Python side, not the
#: scheduler, is the one that declares a collector "timeout".  Kept strictly
#: bounded so that the total run cannot overrun the wall-clock budget by more
#: than one collector timeout.
KILL_GRACE_SECONDS: Final[float] = 3.0
KILL_GRACE_FRACTION: Final[float] = 0.25


class PowerShellError(RuntimeError):
    """PowerShell exited non-zero or produced unusable output."""


class PowerShellTimeout(PowerShellError, TimeoutError):
    """PowerShell did not finish inside its slice of the wall-clock budget."""


def epilogue(depth: int = DEFAULT_DEPTH) -> str:
    """Compressed-JSON emitter appended to every collector script."""
    return (
        "if ($null -ne $scaiResult) { "
        f"ConvertTo-Json -InputObject $scaiResult -Depth {int(depth)} -Compress "
        "}"
    )


def build_command(script: str, depth: int = DEFAULT_DEPTH) -> str:
    """Wrap a collector script body in prelude + JSON epilogue."""
    return PRELUDE + "\n" + script.strip() + "\n" + epilogue(depth) + "\n"


def _kill_tree(process: subprocess.Popen[str]) -> None:
    """Reap a timed-out PowerShell process and any children it spawned."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        process.kill()
    except OSError:
        pass


def run_script(
    script: str,
    *,
    timeout: float,
    depth: int = DEFAULT_DEPTH,
) -> Any:
    """Execute one PowerShell JSON program and return the parsed document.

    Raises:
        PowerShellTimeout: the script exceeded ``timeout`` seconds.
        PowerShellError: the script failed or did not emit valid JSON.
    """
    if timeout <= 0:
        raise PowerShellTimeout("no budget left for this PowerShell invocation")

    command = build_command(script, depth)
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    argv = [
        PS_EXECUTABLE,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]

    hard_timeout = timeout + min(KILL_GRACE_SECONDS, timeout * KILL_GRACE_FRACTION)
    process: subprocess.Popen[str] = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = process.communicate(timeout=hard_timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            process.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError):
            pass
        raise PowerShellTimeout(f"PowerShell exceeded {timeout:.1f}s and was terminated") from None

    text = (stdout or "").strip()
    code = process.returncode or 0
    if code != 0:
        reason = _first_line(stderr) or _first_line(stdout) or f"exit code {code}"
        raise PowerShellError(reason)
    if not text:
        raise PowerShellError(_first_line(stderr) or "PowerShell produced no JSON output")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise PowerShellError(f"invalid JSON from PowerShell: {exc.msg} at line {exc.lineno}") from exc


def _first_line(text: str | None) -> str:
    """First non-empty line of a stream, trimmed to a sane error length."""
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:300]
    return ""


def powershell_available() -> bool:
    """Best-effort check that Windows PowerShell exists on this host."""
    if sys.platform != "win32":
        return False
    try:
        completed = subprocess.run(
            [PS_EXECUTABLE, "-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0
