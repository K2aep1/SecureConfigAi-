#!/usr/bin/env python
"""Build a clean, verifiable release archive from an explicit allow-list.

The research report's release-hygiene finding was blunt: `.gitignore` already excluded
`backend/.env`, the databases and the scanner output, and yet all of them were present in
the delivered folder. The lesson is that a release must be **built from an allow-list**,
never copied from a working tree.

What this script does:

1. copies only the allow-listed paths into a staging directory;
2. refuses to continue if any forbidden artefact is present (`.env`, `*.db`, caches,
   `node_modules`, `dist`, generated scanner output);
3. runs the secret scanner over the staged tree and aborts on a finding;
4. writes ``MANIFEST.sha256`` (every file, its size and its digest) and
   ``RELEASE_NOTES.txt``;
5. produces ``dist_release/SecureConfigAI_v4-<version>.zip``.

Usage::

    python scripts/build_release.py                 # build the archive
    python scripts/build_release.py --no-archive    # stage and validate only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "dist_release"

#: Documentation and top-level files that belong in a release.
ROOT_FILES = [
    "README.md",
    "LICENSE",
    "ARCHITECTURE.md",
    "SCORING_METHODOLOGY.md",
    "SECURITY_MODEL.md",
    "TROUBLESHOOTING.md",
    "VALIDATION_STATUS.md",
    "FINAL_INTEGRATION_NOTES.md",
    "INTEGRATED_BUILD_NOTES.md",
    "PROJECT_AUDIT_AND_ROADMAP.md",
    "pyproject.toml",
    ".gitignore",
    "START_BACKEND.bat",
    "START_FRONTEND.bat",
    "RUN_SCANNER.bat",
]

#: Directories copied whole (subject to the exclusion rules below).
INCLUDE_DIRS = [
    "backend/app",
    "backend/alembic",
    "backend/tests",
    "backend/tools",
    "docs",
    "frontend/src",
    "scanner",
    "scripts",
    ".github",
]

#: Individual files inside otherwise-excluded locations.
INCLUDE_FILES = [
    "backend/alembic.ini",
    "backend/requirements.txt",
    "backend/requirements.lock",
    "backend/pytest.ini",
    "backend/.env.example",
    "backend/uploads/.gitkeep",
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/index.html",
    "frontend/tsconfig.json",
    "frontend/tsconfig.app.json",
    "frontend/tsconfig.node.json",
    "frontend/vite.config.ts",
    "frontend/.env.example",
    "frontend/.gitignore",
    "scanner/examples/configuration_snapshot.example.json",
    "scanner/manual_scan_output/.gitkeep",
]

#: Anything matching one of these is never staged, even inside an included directory.
FORBIDDEN_NAMES = {".env", "secureconfigai.db", "test_secureconfigai.db", ".DS_Store", "Thumbs.db"}
FORBIDDEN_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".git",
    "node_modules",
    "dist",
    ".venv",
    "venv",
    ".vscode",
    "uploads",
    "manual_scan_output",
    "_live_check",
    ".scan-cache",
}
FORBIDDEN_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".db",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".log",
    ".tsbuildinfo",
    ".swp",
    "~",
}

#: Files that must exist in the staged tree for the release to be usable.
REQUIRED_FILES = [
    "README.md",
    "LICENSE",
    "backend/.env.example",
    "backend/requirements.txt",
    "backend/requirements.lock",
    "backend/alembic.ini",
    "backend/app/main.py",
    "backend/app/data/baseline/global_baseline_v1.json",
    "frontend/package.json",
    "frontend/package-lock.json",
    "scanner/cli.py",
    "scripts/scan_secrets.py",
]


def _is_forbidden(relative: Path) -> bool:
    if relative.name in FORBIDDEN_NAMES:
        return True
    # A placeholder file whose only job is to keep an otherwise-ignored directory is not
    # a generated artefact, even when its parent directory is excluded from the release.
    if relative.name == ".gitkeep":
        return False
    if any(part in FORBIDDEN_DIRS for part in relative.parts[:-1]):
        return True
    return relative.suffix.lower() in FORBIDDEN_SUFFIXES or relative.name.endswith("~")


def collect() -> list[Path]:
    """Resolve the allow-list into concrete files, skipping anything forbidden."""
    selected: list[Path] = []

    for name in ROOT_FILES:
        path = ROOT / name
        if path.is_file() and not _is_forbidden(Path(name)):
            selected.append(path)

    for name in INCLUDE_FILES:
        path = ROOT / name
        if path.is_file():
            selected.append(path)

    for name in INCLUDE_DIRS:
        directory = ROOT / name
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.rglob("*")):
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(ROOT)
            if _is_forbidden(relative):
                continue
            if "manual_scan_output" in relative.parts and candidate.name != ".gitkeep":
                continue
            selected.append(candidate)

    # De-duplicate while preserving a deterministic order.
    unique = {path.resolve() for path in selected}
    return sorted(unique, key=lambda item: str(item.relative_to(ROOT)).lower())


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def stage(files: list[Path], destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for source in files:
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def validate(destination: Path) -> list[str]:
    """Re-check the staged tree. Returns a list of problems (empty means good)."""
    problems: list[str] = []

    for required in REQUIRED_FILES:
        if not (destination / required).is_file():
            problems.append(f"missing required file: {required}")

    for candidate in destination.rglob("*"):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(destination)
        if _is_forbidden(relative):
            problems.append(f"forbidden artefact staged: {relative}")
    return problems


def manifest(destination: Path) -> str:
    lines = ["# SecureConfigAI_v3 release manifest", "# path  size_bytes  sha256", ""]
    for path in sorted(destination.rglob("*")):
        if not path.is_file() or path.name == "MANIFEST.sha256":
            continue
        relative = path.relative_to(destination).as_posix()
        lines.append(f"{relative}\t{path.stat().st_size}\t{digest(path)}")
    return "\n".join(lines) + "\n"


def archive(destination: Path, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(destination.rglob("*")):
            if path.is_file():
                bundle.write(path, destination.name + "/" + path.relative_to(destination).as_posix())
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default=str(OUTPUT_DIR), help="directory for the staged tree and archive")
    parser.add_argument("--no-archive", action="store_true", help="stage and validate without writing a zip")
    args = parser.parse_args(argv)

    version = "4.0.0"
    try:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        for line in pyproject.splitlines():
            if line.startswith("version ="):
                version = line.split("=", 1)[1].strip().strip('"')
                break
    except OSError:
        pass

    output_dir = Path(args.output).resolve()
    staged = output_dir / f"SecureConfigAI_v4-{version}"

    files = collect()
    print(f"allow-list resolved: {len(files)} file(s) from {ROOT}")

    stage(files, staged)
    problems = validate(staged)

    # Secret scanning is a hard gate on the staged tree, not on the working tree.
    sys.path.insert(0, str(ROOT / "scripts"))
    import scan_secrets  # noqa: PLC0415 - deliberate late import of a sibling script

    findings: list[dict[str, object]] = []
    for path in sorted(staged.rglob("*")):
        if path.is_file():
            findings.extend(scan_secrets.scan_file(path))
    if findings:
        for finding in findings:
            problems.append(
                f"possible secret: {finding['path']}:{finding['line']} "
                f"({finding['kind']}, {finding['match']})"
            )

    if problems:
        print("\nRELEASE VALIDATION FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    (staged / "MANIFEST.sha256").write_text(manifest(staged), encoding="utf-8")
    total_bytes = sum(path.stat().st_size for path in staged.rglob("*") if path.is_file())
    (staged / "RELEASE_NOTES.txt").write_text(
        f"SecureConfigAI_v3 {version}\n"
        f"Built: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"Files: {len(files)}\n"
        f"Uncompressed bytes: {total_bytes}\n\n"
        "This archive was produced from an explicit allow-list. It excludes local\n"
        "configuration (.env), databases, virtual environments, node_modules, build\n"
        "output, generated scanner artefacts and caches by construction, and the\n"
        "staged tree was secret-scanned before packaging.\n\n"
        "Before first run:\n"
        "  1. copy backend/.env.example to backend/.env and fill in PostgreSQL\n"
        "     credentials and a random JWT_SECRET_KEY;\n"
        "  2. create the database and role, then run `alembic upgrade head` from backend/;\n"
        "  3. install dependencies with `pip install -r requirements.lock`;\n"
        "  4. `npm ci && npm run build` in frontend/.\n",
        encoding="utf-8",
    )

    print(f"staged: {staged}")
    print(f"files: {len(files)}  bytes: {total_bytes}")
    print("validation: passed (allow-list, forbidden artefacts, required files, secrets)")

    if args.no_archive:
        return 0

    output = archive(staged, output_dir / f"SecureConfigAI_v4-{version}.zip")
    print(f"archive: {output}  ({output.stat().st_size} bytes)")

    # Print a small JSON summary so CI can assert on it.
    print(
        json.dumps(
            {
                "version": version,
                "files": len(files),
                "uncompressed_bytes": total_bytes,
                "archive_bytes": output.stat().st_size,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
