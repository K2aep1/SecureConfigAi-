#!/usr/bin/env python3
"""SecureConfigAI V4 — credential rotation and hygiene tool.

Closes the operational gap behind the V3 distribution incident: secrets lived in a
world-readable ``backend/.env``, one of them was a weak human-pattern password, and
there was no supported procedure to rotate anything. This tool makes the healthy
path the easy path:

* generates cryptographically strong replacements (``secrets.token_urlsafe`` /
  ``secrets.token_hex``), never human-memorable passwords;
* checks the ``.env`` file mode and refuses to leave a group/world-readable file
  behind (fixes the mode on request);
* flags weak or personal-pattern secrets already present in the file;
* writes the updated ``.env`` atomically after making a timestamped backup;
* never prints a secret value — output shows fingerprints only, mirroring
  ``scan_secrets.py``.

Usage
-----
    python scripts/rotate_secrets.py --check              # report only, no changes
    python scripts/rotate_secrets.py --jwt --audit-key    # rotate JWT + audit HMAC key
    python scripts/rotate_secrets.py --db-password        # rotate DATABASE_URL password
    python scripts/rotate_secrets.py --all --fix-perms    # everything, fix file mode

Rotation of provider keys (OpenAI / Gemini / DeepSeek) is an EXTERNAL action: this
tool cannot revoke a key at the provider, it can only remove the value from the file.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
ENV_PATH = BACKEND_DIR / ".env"

JWT_LINE_RE = re.compile(r"^(JWT_SECRET_KEY=)(.*)$", re.MULTILINE)
AUDIT_LINE_RE = re.compile(r"^(AUDIT_CHAIN_HMAC_KEY=)(.*)$", re.MULTILINE)
DB_URL_RE = re.compile(r"^(DATABASE_URL=postgresql\+psycopg://[^:]+:)([^@]+)(@.*)$", re.MULTILINE)

# Cheap heuristic screen for weak secrets, tuned to the failure the V3 zip shipped:
# a short human-pattern password ("word+digits") guarding the evidence store.
COMMON_PATTERNS = [
    (r"^(.{1,3})(\1)+$", "repeated-segment pattern"),
    (r"^[A-Za-z]+\d{3,}$", "word followed by digits (dictionary/reuse candidate)"),
    (r"^\d{6,}$", "all digits"),
    (r"(?i)(password|secret|changeme|admin|welcome|qwerty)", "contains a common word"),
]


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _read_env() -> str:
    if not ENV_PATH.exists():
        sys.exit(f"error: {ENV_PATH} not found — copy .env.example first")
    return ENV_PATH.read_text(encoding="utf-8")


def _write_env(content: str) -> Path:
    backup = ENV_PATH.with_suffix(f".backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.env")
    backup.write_text(ENV_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(backup, 0o600)
    fd, tmp_name = tempfile.mkstemp(dir=str(ENV_PATH.parent), prefix=".env.tmp")
    tmp = Path(tmp_name)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(tmp, 0o600)
    tmp.replace(ENV_PATH)
    os.chmod(ENV_PATH, 0o600)
    return backup


def check_permissions() -> list[str]:
    problems: list[str] = []
    if not ENV_PATH.exists():
        return [".env does not exist"]
    mode = stat.S_IMODE(ENV_PATH.stat().st_mode)
    if mode & stat.S_IWOTH or mode & stat.S_IROTH:
        problems.append(
            f".env is world-readable/writable (mode {oct(mode)}) — "
            "any local account can read the JWT signing key"
        )
    elif mode & (stat.S_IRGRP | stat.S_IWGRP):
        problems.append(f".env is group-readable/writable (mode {oct(mode)})")
    return problems


def check_weak_db_password(content: str) -> list[str]:
    problems: list[str] = []
    match = DB_URL_RE.search(content)
    if not match:
        return problems
    password = match.group(2)
    if len(password) < 20:
        problems.append(
            "DATABASE_URL password looks weak "
            f"(length {len(password)} < 20; fingerprint {fingerprint(password)})"
        )
    for pattern, reason in COMMON_PATTERNS:
        if re.search(pattern, password):
            problems.append(f"DATABASE_URL password {reason} (fingerprint {fingerprint(password)})")
            break
    return problems


def rotate_jwt(content: str) -> tuple[str, str]:
    new_secret = secrets.token_urlsafe(48)
    updated, count = JWT_LINE_RE.subn(lambda m: m.group(1) + new_secret, content)
    if count == 0:
        updated = content + f"\nJWT_SECRET_KEY={new_secret}\n"
    return updated, fingerprint(new_secret)


def rotate_audit_key(content: str) -> tuple[str, str]:
    new_key = secrets.token_urlsafe(48)
    if AUDIT_LINE_RE.search(content):
        updated, _ = AUDIT_LINE_RE.subn(lambda m: m.group(1) + new_key, content)
    else:
        updated = content + (
            f"\n# V4: keyed audit chain (server-side secret, never stored in the database)\n"
            f"AUDIT_CHAIN_HMAC_KEY={new_key}\n"
        )
    return updated, fingerprint(new_key)


def rotate_db_password(content: str) -> tuple[str, str]:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    new_password = "".join(secrets.choice(alphabet) for _ in range(28))
    updated, count = DB_URL_RE.subn(lambda m: m.group(1) + new_password + m.group(3), content)
    if count == 0:
        sys.exit("error: DATABASE_URL is not a postgresql+psycopg URL; rotate it manually")
    return updated, fingerprint(new_password)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="report problems without changing anything")
    parser.add_argument("--jwt", action="store_true", help="rotate JWT_SECRET_KEY")
    parser.add_argument("--audit-key", action="store_true", help="rotate/enable AUDIT_CHAIN_HMAC_KEY")
    parser.add_argument("--db-password", action="store_true", help="rotate the DATABASE_URL password")
    parser.add_argument("--all", action="store_true", help="rotate jwt + audit key + db password")
    parser.add_argument("--fix-perms", action="store_true", help="chmod 600 the .env file")
    args = parser.parse_args()

    content = _read_env()
    problems = [*check_permissions(), *check_weak_db_password(content)]

    print("== SecureConfigAI credential hygiene ==")
    if problems:
        for problem in problems:
            print(f"  [!] {problem}")
    else:
        print("  [ok] permissions and secret strength look acceptable")

    if args.check or not (args.jwt or args.audit_key or args.db_password or args.all):
        if not args.check:
            print("\nNothing rotated: pass --jwt / --audit-key / --db-password / --all.")
        print("\nReminder: provider API keys (OpenAI, Gemini, DeepSeek) must be revoked")
        print("in the provider console — removing them here does not revoke them.")
        return 1 if problems else 0

    if args.fix_perms and ENV_PATH.exists():
        os.chmod(ENV_PATH, 0o600)
        print(f"  [ok] {ENV_PATH} set to mode 0600")

    if args.all or args.jwt:
        content, fp = rotate_jwt(content)
        print(f"  [rotated] JWT_SECRET_KEY -> sha256:{fp} (all sessions invalidated)")
    if args.all or args.audit_key:
        content, fp = rotate_audit_key(content)
        print(f"  [rotated] AUDIT_CHAIN_HMAC_KEY -> sha256:{fp} (later entries use the new key)")
    if args.all or args.db_password:
        content, fp = rotate_db_password(content)
        print(f"  [rotated] DATABASE_URL password -> sha256:{fp}")
        print("           NOTE: also update the PostgreSQL role:")
        print("           ALTER ROLE secureconfigai WITH PASSWORD '<the new password>';")

    backup = _write_env(content)
    print(f"\n  [ok] wrote {ENV_PATH} (mode 0600); previous file backed up to {backup.name}")
    print("  [!] restart the backend so the new values take effect")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
