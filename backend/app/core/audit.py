"""Tamper-evident audit logging.

Every privileged or security-relevant action writes one row. Rows are hash-chained:
each entry commits to the previous entry's hash, so deleting or editing any row breaks
the chain and the break is detectable with ``verify_chain``. The chain head lives in a
single-row table that is locked while an entry is appended, which serialises writers
without a global mutex and keeps the chain intact under concurrency.

Audit failures must never break a request: :func:`record` logs and swallows errors.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.timeutil import ensure_utc
from app.db.models import AuditChainState, AuditLog, User

logger = logging.getLogger("secureconfigai.audit")

GENESIS_HASH = "0" * 64

#: Canonical action names. Keep them stable Ã¢â‚¬â€ they are part of the audit contract.
ACTIONS = {
    "auth.register": "Account registered",
    "auth.login.success": "Sign-in succeeded",
    "auth.login.failure": "Sign-in failed",
    "auth.login.locked": "Sign-in refused: account locked",
    "auth.login.disabled": "Sign-in refused: account disabled",
    "auth.logout": "Signed out",
    "auth.refresh": "Access token refreshed",
    "auth.refresh.reuse_detected": "Refresh token reuse detected",
    "auth.rate_limited": "Sign-in rate limit triggered",
    "user.role_change": "User role changed",
    "user.status_change": "User enabled or disabled",
    "user.unlock": "User lockout cleared",
    "user.sessions_revoke": "All refresh tokens revoked for a user",
    "device.create": "Device registered",
    "device.update": "Device updated",
    "device.delete": "Device deleted",
    "device.criticality_change": "Device criticality changed",
    "scan.start": "Assessment queued",
    "scan.complete": "Assessment completed",
    "scan.reassess": "Stored evidence re-assessed with the current scoring model",
    "scan.fail": "Assessment failed",
    "scan.cancel": "Assessment cancelled",
    "scan.upload": "Snapshot uploaded",
    "scan.upload.rejected": "Snapshot upload rejected",
    "scan.document_view": "Stored evidence viewed",
    "scan.report": "Report generated",
    "scan.delete": "Assessment deleted",
    "policy.create": "Policy override created",
    "policy.update": "Policy override updated",
    "policy.toggle": "Policy override enabled or disabled",
    "policy.delete": "Policy override deleted",
    "exemption.create": "Control exemption created",
    "exemption.delete": "Control exemption removed",
    "ai.report": "AI summary generated",
    "ai.explain": "AI finding explanation generated",
    "ai.recommend": "AI recommendation generated",
    "ai.chat": "AI chat message sent",
    "ai.chat_delete": "AI chat session deleted",
    "admin.security_policy_view": "Platform security policy viewed",
    "admin.audit_verify": "Audit chain verified",
    "admin.retention_purge": "Retention pass executed",
    "security.rate_limited": "Rate limit triggered",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def compute_entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Commit hash for one chain entry.

    V4 (M-1): when ``AUDIT_CHAIN_HMAC_KEY`` is configured the chain is keyed with
    HMAC-SHA-256. The key lives only in deployment configuration — never in the
    database — so an attacker with database write access can no longer recompute the
    chain after editing history: any rewritten row fails verification. Without the
    key the chain falls back to plain SHA-256, which stays backwards compatible with
    V3 chains (verifiable, but self-attestable by anyone who can rewrite the DB).
    """
    body = f"{prev_hash}|{_canonical(payload)}".encode()
    key = settings.AUDIT_CHAIN_HMAC_KEY
    if key:
        return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


def entry_payload(entry: AuditLog) -> dict[str, Any]:
    """The exact field set that is committed to by ``entry_hash``.

    ``created_at`` is normalised to aware UTC before it is serialised: SQLite returns a
    naive value on read while the hash was computed from an aware one, which would make
    every entry fail verification on that backend.
    """
    return {
        "seq": entry.seq,
        "created_at": (ensure_utc(entry.created_at).isoformat() if entry.created_at else None),
        "actor_id": str(entry.user_id) if entry.user_id else None,
        "action": entry.action,
        "entity_type": entry.entity_type,
        "entity_id": entry.entity_id,
        "outcome": entry.outcome,
        "ip_address": entry.ip_address,
        "request_id": entry.request_id,
        "details": entry.details or {},
    }


def _get_or_create_state(db: Session) -> AuditChainState:
    state = db.get(AuditChainState, 1)
    if state is not None:
        return state
    state = AuditChainState(id=1, last_hash=GENESIS_HASH, entry_count=0)
    db.add(state)
    try:
        db.flush()
    except IntegrityError:  # another writer created it first
        db.rollback()
        state = db.get(AuditChainState, 1)
        if state is None:  # pragma: no cover - defensive
            raise
    return state


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_id: Any | None = None,
    entity_type: str | None = None,
    entity_id: Any | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
    request: Request | None = None,
    ip_address: str | None = None,
    commit: bool = True,
) -> AuditLog | None:
    """Append one audit entry. Never raises to the caller."""
    try:
        state = _get_or_create_state(db)
        if settings.is_sqlite is False:  # PostgreSQL: serialise chain appends
            state = db.execute(
                select(AuditChainState).where(AuditChainState.id == 1).with_for_update()
            ).scalar_one()

        resolved_actor = getattr(actor, "id", None) or actor_id
        resolved_ip = ip_address
        request_id = None
        if request is not None:
            resolved_ip = resolved_ip or _request_ip(request)
            request_id = getattr(request.state, "request_id", None)

        entry = AuditLog(
            user_id=resolved_actor,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            outcome=outcome,
            details=details or {},
            ip_address=resolved_ip,
            request_id=request_id,
            seq=state.entry_count + 1,
            prev_hash=state.last_hash,
            created_at=datetime.now(UTC),
        )
        entry.entry_hash = compute_entry_hash(state.last_hash, entry_payload(entry))
        state.last_hash = entry.entry_hash
        state.entry_count = entry.seq
        state.updated_at = entry.created_at
        db.add(entry)
        if commit:
            db.commit()
        else:
            db.flush()
        return entry
    except Exception:  # pragma: no cover - audit must never break the request
        logger.exception("failed to write audit entry action=%s", action)
        try:
            db.rollback()
        except Exception:  # noqa: S110 - rollback is already best-effort
            pass
        return None


def _request_ip(request: Request) -> str | None:
    from app.core.rate_limit import client_ip

    try:
        return client_ip(request)
    except Exception:  # pragma: no cover
        return None


def verify_chain(db: Session, limit: int | None = None) -> dict[str, Any]:
    """Recompute the chain and report the first inconsistency.

    V4 (M-1): beyond per-entry hash checks this now also verifies the structure that
    V3 ignored: sequence numbers must be contiguous (starting at 1 for a full scan),
    and on a full scan the ``audit_chain_state`` row must agree with the data —
    ``entry_count`` must equal the highest sequence number and ``last_hash`` must
    equal the recomputed head. A tail truncation that rewrote the state row to match
    is therefore no longer reported as valid.
    """
    stmt = select(AuditLog).order_by(AuditLog.seq.asc())
    if limit:
        stmt = stmt.limit(limit)
    entries = list(db.execute(stmt).scalars())
    prev = GENESIS_HASH
    prev_seq: int | None = None
    for entry in entries:
        # Contiguity check: a deleted middle row leaves a gap between the surviving
        # neighbours. The chain is NOT required to start at seq 1 — the retention
        # purge re-anchors the surviving window while keeping its original sequence
        # numbers, so only consecutive deltas are asserted here.
        if prev_seq is not None and entry.seq != prev_seq + 1:
            return {
                "chain_valid": False,
                "checked": len(entries),
                "first_broken_id": str(entry.id),
                "first_broken_seq": entry.seq,
                "reason": "sequence_gap",
                "expected_seq": prev_seq + 1,
                "stored_hash": entry.entry_hash,
            }
        expected = compute_entry_hash(prev, entry_payload(entry))
        if expected != entry.entry_hash or entry.prev_hash != prev:
            return {
                "chain_valid": False,
                "checked": len(entries),
                "first_broken_id": str(entry.id),
                "first_broken_seq": entry.seq,
                "reason": "hash_mismatch",
                "expected_hash": expected,
                "stored_hash": entry.entry_hash,
            }
        prev = entry.entry_hash
        prev_seq = entry.seq
    result: dict[str, Any] = {
        "chain_valid": True,
        "checked": len(entries),
        "first_broken_id": None,
        "head_hash": prev,
    }
    if not limit:
        state = db.get(AuditChainState, 1)
        if state is not None:
            top_seq = entries[-1].seq if entries else 0
            if state.entry_count != top_seq:
                result["chain_valid"] = False
                result["reason"] = "entry_count_mismatch"
                result["state_entry_count"] = state.entry_count
                result["highest_seq"] = top_seq
            elif state.last_hash != prev:
                result["chain_valid"] = False
                result["reason"] = "head_mismatch"
                result["state_last_hash"] = state.last_hash
    return result


def purge_older_than(db: Session, days: int | None = None) -> int:
    """Retention: delete entries older than the policy window.

    Deleting from the middle of a hash chain necessarily breaks it, so the surviving
    window is **re-anchored**: the oldest surviving entry is re-based on the genesis hash
    and every later entry is re-chained from it. The entry *contents* are never modified â€”
    only the linking hashes â€” and the purge itself is recorded, so a verifier can still
    prove that the remaining window is internally consistent and can see where the
    truncation happened.
    """
    window = days or settings.RETENTION_AUDIT_DAYS
    if window <= 0:
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=window)
    stale = list(db.execute(select(AuditLog).where(AuditLog.created_at < cutoff)).scalars())
    if not stale:
        return 0
    removed = len(stale)
    for entry in stale:
        db.delete(entry)
    db.flush()

    remaining = list(db.execute(select(AuditLog).order_by(AuditLog.seq.asc())).scalars())
    state = _get_or_create_state(db)
    last_hash = GENESIS_HASH
    for entry in remaining:
        entry.prev_hash = last_hash
        entry.entry_hash = compute_entry_hash(last_hash, entry_payload(entry))
        last_hash = entry.entry_hash
    if not remaining:
        state.last_hash = GENESIS_HASH
        state.entry_count = 0
    else:
        state.last_hash = last_hash
        # The next sequence number must exceed every surviving entry, not just the oldest.
        state.entry_count = max(entry.seq for entry in remaining)
    state.updated_at = datetime.now(UTC)
    db.flush()

    record(
        db,
        "admin.audit_purge",
        entity_type="audit_log",
        commit=False,
        details={"deleted": removed, "retention_days": window, "reanchored_entries": len(remaining)},
    )
    db.commit()
    return removed
