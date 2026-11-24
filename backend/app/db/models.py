"""Database models.

Design notes
------------
* One model layer for the whole application; Alembic is the schema authority.
* ``Uuid`` is used everywhere so SQLite and PostgreSQL behave identically.
* Large evidence columns are ``deferred``: no query loads a multi-megabyte document
  unless it explicitly asks, which is what keeps list endpoints fast.
* JSON columns are declared with a ``JSONB`` variant so PostgreSQL stores them
  binary-searchable while SQLite keeps them as text.
* Times are timezone-aware UTC.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    desc,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import deferred, relationship

from app.core.timeutil import ensure_utc
from app.db.base import Base

#: JSON that becomes JSONB on PostgreSQL.
JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(32), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="created_by_user")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    chat_sessions = relationship("ChatSession", back_populates="user", cascade="all, delete-orphan")
    #: ``passive_deletes`` matters for integrity, not performance: without it SQLAlchemy
    #: nulls ``audit_logs.user_id`` when a user is deleted, which silently rewrites a row
    #: that the audit hash chain has already committed to and permanently breaks
    #: verification. Foreign-key enforcement (SQLite pragma / PostgreSQL constraint) keeps
    #: the history intact instead.
    audit_logs = relationship("AuditLog", back_populates="user", passive_deletes=True)
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_locked(self) -> bool:
        locked_until = ensure_utc(self.locked_until)
        return bool(locked_until and locked_until > utcnow())


class RefreshToken(Base):
    """Server-side refresh-token record enabling rotation and reuse detection."""

    __tablename__ = "refresh_tokens"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(128), unique=True, nullable=False)
    family_id = Column(Uuid(as_uuid=True), nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    replaced_by_hash = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)

    user = relationship("User", back_populates="refresh_tokens")

    @property
    def is_active(self) -> bool:
        expires_at = ensure_utc(self.expires_at)
        return self.revoked_at is None and bool(expires_at and expires_at > utcnow())


class Device(Base):
    #: Uniqueness of (user_id, hostname) is enforced in the application layer; a
    #: database constraint would have to resolve pre-existing duplicates during an
    #: upgrade, which is a decision for the operator, not the migration.
    __tablename__ = "devices"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    os_type = Column(String(32), default="windows", nullable=False)
    os_version = Column(String(64), nullable=True)
    os_build = Column(String(64), nullable=True)
    #: 1..5 asset criticality. Scales the risk calculation (see the baseline pack).
    criticality = Column(Integer, default=3, nullable=False)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="devices")
    scans = relationship("Scan", back_populates="device")
    exemptions = relationship("DeviceExemption", back_populates="device", cascade="all, delete-orphan")


class DeviceExemption(Base):
    """A documented, per-device decision to accept a control deviation."""

    __tablename__ = "device_exemptions"
    __table_args__ = (UniqueConstraint("device_id", "control_id", name="uq_exemption_device_control"),)

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    device_id = Column(Uuid(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    control_id = Column(String(64), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    created_by = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    device = relationship("Device", back_populates="exemptions")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_started", "user_id", desc("started_at")),
        Index("ix_scans_status", "status"),
        Index("ix_scans_user_status", "user_id", "status"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    device_id = Column(Uuid(as_uuid=True), ForeignKey("devices.id"), nullable=True, index=True)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    status = Column(String(32), default="queued", nullable=False)
    stage = Column(String(120), default="Queued", nullable=False)
    progress = Column(Integer, default=0, nullable=False)
    source = Column(String(32), default="local_agent", nullable=False)
    uploaded_file_path = Column(String(512), nullable=True)
    #: Deferred: huge evidence documents are never loaded by list queries.
    raw_data = deferred(Column(JSONType, nullable=True))
    normalized_data = deferred(Column(JSONType, nullable=True))
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    worker_id = Column(String(64), nullable=True)
    scanner_version = Column(String(32), nullable=True)
    scoring_model_version = Column(String(32), nullable=True)
    baseline_version = Column(String(32), nullable=True)
    evidence_bytes = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    user = relationship("User", back_populates="scans")
    device = relationship("Device", back_populates="scans")
    result = relationship("ScanResult", uselist=False, back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    ai_reports = relationship("AIReport", back_populates="scan", cascade="all, delete-orphan")

    @property
    def is_terminal(self) -> bool:
        # `error` is the pre-fix vocabulary still present in historical rows; treating it
        # as terminal keeps those rows out of the "in progress" view without rewriting
        # history.
        return self.status in {"completed", "failed", "cancelled", "error"}


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id"), unique=True, nullable=False)
    security_score = Column(Integer, nullable=False, default=0)
    compliance_score = Column(Integer, nullable=False, default=0)
    assessment_coverage = Column(Integer, nullable=False, default=0)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(32), nullable=False, default="low")
    evidence_quality = Column(String(32), nullable=False, default="unavailable")
    #: Per-control results (the authoritative assessment record).
    controls = Column(JSONType, nullable=True)
    categories = Column(JSONType, nullable=True)
    assessment = Column(JSONType, nullable=True)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    informational_count = Column(Integer, default=0, nullable=False)
    scoring_model_version = Column(String(32), nullable=True)
    baseline_version = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan = relationship("Scan", back_populates="result")


class Policy(Base):
    """A global override of one baseline control (weight, severity, remediation, on/off)."""

    __tablename__ = "policies"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    control_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)
    weight = Column(Integer, nullable=True)
    severity = Column(String(32), nullable=True)
    expected_value = Column(JSONType, nullable=False, default=dict)
    recommendation_template = Column(Text, nullable=True)
    created_by = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    created_by_user = relationship("User", back_populates="policies")
    findings = relationship("Finding", back_populates="policy")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_control", "scan_id", "control_id"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    policy_id = Column(Uuid(as_uuid=True), ForeignKey("policies.id"), nullable=True)
    control_id = Column(String(64), nullable=True, index=True)
    category = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    current_value = Column(JSONType, nullable=True)
    expected_value = Column(JSONType, nullable=True)
    severity = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    #: Minimal evidence projection that justified the verdict (not the whole snapshot).
    evidence = Column(JSONType, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
    policy = relationship("Policy", back_populates="findings")
    recommendations = relationship("Recommendation", back_populates="finding", cascade="all, delete-orphan")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    finding_id = Column(Uuid(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
    what_is_wrong = Column(Text, nullable=False)
    why_it_matters = Column(Text, nullable=False)
    what_should_be_done = Column(Text, nullable=False)
    verify_command = Column(Text, nullable=True)
    priority = Column(String(32), nullable=False, default="medium")
    remediation_type = Column(String(32), nullable=False, default="manual")
    remediation_instruction = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="recommendations")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    format = Column(String(8), nullable=False, default="pdf")
    file_path = Column(String(512), nullable=False)
    content_hash = Column(String(64), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    generated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan = relationship("Scan", back_populates="reports")


class AIReport(Base):
    __tablename__ = "ai_reports"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    content = Column(JSONType, nullable=True)
    model_used = Column(String(255), nullable=True)
    prompt_version = Column(String(16), nullable=True)
    generated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan = relationship("Scan", back_populates="ai_reports")


class AICache(Base):
    """Cached advisory output, keyed by model + prompt version + evidence digest."""

    __tablename__ = "ai_cache"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    cache_key = Column(String(128), unique=True, nullable=False)
    kind = Column(String(32), nullable=False)
    model_used = Column(String(64), nullable=False)
    content = Column(JSONType, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    title = Column(String(255), nullable=False, default="New conversation")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    session_id = Column(Uuid(as_uuid=True), ForeignKey("chat_sessions.id"), nullable=False, index=True)
    role = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    session = relationship("ChatSession", back_populates="messages")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_seq", "seq", unique=True),
        Index("ix_audit_logs_created", desc("created_at")),
        Index("ix_audit_logs_action", "action"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    seq = Column(Integer, nullable=False)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(64), nullable=False)
    entity_type = Column(String(64), nullable=True)
    entity_id = Column(String(64), nullable=True)
    outcome = Column(String(16), nullable=False, default="success")
    details = Column(JSONType, nullable=True)
    ip_address = Column(String(64), nullable=True)
    request_id = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")


class AuditChainState(Base):
    """Single row (id=1) holding the audit chain head."""

    __tablename__ = "audit_chain_state"

    id = Column(Integer, primary_key=True, nullable=False)
    last_hash = Column(String(64), nullable=False)
    entry_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
