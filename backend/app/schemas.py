"""Request/response models.

These mirror ``docs/API_CONTRACT.md``. Two deliberate choices:

* Password rules are enforced by a validator that consults the *platform security
  policy*, so the schema and the policy cannot disagree.
* Response models for list endpoints never include the stored evidence document. The
  full document has its own endpoint, which is the single most important reason the
  dashboard stays fast.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.security_policy import PasswordPolicyError, platform_policy

T = TypeVar("T")

#: Deliberately conservative: shape check only, no deliverability claim, and no extra
#: dependency (``email-validator``) is required to run the service.
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")

ControlState = Literal["compliant", "non_compliant", "not_applicable", "unknown", "error"]
ScanState = Literal["queued", "running", "completed", "failed", "cancelled"]
Role = Literal["admin", "user"]


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None
    has_more: bool = False
    limit: int = 25


# --------------------------------------------------------------------------- meta
class BaselineReference(BaseModel):
    standard: str
    control: str
    url: str | None = None


class HealthOut(BaseModel):
    status: str
    service: str
    environment: str
    version: str
    baseline_version: str
    scoring_model_version: str
    database: dict[str, Any]


class MetaOut(BaseModel):
    app_name: str
    app_version: str
    scoring_model_version: str
    baseline: dict[str, Any]
    control_count: int
    control_weight_total: int
    environment: str


# --------------------------------------------------------------------------- auth
class AuthPolicyOut(BaseModel):
    password: dict[str, Any]
    access_token_minutes: int
    refresh_token_days: int
    max_failed_logins: int
    lockout_minutes: int
    password_hint: str


class UserCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8)
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("password")
    @classmethod
    def _policy(cls, value: str) -> str:
        try:
            platform_policy.validate_password(value)
        except PasswordPolicyError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not EMAIL_RE.match(cleaned):
            raise ValueError("Enter a valid email address.")
        return cleaned


class UserLogin(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class MessageOut(BaseModel):
    message: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    email: str
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: datetime | None = None


class UserAdminOut(UserOut):
    failed_login_count: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    is_locked: bool = False


# --------------------------------------------------------------------------- baseline
class BaselineControlOut(BaseModel):
    control_id: str
    title: str
    category: str
    weight: int
    severity: str
    collector: str
    expected_state: str
    applicability: dict[str, Any]
    evaluation: dict[str, Any]
    evidence_paths: list[str]
    rationale: str
    remediation: dict[str, str]
    references: list[BaselineReference]

    @field_validator("references", mode="before")
    @classmethod
    def _coerce_refs(cls, value: Any) -> Any:
        return value or []


class BaselineOut(BaseModel):
    baseline_id: str
    version: str
    schema_version: str
    title: str
    description: str
    published_at: str
    reference_policy: str
    references: list[dict[str, Any]]
    thresholds: dict[str, Any]
    categories: dict[str, Any]
    severity_impact: dict[str, int]
    control_count: int
    control_weight_total: int
    controls: list[BaselineControlOut]


# --------------------------------------------------------------------------- policies
class PolicyBase(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    category: str | None = None
    weight: int | None = Field(default=None, ge=1, le=100)
    severity: str | None = None
    recommendation_template: str | None = None


class PolicyCreate(PolicyBase):
    control_id: str = Field(..., max_length=64)
    expected_value: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    category: str | None = None
    weight: int | None = Field(default=None, ge=1, le=100)
    severity: str | None = None
    recommendation_template: str | None = None
    expected_value: dict[str, Any] | None = None
    is_enabled: bool | None = None


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    control_id: str
    name: str
    description: str | None = None
    category: str | None = None
    weight: int | None = None
    severity: str | None = None
    expected_value: dict[str, Any]
    recommendation_template: str | None = None
    is_enabled: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None


class EffectiveControlOut(BaseModel):
    control_id: str
    title: str
    category: str
    weight: int
    severity: str
    enabled: bool
    baseline_weight: int
    baseline_severity: str
    expected_state: str
    collector: str
    rationale: str
    remediation: dict[str, str]
    references: list[dict[str, Any]]
    sources: dict[str, str]
    exempted: bool
    exemption_reason: str | None = None


class EffectivePolicyOut(BaseModel):
    baseline_id: str
    baseline_version: str
    total_weight: int
    controls: list[EffectiveControlOut]


class ExemptionCreate(BaseModel):
    control_id: str = Field(..., max_length=64)
    reason: str = Field(..., min_length=8, max_length=1000)
    expires_at: datetime | None = None


class ExemptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    device_id: UUID
    control_id: str
    reason: str
    created_by: UUID | None = None
    expires_at: datetime | None = None
    created_at: datetime | None = None


# --------------------------------------------------------------------------- devices
class DeviceCreate(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    os_type: str = Field(default="windows", max_length=32)
    os_version: str | None = Field(default=None, max_length=64)
    os_build: str | None = Field(default=None, max_length=64)
    criticality: int = Field(default=3, ge=1, le=5)


class DeviceUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    os_type: str | None = Field(default=None, max_length=32)
    os_version: str | None = Field(default=None, max_length=64)
    os_build: str | None = Field(default=None, max_length=64)
    criticality: int | None = Field(default=None, ge=1, le=5)


class DeviceLatestResult(BaseModel):
    security_score: int | None = None
    compliance_score: int | None = None
    assessment_coverage: int | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    evidence_quality: str | None = None
    completed_at: datetime | None = None


class DeviceOut(BaseModel):
    id: UUID
    hostname: str
    os_type: str
    os_version: str | None = None
    os_build: str | None = None
    criticality: int
    criticality_label: str
    first_seen_at: datetime | None = None
    last_scan_at: datetime | None = None
    scan_count: int = 0
    latest: DeviceLatestResult | None = None


class DeviceCompareOut(BaseModel):
    devices: list[dict[str, Any]]


# --------------------------------------------------------------------------- scans
class ScanStartRequest(BaseModel):
    device_id: UUID | None = None
    source: str = Field(default="local_agent", max_length=32)
    collectors: list[str] | None = None
    inventory: bool | None = None


class ScanQueuedOut(BaseModel):
    scan_id: UUID
    status: str
    stage: str
    progress: int


class ScanStatusOut(BaseModel):
    scan_id: UUID
    status: str
    stage: str
    progress: int
    heartbeat_at: datetime | None = None
    error_message: str | None = None
    duration_ms: int | None = None


class ScanSummaryOut(BaseModel):
    id: UUID
    device_id: UUID | None = None
    hostname: str | None = None
    status: str
    stage: str
    progress: int
    source: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    security_score: int | None = None
    compliance_score: int | None = None
    assessment_coverage: int | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    evidence_quality: str | None = None
    critical_count: int | None = None
    high_count: int | None = None
    medium_count: int | None = None
    low_count: int | None = None
    informational_count: int | None = None
    total_findings: int | None = None
    controls_assessed: int | None = None
    controls_total: int | None = None
    scanner_version: str | None = None
    scoring_model_version: str | None = None
    baseline_version: str | None = None
    error_message: str | None = None


class ControlResultOut(BaseModel):
    control_id: str
    title: str
    category: str
    weight: int
    severity: str
    status: str
    applicability: str
    expected_state: Any = None
    actual_state: Any = None
    evidence: Any = None
    standard_refs: list[dict[str, Any]] = Field(default_factory=list)
    rationale: str = ""
    remediation: dict[str, str] = Field(default_factory=dict)
    collector: str = ""
    collector_status: str = ""
    notes: list[str] = Field(default_factory=list)
    exempted: bool = False
    exemption_reason: str | None = None
    risk_impact: float = 0.0
    risk_contribution: float = 0.0


class CategoryOut(BaseModel):
    label: str
    score: int | None = None
    count: int = 0
    non_compliant: int = 0
    unknown: int = 0
    weight: int = 0
    status: str = "assessed"
    exposure: int = 3
    description: str = ""


class AssessmentMetaOut(BaseModel):
    scoring_model_version: str
    baseline_id: str
    baseline_version: str
    asset_criticality: int
    total_controls: int
    applicable_controls: int
    assessed_controls: int
    compliant_controls: int
    non_compliant_controls: int
    not_applicable_controls: int
    unknown_or_error_controls: int
    unknown_controls: int
    error_controls: int
    total_weight: int
    assessed_weight: int
    compliant_weight: int
    risk_likelihood_factor: float
    risk_remaining_probability: float


class RecommendationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    what_is_wrong: str
    why_it_matters: str
    what_should_be_done: str
    verify_command: str | None = None
    priority: str
    remediation_type: str
    remediation_instruction: str | None = None


class FindingOut(BaseModel):
    id: UUID
    control_id: str | None = None
    title: str
    category: str
    severity: str
    status: str
    description: str | None = None
    current_value: Any = None
    expected_value: Any = None
    evidence: Any = None
    standard_refs: list[dict[str, Any]] = Field(default_factory=list)
    recommendation: RecommendationOut | None = None


class ScanResultsOut(BaseModel):
    scan_id: UUID
    status: str
    scanner_error: str | None = None
    device: dict[str, Any] | None = None
    results: dict[str, Any]
    findings: list[FindingOut]


class ScanDocumentOut(BaseModel):
    scan_id: UUID
    schema_version: str | None = None
    baseline_version: str | None = None
    scoring_model_version: str | None = None
    evidence_bytes: int | None = None
    normalized_data: dict[str, Any] | None = None


class UploadSummaryOut(BaseModel):
    scan_status: str
    duration_seconds: float
    rules_checked: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    security_score: int
    compliance_score: int
    assessment_coverage: int
    risk_level: str
    risk_score: int
    evidence_quality: str


class UploadResultOut(BaseModel):
    scan_id: UUID
    status: str
    message: str
    snapshot_id: str | None = None
    schema_version: str | None = None
    integrity_verified: bool = False
    #: True only when a configured signing key verified the submitted HMAC envelope.
    #: False means "checksum only" — it is never an authenticity claim.
    authenticity_verified: bool = False
    original_filename: str | None = None
    finding_count: int
    device_id: UUID | None = None
    summary: UploadSummaryOut
    categories: list[CategoryOut] = Field(default_factory=list)
    findings: list[FindingOut] = Field(default_factory=list)


# --------------------------------------------------------------------------- admin
class RoleUpdate(BaseModel):
    role: Role


class StatusUpdate(BaseModel):
    is_active: bool


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    seq: int
    created_at: datetime | None = None
    actor_id: UUID | None = None
    actor_email: str | None = None
    action: str
    entity_type: str | None = None
    entity_id: str | None = None
    outcome: str
    ip_address: str | None = None
    request_id: str | None = None
    details: dict[str, Any] | None = None
    entry_hash: str
    prev_hash: str


class AuditVerifyOut(BaseModel):
    chain_valid: bool
    checked: int
    first_broken_id: str | None = None
    first_broken_seq: int | None = None
    head_hash: str | None = None


class AdminStatsOut(BaseModel):
    users: int
    devices: int
    scans: int
    findings: int
    audit_entries: int
    reports: int
    database_bytes: int
    evidence_bytes: int


# --------------------------------------------------------------------------- AI
class AIStatusOut(BaseModel):
    provider: str
    model: str
    configured: bool
    connected: bool
    enabled: bool
    checked_at: datetime | None = None
    cached: bool = False
    error: str | None = None
    #: Always true: AI output is explanatory and can never change a verdict or a score.
    advisory: bool = True


class AIReportOut(BaseModel):
    report_id: UUID
    scan_id: UUID
    summary: str
    model_used: str
    cached: bool = False
    advisory: bool = True


class AIExplainOut(BaseModel):
    finding_id: UUID
    title: str
    explanation: str
    model_used: str
    cached: bool = False
    advisory: bool = True


class AIRiskPriorityOut(BaseModel):
    finding_id: str
    title: str
    severity: str
    category: str
    priority: str
    score: int
    recommendation: str


class AIRecommendOut(BaseModel):
    finding_id: UUID
    title: str
    priority: str
    recommendation: RecommendationOut
    model_used: str
    cached: bool = False
    advisory: bool = True


class ChatMessageIn(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)
    session_id: UUID | None = None
    #: Optional assessment context. Ownership is validated by the chat endpoint.
    scan_id: UUID | None = None


class ChatMessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    role: str
    content: str
    created_at: datetime | None = None


class ChatSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    title: str
    scan_id: UUID | None = None
    created_at: datetime | None = None
    message_count: int = 0


class ChatAnswerOut(BaseModel):
    session_id: UUID
    question: str
    answer: str
    model_used: str
    advisory: bool = True
