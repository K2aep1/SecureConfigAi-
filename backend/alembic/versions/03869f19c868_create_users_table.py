"""Initial SecureConfigAI schema.

Revision ID: 03869f19c868
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "03869f19c868"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _id():
    return sa.Uuid(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255)),
        sa.Column("role", sa.String(32), nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "devices",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("user_id", _id(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_type", sa.String(32), nullable=False, server_default="windows"),
        sa.Column("os_version", sa.String(64)),
        sa.Column("os_build", sa.String(64)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_devices_user_id", "devices", ["user_id"])

    op.create_table(
        "scans",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("device_id", _id(), sa.ForeignKey("devices.id")),
        sa.Column("user_id", _id(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("source", sa.String(32), nullable=False, server_default="local_agent"),
        sa.Column("uploaded_file_path", sa.String(512)),
        sa.Column("raw_data", sa.JSON()),
        sa.Column("normalized_data", sa.JSON()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("error_message", sa.Text()),
    )
    op.create_index("ix_scans_device_id", "scans", ["device_id"])
    op.create_index("ix_scans_user_id", "scans", ["user_id"])

    op.create_table(
        "scan_results",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("scan_id", _id(), sa.ForeignKey("scans.id"), nullable=False, unique=True),
        sa.Column("security_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("compliance_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_level", sa.String(32), nullable=False, server_default="low"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("informational_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "policies",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("rule_key", sa.String(64), nullable=False, unique=True),
        sa.Column("expected_value", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("recommendation_template", sa.Text()),
        sa.Column("created_by", _id(), sa.ForeignKey("users.id")),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("scan_id", _id(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("policy_id", _id(), sa.ForeignKey("policies.id")),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("current_value", sa.JSON()),
        sa.Column("expected_value", sa.JSON()),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("evidence", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])

    op.create_table(
        "recommendations",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("finding_id", _id(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("what_is_wrong", sa.Text(), nullable=False),
        sa.Column("why_it_matters", sa.Text(), nullable=False),
        sa.Column("what_should_be_done", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("remediation_type", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("remediation_instruction", sa.Text()),
    )
    op.create_index("ix_recommendations_finding_id", "recommendations", ["finding_id"])

    op.create_table(
        "reports",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("scan_id", _id(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ai_reports",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("scan_id", _id(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("content", sa.JSON()),
        sa.Column("model_used", sa.String(255)),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "chat_sessions",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("user_id", _id(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("scan_id", _id(), sa.ForeignKey("scans.id")),
        sa.Column("title", sa.String(255), nullable=False, server_default="New conversation"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "chat_messages",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("session_id", _id(), sa.ForeignKey("chat_sessions.id"), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_chat_messages_session_id", "chat_messages", ["session_id"])
    op.create_table(
        "audit_logs",
        sa.Column("id", _id(), primary_key=True, nullable=False),
        sa.Column("user_id", _id(), sa.ForeignKey("users.id")),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("details", sa.JSON()),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_index("ix_chat_messages_session_id", table_name="chat_messages")
    op.drop_table("chat_messages")
    op.drop_table("chat_sessions")
    op.drop_table("ai_reports")
    op.drop_table("reports")
    op.drop_index("ix_recommendations_finding_id", table_name="recommendations")
    op.drop_table("recommendations")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("policies")
    op.drop_table("scan_results")
    op.drop_index("ix_scans_user_id", table_name="scans")
    op.drop_index("ix_scans_device_id", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_devices_user_id", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
