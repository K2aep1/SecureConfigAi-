"""Platform 2.0: security policy, scan jobs, audit chain, baseline-driven scoring.

Revision ID: 20261006_v2_platform
Revises: 20260910_control_id

This migration is additive except for two renames on the (empty in a fresh install)
``policies`` table, which are expressed with ``batch_alter_table`` so SQLite performs
them by table rebuild. Every new non-nullable column carries a server default so an
existing database with rows upgrades cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20261006_v2_platform"
down_revision: str | Sequence[str] | None = "20260910_control_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type():
    """JSON, stored as JSONB on PostgreSQL."""
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # ---------------------------------------------------------------- users
    op.add_column("users", sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))

    # ---------------------------------------------------------------- devices
    op.add_column("devices", sa.Column("criticality", sa.Integer(), nullable=False, server_default="3"))

    # ---------------------------------------------------------------- scans
    op.add_column("scans", sa.Column("stage", sa.String(120), nullable=False, server_default="Queued"))
    op.add_column("scans", sa.Column("progress", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("duration_ms", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("worker_id", sa.String(64), nullable=True))
    op.add_column("scans", sa.Column("scanner_version", sa.String(32), nullable=True))
    op.add_column("scans", sa.Column("scoring_model_version", sa.String(32), nullable=True))
    op.add_column("scans", sa.Column("baseline_version", sa.String(32), nullable=True))
    op.add_column("scans", sa.Column("evidence_bytes", sa.Integer(), nullable=True))
    op.create_index("ix_scans_user_started", "scans", ["user_id", "started_at"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_user_status", "scans", ["user_id", "status"])

    # ---------------------------------------------------------------- scan_results
    op.add_column("scan_results", sa.Column("categories", _json_type(), nullable=True))
    op.add_column("scan_results", sa.Column("assessment", _json_type(), nullable=True))
    op.add_column("scan_results", sa.Column("scoring_model_version", sa.String(32), nullable=True))
    op.add_column("scan_results", sa.Column("baseline_version", sa.String(32), nullable=True))

    # ---------------------------------------------------------------- policies
    with op.batch_alter_table("policies") as batch:
        batch.alter_column("expected_value", existing_type=sa.JSON(), nullable=True)
        batch.alter_column("category", existing_type=sa.String(64), nullable=True)
        batch.alter_column("severity", existing_type=sa.String(32), nullable=True)
        batch.add_column(sa.Column("weight", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    if dialect != "sqlite":  # batch mode already rebuilt the table for SQLite
        op.alter_column("policies", "rule_key", new_column_name="control_id", existing_type=sa.String(64))
    else:
        # batch_alter_table cannot rename in place here; do it via a rebuild step.
        with op.batch_alter_table("policies") as batch:
            batch.alter_column("rule_key", new_column_name="control_id", existing_type=sa.String(64))
    op.execute("UPDATE policies SET updated_at = created_at WHERE updated_at IS NULL")
    op.execute("UPDATE policies SET expected_value = '{}' WHERE expected_value IS NULL")

    # ---------------------------------------------------------------- findings
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"])
    op.create_index("ix_findings_scan_control", "findings", ["scan_id", "control_id"])

    # ---------------------------------------------------------------- recommendations
    op.add_column("recommendations", sa.Column("verify_command", sa.Text(), nullable=True))

    # ---------------------------------------------------------------- reports
    op.add_column("reports", sa.Column("format", sa.String(8), nullable=False, server_default="pdf"))
    op.add_column("reports", sa.Column("content_hash", sa.String(64), nullable=True))
    op.add_column("reports", sa.Column("size_bytes", sa.Integer(), nullable=True))
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])

    # ---------------------------------------------------------------- ai_reports
    op.add_column("ai_reports", sa.Column("prompt_version", sa.String(16), nullable=True))
    op.create_index("ix_ai_reports_scan_id", "ai_reports", ["scan_id"])

    # ---------------------------------------------------------------- audit_logs
    op.add_column("audit_logs", sa.Column("seq", sa.Integer(), nullable=True))
    op.add_column("audit_logs", sa.Column("entity_type", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("entity_id", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("outcome", sa.String(16), nullable=False, server_default="success"))
    op.add_column("audit_logs", sa.Column("request_id", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("user_agent", sa.String(255), nullable=True))
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("entry_hash", sa.String(64), nullable=True))
    # Backfill so the NOT NULL constraints can be applied on an existing database.
    op.execute("UPDATE audit_logs SET seq = 1 WHERE seq IS NULL")
    op.execute("UPDATE audit_logs SET prev_hash = '" + "0" * 64 + "' WHERE prev_hash IS NULL")
    op.execute("UPDATE audit_logs SET entry_hash = '" + "0" * 64 + "' WHERE entry_hash IS NULL")
    with op.batch_alter_table("audit_logs") as batch:
        batch.alter_column("seq", existing_type=sa.Integer(), nullable=False)
        batch.alter_column("prev_hash", existing_type=sa.String(64), nullable=False)
        batch.alter_column("entry_hash", existing_type=sa.String(64), nullable=False)
    op.create_index("ix_audit_logs_seq", "audit_logs", ["seq"], unique=True)
    op.create_index("ix_audit_logs_created", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])

    # ---------------------------------------------------------------- new tables
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("family_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_hash", sa.String(128), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])

    op.create_table(
        "device_exemptions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("device_id", sa.Uuid(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "control_id", name="uq_exemption_device_control"),
    )
    op.create_index("ix_device_exemptions_device_id", "device_exemptions", ["device_id"])
    op.create_index("ix_device_exemptions_control_id", "device_exemptions", ["control_id"])

    op.create_table(
        "ai_cache",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("cache_key", sa.String(128), nullable=False, unique=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("model_used", sa.String(64), nullable=False),
        sa.Column("content", _json_type(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("last_hash", sa.String(64), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.execute(
        "INSERT INTO audit_chain_state (id, last_hash, entry_count, updated_at) "
        "VALUES (1, '" + "0" * 64 + "', 0, CURRENT_TIMESTAMP)"
    )


def downgrade() -> None:
    op.drop_table("audit_chain_state")
    op.drop_table("ai_cache")
    op.drop_index("ix_device_exemptions_control_id", table_name="device_exemptions")
    op.drop_index("ix_device_exemptions_device_id", table_name="device_exemptions")
    op.drop_table("device_exemptions")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created", table_name="audit_logs")
    op.drop_index("ix_audit_logs_seq", table_name="audit_logs")
    for column in (
        "entry_hash",
        "prev_hash",
        "user_agent",
        "request_id",
        "outcome",
        "entity_id",
        "entity_type",
        "seq",
    ):
        op.drop_column("audit_logs", column)

    op.drop_index("ix_ai_reports_scan_id", table_name="ai_reports")
    op.drop_column("ai_reports", "prompt_version")

    op.drop_index("ix_reports_scan_id", table_name="reports")
    for column in ("size_bytes", "content_hash", "format"):
        op.drop_column("reports", column)

    op.drop_column("recommendations", "verify_command")

    op.drop_index("ix_findings_scan_control", table_name="findings")
    op.drop_index("ix_findings_scan_severity", table_name="findings")

    with op.batch_alter_table("policies") as batch:
        batch.alter_column("control_id", new_column_name="rule_key", existing_type=sa.String(64))
        batch.drop_column("updated_at")
        batch.drop_column("weight")

    for column in ("baseline_version", "scoring_model_version", "assessment", "categories"):
        op.drop_column("scan_results", column)

    op.drop_index("ix_scans_user_status", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_user_started", table_name="scans")
    for column in (
        "evidence_bytes",
        "baseline_version",
        "scoring_model_version",
        "scanner_version",
        "worker_id",
        "duration_ms",
        "heartbeat_at",
        "progress",
        "stage",
    ):
        op.drop_column("scans", column)

    op.drop_column("devices", "criticality")
    for column in ("last_login_at", "locked_until", "failed_login_count"):
        op.drop_column("users", column)
