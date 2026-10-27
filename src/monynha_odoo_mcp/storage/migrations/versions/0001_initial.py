"""Initial tenant, connection, policy and audit tables.

Revision ID: 0001_initial
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("organizations", sa.Column("id", sa.String(128), primary_key=True))
    op.create_table("principals", sa.Column("id", sa.String(256), primary_key=True))
    op.create_table(
        "memberships",
        sa.Column("principal_id", sa.String(256), sa.ForeignKey("principals.id"), primary_key=True),
        sa.Column(
            "organization_id", sa.String(128), sa.ForeignKey("organizations.id"), primary_key=True
        ),
    )
    op.create_table(
        "connections",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column(
            "organization_id", sa.String(128), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("database", sa.String(256)),
        sa.Column("secret_ref", sa.String(256), nullable=False),
    )
    op.create_index("ix_connections_organization_id", "connections", ["organization_id"])
    op.create_table(
        "policies",
        sa.Column("principal_id", sa.String(256), sa.ForeignKey("principals.id"), primary_key=True),
        sa.Column(
            "connection_id", sa.String(128), sa.ForeignKey("connections.id"), primary_key=True
        ),
        sa.Column("operation", sa.String(32), primary_key=True),
        sa.Column("model", sa.String(128), primary_key=True),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("connection_id", sa.String(128), nullable=False),
        sa.Column("operation", sa.String(32), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("policies")
    op.drop_index("ix_connections_organization_id", table_name="connections")
    op.drop_table("connections")
    op.drop_table("memberships")
    op.drop_table("principals")
    op.drop_table("organizations")
