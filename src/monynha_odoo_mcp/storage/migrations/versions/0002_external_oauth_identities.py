"""Bind external issuer/subject to private principals explicitly.

Revision ID: 0002_external_oauth_identities
Revises: 0001_initial
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_external_oauth_identities"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_identities",
        sa.Column("issuer", sa.String(512), primary_key=True),
        sa.Column("subject", sa.String(256), primary_key=True),
        sa.Column(
            "principal_id",
            sa.String(256),
            sa.ForeignKey("principals.id"),
            nullable=False,
        ),
    )
    op.create_index("ix_external_identities_principal_id", "external_identities", ["principal_id"])


def downgrade() -> None:
    op.drop_index("ix_external_identities_principal_id", table_name="external_identities")
    op.drop_table("external_identities")
