"""Deny-by-default OAuth client admission with immediate revocation.

Revision ID: 0003_oauth_client_admissions
Revises: 0002_external_oauth_identities
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_oauth_client_admissions"
down_revision = "0002_external_oauth_identities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_client_admissions",
        sa.Column("client_id", sa.String(256), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_table("oauth_client_admissions")
