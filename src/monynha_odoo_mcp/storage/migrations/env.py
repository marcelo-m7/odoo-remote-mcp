"""Alembic environment for Monynha metadata."""

import os

from alembic import context
from sqlalchemy import create_engine, pool

from monynha_odoo_mcp.storage.db import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("MONYNHA_MCP_DATABASE_URL")
    if not url:
        raise RuntimeError("MONYNHA_MCP_DATABASE_URL is required")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("MONYNHA_MCP_DATABASE_URL")
    if not url:
        raise RuntimeError("MONYNHA_MCP_DATABASE_URL is required")
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
