"""Migrate a disposable metadata database without touching Supabase or Odoo."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_oauth_migrations_preserve_existing_private_grants(tmp_path: Path) -> None:
    migration_dir = (
        Path(__file__).resolve().parents[2] / "src" / "monynha_odoo_mcp" / "storage" / "migrations"
    )
    url = f"sqlite+pysqlite:///{tmp_path / 'monynha-migration-test.db'}"
    config = Config()
    config.set_main_option("script_location", str(migration_dir))
    config.set_main_option("sqlalchemy.url", url)

    command.upgrade(config, "0001_initial")
    engine = create_engine(url)
    with engine.begin() as session:
        session.execute(text("INSERT INTO organizations (id) VALUES ('org-existing')"))
        session.execute(text("INSERT INTO principals (id) VALUES ('principal-existing')"))
        session.execute(
            text(
                "INSERT INTO memberships (principal_id, organization_id) "
                "VALUES ('principal-existing', 'org-existing')"
            )
        )
    command.upgrade(config, "head")

    assert {"external_identities", "oauth_client_admissions"}.issubset(
        inspect(engine).get_table_names()
    )
    with engine.begin() as session:
        assert session.scalar(text("SELECT count(*) FROM memberships")) == 1
        session.execute(
            text(
                "INSERT INTO external_identities (issuer, subject, principal_id) "
                "VALUES ('https://identity.example/auth/v1', 'subject-1', 'principal-existing')"
            )
        )
        session.execute(
            text("INSERT INTO oauth_client_admissions (client_id, enabled) VALUES ('client-1', 1)")
        )
    command.downgrade(config, "0001_initial")
    assert {"external_identities", "oauth_client_admissions"}.isdisjoint(
        inspect(engine).get_table_names()
    )
    with engine.connect() as session:
        assert session.scalar(text("SELECT count(*) FROM memberships")) == 1
    engine.dispose()
