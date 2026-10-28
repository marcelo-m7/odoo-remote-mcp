"""Metadata schema. PostgreSQL is required for hosted deployments."""

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    String,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class OrganizationRow(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)


class PrincipalRow(Base):
    __tablename__ = "principals"
    id: Mapped[str] = mapped_column(String(256), primary_key=True)


class ExternalIdentityRow(Base):
    __tablename__ = "external_identities"
    issuer: Mapped[str] = mapped_column(String(512), primary_key=True)
    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    principal_id: Mapped[str] = mapped_column(
        String(256), ForeignKey("principals.id"), nullable=False, index=True
    )


class OAuthClientAdmissionRow(Base):
    __tablename__ = "oauth_client_admissions"
    client_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class MembershipRow(Base):
    __tablename__ = "memberships"
    principal_id: Mapped[str] = mapped_column(
        String(256), ForeignKey("principals.id"), primary_key=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("organizations.id"), primary_key=True
    )


class ConnectionRow(Base):
    __tablename__ = "connections"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("organizations.id"), nullable=False, index=True
    )
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    database: Mapped[str | None] = mapped_column(String(256))
    secret_ref: Mapped[str] = mapped_column(String(256), nullable=False)


class PolicyRow(Base):
    __tablename__ = "policies"
    principal_id: Mapped[str] = mapped_column(
        String(256), ForeignKey("principals.id"), primary_key=True
    )
    connection_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("connections.id"), primary_key=True
    )
    operation: Mapped[str] = mapped_column(String(32), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), primary_key=True)


class AuditRow(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False)


def create_database(url: str) -> tuple[object, sessionmaker[Session]]:
    engine = create_engine(url, pool_pre_ping=True)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine, sessionmaker(engine, expire_on_commit=False)


def create_schema(engine) -> None:
    """Local/test bootstrap only. Hosted deployments run Alembic migrations."""
    Base.metadata.create_all(engine)
