"""ORM mapping. The schema itself (roles, grants, RLS, triggers) is owned by
the Alembic migration; these classes only describe the columns."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _ws() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[uuid.UUID] = _pk()
    name: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = _now()


class Member(Base):
    __tablename__ = "members"
    id: Mapped[uuid.UUID] = _pk()
    workspace_id: Mapped[uuid.UUID] = _ws()
    display_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(20), default="member")
    created_at: Mapped[datetime] = _now()


class LedgerEntry(Base):
    """Append-only. The database refuses UPDATE, DELETE and TRUNCATE."""

    __tablename__ = "credit_ledger"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    workspace_id: Mapped[uuid.UUID] = _ws()
    kind: Mapped[str] = mapped_column(String(20))
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    reference_kind: Mapped[str] = mapped_column(String(40))
    reference_id: Mapped[str] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _now()


class Reservation(Base):
    __tablename__ = "credit_reservations"
    id: Mapped[uuid.UUID] = _pk()
    workspace_id: Mapped[uuid.UUID] = _ws()
    idempotency_key: Mapped[str] = mapped_column(String(255))
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(20), default="held")
    ledger_entry_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = _now()
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[uuid.UUID] = _pk()
    workspace_id: Mapped[uuid.UUID] = _ws()
    member_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("members.id"))
    kind: Mapped[str] = mapped_column(String(40))
    idempotency_key: Mapped[str] = mapped_column(String(255))
    input: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    max_cost_cents: Mapped[int] = mapped_column(BigInteger)
    cost_cents: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    reservation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = _now()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VaultSecretMeta(Base):
    """Metadata view of vault_secrets. The `ciphertext` column is deliberately
    absent: the application role cannot SELECT it (column-level grant), so any
    code path that tries to load it fails loudly. Only app.services.vault reads
    it, under a dedicated reader role."""

    __tablename__ = "vault_secrets"
    id: Mapped[uuid.UUID] = _pk()
    workspace_id: Mapped[uuid.UUID] = _ws()
    name: Mapped[str] = mapped_column(String(80))
    provider: Mapped[str] = mapped_column(String(40))
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()
