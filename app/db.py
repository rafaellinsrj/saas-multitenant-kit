"""Database access with the tenant pinned to every transaction.

The workspace id lives in `session.info` and is written into the
transaction-scoped setting `app.workspace_id` each time a transaction
begins (`set_config(..., is_local => true)`). Two consequences:

* A pooled connection never carries the previous request's tenant: the
  setting dies with the transaction that set it.
* A session without a workspace sets an empty value. Every RLS policy
  compares against it, so such a session sees and writes nothing
  (fail closed) instead of everything.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.config import load


class TenantSession(Session):
    """Sync session class behind AsyncSession; carries the tenant listener."""


@event.listens_for(TenantSession, "after_begin")
def _pin_tenant(session: Session, transaction, connection) -> None:
    connection.execute(
        text("SELECT set_config('app.workspace_id', :ws, true)"),
        {"ws": session.info.get("workspace_id", "")},
    )


@lru_cache(maxsize=1)
def engine() -> AsyncEngine:
    return create_async_engine(load().database_url, pool_pre_ping=True)


@lru_cache(maxsize=1)
def sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine(), expire_on_commit=False, sync_session_class=TenantSession)


def new_session(workspace_id: uuid.UUID | str | None) -> AsyncSession:
    session = sessionmaker()()
    session.info["workspace_id"] = str(uuid.UUID(str(workspace_id))) if workspace_id else ""
    return session


@asynccontextmanager
async def tenant_tx(workspace_id: uuid.UUID | str) -> AsyncIterator[AsyncSession]:
    """One transaction scoped to one workspace. Commits on success."""
    if not workspace_id:
        raise ValueError("workspace_id is required")
    async with new_session(workspace_id) as session, session.begin():
        yield session


@asynccontextmanager
async def anonymous_tx() -> AsyncIterator[AsyncSession]:
    """Transaction with no tenant. Tenant tables are invisible here."""
    async with new_session(None) as session, session.begin():
        yield session
