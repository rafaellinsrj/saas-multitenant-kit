"""Alembic runs as the OWNER role (DATABASE_OWNER_URL), never as the app role."""

import asyncio
import os

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine


def _do_run(connection) -> None:
    context.configure(connection=connection, target_metadata=None, transaction_per_migration=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run() -> None:
    url = os.environ.get("DATABASE_OWNER_URL")
    if not url:
        raise RuntimeError("DATABASE_OWNER_URL is required to run migrations")
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        await conn.run_sync(_do_run)
    await engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline mode is not supported")
asyncio.run(_run())
