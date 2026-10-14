"""Test setup.

Unit tests (signature, crypto, state machine, tokens) need nothing.
Tests that take the `pg` fixture need PostgreSQL 16:

    docker compose up -d db

They create a throwaway database, run the Alembic migration as the owner
role and then talk to it as `kit_app`, exactly like the API does. Without a
reachable server they are skipped, unless KIT_REQUIRE_PG=1 (set in CI), in
which case they fail.

Every secret below is generated per run and is obviously fake.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

os.environ.setdefault("TOKEN_SECRET", "test-token-" + secrets.token_hex(16))
os.environ.setdefault("PAYMENT_WEBHOOK_SECRET", "test-webhook-" + secrets.token_hex(16))
os.environ.setdefault("VAULT_KEYS", json.dumps({"t1": base64.b64encode(os.urandom(32)).decode()}))
os.environ.setdefault("VAULT_ACTIVE_KEY", "t1")
os.environ.setdefault("KIT_APP_DB_PASSWORD", "kit_app_local")

PG_HOST = os.environ.get("KIT_TEST_PG_HOST", "localhost")
PG_PORT = os.environ.get("KIT_TEST_PG_PORT", "54329")
PG_OWNER = os.environ.get("KIT_TEST_PG_OWNER", "kit_owner")
PG_OWNER_PASSWORD = os.environ.get("KIT_TEST_PG_OWNER_PASSWORD", "kit_owner_local")
TEST_DB = "kit_test"


def _owner_dsn(db: str) -> str:
    return f"postgresql://{PG_OWNER}:{PG_OWNER_PASSWORD}@{PG_HOST}:{PG_PORT}/{db}"


async def _recreate_database() -> None:
    import asyncpg

    conn = await asyncpg.connect(_owner_dsn("postgres"), timeout=5)
    try:
        await conn.execute(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)")
        await conn.execute(f"CREATE DATABASE {TEST_DB}")
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def pg_urls() -> dict[str, str]:
    try:
        asyncio.run(_recreate_database())
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("KIT_REQUIRE_PG") == "1":
            pytest.fail(f"PostgreSQL required but unavailable: {exc!r}")
        pytest.skip(f"PostgreSQL not reachable ({type(exc).__name__}); run `docker compose up -d db`")
    owner = _owner_dsn(TEST_DB).replace("postgresql://", "postgresql+asyncpg://")
    app = f"postgresql+asyncpg://kit_app:{os.environ['KIT_APP_DB_PASSWORD']}@{PG_HOST}:{PG_PORT}/{TEST_DB}"
    env = {**os.environ, "DATABASE_OWNER_URL": owner}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, check=True)
    os.environ["DATABASE_URL"] = app
    return {"owner": owner, "app": app}


@pytest.fixture(scope="session")
async def pg(pg_urls):
    """Application engine (kit_app role). Yields the app.db module."""
    from app import db

    db.engine.cache_clear()
    db.sessionmaker.cache_clear()
    yield db
    await db.engine().dispose()


@pytest.fixture(scope="session")
async def owner_engine(pg_urls):
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(pg_urls["owner"])
    yield engine
    await engine.dispose()


@pytest.fixture
def make_workspace(pg):
    from app.models import Member, Workspace

    async def create(name: str = "Acme") -> tuple[uuid.UUID, uuid.UUID]:
        ws, member = uuid.uuid4(), uuid.uuid4()
        async with pg.tenant_tx(ws) as session:
            session.add(Workspace(id=ws, name=name))
            await session.flush()
            session.add(Member(id=member, workspace_id=ws, display_name=f"{name} owner", role="owner"))
        return ws, member

    return create


@pytest.fixture
async def client(pg):
    import httpx

    from app.main import create_app

    transport = httpx.ASGITransport(app=create_app(), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://kit.test") as c:
        yield c


def bearer(workspace_id: uuid.UUID, member_id: uuid.UUID) -> dict[str, str]:
    from app import auth

    return {"Authorization": "Bearer " + auth.issue(workspace_id, member_id, os.environ["TOKEN_SECRET"])}
