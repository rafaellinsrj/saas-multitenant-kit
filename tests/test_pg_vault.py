"""Secrets are encrypted at rest, never returned by the API, read by one narrow service."""

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.services import vault
from app.services.vault_crypto import VaultUnavailable
from tests.conftest import bearer

FAKE = "fake-credential-for-tests-0123456789"


async def test_api_returns_metadata_only(client, make_workspace):
    ws, member = await make_workspace()
    created = await client.post(
        "/vault/secrets", headers=bearer(ws, member), json={"name": "crm", "provider": "demo", "value": FAKE}
    )
    assert created.status_code == 201
    listed = await client.get("/vault/secrets", headers=bearer(ws, member))
    for resp in (created, listed):
        assert FAKE not in resp.text
        assert "ciphertext" not in resp.text and "value" not in resp.text


async def test_ciphertext_at_rest_is_not_plaintext(client, make_workspace, owner_engine):
    ws, member = await make_workspace()
    await client.post(
        "/vault/secrets", headers=bearer(ws, member), json={"name": "crm", "provider": "demo", "value": FAKE}
    )
    async with owner_engine.connect() as conn:
        stored = (
            await conn.execute(
                text("SELECT ciphertext FROM vault_secrets WHERE workspace_id = :w"), {"w": ws}
            )
        ).scalar_one()
    assert FAKE not in stored and '"kid"' in stored


async def test_app_role_cannot_select_ciphertext(pg, make_workspace):
    ws, _ = await make_workspace()
    async with pg.tenant_tx(ws) as db:
        await vault.create(db, ws, "crm", "demo", FAKE)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with pg.tenant_tx(ws) as db:
            await db.execute(text("SELECT ciphertext FROM vault_secrets"))
    with pytest.raises(DBAPIError, match="permission denied"):
        async with pg.tenant_tx(ws) as db:
            await db.execute(select(vault._secrets))  # even the "full" table object


async def test_use_secret_is_tenant_scoped_and_audited(pg, make_workspace):
    a, _ = await make_workspace("A")
    b, _ = await make_workspace("B")
    async with pg.tenant_tx(a) as db:
        await vault.create(db, a, "crm", "demo", FAKE)
    async with pg.tenant_tx(a) as db:
        assert await vault.use_secret(db, a, "crm") == FAKE
        # the role switch is undone right away: writes work again
        assert (await db.execute(text("SELECT current_user"))).scalar() == "kit_app"
        actions = (await db.execute(text("SELECT action FROM vault_events ORDER BY id"))).scalars().all()
    assert actions == ["created", "used"]
    with pytest.raises(VaultUnavailable):
        async with pg.tenant_tx(b) as db:
            await vault.use_secret(db, a, "crm")  # B asking for A's secret by A's id


async def test_revoke_removes_the_ciphertext(client, make_workspace, pg):
    ws, member = await make_workspace()
    created = (
        await client.post(
            "/vault/secrets",
            headers=bearer(ws, member),
            json={"name": "crm", "provider": "demo", "value": FAKE},
        )
    ).json()
    assert (
        await client.delete(f"/vault/secrets/{created['id']}", headers=bearer(ws, member))
    ).status_code == 204
    listed = (await client.get("/vault/secrets", headers=bearer(ws, member))).json()
    assert listed[0]["status"] == "revoked"
    with pytest.raises(VaultUnavailable):
        async with pg.tenant_tx(ws) as db:
            await vault.use_secret(db, ws, "crm")
