"""Tenant isolation is enforced by PostgreSQL, not by remembering a WHERE clause."""

import uuid

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError

from app.models import Job, LedgerEntry, Member, Reservation, VaultSecretMeta, Workspace
from tests.conftest import bearer

TENANT_TABLES = [
    "workspaces",
    "members",
    "credit_ledger",
    "credit_reservations",
    "vault_secrets",
    "vault_events",
    "jobs",
]


async def test_query_without_filter_only_sees_own_tenant(pg, make_workspace):
    a, _ = await make_workspace("A")
    b, _ = await make_workspace("B")
    async with pg.tenant_tx(a) as db:
        members = (await db.execute(select(Member))).scalars().all()  # "forgot" the filter
        workspaces = (await db.execute(select(Workspace))).scalars().all()
    assert {m.workspace_id for m in members} == {a}
    assert [w.id for w in workspaces] == [a]
    assert b not in {w.id for w in workspaces}


async def test_buggy_query_asking_for_other_tenant_gets_nothing(pg, make_workspace):
    a, _ = await make_workspace("A")
    b, _ = await make_workspace("B")
    async with pg.tenant_tx(a) as db:
        assert (await db.execute(select(Member).where(Member.workspace_id == b))).first() is None
        assert await db.get(Workspace, b) is None


async def test_cannot_write_into_other_tenant(pg, make_workspace):
    a, _ = await make_workspace("A")
    b, _ = await make_workspace("B")
    with pytest.raises(DBAPIError, match="row-level security"):
        async with pg.tenant_tx(a) as db:
            db.add(Member(id=uuid.uuid4(), workspace_id=b, display_name="intruder"))
            await db.flush()


async def test_cannot_update_other_tenant_rows(pg, make_workspace):
    a, _ = await make_workspace("A")
    b, _ = await make_workspace("B")
    async with pg.tenant_tx(a) as db:
        result = await db.execute(update(Member).where(Member.workspace_id == b).values(display_name="x"))
        assert result.rowcount == 0
    async with pg.tenant_tx(b) as db:
        names = (await db.execute(select(Member.display_name))).scalars().all()
    assert names == ["B owner"]


async def test_cannot_move_a_row_to_another_tenant(pg, make_workspace):
    a, _ = await make_workspace("A")
    b, _ = await make_workspace("B")
    with pytest.raises(DBAPIError):
        async with pg.tenant_tx(a) as db:
            await db.execute(text("UPDATE members SET workspace_id = :b"), {"b": b})


async def test_no_tenant_context_means_no_rows(pg, make_workspace):
    await make_workspace("A")
    async with pg.anonymous_tx() as db:
        for model in (Workspace, Member, LedgerEntry, Reservation, VaultSecretMeta, Job):
            assert (await db.execute(select(model))).first() is None


async def test_context_does_not_leak_through_the_pool(pg, make_workspace):
    a, _ = await make_workspace("A")
    async with pg.tenant_tx(a) as db:
        assert (await db.execute(text("SELECT current_setting('app.workspace_id')"))).scalar() == str(a)
    for _ in range(3):  # same pooled connections, new transactions
        async with pg.anonymous_tx() as db:
            assert (await db.execute(text("SELECT current_setting('app.workspace_id', true)"))).scalar() == ""


async def test_malformed_context_fails_closed(pg, make_workspace):
    await make_workspace("A")
    with pytest.raises(DBAPIError):
        async with pg.anonymous_tx() as db:
            await db.execute(text("SELECT set_config('app.workspace_id', 'not-a-uuid', true)"))
            await db.execute(select(Member))


async def test_app_role_cannot_bypass_rls(pg):
    async with pg.anonymous_tx() as db:
        role = (
            await db.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))
        ).one()
        assert tuple(role) == (False, False)
        rows = (
            await db.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner) "
                    "FROM pg_class c WHERE c.relname = ANY(:t)"
                ),
                {"t": TENANT_TABLES},
            )
        ).all()
    assert len(rows) == len(TENANT_TABLES)
    for name, enabled, forced, owner in rows:
        assert enabled and forced, name
        assert owner != "kit_app", name


async def test_api_hides_other_tenants_resources(client, make_workspace):
    a, a_member = await make_workspace("A")
    b, b_member = await make_workspace("B")
    created = await client.post(
        "/vault/secrets",
        headers=bearer(a, a_member),
        json={"name": "svc", "provider": "demo", "value": "fake-value-0001"},
    )
    assert created.status_code == 201
    secret_id = created.json()["id"]
    assert (await client.get("/vault/secrets", headers=bearer(b, b_member))).json() == []
    resp = await client.delete(f"/vault/secrets/{secret_id}", headers=bearer(b, b_member))
    assert resp.status_code == 404
    assert (await client.get(f"/jobs/{uuid.uuid4()}", headers=bearer(b, b_member))).status_code == 404
    me = (await client.get("/workspace", headers=bearer(b, b_member))).json()
    assert me["id"] == str(b) and len(me["members"]) == 1
