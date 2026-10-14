"""Append-only ledger and prepaid credit (reserve worst case, settle, release)."""

import asyncio
import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.models import LedgerEntry, Reservation
from app.services import credits


async def _funded(pg, make_workspace, cents: int = 1_000) -> uuid.UUID:
    ws, _ = await make_workspace()
    async with pg.tenant_tx(ws) as db:
        await credits.top_up(db, ws, cents, reference_kind="checkout", reference_id=f"cs_{uuid.uuid4().hex}")
    return ws


async def _wallet(pg, ws) -> credits.Wallet:
    async with pg.tenant_tx(ws) as db:
        return await credits.wallet(db, ws)


# --- append-only --------------------------------------------------------------


@pytest.mark.parametrize(
    "statement", ["UPDATE credit_ledger SET amount_cents = 1", "DELETE FROM credit_ledger"]
)
async def test_app_role_has_no_update_or_delete_grant(pg, make_workspace, statement):
    ws = await _funded(pg, make_workspace)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with pg.tenant_tx(ws) as db:
            await db.execute(text(statement))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE credit_ledger SET note = 'edited'",
        "DELETE FROM credit_ledger",
        "TRUNCATE credit_ledger CASCADE",
    ],
)
async def test_trigger_stops_even_the_owner(pg, make_workspace, owner_engine, statement):
    await _funded(pg, make_workspace)
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(text(statement))


async def test_balance_is_derived_from_the_ledger(pg, make_workspace):
    ws = await _funded(pg, make_workspace, 700)
    async with pg.tenant_tx(ws) as db:
        await credits.top_up(db, ws, 300, reference_kind="checkout", reference_id="cs_second")
        total = (await db.execute(select(func.sum(LedgerEntry.amount_cents)))).scalar_one()
        assert (await credits.wallet(db, ws)).balance_cents == total == 1_000


async def test_database_refuses_a_negative_balance(pg, make_workspace):
    ws = await _funded(pg, make_workspace, 100)
    with pytest.raises(DBAPIError, match="negative"):
        async with pg.tenant_tx(ws) as db:  # bypassing the service on purpose
            db.add(
                LedgerEntry(
                    workspace_id=ws,
                    kind="adjustment",
                    amount_cents=-101,
                    reference_kind="test",
                    reference_id="overdraw",
                )
            )


# --- top-up idempotency -------------------------------------------------------


async def test_same_payment_reference_credits_once(pg, make_workspace):
    ws, _ = await make_workspace()
    for _ in range(3):
        async with pg.tenant_tx(ws) as db:
            await credits.top_up(db, ws, 500, reference_kind="checkout", reference_id="cs_same")
    assert (await _wallet(pg, ws)).balance_cents == 500
    with pytest.raises(credits.IdempotencyConflict):
        async with pg.tenant_tx(ws) as db:
            await credits.top_up(db, ws, 900, reference_kind="checkout", reference_id="cs_same")


# --- reserve / settle / release ------------------------------------------------


async def test_reserve_settle_release_cycle(pg, make_workspace):
    ws = await _funded(pg, make_workspace, 1_000)
    async with pg.tenant_tx(ws) as db:
        hold = await credits.reserve(db, ws, "req-1", 400)
    assert await _wallet(pg, ws) == credits.Wallet(balance_cents=1_000, reserved_cents=400)

    async with pg.tenant_tx(ws) as db:
        entry = await credits.settle(db, ws, hold.id, 120)
    assert entry.amount_cents == -120
    w = await _wallet(pg, ws)
    assert (w.balance_cents, w.reserved_cents, w.available_cents) == (880, 0, 880)

    async with pg.tenant_tx(ws) as db:  # settling again is a replay, not a second charge
        again = await credits.settle(db, ws, hold.id, 120)
    assert again.id == entry.id and (await _wallet(pg, ws)).balance_cents == 880

    async with pg.tenant_tx(ws) as db:
        other = await credits.reserve(db, ws, "req-2", 500)
    async with pg.tenant_tx(ws) as db:
        await credits.release(db, ws, other.id)
        await credits.release(db, ws, other.id)  # idempotent
    assert (await _wallet(pg, ws)).available_cents == 880


async def test_reservation_beyond_available_is_refused(pg, make_workspace):
    ws = await _funded(pg, make_workspace, 300)
    async with pg.tenant_tx(ws) as db:
        await credits.reserve(db, ws, "a", 200)
    with pytest.raises(credits.InsufficientCredit) as info:
        async with pg.tenant_tx(ws) as db:
            await credits.reserve(db, ws, "b", 101)
    assert info.value.available_cents == 100


async def test_reserve_replay_returns_same_hold(pg, make_workspace):
    ws = await _funded(pg, make_workspace)
    async with pg.tenant_tx(ws) as db:
        first = await credits.reserve(db, ws, "same-key", 100)
    async with pg.tenant_tx(ws) as db:
        second = await credits.reserve(db, ws, "same-key", 100)
    assert first.id == second.id and (await _wallet(pg, ws)).reserved_cents == 100
    with pytest.raises(credits.IdempotencyConflict):
        async with pg.tenant_tx(ws) as db:
            await credits.reserve(db, ws, "same-key", 999)


async def test_actual_cost_cannot_exceed_the_hold(pg, make_workspace):
    ws = await _funded(pg, make_workspace)
    async with pg.tenant_tx(ws) as db:
        hold = await credits.reserve(db, ws, "k", 50)
    with pytest.raises(credits.CreditError, match="worst case"):
        async with pg.tenant_tx(ws) as db:
            await credits.settle(db, ws, hold.id, 51)
    assert (await _wallet(pg, ws)).reserved_cents == 50  # hold kept for a human to decide


async def test_closed_reservation_is_frozen_in_the_database(pg, make_workspace):
    ws = await _funded(pg, make_workspace)
    async with pg.tenant_tx(ws) as db:
        hold = await credits.reserve(db, ws, "k", 50)
    async with pg.tenant_tx(ws) as db:
        await credits.release(db, ws, hold.id)
    with pytest.raises(DBAPIError, match="already released"):
        async with pg.tenant_tx(ws) as db:
            await db.execute(
                text("UPDATE credit_reservations SET status = 'held', closed_at = NULL WHERE id = :id"),
                {"id": hold.id},
            )


async def test_concurrent_reservations_never_overspend(pg, make_workspace):
    ws = await _funded(pg, make_workspace, 100)

    async def attempt(i: int) -> bool:
        try:
            async with pg.tenant_tx(ws) as db:
                await credits.reserve(db, ws, f"race-{i}", 30)
            return True
        except credits.InsufficientCredit:
            return False

    results = await asyncio.gather(*(attempt(i) for i in range(10)))
    assert sum(results) == 3
    async with pg.tenant_tx(ws) as db:
        held = (await db.execute(select(func.sum(Reservation.amount_cents)))).scalar_one()
    assert held == 90
