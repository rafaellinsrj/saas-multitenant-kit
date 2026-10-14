"""Prepaid credit: reserve the worst case, settle the actual cost, release on failure.

Invariants (enforced here and again by the database):

1. The ledger is the only source of truth. The balance is SUM(amount_cents);
   there is no mutable balance column to drift.
2. Ledger rows are never updated or deleted (grants + trigger).
3. available = balance - held reservations, and it never goes below zero:
   a reservation that does not fit is refused before any work starts.
4. Every write is idempotent. Top-ups key on the payment reference,
   reservations on a caller-supplied idempotency key, settlements on the
   reservation id.
5. Writes for one workspace are serialized with a transaction-scoped
   advisory lock, so two concurrent reservations cannot both spend the
   same last cent.

Amounts are integer cents. No floats anywhere near money.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import LedgerEntry, Reservation


class CreditError(Exception):
    pass


class InsufficientCredit(CreditError):
    def __init__(self, available_cents: int, needed_cents: int):
        self.available_cents = available_cents
        self.needed_cents = needed_cents
        super().__init__(f"available {available_cents} < needed {needed_cents}")


class IdempotencyConflict(CreditError):
    """Same idempotency key replayed with different parameters."""


@dataclass(frozen=True)
class Wallet:
    balance_cents: int
    reserved_cents: int

    @property
    def available_cents(self) -> int:
        return self.balance_cents - self.reserved_cents


def _positive_int(value: object, what: str) -> int:
    if type(value) is not int or value <= 0:
        raise CreditError(f"{what} must be a positive integer number of cents")
    return value


async def _lock(db: AsyncSession, workspace_id: uuid.UUID) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"credit:{workspace_id}"}
    )


async def wallet(db: AsyncSession, workspace_id: uuid.UUID) -> Wallet:
    """Balance and holds in one statement, so both come from the same snapshot."""
    balance = (
        select(func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .where(LedgerEntry.workspace_id == workspace_id)
        .scalar_subquery()
    )
    held = (
        select(func.coalesce(func.sum(Reservation.amount_cents), 0))
        .where(Reservation.workspace_id == workspace_id, Reservation.status == "held")
        .scalar_subquery()
    )
    row = (await db.execute(select(balance, held))).one()
    return Wallet(balance_cents=int(row[0]), reserved_cents=int(row[1]))


async def _append(db: AsyncSession, **fields) -> LedgerEntry:
    entry = LedgerEntry(**fields)
    db.add(entry)
    await db.flush()
    return entry


async def top_up(
    db: AsyncSession, workspace_id: uuid.UUID, amount_cents: int, *, reference_kind: str, reference_id: str
) -> LedgerEntry:
    """Credit a confirmed payment. The payment reference is the idempotency key."""
    _positive_int(amount_cents, "amount")
    if not reference_id:
        raise CreditError("top-up needs a payment reference")
    await _lock(db, workspace_id)
    existing = (
        await db.execute(
            select(LedgerEntry).where(
                LedgerEntry.workspace_id == workspace_id,
                LedgerEntry.kind == "topup",
                LedgerEntry.reference_id == reference_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.amount_cents != amount_cents or existing.reference_kind != reference_kind:
            raise IdempotencyConflict("payment reference already credited with a different amount")
        return existing
    return await _append(
        db,
        workspace_id=workspace_id,
        kind="topup",
        amount_cents=amount_cents,
        reference_kind=reference_kind,
        reference_id=reference_id,
    )


async def reserve(
    db: AsyncSession, workspace_id: uuid.UUID, idempotency_key: str, amount_cents: int
) -> Reservation:
    """Hold the worst-case cost before starting work. Replays return the same hold."""
    _positive_int(amount_cents, "reservation")
    if not idempotency_key:
        raise CreditError("idempotency key is required")
    await _lock(db, workspace_id)
    existing = (
        await db.execute(
            select(Reservation).where(
                Reservation.workspace_id == workspace_id, Reservation.idempotency_key == idempotency_key
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.amount_cents != amount_cents:
            raise IdempotencyConflict("idempotency key reused with a different amount")
        return existing
    current = await wallet(db, workspace_id)
    if current.available_cents < amount_cents:
        raise InsufficientCredit(current.available_cents, amount_cents)
    hold = Reservation(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        idempotency_key=idempotency_key,
        amount_cents=amount_cents,
        status="held",
    )
    db.add(hold)
    await db.flush()
    return hold


async def _held(db: AsyncSession, workspace_id: uuid.UUID, reservation_id: uuid.UUID) -> Reservation:
    await _lock(db, workspace_id)
    return (
        await db.execute(
            select(Reservation)
            .where(Reservation.workspace_id == workspace_id, Reservation.id == reservation_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def settle(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    reservation_id: uuid.UUID,
    actual_cents: int,
    *,
    note: str | None = None,
) -> LedgerEntry | None:
    """Charge the real cost (<= the hold) and close the reservation.

    Settling twice returns the original entry. A zero actual cost closes the
    hold without writing a ledger row (the ledger never stores zero).
    """
    if type(actual_cents) is not int or actual_cents < 0:
        raise CreditError("actual cost must be a non-negative integer")
    hold = await _held(db, workspace_id, reservation_id)
    if hold.status == "settled":
        entry = await db.get(LedgerEntry, hold.ledger_entry_id)
        if entry is None or -entry.amount_cents != actual_cents:
            raise IdempotencyConflict("reservation already settled with a different amount")
        return entry
    if hold.status != "held":
        raise CreditError(f"reservation is {hold.status}")
    if actual_cents > hold.amount_cents:
        # The worst case was wrong. Refuse instead of silently overdrawing;
        # the caller decides (alert, adjustment) with the hold still in place.
        raise CreditError("actual cost exceeds the reserved worst case")
    now = datetime.now(UTC)
    if actual_cents == 0:
        hold.status, hold.closed_at = "released", now
        await db.flush()
        return None
    entry = await _append(
        db,
        workspace_id=workspace_id,
        kind="usage",
        amount_cents=-actual_cents,
        reference_kind="reservation",
        reference_id=str(hold.id),
        note=note,
    )
    hold.status, hold.ledger_entry_id, hold.closed_at = "settled", entry.id, now
    await db.flush()
    return entry


async def release(db: AsyncSession, workspace_id: uuid.UUID, reservation_id: uuid.UUID) -> None:
    """Give the hold back after a confirmed failure. Idempotent."""
    hold = await _held(db, workspace_id, reservation_id)
    if hold.status == "released":
        return
    if hold.status != "held":
        raise CreditError(f"reservation is {hold.status}")
    hold.status, hold.closed_at = "released", datetime.now(UTC)
    await db.flush()
