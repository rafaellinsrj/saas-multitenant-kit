"""Payment webhooks: verify the signature, record the event once, then credit.

Signature scheme (compatible with Stripe's `Stripe-Signature` header):

    Stripe-Signature: t=<unix seconds>,v1=<hex hmac>[,v1=<hex hmac>...]
    v1 = HMAC-SHA256(secret, f"{t}.{raw_body}")

* The raw request body is signed. Re-serializing parsed JSON changes bytes
  and breaks verification, so the endpoint passes bytes through untouched.
* Several v1 entries can appear during secret rotation; any match passes.
* A timestamp outside the tolerance window is rejected (replay of a
  captured request), and comparisons use constant time.

Idempotency: the event id is inserted with ON CONFLICT DO NOTHING in the
same transaction that credits the ledger. Either both commit or neither
does, so a crash mid-processing lets the provider's retry try again, and a
replay of a processed event is a no-op. The top-up itself is also keyed on
the checkout session id, which covers two *different* events that describe
the same payment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as database
from app.services import credits

CREDIT_EVENTS = {"checkout.session.completed", "checkout.session.async_payment_succeeded"}


class SignatureError(Exception):
    """Any verification failure. Callers must not reveal which check failed."""


def sign(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Build a header value. Used by tests and local tooling, not in production paths."""
    ts = int(time.time()) if timestamp is None else timestamp
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify(
    payload: bytes, header: str | None, secret: str, *, tolerance_s: int = 300, now: int | None = None
) -> dict:
    if not secret:
        raise SignatureError("webhook secret not configured")
    if not header:
        raise SignatureError("missing signature header")
    timestamp: int | None = None
    candidates: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                raise SignatureError("bad timestamp") from None
        elif key == "v1" and value:
            candidates.append(value)
    if timestamp is None or not candidates:
        raise SignatureError("malformed signature header")
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance_s:
        raise SignatureError("timestamp outside tolerance")
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, c) for c in candidates):
        raise SignatureError("signature mismatch")
    try:
        event = json.loads(payload)
    except ValueError:
        raise SignatureError("body is not JSON") from None
    if not isinstance(event, dict) or not event.get("id") or not event.get("type"):
        raise SignatureError("event without id or type")
    return event


@dataclass(frozen=True)
class Outcome:
    status: str  # "processed", "duplicate" or "ignored"
    credited_cents: int = 0


async def _first_time(db: AsyncSession, event: dict) -> bool:
    inserted = await db.execute(
        text(
            "INSERT INTO webhook_events (event_id, event_type) VALUES (:id, :type) "
            "ON CONFLICT (event_id) DO NOTHING RETURNING event_id"
        ),
        {"id": str(event["id"])[:255], "type": str(event["type"])[:100]},
    )
    return inserted.scalar_one_or_none() is not None


def _checkout(event: dict) -> tuple[uuid.UUID, str, int] | None:
    obj = (event.get("data") or {}).get("object") or {}
    if obj.get("payment_status") != "paid":
        return None
    workspace = (obj.get("metadata") or {}).get("workspace_id")
    amount = obj.get("amount_total")
    if not obj.get("id") or type(amount) is not int or amount <= 0:
        raise ValueError("checkout session without id or amount")
    return uuid.UUID(str(workspace)), str(obj["id"]), amount


async def process(event: dict) -> Outcome:
    """Process a verified event. Raises on bad data so the provider retries."""
    if event["type"] not in CREDIT_EVENTS:
        async with database.anonymous_tx() as db:
            return Outcome("processed" if await _first_time(db, event) else "duplicate")
    checkout = _checkout(event)
    if checkout is None:
        # Paid later (async methods): the async_payment_succeeded event credits.
        async with database.anonymous_tx() as db:
            return Outcome("ignored" if await _first_time(db, event) else "duplicate")
    workspace_id, session_id, amount = checkout
    # The tenant comes from metadata we attached when creating the checkout.
    # Under RLS the credit can only land in that workspace, and the FK on the
    # ledger fails if the workspace does not exist.
    async with database.tenant_tx(workspace_id) as db:
        if not await _first_time(db, event):
            return Outcome("duplicate")
        entry = await credits.top_up(
            db, workspace_id, amount, reference_kind="checkout", reference_id=session_id
        )
        return Outcome("processed", entry.amount_cents)
