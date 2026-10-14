"""Signed, idempotent payment webhooks crediting the ledger."""

import json
import os
import uuid

from sqlalchemy import select, text

from app.models import LedgerEntry
from app.services.webhooks import sign
from tests.conftest import bearer


def _event(
    workspace_id,
    *,
    event_id=None,
    session_id="cs_test_1",
    amount=2_500,
    type_="checkout.session.completed",
    paid=True,
) -> bytes:
    return json.dumps(
        {
            "id": event_id or f"evt_{uuid.uuid4().hex}",
            "type": type_,
            "data": {
                "object": {
                    "id": session_id,
                    "amount_total": amount,
                    "currency": "usd",
                    "payment_status": "paid" if paid else "unpaid",
                    "metadata": {"workspace_id": str(workspace_id)},
                }
            },
        }
    ).encode()


async def _post(client, body: bytes, secret: str | None = None):
    header = sign(body, secret or os.environ["PAYMENT_WEBHOOK_SECRET"])
    return await client.post(
        "/webhooks/payments",
        content=body,
        headers={"stripe-signature": header, "content-type": "application/json"},
    )


async def _balance(client, ws, member) -> int:
    return (await client.get("/credits", headers=bearer(ws, member))).json()["balance_cents"]


async def test_bad_signature_is_rejected_and_credits_nothing(client, make_workspace):
    ws, member = await make_workspace()
    resp = await _post(client, _event(ws), secret="test-wrong-secret")
    assert resp.status_code == 400
    assert await _balance(client, ws, member) == 0


async def test_checkout_completed_credits_once_even_when_replayed(client, make_workspace):
    ws, member = await make_workspace()
    body = _event(ws, event_id="evt_replay_me")
    assert (await _post(client, body)).json() == {"status": "processed"}
    for _ in range(3):
        assert (await _post(client, body)).json() == {"status": "duplicate"}
    assert await _balance(client, ws, member) == 2_500


async def test_two_events_for_the_same_payment_credit_once(client, make_workspace, pg):
    ws, member = await make_workspace()
    await _post(client, _event(ws, session_id="cs_async"))
    await _post(client, _event(ws, session_id="cs_async", type_="checkout.session.async_payment_succeeded"))
    assert await _balance(client, ws, member) == 2_500
    async with pg.tenant_tx(ws) as db:
        assert len((await db.execute(select(LedgerEntry))).all()) == 1


async def test_unpaid_and_unrelated_events_do_not_credit(client, make_workspace, pg):
    ws, member = await make_workspace()
    assert (await _post(client, _event(ws, paid=False))).json() == {"status": "ignored"}
    assert (await _post(client, _event(ws, type_="customer.created"))).json() == {"status": "processed"}
    assert await _balance(client, ws, member) == 0


async def test_failed_processing_does_not_mark_the_event_as_seen(client, pg):
    missing_workspace = uuid.uuid4()
    body = _event(missing_workspace, event_id="evt_retry_later")
    assert (await _post(client, body)).status_code == 500  # provider will retry
    async with pg.anonymous_tx() as db:
        seen = (
            await db.execute(text("SELECT 1 FROM webhook_events WHERE event_id = 'evt_retry_later'"))
        ).first()
    assert seen is None  # the provider's retry will be processed
