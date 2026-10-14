"""Webhook signature verification. No network, no database."""

import json
import secrets

import pytest

from app.services.webhooks import SignatureError, sign, verify

SECRET = "test-webhook-" + secrets.token_hex(8)
BODY = json.dumps({"id": "evt_1", "type": "checkout.session.completed"}).encode()
NOW = 1_800_000_000


def test_valid_signature_returns_event():
    assert verify(BODY, sign(BODY, SECRET, NOW), SECRET, now=NOW)["id"] == "evt_1"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b, h, s: (b + b" ", h, s),  # body changed after signing
        lambda b, h, s: (b, h, s + "x"),  # wrong secret
        lambda b, h, s: (b, h.replace("v1=", "v0="), s),  # unsupported scheme only
        lambda b, h, s: (b, None, s),  # header missing
        lambda b, h, s: (b, "garbage", s),  # malformed header
        lambda b, h, s: (b, h, ""),  # secret not configured: fail closed
    ],
)
def test_rejections(mutate):
    body, header, secret = mutate(BODY, sign(BODY, SECRET, NOW), SECRET)
    with pytest.raises(SignatureError):
        verify(body, header, secret, now=NOW)


def test_old_timestamp_is_a_replay():
    with pytest.raises(SignatureError):
        verify(BODY, sign(BODY, SECRET, NOW - 301), SECRET, now=NOW, tolerance_s=300)


def test_any_v1_matches_during_secret_rotation():
    good = sign(BODY, SECRET, NOW).split("v1=")[1]
    header = f"t={NOW},v1={'0' * 64},v1={good}"
    assert verify(BODY, header, SECRET, now=NOW)["type"] == "checkout.session.completed"


def test_signed_but_not_an_event():
    body = b'{"hello": "world"}'
    with pytest.raises(SignatureError):
        verify(body, sign(body, SECRET, NOW), SECRET, now=NOW)
