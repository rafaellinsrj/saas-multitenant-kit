"""Vault envelope encryption. No database."""

import base64
import json
import os

import pytest

from app.services import vault_crypto as vc

SCOPE = {"workspace_id": "ws-a", "secret_id": "s-1", "version": 1}


def _keys(monkeypatch, active: str, **keys: bytes) -> None:
    monkeypatch.setenv("VAULT_KEYS", json.dumps({k: base64.b64encode(v).decode() for k, v in keys.items()}))
    monkeypatch.setenv("VAULT_ACTIVE_KEY", active)


def test_round_trip_and_no_plaintext_in_envelope(monkeypatch):
    _keys(monkeypatch, "k1", k1=os.urandom(32))
    envelope = vc.seal("not-a-real-token-123", **SCOPE)
    assert "not-a-real-token-123" not in envelope
    assert vc.unseal(envelope, **SCOPE) == "not-a-real-token-123"


@pytest.mark.parametrize("field,value", [("workspace_id", "ws-b"), ("secret_id", "s-2"), ("version", 2)])
def test_ciphertext_is_bound_to_its_row(monkeypatch, field, value):
    _keys(monkeypatch, "k1", k1=os.urandom(32))
    envelope = vc.seal("value", **SCOPE)
    with pytest.raises(vc.VaultUnavailable):
        vc.unseal(envelope, **{**SCOPE, field: value})


def test_missing_or_bad_keyring_fails_closed(monkeypatch):
    monkeypatch.delenv("VAULT_KEYS", raising=False)
    with pytest.raises(vc.VaultUnavailable):
        vc.seal("value", **SCOPE)
    _keys(monkeypatch, "k1", k1=b"short")
    with pytest.raises(vc.VaultUnavailable):
        vc.seal("value", **SCOPE)


def test_rotation_keeps_old_envelopes_readable(monkeypatch):
    old, new = os.urandom(32), os.urandom(32)
    _keys(monkeypatch, "k1", k1=old)
    envelope = vc.seal("value", **SCOPE)
    _keys(monkeypatch, "k2", k1=old, k2=new)
    assert vc.unseal(envelope, **SCOPE) == "value"
    rotated, changed = vc.reseal(envelope, **SCOPE)
    assert changed and json.loads(rotated)["kid"] == "k2"
    assert vc.reseal(rotated, **SCOPE) == (rotated, False)


def test_tampering_is_detected(monkeypatch):
    _keys(monkeypatch, "k1", k1=os.urandom(32))
    obj = json.loads(vc.seal("value", **SCOPE))
    blob = bytearray(base64.b64decode(obj["data"]))
    blob[-1] ^= 1
    obj["data"] = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(vc.VaultUnavailable):
        vc.unseal(json.dumps(obj), **SCOPE)


def test_redact():
    assert vc.redact("token abc123xyz used", ["abc123xyz"]) == "token [redacted] used"
