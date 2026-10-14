"""AES-256-GCM envelope with a versioned keyring. Pure functions, no ORM.

* Keys come from the environment (VAULT_KEYS as {"kid": base64(32 bytes)}
  and VAULT_ACTIVE_KEY). There is no fallback key and no plaintext mode:
  a missing or malformed keyring makes the vault unavailable.
* The associated data binds each ciphertext to workspace, secret id and
  version. Copying a ciphertext into another row or tenant makes it
  undecryptable instead of readable.
* Each envelope records its key id, so keys can rotate: new writes use the
  active key, old envelopes stay readable until re-encrypted (`reseal`).
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_VERSION = 1


class VaultUnavailable(Exception):
    """Raised for every failure; the message never contains key material."""


def keyring() -> tuple[str, dict[str, bytes]]:
    try:
        active = os.environ["VAULT_ACTIVE_KEY"]
        raw = json.loads(os.environ["VAULT_KEYS"])
        keys = {kid: base64.b64decode(value, validate=True) for kid, value in raw.items()}
        if active not in keys or any(len(k) != 32 for k in keys.values()):
            raise ValueError
        return active, keys
    except (KeyError, ValueError, TypeError, AttributeError):
        raise VaultUnavailable("vault keyring is not configured") from None


def _aad(workspace_id: str, secret_id: str, version: int) -> bytes:
    return json.dumps(
        ["kit-vault", ENVELOPE_VERSION, str(workspace_id), str(secret_id), int(version)],
        separators=(",", ":"),
    ).encode()


def seal(value: str, *, workspace_id: str, secret_id: str, version: int) -> str:
    active, keys = keyring()
    nonce = os.urandom(12)
    data = AESGCM(keys[active]).encrypt(nonce, value.encode(), _aad(workspace_id, secret_id, version))
    return json.dumps({"v": ENVELOPE_VERSION, "kid": active, "data": base64.b64encode(nonce + data).decode()})


def unseal(envelope: str, *, workspace_id: str, secret_id: str, version: int) -> str:
    _, keys = keyring()
    try:
        obj = json.loads(envelope)
        if obj["v"] != ENVELOPE_VERSION:
            raise ValueError
        blob = base64.b64decode(obj["data"], validate=True)
        aad = _aad(workspace_id, secret_id, version)
        return AESGCM(keys[obj["kid"]]).decrypt(blob[:12], blob[12:], aad).decode()
    except Exception:
        raise VaultUnavailable("could not open the protected credential") from None


def reseal(envelope: str, **scope) -> tuple[str, bool]:
    """Re-encrypt under the active key. Returns (envelope, changed)."""
    active, _ = keyring()
    value = unseal(envelope, **scope)
    if json.loads(envelope)["kid"] == active:
        return envelope, False
    return seal(value, **scope), True


def redact(text: str, secrets: list[str]) -> str:
    """Remove known secret values from text before it is stored or logged."""
    for secret in sorted((s for s in secrets if s and len(s) >= 4), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text
