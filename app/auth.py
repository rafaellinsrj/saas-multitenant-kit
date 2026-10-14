"""Minimal signed bearer tokens so the kit runs end to end.

This is a stand-in for a real identity provider (OIDC, sessions, ...). The
part that matters for tenancy is the contract: the workspace id comes from
a credential the server verified, never from a header or body field the
client controls.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status

from app.config import load


@dataclass(frozen=True)
class Principal:
    workspace_id: uuid.UUID
    member_id: uuid.UUID


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue(workspace_id: uuid.UUID, member_id: uuid.UUID, secret: str, ttl_s: int = 3600) -> str:
    body = _b64(
        json.dumps({"ws": str(workspace_id), "m": str(member_id), "exp": int(time.time()) + ttl_s}).encode()
    )
    mac = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def parse(token: str, secret: str) -> Principal:
    try:
        body, mac = token.split(".")
        expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, expected):
            raise ValueError
        claims = json.loads(_unb64(body))
        if int(claims["exp"]) < time.time():
            raise ValueError
        return Principal(uuid.UUID(claims["ws"]), uuid.UUID(claims["m"]))
    except (ValueError, KeyError, TypeError):
        raise PermissionError("invalid token") from None


def principal(request: Request) -> Principal:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        return parse(token, load().token_secret)
    except PermissionError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required") from None


CurrentPrincipal = Depends(principal)
