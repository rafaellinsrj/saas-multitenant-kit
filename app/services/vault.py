"""The only module that reads ciphertext.

Public surface for the API: create / replace / revoke / list metadata.
There is no "reveal" endpoint. Plaintext is produced only by `use_secret`,
called by server-side code (the job executor) inside a tenant transaction,
and every use leaves an audit row in the append-only `vault_events`.

Database side, the application role cannot SELECT `vault_secrets.ciphertext`.
`use_secret` switches to `kit_vault_reader` for exactly one statement with
`SET LOCAL ROLE` and switches back right after. A stray ORM query anywhere
else that touches the column fails with "permission denied".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, Text, insert, select, text, update
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import VaultSecretMeta
from app.services import vault_crypto
from app.services.vault_crypto import VaultUnavailable

# Core table that includes ciphertext, on its own MetaData; used only here.
_CIPHERTEXT = "ciphertext"
_secrets = Table(
    "vault_secrets",
    MetaData(),
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("workspace_id", UUID(as_uuid=True)),
    Column("name", String(80)),
    Column("provider", String(40)),
    Column(_CIPHERTEXT, Text),
    Column("version", Integer),
    Column("status", String(20)),
    Column("updated_at", DateTime(timezone=True)),
)


def metadata(row: VaultSecretMeta) -> dict:
    return {
        "id": str(row.id),
        "name": row.name,
        "provider": row.provider,
        "version": row.version,
        "status": row.status,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


async def _event(
    db: AsyncSession, workspace_id: uuid.UUID, secret_id: uuid.UUID, action: str, version: int
) -> None:
    await db.execute(
        text(
            "INSERT INTO vault_events (workspace_id, secret_id, action, version) "
            "VALUES (:ws, :sid, :action, :version)"
        ),
        {"ws": workspace_id, "sid": secret_id, "action": action, "version": version},
    )


async def create(
    db: AsyncSession, workspace_id: uuid.UUID, name: str, provider: str, value: str
) -> VaultSecretMeta:
    if not value:
        raise ValueError("secret value is empty")
    secret_id = uuid.uuid4()
    envelope = vault_crypto.seal(value, workspace_id=str(workspace_id), secret_id=str(secret_id), version=1)
    await db.execute(
        insert(_secrets).values(
            id=secret_id,
            workspace_id=workspace_id,
            name=name,
            provider=provider,
            version=1,
            status="active",
            **{_CIPHERTEXT: envelope},
        )
    )
    await _event(db, workspace_id, secret_id, "created", 1)
    return (await db.execute(select(VaultSecretMeta).where(VaultSecretMeta.id == secret_id))).scalar_one()


async def list_metadata(db: AsyncSession) -> list[VaultSecretMeta]:
    # No workspace filter needed for correctness: RLS scopes the rows.
    return list((await db.execute(select(VaultSecretMeta).order_by(VaultSecretMeta.created_at))).scalars())


async def replace(db: AsyncSession, row: VaultSecretMeta, value: str) -> VaultSecretMeta:
    if row.status != "active":
        raise ValueError("secret is revoked")
    version = row.version + 1
    envelope = vault_crypto.seal(
        value, workspace_id=str(row.workspace_id), secret_id=str(row.id), version=version
    )
    await db.execute(
        update(_secrets)
        .where(_secrets.c.id == row.id)
        .values(version=version, updated_at=datetime.now(UTC), **{_CIPHERTEXT: envelope})
    )
    await _event(db, row.workspace_id, row.id, "replaced", version)
    await db.refresh(row)
    return row


async def revoke(db: AsyncSession, row: VaultSecretMeta) -> None:
    """Drops the live ciphertext. Backups follow their own retention policy."""
    await db.execute(
        update(_secrets)
        .where(_secrets.c.id == row.id)
        .values(status="revoked", updated_at=datetime.now(UTC), **{_CIPHERTEXT: None})
    )
    await _event(db, row.workspace_id, row.id, "revoked", row.version)


async def use_secret(db: AsyncSession, workspace_id: uuid.UUID, name: str) -> str:
    """Decrypt one active secret for server-side use. Never return this to a client."""
    # If the SELECT fails the transaction is aborted and rolls back, which also
    # discards the SET LOCAL; so the reset only needs to run on success.
    await db.execute(text("SET LOCAL ROLE kit_vault_reader"))
    row = (
        await db.execute(
            select(_secrets.c.id, _secrets.c.version, _secrets.c[_CIPHERTEXT]).where(
                _secrets.c.workspace_id == workspace_id,
                _secrets.c.name == name,
                _secrets.c.status == "active",
            )
        )
    ).one_or_none()
    await db.execute(text("SET LOCAL ROLE NONE"))
    if row is None:
        raise VaultUnavailable("credential not found")
    value = vault_crypto.unseal(row[2], workspace_id=str(workspace_id), secret_id=str(row[0]), version=row[1])
    await _event(db, workspace_id, row[0], "used", row[1])
    return value
