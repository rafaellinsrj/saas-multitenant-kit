"""HTTP layer. Thin on purpose: every rule lives in app/services and in the database."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import auth
from app import db as database
from app.config import load
from app.models import Job, LedgerEntry, Member, VaultSecretMeta, Workspace
from app.services import credits, jobs, vault, webhooks

router = APIRouter()


async def tenant_db(who: auth.Principal = auth.CurrentPrincipal) -> AsyncIterator[AsyncSession]:
    """One transaction per request, pinned to the caller's workspace."""
    async with database.tenant_tx(who.workspace_id) as session:
        yield session


# scope="function": the transaction commits BEFORE the response is sent, so a
# failed commit can never be reported to the client as success.
TenantDB = Depends(tenant_db, scope="function")


# --- Workspaces ----------------------------------------------------------------


class WorkspaceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    owner_name: str = Field(min_length=1, max_length=120)


@router.post("/workspaces", status_code=status.HTTP_201_CREATED)
async def create_workspace(body: WorkspaceIn) -> dict:
    # The new id is chosen first and pinned to the transaction, so even
    # sign-up runs under RLS: the insert must match the policy's WITH CHECK.
    workspace_id, member_id = uuid.uuid4(), uuid.uuid4()
    async with database.tenant_tx(workspace_id) as db:
        db.add(Workspace(id=workspace_id, name=body.name))
        await db.flush()
        db.add(Member(id=member_id, workspace_id=workspace_id, display_name=body.owner_name, role="owner"))
    return {
        "workspace_id": str(workspace_id),
        "member_id": str(member_id),
        "token": auth.issue(workspace_id, member_id, load().token_secret),
    }


@router.get("/workspace")
async def my_workspace(db: AsyncSession = TenantDB) -> dict:
    # No WHERE clause: RLS returns exactly one row, the caller's.
    ws = (await db.execute(select(Workspace))).scalar_one()
    members = (await db.execute(select(Member).order_by(Member.created_at))).scalars().all()
    return {
        "id": str(ws.id),
        "name": ws.name,
        "members": [{"id": str(m.id), "name": m.display_name, "role": m.role} for m in members],
    }


# --- Credits -------------------------------------------------------------------


@router.get("/credits")
async def get_credits(who: auth.Principal = auth.CurrentPrincipal, db: AsyncSession = TenantDB) -> dict:
    w = await credits.wallet(db, who.workspace_id)
    entries = (await db.execute(select(LedgerEntry).order_by(LedgerEntry.id.desc()).limit(50))).scalars()
    return {
        "balance_cents": w.balance_cents,
        "reserved_cents": w.reserved_cents,
        "available_cents": w.available_cents,
        "ledger": [
            {
                "id": e.id,
                "kind": e.kind,
                "amount_cents": e.amount_cents,
                "reference_kind": e.reference_kind,
                "created_at": e.created_at.isoformat(),
            }
            for e in entries
        ],
    }


# --- Jobs ----------------------------------------------------------------------


class JobIn(BaseModel):
    kind: str = Field(min_length=1, max_length=40)
    input: dict = Field(default_factory=dict)


def _job(job: Job) -> dict:
    return {
        "id": str(job.id),
        "kind": job.kind,
        "status": job.status,
        "max_cost_cents": job.max_cost_cents,
        "cost_cents": job.cost_cents,
        "result": job.result,
        "error_code": job.error_code,
    }


@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
async def create_job(
    body: JobIn,
    idempotency_key: str = Header(min_length=8, max_length=200),
    who: auth.Principal = auth.CurrentPrincipal,
    db: AsyncSession = TenantDB,
) -> dict:
    try:
        job = await jobs.enqueue(db, who.workspace_id, who.member_id, body.kind, body.input, idempotency_key)
    except credits.InsufficientCredit as exc:
        detail = {"available_cents": exc.available_cents, "needed_cents": exc.needed_cents}
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, detail) from None
    except credits.IdempotencyConflict:
        raise HTTPException(status.HTTP_409_CONFLICT, "idempotency key already used") from None
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid job") from None
    return _job(job)


@router.get("/jobs/{job_id}")
async def get_job(job_id: uuid.UUID, db: AsyncSession = TenantDB) -> dict:
    job = await db.get(Job, job_id)
    if job is None:  # another tenant's job is simply invisible
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return _job(job)


# --- Vault ---------------------------------------------------------------------


class SecretIn(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_.-]+$")
    provider: str = Field(min_length=1, max_length=40)
    value: str = Field(min_length=1, max_length=8192, repr=False)


@router.post("/vault/secrets", status_code=status.HTTP_201_CREATED)
async def create_secret(
    body: SecretIn, who: auth.Principal = auth.CurrentPrincipal, db: AsyncSession = TenantDB
) -> dict:
    row = await vault.create(db, who.workspace_id, body.name, body.provider, body.value)
    return vault.metadata(row)  # metadata only, never the value


@router.get("/vault/secrets")
async def list_secrets(db: AsyncSession = TenantDB) -> list[dict]:
    return [vault.metadata(r) for r in await vault.list_metadata(db)]


@router.delete("/vault/secrets/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_secret(secret_id: uuid.UUID, db: AsyncSession = TenantDB) -> None:
    row = await db.get(VaultSecretMeta, secret_id)
    if row is None or row.status != "active":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    await vault.revoke(db, row)


# --- Payment webhook -----------------------------------------------------------


@router.post("/webhooks/payments")
async def payment_webhook(request: Request) -> dict:
    settings = load()
    raw = await request.body()  # raw bytes: re-serialized JSON would break the signature
    try:
        event = webhooks.verify(
            raw,
            request.headers.get("stripe-signature"),
            settings.webhook_secret,
            tolerance_s=settings.webhook_tolerance_s,
        )
    except webhooks.SignatureError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid signature") from None
    outcome = await webhooks.process(event)
    return {"status": outcome.status}
