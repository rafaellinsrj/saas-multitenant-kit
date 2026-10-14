"""Metered background jobs with at-most-once dispatch.

Lifecycle::

    queued --claim--> running --> succeeded   (settle the actual cost)
       |                     \\--> failed      (handler proved nothing happened: release)
       |                      \\-> unknown     (timeout, crash, lost answer: keep the hold)
       \\--> cancelled (release)

Why there is no automatic retry once a job is `running`:

A job may call a paid or side-effecting provider. When the call times out
or the worker dies, we do not know whether the provider did the work. A
retry could charge the customer twice or perform the action twice (send
twice, book twice). So the claim is committed *before* dispatch, and from
then on the only exits are terminal states. Uncertain outcomes become
`unknown`, the credit hold stays in place, and a human or a reconciliation
job that can ask the provider decides. Retrying is the client's explicit
choice: a new job with a new idempotency key.

The database enforces the same state machine (trigger `jobs_transition`).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as database
from app.models import Job
from app.services import credits, vault
from app.services.vault_crypto import VaultUnavailable, redact

TRANSITIONS: dict[str, set[str]] = {
    "queued": {"running", "cancelled"},
    "running": {"succeeded", "failed", "unknown"},
    "succeeded": set(),
    "failed": set(),
    "unknown": set(),
    "cancelled": set(),
}


def transition(current: str, target: str) -> str:
    if target not in TRANSITIONS.get(current, set()):
        raise ValueError(f"job transition {current} -> {target} not allowed")
    return target


class JobFailed(Exception):
    """Raise from a handler ONLY when it is certain no billable work happened."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass
class JobContext:
    workspace_id: uuid.UUID
    job_id: uuid.UUID
    input: dict
    _secrets: dict[str, str] = field(default_factory=dict)

    def secret(self, name: str) -> str:
        """Credentials are loaded by the executor, never placed in job input."""
        return self._secrets[name]


@dataclass(frozen=True)
class Result:
    output: dict
    cost_cents: int


@dataclass(frozen=True)
class Handler:
    run: Callable[[JobContext], Awaitable[Result]]
    worst_case_cents: Callable[[dict], int]
    secrets: tuple[str, ...] = ()
    timeout_s: float = 60.0


HANDLERS: dict[str, Handler] = {}


def handler(
    kind: str,
    *,
    worst_case_cents: Callable[[dict], int],
    secrets: tuple[str, ...] = (),
    timeout_s: float = 60.0,
):
    def register(fn: Callable[[JobContext], Awaitable[Result]]):
        HANDLERS[kind] = Handler(fn, worst_case_cents, secrets, timeout_s)
        return fn

    return register


# --- Enqueue (API side) -------------------------------------------------------


async def enqueue(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    member_id: uuid.UUID,
    kind: str,
    payload: dict,
    idempotency_key: str,
) -> Job:
    """Reserve the worst case and queue the job, atomically. Replays return the same job."""
    spec = HANDLERS.get(kind)
    if spec is None:
        raise ValueError(f"unknown job kind {kind!r}")
    existing = (
        await db.execute(
            select(Job).where(Job.workspace_id == workspace_id, Job.idempotency_key == idempotency_key)
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.kind != kind or existing.input != payload:
            raise credits.IdempotencyConflict("idempotency key reused for a different job")
        return existing
    worst = spec.worst_case_cents(payload)
    hold = await credits.reserve(db, workspace_id, f"job:{idempotency_key}", worst)
    job = Job(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        member_id=member_id,
        kind=kind,
        idempotency_key=idempotency_key,
        input=payload,
        status="queued",
        max_cost_cents=worst,
        reservation_id=hold.id,
    )
    db.add(job)
    await db.flush()
    return job


async def cancel(db: AsyncSession, job: Job) -> Job:
    job.status = transition(job.status, "cancelled")
    job.finished_at = datetime.now(UTC)
    await credits.release(db, job.workspace_id, job.reservation_id)
    await db.flush()
    return job


# --- Executor (worker side) -----------------------------------------------------


async def _candidates(limit: int = 10) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """(workspace_id, job_id) of the oldest queued jobs.

    The worker has no tenant yet, so plain SELECTs see nothing. Instead of a
    bypass, it calls a narrow SECURITY DEFINER function that exposes ids of
    queued jobs only; everything else happens in a tenant-scoped transaction.
    """
    async with database.anonymous_tx() as db:
        rows = await db.execute(
            text("SELECT job_workspace_id, job_id FROM jobs_queued_candidates(:n)"), {"n": limit}
        )
        return [(uuid.UUID(str(ws)), uuid.UUID(str(job))) for ws, job in rows]


async def _claim(workspace_id: uuid.UUID, job_id: uuid.UUID) -> tuple[Job, dict[str, str]] | None:
    """Mark the job running and COMMIT before any side effect happens."""
    async with database.tenant_tx(workspace_id) as db:
        job = (
            await db.execute(
                select(Job).where(Job.id == job_id, Job.status == "queued").with_for_update(skip_locked=True)
            )
        ).scalar_one_or_none()
        if job is None:
            return None  # another worker took it, or it was cancelled
        spec = HANDLERS.get(job.kind)
        try:
            names = spec.secrets if spec else ()
            loaded = {name: await vault.use_secret(db, workspace_id, name) for name in names}
        except VaultUnavailable:
            loaded = None
        if spec is None or loaded is None:
            # Nothing was dispatched, so cancelling (and releasing) is safe.
            job.status = transition(job.status, "cancelled")
            job.error_code = "handler_missing" if spec is None else "credential_unavailable"
            job.finished_at = datetime.now(UTC)
            await credits.release(db, workspace_id, job.reservation_id)
            return None
        job.status = transition(job.status, "running")
        job.started_at = datetime.now(UTC)
        await db.flush()
        db.expunge(job)
        return job, loaded


async def _record(
    job: Job, status: str, *, output: dict | None = None, cost: int | None = None, error: str | None = None
) -> None:
    async with database.tenant_tx(job.workspace_id) as db:
        row = (await db.execute(select(Job).where(Job.id == job.id).with_for_update())).scalar_one()
        if row.status != "running":
            return  # reconciliation already recorded an outcome; never overwrite it
        if status == "succeeded" and cost is not None and cost > row.max_cost_cents:
            status, output, error = "unknown", None, "cost_above_reservation"
        row.status = transition(row.status, status)
        row.result, row.error_code, row.finished_at = output, error, datetime.now(UTC)
        if status == "succeeded":
            row.cost_cents = cost
            await credits.settle(db, row.workspace_id, row.reservation_id, cost, note=f"job {row.kind}")
        elif status == "failed":
            row.cost_cents = 0
            await credits.release(db, row.workspace_id, row.reservation_id)
        # unknown: the hold stays until someone reconciles with the provider.


async def run_job(workspace_id: uuid.UUID, job_id: uuid.UUID) -> str | None:
    claimed = await _claim(workspace_id, job_id)
    if claimed is None:
        return None
    job, secrets = claimed
    spec = HANDLERS[job.kind]
    ctx = JobContext(workspace_id=workspace_id, job_id=job.id, input=dict(job.input), _secrets=secrets)
    try:
        async with asyncio.timeout(spec.timeout_s):
            result = await spec.run(ctx)
    except JobFailed as exc:
        await _record(job, "failed", error=exc.code)
        return "failed"
    except Exception:  # noqa: BLE001 - any other outcome is uncertain by definition
        # A timeout is not evidence that the remote side did nothing.
        await _record(job, "unknown", error="outcome_unconfirmed")
        return "unknown"
    if type(result.cost_cents) is not int or result.cost_cents < 0:
        await _record(job, "unknown", error="invalid_cost")
        return "unknown"
    output = {
        k: redact(v, list(secrets.values())) if isinstance(v, str) else v for k, v in result.output.items()
    }
    await _record(job, "succeeded", output=output, cost=result.cost_cents)
    return "succeeded"


async def run_once(limit: int = 10) -> int:
    """Try the oldest queued jobs once. Returns how many this worker ran."""
    ran = 0
    for workspace_id, job_id in await _candidates(limit):
        if await run_job(workspace_id, job_id) is not None:
            ran += 1
    return ran


async def reconcile_stale(workspace_id: uuid.UUID, older_than: timedelta = timedelta(minutes=15)) -> int:
    """A dead worker cannot prove the provider did nothing: mark unknown, never requeue."""
    cutoff = datetime.now(UTC) - older_than
    async with database.tenant_tx(workspace_id) as db:
        rows = (
            (
                await db.execute(
                    select(Job)
                    .where(Job.status == "running", Job.started_at < cutoff)
                    .with_for_update(skip_locked=True)
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            row.status = transition(row.status, "unknown")
            row.error_code, row.finished_at = "worker_lost", datetime.now(UTC)
        return len(rows)


# --- Example handler -------------------------------------------------------------

UNIT_PRICE_CENTS = 3


@handler("word_count", worst_case_cents=lambda p: max(1, int(p.get("max_units", 1))) * UNIT_PRICE_CENTS)
async def word_count(ctx: JobContext) -> Result:
    """Toy metered job: bills per 100 words, capped by the caller's max_units."""
    words = len(str(ctx.input.get("text", "")).split())
    units = min(max(1, -(-words // 100)), max(1, int(ctx.input.get("max_units", 1))))
    return Result(output={"words": words, "units": units}, cost_cents=units * UNIT_PRICE_CENTS)


async def main() -> None:  # pragma: no cover - CLI loop
    while True:
        if not await run_once():
            await asyncio.sleep(2)


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(main())
