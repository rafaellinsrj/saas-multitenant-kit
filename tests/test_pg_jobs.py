"""Metered jobs: worst-case hold at enqueue, at-most-once dispatch, honest outcomes."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import DBAPIError

from app.models import Job
from app.services import credits, jobs, vault
from tests.conftest import bearer

CALLS: dict[str, int] = {}


@jobs.handler("t_fail", worst_case_cents=lambda p: 50)
async def _fail(ctx):
    raise jobs.JobFailed("provider_rejected_before_work")


@jobs.handler("t_timeout", worst_case_cents=lambda p: 50, timeout_s=0.05)
async def _timeout(ctx):
    CALLS["t_timeout"] = CALLS.get("t_timeout", 0) + 1
    await asyncio.sleep(1)


@jobs.handler("t_slow", worst_case_cents=lambda p: 10)
async def _slow(ctx):
    CALLS["t_slow"] = CALLS.get("t_slow", 0) + 1
    await asyncio.sleep(0.2)
    return jobs.Result(output={}, cost_cents=10)


@jobs.handler("t_secret", worst_case_cents=lambda p: 10, secrets=("api_token",))
async def _secret(ctx):
    # A careless handler that echoes its credential back.
    return jobs.Result(output={"echo": f"used {ctx.secret('api_token')}"}, cost_cents=5)


async def _funded(pg, make_workspace, cents=1_000):
    ws, member = await make_workspace()
    async with pg.tenant_tx(ws) as db:
        await credits.top_up(db, ws, cents, reference_kind="checkout", reference_id=f"cs_{uuid.uuid4().hex}")
    return ws, member


async def _enqueue(pg, ws, member, kind, payload=None) -> Job:
    async with pg.tenant_tx(ws) as db:
        return await jobs.enqueue(db, ws, member, kind, payload or {}, uuid.uuid4().hex)


async def _job(pg, ws, job_id) -> Job:
    async with pg.tenant_tx(ws) as db:
        return await db.get(Job, job_id)


async def _wallet(pg, ws):
    async with pg.tenant_tx(ws) as db:
        return await credits.wallet(db, ws)


async def test_api_flow_hold_then_settle(client, make_workspace, pg):
    ws, member = await make_workspace()
    body = {"kind": "word_count", "input": {"text": "one two three", "max_units": 5}}
    headers = {**bearer(ws, member), "Idempotency-Key": "client-key-0001"}

    assert (await client.post("/jobs", json=body, headers=headers)).status_code == 402

    async with pg.tenant_tx(ws) as db:
        await credits.top_up(db, ws, 100, reference_kind="checkout", reference_id="cs_jobs")
    created = await client.post("/jobs", json=body, headers=headers)
    assert created.status_code == 202 and created.json()["status"] == "queued"
    replay = await client.post("/jobs", json=body, headers=headers)
    assert replay.json()["id"] == created.json()["id"]  # same job, one hold
    assert (await _wallet(pg, ws)).reserved_cents == 5 * jobs.UNIT_PRICE_CENTS

    job_id = uuid.UUID(created.json()["id"])
    assert await jobs.run_job(ws, job_id) == "succeeded"
    done = (await client.get(f"/jobs/{job_id}", headers=bearer(ws, member))).json()
    assert done["status"] == "succeeded" and done["cost_cents"] == jobs.UNIT_PRICE_CENTS
    w = await _wallet(pg, ws)
    assert (w.balance_cents, w.reserved_cents) == (100 - jobs.UNIT_PRICE_CENTS, 0)

    conflict = await client.post("/jobs", json={**body, "input": {"text": "x"}}, headers=headers)
    assert conflict.status_code == 409


async def test_confirmed_failure_releases_the_hold(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    job = await _enqueue(pg, ws, member, "t_fail")
    assert await jobs.run_job(ws, job.id) == "failed"
    assert (await _job(pg, ws, job.id)).error_code == "provider_rejected_before_work"
    assert await _wallet(pg, ws) == credits.Wallet(1_000, 0)


async def test_uncertain_outcome_is_unknown_and_never_retried(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    job = await _enqueue(pg, ws, member, "t_timeout")
    CALLS["t_timeout"] = 0
    assert await jobs.run_job(ws, job.id) == "unknown"
    assert (await _wallet(pg, ws)).reserved_cents == 50  # money stays on hold
    assert await jobs.run_job(ws, job.id) is None  # not queued: not run again
    await jobs.run_once(limit=100)  # a worker sweep skips it too
    assert CALLS["t_timeout"] == 1
    with pytest.raises(DBAPIError, match="not allowed"):
        async with pg.tenant_tx(ws) as db:  # the database agrees
            await db.execute(update(Job).where(Job.id == job.id).values(status="queued"))


async def test_two_workers_dispatch_a_job_once(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    job = await _enqueue(pg, ws, member, "t_slow")
    CALLS["t_slow"] = 0
    outcomes = await asyncio.gather(jobs.run_job(ws, job.id), jobs.run_job(ws, job.id))
    assert sorted(outcomes, key=str) == sorted(["succeeded", None], key=str)
    assert CALLS["t_slow"] == 1


async def test_worker_discovers_jobs_without_bypassing_rls(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    job = await _enqueue(pg, ws, member, "word_count", {"text": "hello", "max_units": 1})
    assert await jobs.run_once(limit=100) >= 1
    assert (await _job(pg, ws, job.id)).status == "succeeded"


async def test_credentials_reach_the_handler_but_not_the_stored_result(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    async with pg.tenant_tx(ws) as db:
        await vault.create(db, ws, "api_token", "demo", "fake-token-for-tests-42")
    job = await _enqueue(pg, ws, member, "t_secret")
    assert "fake-token" not in str(job.input)
    assert await jobs.run_job(ws, job.id) == "succeeded"
    assert (await _job(pg, ws, job.id)).result == {"echo": "used [redacted]"}


async def test_missing_credential_cancels_before_dispatch(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    job = await _enqueue(pg, ws, member, "t_secret")
    assert await jobs.run_job(ws, job.id) is None
    row = await _job(pg, ws, job.id)
    assert (row.status, row.error_code) == ("cancelled", "credential_unavailable")
    assert (await _wallet(pg, ws)).reserved_cents == 0


async def test_stale_running_jobs_become_unknown(pg, make_workspace):
    ws, member = await _funded(pg, make_workspace)
    job = await _enqueue(pg, ws, member, "t_slow")
    claimed = await jobs._claim(ws, job.id)  # a worker claims it, then dies
    assert claimed is not None
    async with pg.tenant_tx(ws) as db:
        await db.execute(
            text("UPDATE jobs SET started_at = :t WHERE id = :id"),
            {"t": datetime.now(UTC) - timedelta(hours=1), "id": job.id},
        )
    assert await jobs.reconcile_stale(ws) == 1
    row = await _job(pg, ws, job.id)
    assert (row.status, row.error_code) == ("unknown", "worker_lost")
    assert (await _wallet(pg, ws)).reserved_cents == 10
