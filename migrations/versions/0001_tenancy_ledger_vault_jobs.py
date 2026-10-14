"""Roles, tenant tables, RLS, append-only ledger, vault and jobs.

Revision ID: 0001
Revises:
"""

import os

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

APP = "kit_app"  # API and worker. Not owner, no BYPASSRLS.
VAULT_READER = "kit_vault_reader"  # Only role allowed to SELECT ciphertext.
DISPATCHER = "kit_dispatcher"  # Owns the narrow "find queued jobs" function.

TENANT_TABLES = ["members", "credit_ledger", "credit_reservations", "vault_secrets", "vault_events", "jobs"]


def _sql(script: str) -> None:
    """Run a script statement by statement (asyncpg prepares one at a time).
    Splits on `;` outside of $$-quoted function bodies and `--` comments."""
    statements, current, quoted = [], [], False
    for line in script.splitlines():
        stripped = line.strip()
        if not quoted and stripped.startswith("--"):
            continue
        current.append(line)
        quoted ^= line.count("$$") % 2 == 1
        if not quoted and stripped.endswith(";"):
            statements.append("\n".join(current).strip().rstrip(";"))
            current = []
    if "".join(current).strip():
        statements.append("\n".join(current).strip())
    for statement in statements:
        op.execute(statement)


# Fail closed: an empty setting becomes NULL and matches nothing; a malformed
# value raises on the cast instead of matching something by accident.
CURRENT_WS = "nullif(current_setting('app.workspace_id', true), '')::uuid"


def _roles() -> None:
    conn = op.get_bind()
    for role, login in ((APP, True), (VAULT_READER, False), (DISPATCHER, False)):
        exists = conn.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar()
        if not exists:
            op.execute(
                f"CREATE ROLE {role} {'LOGIN' if login else 'NOLOGIN'} "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
            )
    password = os.environ.get("KIT_APP_DB_PASSWORD")
    if password:
        literal = conn.execute(sa.text("SELECT quote_literal(:p)"), {"p": password}).scalar()
        op.execute(f"ALTER ROLE {APP} PASSWORD {literal}")
    # PostgreSQL 16: membership without inheritance. kit_app does NOT get the
    # reader's privileges implicitly; it must `SET LOCAL ROLE kit_vault_reader`,
    # which only app/services/vault.py does.
    op.execute(f"GRANT {VAULT_READER} TO {APP} WITH INHERIT FALSE, SET TRUE")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP}, {VAULT_READER}, {DISPATCHER}")


def _tables() -> None:
    _sql("""
    CREATE TABLE workspaces (
        id uuid PRIMARY KEY,
        name varchar(120) NOT NULL CHECK (length(trim(name)) > 0),
        created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE members (
        id uuid PRIMARY KEY,
        workspace_id uuid NOT NULL REFERENCES workspaces(id),
        display_name varchar(120) NOT NULL,
        role varchar(20) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
        created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_members_workspace ON members(workspace_id);

    CREATE TABLE credit_ledger (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        workspace_id uuid NOT NULL REFERENCES workspaces(id),
        kind varchar(20) NOT NULL CHECK (kind IN ('topup', 'usage', 'adjustment')),
        amount_cents bigint NOT NULL CHECK (amount_cents <> 0),
        reference_kind varchar(40) NOT NULL,
        reference_id varchar(255) NOT NULL,
        note text,
        created_at timestamptz NOT NULL DEFAULT now(),
        CHECK (kind <> 'topup' OR amount_cents > 0),
        CHECK (kind <> 'usage' OR amount_cents < 0),
        -- Idempotency: one external reference produces at most one entry per kind.
        UNIQUE (workspace_id, kind, reference_id)
    );
    CREATE INDEX ix_ledger_workspace_created ON credit_ledger(workspace_id, created_at);

    CREATE TABLE credit_reservations (
        id uuid PRIMARY KEY,
        workspace_id uuid NOT NULL REFERENCES workspaces(id),
        idempotency_key varchar(255) NOT NULL,
        amount_cents bigint NOT NULL CHECK (amount_cents > 0),
        status varchar(20) NOT NULL DEFAULT 'held' CHECK (status IN ('held', 'settled', 'released')),
        ledger_entry_id bigint REFERENCES credit_ledger(id),
        created_at timestamptz NOT NULL DEFAULT now(),
        closed_at timestamptz,
        UNIQUE (workspace_id, idempotency_key),
        CHECK ((status = 'settled') = (ledger_entry_id IS NOT NULL)),
        CHECK ((status = 'held') = (closed_at IS NULL))
    );
    CREATE INDEX ix_reservations_held ON credit_reservations(workspace_id) WHERE status = 'held';

    CREATE TABLE webhook_events (
        event_id varchar(255) PRIMARY KEY,
        event_type varchar(100) NOT NULL,
        received_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE vault_secrets (
        id uuid PRIMARY KEY,
        workspace_id uuid NOT NULL REFERENCES workspaces(id),
        name varchar(80) NOT NULL,
        provider varchar(40) NOT NULL,
        ciphertext text,
        version integer NOT NULL DEFAULT 1 CHECK (version > 0),
        status varchar(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        CHECK ((status = 'active') = (ciphertext IS NOT NULL))
    );
    CREATE UNIQUE INDEX uq_vault_active_name ON vault_secrets(workspace_id, name) WHERE status = 'active';

    CREATE TABLE vault_events (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        workspace_id uuid NOT NULL REFERENCES workspaces(id),
        secret_id uuid NOT NULL REFERENCES vault_secrets(id),
        action varchar(20) NOT NULL CHECK (action IN ('created', 'replaced', 'revoked', 'used')),
        version integer NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE jobs (
        id uuid PRIMARY KEY,
        workspace_id uuid NOT NULL REFERENCES workspaces(id),
        member_id uuid NOT NULL REFERENCES members(id),
        kind varchar(40) NOT NULL,
        idempotency_key varchar(255) NOT NULL,
        input jsonb NOT NULL DEFAULT '{}'::jsonb,
        status varchar(20) NOT NULL DEFAULT 'queued'
            CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'unknown', 'cancelled')),
        max_cost_cents bigint NOT NULL CHECK (max_cost_cents > 0),
        cost_cents bigint CHECK (cost_cents >= 0),
        reservation_id uuid NOT NULL REFERENCES credit_reservations(id),
        result jsonb,
        error_code varchar(80),
        created_at timestamptz NOT NULL DEFAULT now(),
        started_at timestamptz,
        finished_at timestamptz,
        UNIQUE (workspace_id, idempotency_key)
    );
    CREATE INDEX ix_jobs_queued ON jobs(created_at) WHERE status = 'queued';
    """)


def _guards() -> None:
    _sql("""
    CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION '% is append-only (% refused)', TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'restrict_violation';
    END $$;
    """)
    for table in ("credit_ledger", "vault_events", "webhook_events"):
        # Grants already deny UPDATE/DELETE to the app role. The trigger also
        # stops the owner and any future role someone grants too much.
        _sql(f"""
        CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
        CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
        """)

    # The balance is derived from the ledger. Checked at commit time so a
    # multi-row transaction is judged on its final state.
    _sql("""
    CREATE FUNCTION ledger_balance_not_negative() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE total bigint;
    BEGIN
        SELECT COALESCE(SUM(amount_cents), 0) INTO total
          FROM credit_ledger WHERE workspace_id = NEW.workspace_id;
        IF total < 0 THEN
            RAISE EXCEPTION 'ledger balance would be negative (%)', total
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER credit_ledger_balance_check AFTER INSERT ON credit_ledger
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_balance_not_negative();
    """)

    # A closed reservation is history: it cannot be reopened or edited.
    _sql("""
    CREATE FUNCTION reservation_frozen_when_closed() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF OLD.status <> 'held' THEN
            RAISE EXCEPTION 'reservation % is already %', OLD.id, OLD.status
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END $$;
    CREATE TRIGGER credit_reservations_frozen BEFORE UPDATE ON credit_reservations
        FOR EACH ROW EXECUTE FUNCTION reservation_frozen_when_closed();
    """)

    # Job state machine, mirrored from app/services/jobs.py. No path leads
    # from running (or unknown) back to queued: nothing is re-dispatched.
    _sql("""
    CREATE FUNCTION job_transition_allowed() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.status = OLD.status THEN
            RETURN NEW;
        END IF;
        IF (OLD.status, NEW.status) IN (('queued', 'running'), ('queued', 'cancelled'),
            ('running', 'succeeded'), ('running', 'failed'), ('running', 'unknown')) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'job transition % -> % not allowed', OLD.status, NEW.status
            USING ERRCODE = 'restrict_violation';
    END $$;
    CREATE TRIGGER jobs_transition BEFORE UPDATE OF status ON jobs
        FOR EACH ROW EXECUTE FUNCTION job_transition_allowed();
    """)


def _rls() -> None:
    op.execute("ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE workspaces FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON workspaces USING (id = {CURRENT_WS}) "
        f"WITH CHECK (id = {CURRENT_WS})"
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE: without it the table owner ignores every policy.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING (workspace_id = {CURRENT_WS}) "
            f"WITH CHECK (workspace_id = {CURRENT_WS})"
        )
    # The dispatcher may see which jobs are queued (ids only, see grants).
    op.execute(f"CREATE POLICY dispatcher_scan ON jobs FOR SELECT TO {DISPATCHER} USING (status = 'queued')")


def _grants() -> None:
    _sql(f"""
    GRANT SELECT, INSERT, UPDATE (name) ON workspaces TO {APP};
    GRANT SELECT, INSERT, UPDATE (display_name, role) ON members TO {APP};
    GRANT SELECT, INSERT ON credit_ledger TO {APP};
    GRANT SELECT, INSERT, UPDATE (status, ledger_entry_id, closed_at) ON credit_reservations TO {APP};
    GRANT SELECT, INSERT ON webhook_events TO {APP};
    GRANT SELECT, INSERT ON vault_events TO {APP};
    GRANT SELECT, INSERT, UPDATE (status, cost_cents, result, error_code, started_at, finished_at)
        ON jobs TO {APP};

    -- Vault: the app can write ciphertext but cannot read it back.
    GRANT INSERT ON vault_secrets TO {APP};
    GRANT SELECT (id, workspace_id, name, provider, version, status, created_at, updated_at)
        ON vault_secrets TO {APP};
    GRANT UPDATE (ciphertext, version, status, updated_at) ON vault_secrets TO {APP};
    GRANT SELECT (id, workspace_id, name, ciphertext, version, status) ON vault_secrets TO {VAULT_READER};

    GRANT SELECT (id, workspace_id, status, created_at) ON jobs TO {DISPATCHER};
    """)
    _sql(f"""
    CREATE FUNCTION jobs_queued_candidates(max_rows integer)
    RETURNS TABLE (job_id uuid, job_workspace_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
        SELECT j.id, j.workspace_id FROM public.jobs j
         WHERE j.status = 'queued' ORDER BY j.created_at LIMIT least(max_rows, 100)
    $$;
    ALTER FUNCTION jobs_queued_candidates(integer) OWNER TO {DISPATCHER};
    REVOKE ALL ON FUNCTION jobs_queued_candidates(integer) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION jobs_queued_candidates(integer) TO {APP};
    """)


def upgrade() -> None:
    _roles()
    _tables()
    _guards()
    _rls()
    _grants()


def downgrade() -> None:
    # Development only. Roles are cluster-wide and are left in place.
    op.execute("DROP FUNCTION IF EXISTS jobs_queued_candidates(integer)")
    for table in (
        "jobs",
        "vault_events",
        "vault_secrets",
        "webhook_events",
        "credit_reservations",
        "credit_ledger",
        "members",
        "workspaces",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    for fn in (
        "forbid_mutation",
        "ledger_balance_not_negative",
        "reservation_frozen_when_closed",
        "job_transition_allowed",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}() CASCADE")
