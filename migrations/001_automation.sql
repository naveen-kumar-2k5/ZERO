-- ─────────────────────────────────────────────────────
-- ZeroRespond — automation layer migration
-- Run with:  psql "$DATABASE_URL" -f migrations/001_automation.sql
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────

BEGIN;

-- ── agents ────────────────────────────────────────────
-- One row per endpoint that can execute playbook actions.
-- The secret itself is NEVER stored here — only the name of the env var
-- that holds it (e.g. ZR_SECRET_WIN_AGENT1), so the DB is useless without
-- the host's environment.
CREATE TABLE IF NOT EXISTS agents (
    name           TEXT PRIMARY KEY,                    -- matches case.agent_name
    os             TEXT NOT NULL CHECK (os IN ('windows','linux')),
    ip             INET,
    port           INTEGER NOT NULL DEFAULT 5055,
    secret_env_var TEXT NOT NULL,                       -- e.g. 'ZR_SECRET_WIN_AGENT1'
    version        TEXT,
    protected      BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── playbook_steps ────────────────────────────────────
-- Per-step automation metadata. The existing PLAYBOOKS dict in app.py
-- still supplies the human-readable title/plain/linux/windows/expected;
-- this table adds the machine-executable action (if any) and the
-- automation level. A step with step_type='manual' has action=NULL and
-- is not runnable — the case page shows only the Copy button for it.
CREATE TABLE IF NOT EXISTS playbook_steps (
    playbook_key TEXT NOT NULL,
    step_num     INTEGER NOT NULL,                      -- 0-indexed, matches PLAYBOOKS
    step_type    TEXT NOT NULL CHECK (step_type IN ('manual','assisted')),
    action       JSONB,                                 -- {"name":"block_ip","args":{"ip":"{source_ip}"}}
    undo_action  JSONB,                                 -- {"name":"unblock_ip","args":{"ip":"{source_ip}"}}
    timeout_sec  INTEGER NOT NULL DEFAULT 30,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (playbook_key, step_num),
    CONSTRAINT action_required_unless_manual
        CHECK (step_type = 'manual' OR action IS NOT NULL)
);

-- ── case_step_runs ────────────────────────────────────
-- One row per execution attempt. Multiple rows per (case, step) are
-- allowed and expected: a failed attempt, a retry, an undo — each is a
-- separate row so the audit trail is complete and honest.
-- We do NOT store the final "done" state of the step here; that's still
-- driven by cases.cur_step. A run only says "the agent did (or failed to
-- do) this specific action at this time".
CREATE TABLE IF NOT EXISTS case_step_runs (
    id           BIGSERIAL PRIMARY KEY,
    case_id      BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    step_num     INTEGER NOT NULL,
    mode         TEXT NOT NULL CHECK (mode IN ('assisted')),  -- 'auto' reserved for later
    status       TEXT NOT NULL CHECK (status IN
                   ('queued','running','done','failed','undone')),
    action_json  JSONB NOT NULL,                        -- resolved action+args actually sent
    result_json  JSONB,                                 -- agent's full response (incl. audit_id)
    executed_by  TEXT NOT NULL,                         -- session user, or 'System'
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    error        TEXT,                                  -- short error message, if failed
    undo_of      BIGINT REFERENCES case_step_runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_case_step_runs_case_step
    ON case_step_runs (case_id, step_num, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_case_step_runs_status
    ON case_step_runs (status) WHERE status IN ('queued','running');

-- ── cases.mode ────────────────────────────────────────
-- Manual   = instructions only (current behavior, no run buttons)
-- Assisted = run buttons, every action human-approved
-- 'auto' is intentionally NOT allowed yet — we'll relax this CHECK when
-- auto is implemented, after the assisted path has been shaken out.
ALTER TABLE cases
    ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'assisted';
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cases_mode_check'
    ) THEN
        ALTER TABLE cases
            ADD CONSTRAINT cases_mode_check
            CHECK (mode IN ('manual','assisted'));
    END IF;
END$$;

COMMIT;