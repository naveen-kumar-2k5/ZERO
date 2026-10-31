-- =========================================================
-- ZeroRespond — Full database bootstrap
-- Runs automatically on first `docker compose up`.
-- Idempotent: safe to re-run (uses IF NOT EXISTS / ON CONFLICT).
-- =========================================================

-- ── 1. Raw alerts (populated by poller) ──────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    agent       TEXT,
    agent_ip    TEXT,
    description TEXT,
    level       INTEGER,
    mitre_id    TEXT,
    rule_id     TEXT,
    source_ip   TEXT,
    target_user TEXT,
    threat_type TEXT,
    time        TIMESTAMPTZ,
    dedup_hash  TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS ix_alerts_time       ON alerts (time DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS ix_alerts_agent      ON alerts (agent);
CREATE INDEX IF NOT EXISTS ix_alerts_level      ON alerts (level);

-- ── 2. Incident cases ────────────────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    id               BIGSERIAL PRIMARY KEY,
    case_ref         TEXT UNIQUE NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open',
    severity         TEXT NOT NULL DEFAULT 'medium',
    threat_type      TEXT NOT NULL,
    playbook_key     TEXT,
    agent_name       TEXT,
    agent_ip         TEXT,
    source_ip        TEXT,
    target_user      TEXT,
    title            TEXT NOT NULL,
    description      TEXT,
    assigned_to      TEXT,
    data_categories  TEXT,
    persons_affected INTEGER DEFAULT 0,
    cur_step         INTEGER NOT NULL DEFAULT 0,
    total_steps      INTEGER NOT NULL DEFAULT 7,
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_cases_status      ON cases (status);
CREATE INDEX IF NOT EXISTS ix_cases_opened_at   ON cases (opened_at DESC);
CREATE INDEX IF NOT EXISTS ix_cases_threat_type ON cases (threat_type);

-- ── 3. Case events (timeline) ────────────────────────────
CREATE TABLE IF NOT EXISTS case_events (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    message    TEXT NOT NULL,
    actor      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_case_events_case
    ON case_events (case_id, created_at DESC);

-- ── 4. Case evidence ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_evidence (
    id          BIGSERIAL PRIMARY KEY,
    case_id     BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'Other',
    notes       TEXT,
    uploaded_by TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_case_evidence_case
    ON case_evidence (case_id, created_at DESC);

-- ── 5. Reports (generated) ───────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id           BIGSERIAL PRIMARY KEY,
    report_ref   TEXT UNIQUE NOT NULL,
    case_id      BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    snapshot     JSONB NOT NULL,
    generated_by TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_reports_case    ON reports (case_id);
CREATE INDEX IF NOT EXISTS ix_reports_created ON reports (created_at DESC);

-- ── 6. Audit log ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    action     TEXT NOT NULL,
    ref        TEXT,
    detail     TEXT,
    actor      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_audit_log_created ON audit_log (created_at DESC);

-- ── 7. Settings (single row) ─────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    id         SMALLINT PRIMARY KEY DEFAULT 1,
    org_name   TEXT NOT NULL DEFAULT 'Kumaraguru College of Technology',
    org_type   TEXT NOT NULL DEFAULT 'Educational Institution',
    city       TEXT NOT NULL DEFAULT 'Coimbatore',
    state      TEXT NOT NULL DEFAULT 'Tamil Nadu',
    dpo_name   TEXT NOT NULL DEFAULT 'KCT IT Department',
    dpo_email  TEXT NOT NULL DEFAULT 'it@kct.ac.in',
    dpo_phone  TEXT NOT NULL DEFAULT '+91 422 000 0000',
    dpdp_id    TEXT,
    autoreport TEXT NOT NULL DEFAULT 'prompt',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT single_row CHECK (id = 1)
);

INSERT INTO settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- ── 8. Users (login) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT NOT NULL,
    email         TEXT,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    status        TEXT NOT NULL DEFAULT 'active',
    last_login    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);

-- ── 9. Seed default admin (password: Zero@post1122) ─────
-- SHA-256 of "Zero@post1122" = 6867fab496d5a1cef4c759ffdf6efee394bf27236dfc0cbacc6f8fc777658bc9
INSERT INTO users (username, display_name, email, password_hash, role)
VALUES (
  'admin',
  'IT Administrator',
  'it-admin@kct.ac.in',
  '6867fab496d5a1cef4c759ffdf6efee394bf27236dfc0cbacc6f8fc777658bc9',
  'admin'
) ON CONFLICT (username) DO NOTHING;

-- ── Done ─────────────────────────────────────────────────