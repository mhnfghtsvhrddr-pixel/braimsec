"""SQLite storage for BraimSec API (prototype)."""
import os
import sqlite3

DB_PATH = os.environ.get(
    "BRAIMSEC_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "braimsec.db"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    total_findings INTEGER DEFAULT 0,
    error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    tool TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT,
    file TEXT,
    line INTEGER,
    col INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
-- Subscription foundation: orgs, per-customer API keys, monthly quotas.
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    period TEXT NOT NULL DEFAULT '',
    scans_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'member',
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
-- Phase 2 (enterprise): projects group scans and scope API keys within an org.
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
-- Phase 1 (subscriptions): plans catalog, subscription lifecycle, usage ledger.
CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    monthly_price_cents INTEGER NOT NULL DEFAULT 0,
    scan_quota INTEGER NOT NULL,
    ai_review_quota INTEGER NOT NULL,
    max_projects INTEGER NOT NULL DEFAULT 1,
    max_seats INTEGER NOT NULL DEFAULT 1,
    features TEXT NOT NULL DEFAULT '[]',
    rate_limit_tier TEXT NOT NULL DEFAULT 'standard'
);
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL UNIQUE REFERENCES organizations(id),
    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
    status TEXT NOT NULL DEFAULT 'active',
    current_period_start TEXT NOT NULL,
    current_period_end TEXT NOT NULL,
    trial_ends_at TEXT,
    canceled_at TEXT,
    payment_provider TEXT,
    external_subscription_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    scan_id TEXT,
    kind TEXT NOT NULL,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    wall_time_ms INTEGER NOT NULL DEFAULT 0,
    period TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_org_period ON usage_ledger(org_id, period, kind);
-- Phase 2 (enterprise): immutable audit trail. Who did what, when, from
-- where. Append-only by convention: no UPDATE/DELETE statements exist for
-- this table anywhere in the codebase. actor is an API key prefix or
-- 'owner'/'system' — the full secret never enters the log.
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}',
    ip TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_log(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org_action ON audit_log(org_id, action);
CREATE TABLE IF NOT EXISTS audit_archives (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    cutoff TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    filename TEXT NOT NULL,
    first_id INTEGER,
    last_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_archives_org ON audit_archives(org_id, created_at DESC);
-- Scheduled scans + new-findings alerts (webhooks only; email deliberately
-- out of scope). A schedule re-scans a server-local target_path on a
-- daily/weekly cadence; each run incrementalizes against the previous
-- scheduled scan. last_error surfaces the latest driver failure in the UI.
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    target_path TEXT NOT NULL,
    frequency TEXT NOT NULL DEFAULT 'daily',
    run_time TEXT NOT NULL DEFAULT '02:00',
    weekday INTEGER,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    alert_severity TEXT NOT NULL DEFAULT 'warning',
    webhook_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    next_run_at TEXT NOT NULL,
    last_scan_id TEXT,
    prev_scan_id TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_schedules_org ON schedules(org_id);
-- Alert delivery log: one row per fired (or attempted) notification.
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    schedule_id TEXT NOT NULL REFERENCES schedules(id),
    scan_id TEXT NOT NULL,
    event TEXT NOT NULL DEFAULT 'schedule.alert',
    severity TEXT NOT NULL,
    new_count INTEGER NOT NULL DEFAULT 0,
    webhook_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    response_code INTEGER,
    error TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_sched ON notifications(schedule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications(org_id, created_at DESC);
"""


# Concurrency: the API server and Celery workers are separate processes
# writing to the same SQLite file. Rollback-journal mode serializes every
# writer and blocks readers during writes — under load that surfaces as
# "database is locked" 500s. WAL mode lets readers proceed during writes
# and a generous busy timeout lets writers queue instead of failing fast.
# synchronous stays FULL (the default): with WAL this is crash-safe and
# still far cheaper than rollback-journal FULL, and the audit trail must
# never lose a committed record to a power cut.
WAL_BUSY_TIMEOUT_MS = 30000


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=WAL_BUSY_TIMEOUT_MS / 1000)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={WAL_BUSY_TIMEOUT_MS}")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    # Lightweight migration: AI review columns on findings
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    for col, ctype in (("ai_verdict", "TEXT"), ("ai_confidence", "REAL"),
                       ("ai_explanation", "TEXT"), ("ai_fix", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {ctype}")
    # Lightweight migration: org ownership on scans (multi-tenancy)
    scan_cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
    if "org_id" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN org_id TEXT")
        conn.execute("UPDATE scans SET org_id='owner' WHERE org_id IS NULL")
    # Lightweight migration: scan-completion webhooks (async queue)
    if "webhook_url" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN webhook_url TEXT")
    if "webhook_secret" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN webhook_secret TEXT")
    # Lightweight migration: scan target dir (high-risk sink auditing needs
    # the sources at AI-review time; may be gone for cleaned-up zip uploads)
    if "target_dir" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN target_dir TEXT")
    # Lightweight migration: AI fix suggestions (cached per finding)
    finding_cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    for col, ctype in (("fix_diff", "TEXT"), ("fix_explanation", "TEXT"),
                       ("fix_confidence", "REAL"), ("fix_caveats", "TEXT"),
                       ("fix_checks", "TEXT"), ("fix_generated_at", "TEXT")):
        if col not in finding_cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {ctype}")
    # Lightweight migration: incremental scanning (diff-based rescans).
    # fingerprint_json: {relpath: sha256} of the scannable tree, captured
    # after every scan. incremental_of: id of the baseline scan when this
    # scan ran incrementally (NULL = full scan).
    if "fingerprint_json" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN fingerprint_json TEXT")
    if "incremental_of" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN incremental_of TEXT")
    # Lightweight migration: engine versions for the report honesty
    # appendix (proposal Part 5 §4.1). JSON: {semgrep, gitleaks,
    # braimsec_taint_rules}. NULL on scans that predate this logging.
    if "engines_json" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN engines_json TEXT")
    # Lightweight migration: RBAC roles on API keys (enterprise).
    # viewer < member < admin < owner. Existing keys keep full historical
    # behavior as 'member' (scan + AI, no key management — which had no
    # HTTP surface before this migration anyway).
    key_cols = {r["name"] for r in conn.execute("PRAGMA table_info(api_keys)")}
    if "role" not in key_cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
        conn.execute("UPDATE api_keys SET role='member' WHERE role IS NULL")
    # Lightweight migration: projects (enterprise). scans.project_id and
    # api_keys.project_id are NULL for org-wide (unscoped) rows.
    if "project_id" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN project_id TEXT")
    if "project_id" not in key_cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN project_id TEXT")
    conn.commit()
    conn.close()
