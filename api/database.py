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
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
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
"""


def get_db():
    conn = sqlite3.connect(DB_PATH)
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
    conn.commit()
    conn.close()
