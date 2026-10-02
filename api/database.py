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
-- Scheduled scans + new-findings alerts (webhooks + email). A schedule re-scans a server-local target_path on a
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
-- Scheduled executive reports: weekly/monthly manager PDFs emailed to the
-- org's alert_emails recipients. Separate from scan schedules (no target,
-- no webhook): the report is built from stored scan data, no rescan.
CREATE TABLE IF NOT EXISTS report_schedules (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    frequency TEXT NOT NULL DEFAULT 'weekly',
    run_time TEXT NOT NULL DEFAULT '08:00',
    weekday INTEGER,
    day_of_month INTEGER,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    project_id TEXT,
    days INTEGER NOT NULL DEFAULT 90,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    next_run_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_schedules_due
    ON report_schedules(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_report_schedules_org
    ON report_schedules(org_id);
-- Alert delivery log: one row per fired (or attempted) notification.
CREATE TABLE IF NOT EXISTS vcs_repos (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    project_id TEXT,
    provider TEXT NOT NULL,          -- github | gitlab
    repo_url TEXT NOT NULL,          -- normalized https://host/owner/repo
    full_name TEXT NOT NULL,         -- owner/repo (or gitlab group path)
    branch TEXT NOT NULL DEFAULT 'main',
    webhook_secret_hash TEXT NOT NULL,
    webhook_secret_enc TEXT,         -- encrypted raw secret (github HMAC only)
    webhook_url TEXT NOT NULL DEFAULT '',
    alert_severity TEXT NOT NULL DEFAULT 'warning',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_scan_id TEXT,
    prev_scan_id TEXT,
    last_scan_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vcs_repos_org ON vcs_repos(org_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vcs_repos_org_url
    ON vcs_repos(org_id, repo_url);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    schedule_id TEXT REFERENCES schedules(id),
    vcs_repo_id TEXT REFERENCES vcs_repos(id),
    scan_id TEXT NOT NULL,
    event TEXT NOT NULL DEFAULT 'schedule.alert',
    severity TEXT NOT NULL,
    new_count INTEGER NOT NULL DEFAULT 0,
    webhook_url TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL DEFAULT 'webhook',
    recipient TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    response_code INTEGER,
    error TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
-- Email alert recipients: per-org addresses for new-findings alerts.
-- The list itself is the switch: no enabled rows => no email alerts.
-- (channel='email' rows in notifications carry the address in recipient.)
CREATE TABLE IF NOT EXISTS alert_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    email TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_emails_org_email
    ON alert_emails(org_id, email);
CREATE INDEX IF NOT EXISTS idx_alert_emails_org ON alert_emails(org_id);
-- Telegram alert chats: per-org chat ids for new-findings alerts.
-- The list itself is the switch: no rows => no telegram alerts.
-- (channel='telegram' rows in notifications carry the chat id in recipient.)
CREATE TABLE IF NOT EXISTS telegram_chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    chat_id TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_telegram_chats_org_chat
    ON telegram_chats(org_id, chat_id);
CREATE INDEX IF NOT EXISTS idx_telegram_chats_org ON telegram_chats(org_id);
CREATE TABLE IF NOT EXISTS slack_webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    webhook_url_enc TEXT NOT NULL,
    url_hash TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_slack_webhooks_org_hash
    ON slack_webhooks(org_id, url_hash);
CREATE INDEX IF NOT EXISTS idx_slack_webhooks_org ON slack_webhooks(org_id);
CREATE TABLE IF NOT EXISTS teams_webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    webhook_url_enc TEXT NOT NULL,
    url_hash TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_webhooks_org_hash
    ON teams_webhooks(org_id, url_hash);
CREATE INDEX IF NOT EXISTS idx_teams_webhooks_org ON teams_webhooks(org_id);
-- TLS certificate expiry monitoring: per-org hostnames probed by the beat
-- worker (~daily). last_status: never|ok|expiring|error. last_alerted_at
-- drives the anti-spam repeat window (see cert_monitor.py).
CREATE TABLE IF NOT EXISTS cert_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    warn_days INTEGER NOT NULL DEFAULT 14,
    webhook_url TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_checked_at TEXT,
    last_expires_at TEXT,
    last_days_left INTEGER,
    last_status TEXT NOT NULL DEFAULT 'never',
    last_error TEXT,
    last_alerted_at TEXT,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_domains_org_host
    ON cert_domains(org_id, hostname, port);
CREATE INDEX IF NOT EXISTS idx_cert_domains_org ON cert_domains(org_id);
-- HTTP(S) uptime monitoring: per-org URL targets probed by the beat worker
-- (each at most every check_interval_s). last_status: never|up|down|error.
-- consecutive_failures gates the down alert (anti-flap); last_alert_event
-- tracks which alert fired last ('uptime.down' -> a recovery alert is due).
CREATE TABLE IF NOT EXISTS uptime_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    path TEXT NOT NULL DEFAULT '/',
    use_https INTEGER NOT NULL DEFAULT 1,
    expected_status INTEGER,
    keyword TEXT NOT NULL DEFAULT '',
    check_interval_s INTEGER NOT NULL DEFAULT 300,
    webhook_url TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    latency_warn_ms INTEGER,
    last_slow_alerted_at TEXT,
    last_slow_alert_event TEXT,
    last_checked_at TEXT,
    last_status TEXT NOT NULL DEFAULT 'never',
    last_http_code INTEGER,
    last_latency_ms INTEGER,
    last_error TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_alerted_at TEXT,
    last_alert_event TEXT,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_uptime_targets_org_host
    ON uptime_targets(org_id, hostname, port, path);
CREATE INDEX IF NOT EXISTS idx_uptime_targets_org ON uptime_targets(org_id);
-- Public status pages: one org may publish several pages (per product),
-- each under a globally unique slug. Public endpoints expose only enabled
-- pages and their org's targets / public incidents.
CREATE TABLE IF NOT EXISTS status_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    headline TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_status_pages_org ON status_pages(org_id);
-- Incident log. Incidents are opened automatically by uptime.down alerts
-- (one open incident per target) and resolved automatically by
-- uptime.recovered; orgs can also manage them manually.
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'investigating',
    impact TEXT NOT NULL DEFAULT 'minor',
    target_id INTEGER,
    public_visible INTEGER NOT NULL DEFAULT 1,
    started_at TEXT NOT NULL,
    resolved_at TEXT,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents(org_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_target_open
    ON incidents(target_id, status);
CREATE TABLE IF NOT EXISTS incident_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_updates_inc
    ON incident_updates(incident_id, created_at);
-- Daily uptime aggregates: one row per target per UTC day, feeding the
-- 90-day uptime bars on status pages. Pruned after 120 days.
CREATE TABLE IF NOT EXISTS uptime_daily (
    target_id INTEGER NOT NULL REFERENCES uptime_targets(id),
    day TEXT NOT NULL,
    checks_up INTEGER NOT NULL DEFAULT 0,
    checks_down INTEGER NOT NULL DEFAULT 0,
    checks_error INTEGER NOT NULL DEFAULT 0,
    latency_sum_ms INTEGER NOT NULL DEFAULT 0,
    latency_n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (target_id, day)
);
-- Scheduled maintenance windows. While a window is active, uptime.down
-- alerts for covered targets are suppressed (logged, not sent) and no
-- incident auto-opens. Empty target_ids_json = covers all targets.
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    target_ids_json TEXT NOT NULL DEFAULT '[]',
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maintenance_org
    ON maintenance_windows(org_id, starts_at);
-- Per-org uptime digest configuration (weekly/monthly email summary of
-- uptime %, latency, incidents and expiring certs). One row per org.
CREATE TABLE IF NOT EXISTS uptime_digests (
    org_id TEXT PRIMARY KEY REFERENCES organizations(id),
    enabled INTEGER NOT NULL DEFAULT 1,
    frequency TEXT NOT NULL DEFAULT 'weekly',
    day_of_week INTEGER NOT NULL DEFAULT 0,
    day_of_month INTEGER NOT NULL DEFAULT 1,
    hour INTEGER NOT NULL DEFAULT 8,
    last_sent_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
-- Per-org HMAC signing secrets for outgoing alert webhooks. The secret is
-- generated server-side, Fernet-encrypted at rest, and shown to the org
-- owner exactly once at rotation time (never returned by the API again).
CREATE TABLE IF NOT EXISTS webhook_signing_secrets (
    org_id TEXT PRIMARY KEY REFERENCES organizations(id),
    secret_enc TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_sched ON notifications(schedule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications(org_id, created_at DESC);
-- idx_notifications_vcs is created post-migration in init_db(): the column
-- does not exist on pre-VCS databases when this script first runs.
-- Team finding triage: one row per finding with its workflow status,
-- assignee (an api_keys.id of the same org) and a note. Change history
-- is append-only in triage_history.
CREATE TABLE IF NOT EXISTS finding_triage (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id),
    status TEXT NOT NULL DEFAULT 'open',
    assigned_to TEXT,
    note TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_status ON finding_triage(status);
CREATE INDEX IF NOT EXISTS idx_triage_assignee ON finding_triage(assigned_to);
CREATE TABLE IF NOT EXISTS triage_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    org_id TEXT NOT NULL REFERENCES organizations(id),
    changed_by TEXT NOT NULL DEFAULT '',
    changed_at TEXT NOT NULL,
    from_status TEXT NOT NULL DEFAULT '',
    to_status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_triage_hist ON triage_history(finding_id, changed_at DESC);
-- False-positive suppressions: per-org fingerprints (tool|rule_id|file|message,
-- same scheme as scheduler.finding_fingerprint) triaged as false_positive.
-- The scheduler's new-findings diff skips these, so a triaged false
-- positive never re-alerts on later scheduled runs. Leaving
-- false_positive (any other status) deletes the suppression row.
CREATE TABLE IF NOT EXISTS finding_suppressions (
    org_id TEXT NOT NULL REFERENCES organizations(id),
    fingerprint TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (org_id, fingerprint)
);
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
    # Lightweight migration: latency-degradation alerts on uptime targets.
    uptime_cols = {r["name"]
                   for r in conn.execute("PRAGMA table_info(uptime_targets)")}
    for col, ctype in (("latency_warn_ms", "INTEGER"),
                       ("last_slow_alerted_at", "TEXT"),
                       ("last_slow_alert_event", "TEXT")):
        if col not in uptime_cols:
            conn.execute(f"ALTER TABLE uptime_targets ADD COLUMN {col} {ctype}")
    # Lightweight migration: RBAC roles on API keys (enterprise).    # viewer < member < admin < owner. Existing keys keep full historical
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
    # Lightweight migration: VCS integration (scan on push). scans.vcs_repo_id
    # links a scan to its repo; commit_sha records the exact commit scanned.
    if "vcs_repo_id" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN vcs_repo_id TEXT")
    if "commit_sha" not in scan_cols:
        conn.execute("ALTER TABLE scans ADD COLUMN commit_sha TEXT")
    # Lightweight migration: scan attempt counting (retry-policy
    # visibility). Incremented each time a scan attempt starts; a scan
    # that failed on a deterministic error shows attempt_count=1.
    if "attempt_count" not in scan_cols:
        conn.execute(
            "ALTER TABLE scans ADD COLUMN attempt_count INTEGER "
            "NOT NULL DEFAULT 0")
    # Migration: notifications gains vcs_repo_id and a nullable schedule_id
    # (VCS alerts have no schedule). SQLite cannot ALTER a column's NOT NULL,
    # so the table is rebuilt when the new column is absent.
    notif_cols = {r["name"] for r in conn.execute("PRAGMA table_info(notifications)")}
    if "vcs_repo_id" not in notif_cols:
        conn.execute("""
            CREATE TABLE notifications_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL REFERENCES organizations(id),
                schedule_id TEXT REFERENCES schedules(id),
                vcs_repo_id TEXT REFERENCES vcs_repos(id),
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
            )
        """)
        conn.execute("""
            INSERT INTO notifications_new (id, org_id, schedule_id, scan_id,
                event, severity, new_count, webhook_url, status, attempts,
                response_code, error, payload, created_at)
            SELECT id, org_id, schedule_id, scan_id, event, severity,
                new_count, webhook_url, status, attempts, response_code,
                error, payload, created_at FROM notifications
        """)
        conn.execute("DROP TABLE notifications")
        conn.execute("ALTER TABLE notifications_new RENAME TO notifications")
        conn.execute("CREATE INDEX idx_notifications_sched"
                     " ON notifications(schedule_id, created_at DESC)")
        conn.execute("CREATE INDEX idx_notifications_org"
                     " ON notifications(org_id, created_at DESC)")
        conn.execute("CREATE INDEX idx_notifications_vcs"
                     " ON notifications(vcs_repo_id, created_at DESC)")
    # Post-migration index (kept out of the SCHEMA script: the vcs_repo_id
    # column does not exist yet on pre-VCS databases when it runs).
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_vcs"
                 " ON notifications(vcs_repo_id, created_at DESC)")
    # Migration: email alerts. notifications gains channel ('webhook' or
    # 'email') and recipient (the address for email rows). Plain ADD COLUMN
    # with defaults backfills old rows, so no table rebuild is needed.
    # alert_emails itself is covered by CREATE TABLE IF NOT EXISTS in the
    # SCHEMA script (runs on every init_db).
    notif_cols2 = {r["name"]
                   for r in conn.execute("PRAGMA table_info(notifications)")}
    if "channel" not in notif_cols2:
        conn.execute("ALTER TABLE notifications ADD COLUMN"
                     " channel TEXT NOT NULL DEFAULT 'webhook'")
    if "recipient" not in notif_cols2:
        conn.execute("ALTER TABLE notifications ADD COLUMN"
                     " recipient TEXT NOT NULL DEFAULT ''")
    # Migration: scheduled executive reports. report_schedules itself is
    # covered by CREATE TABLE IF NOT EXISTS in the SCHEMA script (runs on
    # every init_db); notifications gains a nullable report_schedule_id so
    # report deliveries are attributable (channel='email_report').
    notif_cols3 = {r["name"]
                   for r in conn.execute("PRAGMA table_info(notifications)")}
    if "report_schedule_id" not in notif_cols3:
        conn.execute("ALTER TABLE notifications"
                     " ADD COLUMN report_schedule_id TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_rsch"
                 " ON notifications(report_schedule_id, created_at DESC)")
    conn.commit()
    conn.close()
