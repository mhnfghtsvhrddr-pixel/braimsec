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
    conn.commit()
    conn.close()
