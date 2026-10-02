#!/bin/bash
# BraimSec nightly backup — company-grade data protection.
# - Online SQLite snapshot via the backup API (WAL-safe, no downtime)
# - Packages DB snapshot + uploads + scans
# - Verifies integrity of every backup; keeps 7 daily + 4 weekly
# - Logs to /root/backups/backup.log
# Installed on the server as /root/braimsec-backup.sh, run daily from crontab.
set -euo pipefail

BACKUP_ROOT="/root/backups"
DATA_DIR="/data/braimsec"
DATE="$(date +%F)"
DOW="$(date +%u)"          # 1 = Monday
STAMP="$(date '+%F %T')"
mkdir -p "$BACKUP_ROOT/daily" "$BACKUP_ROOT/weekly"

# 1. Consistent DB snapshot (works on a live WAL-mode database)
python3 - <<'EOF'
import sqlite3
src = sqlite3.connect('/data/braimsec/braimsec.db', timeout=30)
dst = sqlite3.connect('/tmp/braimsec-backup.db')
with dst:
    src.backup(dst)
row = dst.execute('PRAGMA integrity_check').fetchone()
assert row and row[0] == 'ok', f'integrity_check failed: {row}'
tables = dst.execute(
    "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
print(f'snapshot ok, {tables} tables')
src.close(); dst.close()
EOF

# 2. Package snapshot + scan artifacts (uploads/scans are small)
tar -czf "$BACKUP_ROOT/daily/braimsec-$DATE.tar.gz" \
    -C /tmp braimsec-backup.db \
    -C "$DATA_DIR" uploads scans
rm -f /tmp/braimsec-backup.db

# 3. Weekly copy (Mondays)
if [ "$DOW" = "1" ]; then
    cp "$BACKUP_ROOT/daily/braimsec-$DATE.tar.gz" \
       "$BACKUP_ROOT/weekly/braimsec-$DATE.tar.gz"
fi

# 4. Retention: newest 7 daily, 4 weekly (|| true: ls fails when glob matches nothing)
ls -1t "$BACKUP_ROOT/daily"/braimsec-*.tar.gz 2>/dev/null \
    | tail -n +8 | xargs -r rm -- || true
ls -1t "$BACKUP_ROOT/weekly"/braimsec-*.tar.gz 2>/dev/null \
    | tail -n +5 | xargs -r rm -- || true

SIZE="$(du -h "$BACKUP_ROOT/daily/braimsec-$DATE.tar.gz" | cut -f1)"
echo "$STAMP OK braimsec-$DATE.tar.gz ($SIZE)" >> "$BACKUP_ROOT/backup.log"
echo "backup ok: $SIZE"
