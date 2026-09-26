"""Subscription foundation for BraimSec: organizations, API keys, quotas.

What this is: the no-regrets infrastructure every monetization path needs —
per-customer API keys, monthly scan quotas per plan, usage metering.
What this is NOT (waits for the 5 professional conversations):
payment processing, final pricing/packaging, on-prem, SSO.

DRAFT plans — do not treat as final until the conversations validate them:
    free:  10 scans / month
    pro:   500 scans / month
    team:  5000 scans / month
"""
import hashlib
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import get_db, init_db  # noqa: E402

PLANS = {
    "free": {"scans_per_month": 10, "label": "Free"},
    "pro": {"scans_per_month": 500, "label": "Pro"},
    "team": {"scans_per_month": 5000, "label": "Team"},
}
DEFAULT_PLAN = "free"
OWNER_ORG_ID = "owner"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _period():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _hash_key(raw: str) -> str:
    # Keys are stored hashed only — a DB leak must not yield usable keys.
    return hashlib.sha256(raw.encode()).hexdigest()


def ensure_owner_org():
    """Make sure the built-in owner org exists (used by the master API key)."""
    db = get_db()
    try:
        row = db.execute(
            "SELECT id FROM organizations WHERE id=?", (OWNER_ORG_ID,)).fetchone()
        if not row:
            db.execute(
                "INSERT INTO organizations (id, name, plan, status, created_at,"
                " period, scans_used) VALUES (?,?,?,?,?,?,?)",
                (OWNER_ORG_ID, "Owner", "team", "active", _now(), _period(), 0),
            )
            db.commit()
    finally:
        db.close()


def create_org(name: str, plan: str = DEFAULT_PLAN) -> str:
    if plan not in PLANS:
        raise ValueError(f"Unknown plan: {plan} (choose from {sorted(PLANS)})")
    org_id = "org_" + uuid.uuid4().hex[:12]
    db = get_db()
    try:
        db.execute(
            "INSERT INTO organizations (id, name, plan, status, created_at,"
            " period, scans_used) VALUES (?,?,?,?,?,?,?)",
            (org_id, name, plan, "active", _now(), _period(), 0),
        )
        db.commit()
    finally:
        db.close()
    return org_id


def set_plan(org_id: str, plan: str):
    if plan not in PLANS:
        raise ValueError(f"Unknown plan: {plan}")
    db = get_db()
    try:
        cur = db.execute("UPDATE organizations SET plan=? WHERE id=?", (plan, org_id))
        if cur.rowcount == 0:
            raise KeyError(f"No such org: {org_id}")
        db.commit()
    finally:
        db.close()


def provision_key(org_id: str, name: str = "") -> str:
    """Create an API key for an org. Returns the RAW key — shown once, never stored."""
    raw = "bs_" + secrets.token_urlsafe(32)
    db = get_db()
    try:
        org = db.execute(
            "SELECT id FROM organizations WHERE id=? AND status='active'",
            (org_id,)).fetchone()
        if not org:
            raise KeyError(f"No active org: {org_id}")
        db.execute(
            "INSERT INTO api_keys (id, org_id, key_hash, key_prefix, name,"
            " created_at, revoked) VALUES (?,?,?,?,?,?,0)",
            ("key_" + uuid.uuid4().hex[:12], org_id, _hash_key(raw),
             raw[:8], name, _now()),
        )
        db.commit()
    finally:
        db.close()
    return raw


def revoke_key(key_id: str):
    db = get_db()
    try:
        db.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
        db.commit()
    finally:
        db.close()


def verify_key(raw: str):
    """Validate a presented key. Returns {org_id, plan, key_id} or None."""
    db = get_db()
    try:
        row = db.execute(
            """SELECT k.id AS key_id, k.org_id, o.plan
               FROM api_keys k JOIN organizations o ON o.id = k.org_id
               WHERE k.key_hash=? AND k.revoked=0 AND o.status='active'""",
            (_hash_key(raw),)).fetchone()
        if not row:
            return None
        db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?",
                   (_now(), row["key_id"]))
        db.commit()
        return {"org_id": row["org_id"], "plan": row["plan"], "key_id": row["key_id"]}
    finally:
        db.close()


def _rollover_if_needed(db, org):
    """Reset the monthly counter when the calendar period changes."""
    current = _period()
    if org["period"] != current:
        db.execute("UPDATE organizations SET period=?, scans_used=0 WHERE id=?",
                   (current, org["id"]))
        db.commit()
        org = dict(org)
        org["period"] = current
        org["scans_used"] = 0
    return org


def quota_status(org_id: str):
    """Returns (allowed: bool, used: int, quota: int). Rolls the period over."""
    db = get_db()
    try:
        org = db.execute(
            "SELECT id, plan, period, scans_used FROM organizations WHERE id=?",
            (org_id,)).fetchone()
        if not org:
            raise KeyError(f"No such org: {org_id}")
        org = _rollover_if_needed(db, org)
        quota = PLANS[org["plan"]]["scans_per_month"]
        return (org["scans_used"] < quota, org["scans_used"], quota)
    finally:
        db.close()


def consume_scan(org_id: str) -> bool:
    """Consume one scan from the org's monthly quota. False if exhausted."""
    allowed, _, _ = quota_status(org_id)
    if not allowed:
        return False
    db = get_db()
    try:
        # Re-check inside the write transaction to avoid double-spend races.
        org = db.execute(
            "SELECT plan, period, scans_used FROM organizations WHERE id=?",
            (org_id,)).fetchone()
        org = _rollover_if_needed(db, org)
        quota = PLANS[org["plan"]]["scans_per_month"]
        if org["scans_used"] >= quota:
            return False
        db.execute("UPDATE organizations SET scans_used=scans_used+1 WHERE id=?",
                   (org_id,))
        db.commit()
        return True
    finally:
        db.close()


def org_summary(org_id: str):
    db = get_db()
    try:
        org = db.execute("SELECT * FROM organizations WHERE id=?", (org_id,)).fetchone()
        if not org:
            return None
        org = _rollover_if_needed(db, dict(org))
        keys = db.execute(
            "SELECT id, key_prefix, name, created_at, last_used_at, revoked"
            " FROM api_keys WHERE org_id=? ORDER BY created_at DESC",
            (org_id,)).fetchall()
        return {"org": org, "keys": [dict(k) for k in keys],
                "quota": PLANS[org["plan"]]["scans_per_month"]}
    finally:
        db.close()


if __name__ == "__main__":
    import argparse

    init_db()
    ensure_owner_org()
    ap = argparse.ArgumentParser(description="BraimSec billing admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_new = sub.add_parser("new-org", help="Create an organization")
    p_new.add_argument("name")
    p_new.add_argument("--plan", default=DEFAULT_PLAN, choices=sorted(PLANS))
    p_key = sub.add_parser("new-key", help="Provision an API key (printed once)")
    p_key.add_argument("org_id")
    p_key.add_argument("--name", default="")
    p_plan = sub.add_parser("set-plan", help="Change an org's plan")
    p_plan.add_argument("org_id")
    p_plan.add_argument("plan", choices=sorted(PLANS))
    p_show = sub.add_parser("show", help="Show org summary")
    p_show.add_argument("org_id")
    p_rev = sub.add_parser("revoke", help="Revoke a key by id")
    p_rev.add_argument("key_id")
    args = ap.parse_args()

    if args.cmd == "new-org":
        print(create_org(args.name, args.plan))
    elif args.cmd == "new-key":
        # The raw key is printed once — store it somewhere safe now.
        print(provision_key(args.org_id, args.name))
    elif args.cmd == "set-plan":
        set_plan(args.org_id, args.plan)
        print(f"plan -> {args.plan}")
    elif args.cmd == "revoke":
        revoke_key(args.key_id)
        print("revoked")
    elif args.cmd == "show":
        import json as _json
        print(_json.dumps(org_summary(args.org_id), indent=2, default=str))
