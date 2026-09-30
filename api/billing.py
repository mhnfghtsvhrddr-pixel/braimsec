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
from audit import log_event  # noqa: E402
from database import get_db, init_db  # noqa: E402

PLANS = {
    "free": {"scans_per_month": 10, "label": "Free"},
    "pro": {"scans_per_month": 500, "label": "Pro"},
    "team": {"scans_per_month": 5000, "label": "Team"},
}
DEFAULT_PLAN = "free"
OWNER_ORG_ID = "owner"

# RBAC roles, weakest to strongest.
#   viewer: read-only (scans, findings, reports, audit log)
#   member: viewer + create scans + quota-consuming AI actions
#   admin:  member + manage API keys (provision/revoke member & viewer keys)
#   owner:  admin + grant owner/admin roles (master env key is always owner)
ROLES = ("viewer", "member", "admin", "owner")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


def role_rank(role: str) -> int:
    """Numeric rank for role comparison; unknown roles rank below viewer."""
    return _ROLE_RANK.get(role, -1)


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


def provision_key(org_id: str, name: str = "", actor: str = "system",
                  role: str = "member") -> str:
    """Create an API key for an org. Returns the RAW key — shown once, never stored."""
    if role not in ROLES:
        raise ValueError(f"unknown role: {role!r} (expected one of {ROLES})")
    raw = "bs_" + secrets.token_urlsafe(32)
    db = get_db()
    try:
        org = db.execute(
            "SELECT id FROM organizations WHERE id=? AND status='active'",
            (org_id,)).fetchone()
        if not org:
            raise KeyError(f"No active org: {org_id}")
        key_id = "key_" + uuid.uuid4().hex[:12]
        db.execute(
            "INSERT INTO api_keys (id, org_id, key_hash, key_prefix, name, role,"
            " created_at, revoked) VALUES (?,?,?,?,?,?,?,0)",
            (key_id, org_id, _hash_key(raw),
             raw[:8], name, role, _now()),
        )
        db.commit()
    finally:
        db.close()
    log_event(org_id, actor, "api_key.created", "api_key", key_id,
              {"name": name, "key_prefix": raw[:8], "role": role})
    return raw


def revoke_key(key_id: str, actor: str = "system"):
    db = get_db()
    try:
        row = db.execute("SELECT org_id, key_prefix FROM api_keys WHERE id=?",
                         (key_id,)).fetchone()
        db.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
        db.commit()
    finally:
        db.close()
    if row:
        log_event(row["org_id"], actor, "api_key.revoked", "api_key", key_id,
                  {"key_prefix": row["key_prefix"]})


def verify_key(raw: str):
    """Validate a presented key. Returns {org_id, plan, key_id, key_prefix, role} or None."""
    db = get_db()
    try:
        row = db.execute(
            """SELECT k.id AS key_id, k.org_id, k.key_prefix, k.role, o.plan
               FROM api_keys k JOIN organizations o ON o.id = k.org_id
               WHERE k.key_hash=? AND k.revoked=0 AND o.status='active'""",
            (_hash_key(raw),)).fetchone()
        if not row:
            return None
        db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?",
                   (_now(), row["key_id"]))
        db.commit()
        return {"org_id": row["org_id"], "plan": row["plan"],
                "key_id": row["key_id"], "key_prefix": row["key_prefix"],
                "role": row["role"] or "member"}
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


# ---------------------------------------------------------------------------
# Phase 1: plans catalog, subscription lifecycle, usage ledger.
#
# The PLANS dict above stays as the seed definition (placeholder prices until
# the 5 customer conversations). The DB tables are the source of truth at
# runtime. Quota -1 means unlimited (enterprise, set per contract).
# ---------------------------------------------------------------------------

SEED_PLANS = [
    # plan_id, name, price_cents/month (PLACEHOLDER), scans, ai_reviews,
    # max_projects, max_seats, features, rate_limit_tier
    ("free", "Free", 0,
     10, 0, 1, 1, ["sarif-export"], "standard"),
    ("pro", "Pro", 4900,
     500, 200, 5, 3, ["sarif-export", "webhooks", "pdf-reports"], "standard"),
    ("team", "Team", 19900,
     5000, 2000, -1, 10,
     ["sarif-export", "webhooks", "pdf-reports", "sso", "priority-support"],
     "elevated"),
    ("enterprise", "Enterprise", -1,
     -1, -1, -1, -1,
     ["sarif-export", "webhooks", "pdf-reports", "sso", "priority-support",
      "on-prem", "sla", "custom-invoices"],
     "elevated"),
]

VALID_STATUSES = ("trialing", "active", "past_due", "canceled", "expired")


def seed_plans():
    """Insert/refresh the draft plan catalog. Prices are placeholders."""
    db = get_db()
    try:
        for pid, name, cents, scans, ai, proj, seats, feats, tier in SEED_PLANS:
            db.execute(
                """INSERT INTO plans (plan_id, name, monthly_price_cents, scan_quota,
                                      ai_review_quota, max_projects, max_seats,
                                      features, rate_limit_tier)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(plan_id) DO UPDATE SET
                     name=excluded.name, scan_quota=excluded.scan_quota,
                     ai_review_quota=excluded.ai_review_quota,
                     max_projects=excluded.max_projects,
                     max_seats=excluded.max_seats, features=excluded.features,
                     rate_limit_tier=excluded.rate_limit_tier""",
                (pid, name, cents, scans, ai, proj, seats,
                 __import__("json").dumps(feats), tier),
            )
        db.commit()
    finally:
        db.close()


def list_plans():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM plans ORDER BY monthly_price_cents").fetchall()
        plans = []
        for r in rows:
            p = dict(r)
            p["features"] = __import__("json").loads(p["features"])
            # Never expose a fake price: -1 means "contact us".
            p["price_display"] = ("Custom" if p["monthly_price_cents"] < 0
                                  else f"${p['monthly_price_cents'] / 100:.0f}/mo")
            plans.append(p)
        return plans
    finally:
        db.close()


def ensure_subscription(org_id: str):
    """Every org gets exactly one subscription; backfilled from the org's plan."""
    db = get_db()
    try:
        row = db.execute("SELECT id FROM subscriptions WHERE org_id=?",
                         (org_id,)).fetchone()
        if row:
            return
        org = db.execute("SELECT plan FROM organizations WHERE id=?",
                         (org_id,)).fetchone()
        plan_id = (org["plan"] if org and org["plan"] in PLANS else DEFAULT_PLAN)
        now_s, month_end = _now(), _month_end()
        db.execute(
            """INSERT INTO subscriptions (id, org_id, plan_id, status,
                                          current_period_start, current_period_end,
                                          created_at)
               VALUES (?,?,?,?,?,?,?)""",
            ("sub_" + uuid.uuid4().hex[:12], org_id, plan_id, "active",
             now_s, month_end, now_s),
        )
        db.commit()
    finally:
        db.close()


def _month_end():
    from calendar import monthrange
    n = datetime.now(timezone.utc)
    last = monthrange(n.year, n.month)[1]
    return n.replace(day=last, hour=23, minute=59, second=59).isoformat()


def get_subscription(org_id: str):
    ensure_subscription(org_id)
    db = get_db()
    try:
        row = db.execute(
            """SELECT s.*, p.name AS plan_name, p.monthly_price_cents,
                      p.scan_quota, p.ai_review_quota, p.max_projects,
                      p.max_seats, p.features, p.rate_limit_tier
               FROM subscriptions s JOIN plans p ON p.plan_id = s.plan_id
               WHERE s.org_id=?""",
            (org_id,)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def effective_plan(org_id: str):
    """The plan that actually applies right now, after lifecycle mapping.

    trialing/active/past_due/canceled(within paid period) -> full plan quotas.
    expired -> free plan quotas (data kept, nothing deleted).
    """
    sub = get_subscription(org_id)
    status = sub["status"]
    if status == "expired":
        plan_id = "free"
    else:
        plan_id = sub["plan_id"]
    db = get_db()
    try:
        row = db.execute("SELECT * FROM plans WHERE plan_id=?", (plan_id,)).fetchone()
        plan = dict(row)
        plan["features"] = __import__("json").loads(plan["features"])
        plan["subscription_status"] = status
        return plan
    finally:
        db.close()


def set_subscription_plan(org_id: str, plan_id: str, status: str = "active",
                          provider: str | None = None, external_id: str | None = None,
                          period_end: str | None = None):
    if status not in VALID_STATUSES:
        raise ValueError(f"Unknown status: {status}")
    ensure_subscription(org_id)
    db = get_db()
    try:
        cur = db.execute(
            """UPDATE subscriptions SET plan_id=?, status=?,
                      payment_provider=COALESCE(?, payment_provider),
                      external_subscription_id=COALESCE(?, external_subscription_id),
                      current_period_start=?, current_period_end=?
               WHERE org_id=?""",
            (plan_id, status, provider, external_id, _now(),
             period_end or _month_end(), org_id))
        if cur.rowcount == 0:
            raise KeyError(f"No subscription for org: {org_id}")
        db.execute("UPDATE organizations SET plan=? WHERE id=?", (plan_id, org_id))
        db.commit()
    finally:
        db.close()


def start_trial(org_id: str, plan_id: str = "pro", days: int = 14):
    """14-day full-feature trial. Warn 3 days before end (email comes in Phase 3)."""
    ensure_subscription(org_id)
    trial_end = (datetime.now(timezone.utc)
                 + __import__("datetime").timedelta(days=days)).isoformat()
    db = get_db()
    try:
        db.execute(
            """UPDATE subscriptions SET plan_id=?, status='trialing',
                      trial_ends_at=?, current_period_start=?, current_period_end=?
               WHERE org_id=?""",
            (plan_id, trial_end, _now(), trial_end, org_id))
        db.execute("UPDATE organizations SET plan=? WHERE id=?", (plan_id, org_id))
        db.commit()
    finally:
        db.close()
    return trial_end


def cancel_subscription(org_id: str):
    """Cancel at end of paid period: keeps working until current_period_end."""
    ensure_subscription(org_id)
    db = get_db()
    try:
        db.execute(
            "UPDATE subscriptions SET status='canceled', canceled_at=? WHERE org_id=?",
            (_now(), org_id))
        db.commit()
    finally:
        db.close()


def run_expiry(org_id: str | None = None):
    """Apply time-based transitions. Run from a cron once Phase 2 lands.

    - trialing past trial_ends_at -> expired (falls back to free quotas)
    - canceled past current_period_end -> expired
    - active past current_period_end, one-time crypto (provider='nowpayments')
      -> expired. Card subscriptions (Paddle) stay webhook-driven: never
      auto-expire an active card sub from here, a missed renewal webhook
      must not cut off a paying customer.
    Returns the list of orgs whose status changed.
    """
    db = get_db()
    changed = []
    try:
        q = ("SELECT org_id, status, trial_ends_at, current_period_end,"
             " payment_provider FROM subscriptions")
        args: tuple = ()
        if org_id:
            q += " WHERE org_id=?"
            args = (org_id,)
        for r in db.execute(q, args).fetchall():
            now_s = _now()
            new_status = None
            if r["status"] == "trialing" and r["trial_ends_at"] and r["trial_ends_at"] < now_s:
                new_status = "expired"
            elif (r["status"] == "canceled" and r["current_period_end"]
                  and r["current_period_end"] < now_s):
                new_status = "expired"
            elif (r["status"] == "active" and r["current_period_end"]
                  and r["current_period_end"] < now_s
                  and r["payment_provider"] == "nowpayments"):
                new_status = "expired"
            if new_status:
                db.execute("UPDATE subscriptions SET status=? WHERE org_id=?",
                           (new_status, r["org_id"]))
                changed.append(r["org_id"])
        db.commit()
    finally:
        db.close()
    return changed


def record_usage(org_id: str, kind: str, scan_id: str | None = None,
                 tokens_used: int = 0, wall_time_ms: int = 0):
    """Append one usage event. kind: 'scan' | 'ai_review'."""
    if kind not in ("scan", "ai_review"):
        raise ValueError(f"Unknown usage kind: {kind}")
    db = get_db()
    try:
        db.execute(
            """INSERT INTO usage_ledger (org_id, scan_id, kind, tokens_used,
                                         wall_time_ms, period, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (org_id, scan_id, kind, tokens_used, wall_time_ms, _period(), _now()))
        if kind == "scan":
            # Legacy mirror kept for the dashboard; ledger is source of truth.
            db.execute("UPDATE organizations SET scans_used=scans_used+1 WHERE id=?",
                       (org_id,))
        db.commit()
    finally:
        db.close()


def usage_count(org_id: str, kind: str, period: str | None = None) -> int:
    db = get_db()
    try:
        row = db.execute(
            "SELECT COUNT(*) c FROM usage_ledger WHERE org_id=? AND kind=? AND period=?",
            (org_id, kind, period or _period())).fetchone()
        return row["c"]
    finally:
        db.close()


def quota_check(org_id: str, kind: str = "scan", units: int = 1):
    """Check quota for `units` of usage. Returns (allowed, used, quota).

    Quota -1 (enterprise) means unlimited. Monthly quotas never roll over.
    """
    plan = effective_plan(org_id)
    quota = plan["scan_quota"] if kind == "scan" else plan["ai_review_quota"]
    if quota < 0:
        return (True, usage_count(org_id, kind), -1)
    used = usage_count(org_id, kind)
    return (used + units <= quota, used, quota)


# --- v1 compatibility: these now run on the subscription system -------------

def _v1_sync_org_plan(org_id: str):
    ensure_subscription(org_id)


def quota_status(org_id: str):
    _v1_sync_org_plan(org_id)
    return quota_check(org_id, "scan", 1)


def consume_scan(org_id: str) -> bool:
    _v1_sync_org_plan(org_id)
    allowed, _, _ = quota_check(org_id, "scan", 1)
    if not allowed:
        return False
    # Re-check inside the write to avoid double-spend races.
    db = get_db()
    try:
        allowed2, _, _ = quota_check(org_id, "scan", 1)
        if not allowed2:
            return False
        record_usage(org_id, "scan")
        return True
    finally:
        db.close()


_orig_create_org = create_org
_orig_set_plan = set_plan


def create_org(name: str, plan: str = DEFAULT_PLAN) -> str:
    org_id = _orig_create_org(name, plan)
    ensure_subscription(org_id)
    return org_id


def set_plan(org_id: str, plan: str):
    _orig_set_plan(org_id, plan)
    set_subscription_plan(org_id, plan, status="active")


if __name__ == "__main__":
    import argparse

    init_db()
    seed_plans()
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
    p_trial = sub.add_parser("new-trial", help="Start a full-feature trial")
    p_trial.add_argument("org_id")
    p_trial.add_argument("--plan", default="pro", choices=sorted(PLANS))
    p_trial.add_argument("--days", type=int, default=14)
    p_sub = sub.add_parser("set-subscription",
                           help="Set plan+status directly (admin/manual billing)")
    p_sub.add_argument("org_id")
    p_sub.add_argument("plan_id")
    p_sub.add_argument("--status", default="active", choices=list(VALID_STATUSES))
    p_cancel = sub.add_parser("cancel", help="Cancel at end of paid period")
    p_cancel.add_argument("org_id")
    p_exp = sub.add_parser("expire-run", help="Apply time-based transitions")
    p_exp.add_argument("--org", default=None)
    p_plans = sub.add_parser("plans", help="List the plan catalog")
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
    elif args.cmd == "new-trial":
        print("trial ends:", start_trial(args.org_id, args.plan, args.days))
    elif args.cmd == "set-subscription":
        set_subscription_plan(args.org_id, args.plan_id, args.status)
        print(f"subscription -> {args.plan_id}/{args.status}")
    elif args.cmd == "cancel":
        cancel_subscription(args.org_id)
        print("canceled (active until period end)")
    elif args.cmd == "expire-run":
        print("transitioned:", run_expiry(args.org))
    elif args.cmd == "plans":
        import json as _json
        print(_json.dumps(list_plans(), indent=2, default=str))
