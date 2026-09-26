"""Tests for subscription Phase 1: plans, lifecycle, AI-review quotas, usage API."""
import os
import sys
import tempfile

os.environ["BRAIMSEC_API_KEY"] = "master-key-phase1"
os.environ["BRAIMSEC_DB"] = os.path.join(tempfile.gettempdir(), "braimsec_test_subs.db")
os.environ["BRAIMSEC_SCAN_ROOT"] = os.path.join(tempfile.gettempdir(), "braimsec_test_scans1")
os.environ["SEMGREP_BIN"] = os.path.expanduser("~/.sttenv/bin/semgrep")
os.environ["GITLEAKS_BIN"] = os.path.expanduser("~/workspace/bin/gitleaks")
if os.path.exists(os.environ["BRAIMSEC_DB"]):
    os.remove(os.environ["BRAIMSEC_DB"])
os.makedirs(os.environ["BRAIMSEC_SCAN_ROOT"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main  # noqa: E402
from billing import (  # noqa: E402
    cancel_subscription, create_org, effective_plan, ensure_owner_org,
    get_subscription, list_plans, provision_key, quota_check, record_usage,
    run_expiry, seed_plans, set_subscription_plan, start_trial, usage_count,
)
from database import get_db, init_db  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

init_db()
seed_plans()
ensure_owner_org()

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


# --- Plan catalog -------------------------------------------------------------
plans = list_plans()
by_id = {p["plan_id"]: p for p in plans}
check("4 plans seeded", len(plans) == 4)
check("free: 10 scans, 0 ai_reviews",
      by_id["free"]["scan_quota"] == 10 and by_id["free"]["ai_review_quota"] == 0)
check("enterprise price hidden as Custom",
      by_id["enterprise"]["price_display"] == "Custom")
check("pro price is placeholder-labeled",
      by_id["pro"]["monthly_price_cents"] == 4900)

# --- New org gets a subscription automatically ---------------------------------
org = create_org("PhaseOne", plan="free")
sub = get_subscription(org)
check("new org auto-subscribed free/active",
      sub["plan_id"] == "free" and sub["status"] == "active")

# --- Trial lifecycle -----------------------------------------------------------
trial_end = start_trial(org, "pro", days=14)
plan = effective_plan(org)
check("trial unlocks pro quotas",
      plan["plan_id"] == "pro" and plan["scan_quota"] == 500
      and plan["subscription_status"] == "trialing")

db = get_db()
db.execute("UPDATE subscriptions SET trial_ends_at='2000-01-01T00:00:00' WHERE org_id=?",
           (org,))
db.commit()
db.close()
changed = run_expiry(org)
plan = effective_plan(org)
check("expired trial falls back to free quotas",
      changed == [org] and plan["plan_id"] == "free" and plan["scan_quota"] == 10)

# --- Cancel at period end -------------------------------------------------------
org2 = create_org("CancelCo", plan="pro")
cancel_subscription(org2)
sub2 = get_subscription(org2)
check("cancel keeps pro until period end",
      sub2["status"] == "canceled"
      and effective_plan(org2)["scan_quota"] == 500)
db = get_db()
db.execute("UPDATE subscriptions SET current_period_end='2000-01-01T00:00:00'"
           " WHERE org_id=?", (org2,))
db.commit()
db.close()
run_expiry(org2)
check("canceled past period end -> expired/free",
      effective_plan(org2)["plan_id"] == "free")

# --- Enterprise unlimited -------------------------------------------------------
org3 = create_org("BigCo", plan="free")
set_subscription_plan(org3, "enterprise", "active")
allowed, used, quota = quota_check(org3, "scan", 10_000_000)
check("enterprise quota unlimited", allowed and quota == -1)

# --- Usage ledger ---------------------------------------------------------------
record_usage(org3, "scan", scan_id="s1", wall_time_ms=123)
record_usage(org3, "ai_review", scan_id="s1", wall_time_ms=456)
check("ledger counts per kind",
      usage_count(org3, "scan") == 1 and usage_count(org3, "ai_review") == 1)

# --- API: plans public, subscription/usage gated, AI-review 402 ------------------
with TestClient(main.app) as client:
    r = client.get("/api/plans")
    check("GET /api/plans public", r.status_code == 200 and len(r.json()) == 4)

    check("GET /api/usage needs key", client.get("/api/usage").status_code == 401)

    key = provision_key(org3, "t")
    H = {"x-api-key": key}
    r = client.get("/api/usage", headers=H)
    u = r.json()
    check("GET /api/usage shows both quotas",
          r.status_code == 200 and u["scans"]["used"] == 1
          and u["ai_reviews"]["quota"] == -1 and u["ai_reviews"]["unlimited"])

    r = client.get("/api/subscription", headers=H)
    s = r.json()
    check("GET /api/subscription reflects enterprise",
          s["plan_id"] == "enterprise" and s["status"] == "active")

    # Free org: AI-review quota is 0 -> creating a scan then requesting
    # ai-review must 402 without touching the LLM.
    key_f = provision_key(org, "f")
    HF = {"x-api-key": key_f}
    target = os.environ["BRAIMSEC_SCAN_ROOT"]
    r = client.post("/api/scans", headers=HF, data={"target_path": target})
    assert r.status_code == 200, r.text
    scan_id = r.json()["scan_id"]
    r = client.post(f"/api/scans/{scan_id}/ai-review", headers=HF)
    check("ai-review on free (0 quota) -> 402", r.status_code == 402)

    # Pro trial org: ai-review queues (LLM patched out in test).
    main.do_ai_review = lambda scan_id: None
    org4 = create_org("ProAI", plan="pro")
    key_p = provision_key(org4, "p")
    HP = {"x-api-key": key_p}
    r = client.post("/api/scans", headers=HP, data={"target_path": target})
    scan_p = r.json()["scan_id"]
    r = client.post(f"/api/scans/{scan_p}/ai-review", headers=HP)
    check("ai-review on pro queues", r.status_code == 200
          and r.json()["ai_review"] == "queued")

print(f"\n{sum(1 for _, ok in results if ok)}/{len(results)} subscription tests passed",
      flush=True)
sys.exit(0 if all(ok for _, ok in results) else 1)
