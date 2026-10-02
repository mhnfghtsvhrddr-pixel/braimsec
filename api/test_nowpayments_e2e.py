"""End-to-end tests for the crypto checkout flow (FastAPI level).

Key delivery, org reuse on renewal, status endpoint, success page,
cycle-based periods, and expiry. Network calls to NOWPayments are mocked.

Run: ~/workspace/venvs/braimsec-api/bin/python api/test_nowpayments_e2e.py
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["BRAIMSEC_API_KEY"] = "master-key-for-tests"
os.environ["BRAIMSEC_DB"] = os.path.join(tempfile.gettempdir(),
                                         "braimsec_test_nowp_e2e2.db")
os.environ["BRAIMSEC_SCAN_ROOT"] = os.path.join(tempfile.gettempdir(),
                                                "braimsec_test_nowp_e2e2_scans")
os.environ["NOWPAYMENTS_API_KEY"] = "dummy-key"
os.environ["NOWPAYMENTS_IPN_SECRET"] = "dummy-secret"
for p in (os.environ["BRAIMSEC_DB"],):
    if os.path.exists(p):
        os.remove(p)
os.makedirs(os.environ["BRAIMSEC_SCAN_ROOT"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import get_db, init_db  # noqa: E402
from billing import (  # noqa: E402
    effective_plan, ensure_subscription, get_subscription, run_expiry,
    seed_plans, set_subscription_plan, verify_key,
)
import nowpayments_pay as npay  # noqa: E402
import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

init_db()
seed_plans()
npay.init_crypto_tables()

# mock the NOWPayments network call (unique id per invoice, like production)
_inv_counter = [0]


def _mock_invoice(*a, **k):
    _inv_counter[0] += 1
    return {"id": f"inv-test-{_inv_counter[0]}",
            "invoice_url": "https://nowpayments.io/pay/test"}


main.nowpay.create_invoice = _mock_invoice

c = TestClient(main.app)
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def checkout(email, tier="pro", cycle="monthly"):
    return c.post("/api/checkout/crypto",
                  json={"tier": tier, "cycle": cycle, "email": email})


def fulfill(order_id, tier, cycle, usd, pay_id):
    return npay.fulfill_ipn({"payment_id": pay_id, "payment_status": "finished",
                             "price_amount": usd, "price_currency": "usd",
                             "order_id": order_id})


# --- key delivery --------------------------------------------------------
r = checkout("new-buyer@example.com")
j = r.json()
check("checkout 200", r.status_code == 200)
check("api_key returned for new org", bool(j.get("api_key")))
vk = verify_key(j["api_key"])
check("returned key verifies", vk is not None)
org1 = vk["org_id"] if vk else None
st = npay.get_order_status(j["order_id"])
check("order linked to key org", st and st["org_id"] == org1)

# --- renewal reuses org, no key leak --------------------------------------
r2 = checkout("new-buyer@example.com")
j2 = r2.json()
check("second checkout 200", r2.status_code == 200)
check("no key on renewal", j2.get("api_key") is None)
st2 = npay.get_order_status(j2["order_id"])
check("renewal reuses same org", st2 and st2["org_id"] == org1)

# --- fulfillment sets cycle-based periods ---------------------------------
v, _ = fulfill(j["order_id"], "pro", "monthly", 40, "pay-m-1")
sub = get_subscription(org1)
pe = datetime.fromisoformat(sub["current_period_end"])
days = (pe - datetime.now(timezone.utc)).days
check("monthly period ~30d", v == "fulfilled" and 28 <= days <= 31)

r3 = checkout("annual-buyer@example.com", tier="advanced", cycle="annual")
j3 = r3.json()
v3, _ = fulfill(j3["order_id"], "advanced", "annual", 1200, "pay-a-1")
org3 = verify_key(j3["api_key"])["org_id"]
pe3 = datetime.fromisoformat(get_subscription(org3)["current_period_end"])
days3 = (pe3 - datetime.now(timezone.utc)).days
check("annual period ~365d", v3 == "fulfilled" and 363 <= days3 <= 367)

# --- status endpoint -------------------------------------------------------
r = c.get("/api/checkout/status", params={"order_id": "nope"})
check("unknown order -> 404", r.status_code == 404)
r = c.get("/api/checkout/status", params={"order_id": j["order_id"]})
sj = r.json()
check("status shows fulfilled/active",
      r.status_code == 200 and sj["pay_status"] == "fulfilled"
      and sj["subscription"] == "active" and sj["plan"] == "pro")

# --- success page ------------------------------------------------------------
r = c.get("/checkout/success", params={"order_id": j["order_id"]})
check("success page 200 html",
      r.status_code == 200 and "order_id" in r.text and "poll" in r.text)

# --- expiry: nowpayments expires, paddle does not ------------------------------
db = get_db()
past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
db.execute("UPDATE subscriptions SET current_period_end=? WHERE org_id=?",
           (past, org1))
db.execute(
    "UPDATE subscriptions SET current_period_end=?, payment_provider='paddle',"
    " external_subscription_id='sub_paddle_1' WHERE org_id=?", (past, org3))
db.commit()
db.close()
changed = run_expiry()
check("nowpayments past-due expired", org1 in changed
      and get_subscription(org1)["status"] == "expired")
check("paddle past-due untouched", org3 not in changed
      and get_subscription(org3)["status"] == "active")
check("expired falls back to free", effective_plan(org1)["plan_id"] == "free")

# --- renewal after expiry re-activates ------------------------------------------
r4 = checkout("new-buyer@example.com")
j4 = r4.json()
v4, _ = fulfill(j4["order_id"], "pro", "monthly", 40, "pay-m-2")
sub4 = get_subscription(org1)
check("renewal re-activates", v4 == "fulfilled"
      and sub4["status"] == "active" and sub4["plan_id"] == "pro")

# --- set_subscription_plan default still month-end (backwards compat) --------------
set_subscription_plan(org3, "team", "active", provider="paddle")
pe5 = datetime.fromisoformat(get_subscription(org3)["current_period_end"])
check("default period still month-end", pe5.day >= 28)

# --- hostile bodies are 400, never 500 -------------------------------------------
r_bad = c.post("/api/checkout/crypto", json=["not", "a", "dict"])
check("crypto checkout array body -> 400", r_bad.status_code == 400)
check("fulfill_ipn rejects non-dict payload",
      npay.fulfill_ipn(["not", "a", "dict"])[0] == "reject")

n_fail = sum(1 for _, ok in results if not ok)
print(f"\n{len(results) - n_fail}/{len(results)} passed")
sys.exit(1 if n_fail else 0)
