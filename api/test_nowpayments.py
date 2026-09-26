"""Tests for the NOWPayments crypto checkout.

Run: python3 api/test_nowpayments.py  (no network needed; API calls are not
exercised here — only signature verification, IPN evaluation, fulfillment.)
"""
import hashlib
import hmac
import os
import sys
import tempfile

os.environ["BRAIMSEC_API_KEY"] = "master-key-for-tests"
os.environ["BRAIMSEC_DB"] = os.path.join(tempfile.gettempdir(),
                                         "braimsec_test_nowp.db")
os.environ["BRAIMSEC_SCAN_ROOT"] = os.path.join(tempfile.gettempdir(),
                                                "braimsec_test_nowp_scans")
if os.path.exists(os.environ["BRAIMSEC_DB"]):
    os.remove(os.environ["BRAIMSEC_DB"])
os.makedirs(os.environ["BRAIMSEC_SCAN_ROOT"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import init_db  # noqa: E402
from billing import (  # noqa: E402
    create_org, ensure_subscription, get_subscription, seed_plans,
)
import nowpayments_pay as npay  # noqa: E402

init_db()
seed_plans()
npay.init_crypto_tables()

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


SECRET = "test-ipn-secret"


def sign(payload):
    body = npay.sorted_json(payload).encode()
    sig = hmac.new(SECRET.encode(), body, hashlib.sha512).hexdigest()
    return body, sig


# --- signature verification -------------------------------------------
p1 = {"payment_id": "111", "payment_status": "finished", "price_amount": 40,
      "price_currency": "usd", "order_id": "bs_pro_monthly_orgx_ab12"}
body, sig = sign(p1)
check("valid signature verifies", npay.verify_ipn_signature(body, sig, SECRET))
check("tampered body fails",
      not npay.verify_ipn_signature(body + b" ", sig, SECRET))
check("wrong secret fails",
      not npay.verify_ipn_signature(body, sig, "nope"))
check("missing signature fails",
      not npay.verify_ipn_signature(body, None, SECRET))
check("signature case-insensitive",
      npay.verify_ipn_signature(body, sig.upper(), SECRET))

# --- order id roundtrip -------------------------------------------------
oid = npay.make_order_id("starter", "annual", "org123")
parsed = npay.parse_order_id(oid)
check("order id roundtrip",
      parsed and parsed["tier"] == "starter" and parsed["cycle"] == "annual"
      and parsed["org_id"] == "org123")
check("bad order id -> None", npay.parse_order_id("garbage") is None)
check("unknown tier -> None",
      npay.parse_order_id("bs_xxx_monthly_org123_ab12") is None)

# --- IPN evaluation ------------------------------------------------------
def ipn(**kw):
    base = {"payment_id": "222", "payment_status": "finished",
            "price_amount": 40, "price_currency": "usd",
            "order_id": npay.make_order_id("pro", "monthly", "orgA")}
    base.update(kw)
    return base


check("finished -> fulfill", npay.evaluate_ipn(ipn())[0] == "fulfill")
check("confirmed -> fulfill",
      npay.evaluate_ipn(ipn(payment_status="confirmed"))[0] == "fulfill")
check("waiting -> ignore",
      npay.evaluate_ipn(ipn(payment_status="waiting"))[0] == "ignore")
check("expired -> ignore",
      npay.evaluate_ipn(ipn(payment_status="expired"))[0] == "ignore")
check("parent_payment_id -> reject",
      npay.evaluate_ipn(ipn(parent_payment_id="999"))[0] == "reject")
check("amount mismatch -> reject",
      npay.evaluate_ipn(ipn(price_amount=39.5))[0] == "reject")
check("wrong currency -> reject",
      npay.evaluate_ipn(ipn(price_currency="eur"))[0] == "reject")
check("bad order -> reject",
      npay.evaluate_ipn(ipn(order_id="nope"))[0] == "reject")

# --- fulfillment (DB-backed, idempotent) ----------------------------------
org = create_org("paying-customer@example.com")
ensure_subscription(org)
payload = ipn(payment_id="pay-001",
              order_id=npay.make_order_id("pro", "monthly", org))
verdict, info = npay.fulfill_ipn(payload)
check("first fulfill activates", verdict == "fulfilled")
sub = get_subscription(org)
check("plan is pro/active/nowpayments",
      sub["plan_id"] == "pro" and sub["status"] == "active"
      and sub["payment_provider"] == "nowpayments"
      and sub["external_subscription_id"] == "pay-001")
verdict2, _ = npay.fulfill_ipn(payload)
check("second fulfill is duplicate", verdict2 == "duplicate")
check("already_fulfilled true", npay.already_fulfilled("pay-001"))

# advanced -> team mapping
org2 = create_org("big-customer@example.com")
ensure_subscription(org2)
payload2 = ipn(payment_id="pay-002", price_amount=120,
               order_id=npay.make_order_id("advanced", "monthly", org2))
v3, i3 = npay.fulfill_ipn(payload2)
check("advanced maps to team",
      v3 == "fulfilled" and i3["plan"] == "team"
      and get_subscription(org2)["plan_id"] == "team")

# catalog sanity: every entry has a positive price
check("catalog all priced",
      all(usd > 0 for usd, _ in npay.CRYPTO_CATALOG.values()))
check("catalog unknown -> None",
      npay.catalog_entry("nope", "monthly") is None)

n_fail = sum(1 for _, ok in results if not ok)
print(f"\n{len(results) - n_fail}/{len(results)} passed")
sys.exit(1 if n_fail else 0)
