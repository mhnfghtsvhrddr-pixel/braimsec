"""NOWPayments crypto checkout (USDT) for BraimSec.

DRAFT — public prices mirror the live Paddle catalog, i.e. what
https://braimsec.world/pricing.html advertises. The internal plan mapping is
a best-effort draft: Mahmoud must confirm it before going live.
Do NOT change billing.SEED_PLANS from here.

Flow:
  1. POST /api/checkout/crypto {tier, cycle, email}
     -> reuses the org for a known email (renewal) or creates a free org +
        provisions an API key (raw key returned once — the buyer saves it
        before paying). Creates a NOWPayments hosted invoice.
  2. Customer pays USDT on the NOWPayments hosted page.
  3. NOWPayments POSTs an IPN to /api/webhooks/nowpayments.
  4. Signature verified: HMAC-SHA512 over the raw body with the IPN secret,
     compared (constant-time) to the x-nowpayments-sig header.
  5. payment_status in {"finished", "confirmed"} -> activate the mapped plan
     with provider="nowpayments" and a cycle-based period end
     (monthly +30d, annual +365d). Idempotent on payment_id.
  6. Renewal = same email checks out again -> same org, fresh period.
     run_expiry() expires past-due nowpayments subs (never Paddle ones).
  7. GET /checkout/success?order_id=... shows live payment status;
     GET /api/checkout/status backs it.

Deploy-time env:
  NOWPAYMENTS_API_KEY      API key from the NOWPayments dashboard
  NOWPAYMENTS_IPN_SECRET   IPN secret from the NOWPayments dashboard
  PUBLIC_BASE_URL          e.g. https://api.braimsec.world (callback URLs)
"""
import hashlib
import hmac
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import get_db  # noqa: E402

NOWP_API = "https://api.nowpayments.io/v1"
# USDT on BNB Smart Chain (Mahmoud's payout wallet). Override per deploy:
# NOWPAYMENTS_PAY_CURRENCY=usdttrc20
PAY_CURRENCY = os.environ.get("NOWPAYMENTS_PAY_CURRENCY", "usdtbsc")

# (public tier, billing cycle) -> (USD price, internal plan_id). DRAFT.
CRYPTO_CATALOG = {
    ("starter", "monthly"): (10, "pro"),
    ("starter", "annual"): (100, "pro"),
    ("pro", "monthly"): (40, "pro"),
    ("pro", "annual"): (400, "pro"),
    ("advanced", "monthly"): (120, "team"),
    ("advanced", "annual"): (1200, "team"),
}

FULFILL_STATUSES = ("finished", "confirmed")


def _now():
    return datetime.now(timezone.utc).isoformat()


def period_end_for_cycle(cycle):
    """Crypto is one-time, not auto-renewing: monthly=+30d, annual=+365d."""
    from datetime import timedelta
    days = 365 if cycle == "annual" else 30
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def find_org_by_email(email):
    """Existing org created by an earlier checkout (renewal path)."""
    db = get_db()
    try:
        row = db.execute(
            "SELECT id FROM organizations WHERE name=? AND status='active'"
            " ORDER BY created_at LIMIT 1", (email,)).fetchone()
        return row["id"] if row else None
    finally:
        db.close()


def get_order_status(order_id):
    """Public status view for the success page. Returns dict or None.

    One order can have two rows (the invoice row + the IPN fulfillment row);
    the fulfilled one wins so the success page shows the truth.
    """
    init_crypto_tables()
    db = get_db()
    try:
        row = db.execute(
            """SELECT c.order_id, c.status AS pay_status, c.tier, c.cycle,
                      c.amount_usd, c.org_id,
                      s.status AS sub_status, s.plan_id, s.current_period_end
               FROM crypto_payments c
               LEFT JOIN subscriptions s ON s.org_id = c.org_id
               WHERE c.order_id=?
               ORDER BY CASE c.status WHEN 'fulfilled' THEN 0 ELSE 1 END,
                        c.created_at DESC""", (order_id,)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def catalog_entry(tier, cycle):
    """Return (usd_price, internal_plan_id) or None for unknown tier/cycle."""
    return CRYPTO_CATALOG.get((tier, cycle))


def make_order_id(tier, cycle, org_id):
    """Opaque-but-parseable order id. org_id goes LAST so its own
    underscores can't break parsing: bs_<tier>_<cycle>_<rand>_<org_id>."""
    rand = os.urandom(4).hex()
    return f"bs_{tier}_{cycle}_{rand}_{org_id}"


def parse_order_id(order_id):
    """Inverse of make_order_id. Returns dict or None."""
    try:
        _, tier, cycle, _rand, org_id = str(order_id).split("_", 4)
    except (ValueError, AttributeError):
        return None
    if (tier, cycle) not in CRYPTO_CATALOG or not org_id:
        return None
    return {"tier": tier, "cycle": cycle, "org_id": org_id}


def _sort_recursive(obj):
    if isinstance(obj, dict):
        return {k: _sort_recursive(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_sort_recursive(x) for x in obj]
    return obj


def sorted_json(payload):
    """JS-compatible canonical JSON (for crafting test signatures)."""
    return json.dumps(_sort_recursive(payload), separators=(",", ":"),
                      ensure_ascii=False)


def verify_ipn_signature(raw_body: bytes, signature: str | None,
                         ipn_secret: str) -> bool:
    """HMAC-SHA512 of the raw body vs the x-nowpayments-sig header."""
    if not signature or not ipn_secret:
        return False
    digest = hmac.new(ipn_secret.encode(), raw_body,
                      hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature.strip().lower())


def _nowp_request(api_key, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(NOWP_API + path, data=data, method=method)
    req.add_header("x-api-key", api_key)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def create_invoice(api_key, amount_usd, order_id, description,
                   ipn_url, success_url, cancel_url):
    """Create a NOWPayments hosted invoice. Returns the invoice dict."""
    return _nowp_request(api_key, "POST", "/invoice", {
        "price_amount": amount_usd,
        "price_currency": "usd",
        "pay_currency": PAY_CURRENCY,
        "order_id": order_id,
        "order_description": description,
        "ipn_callback_url": ipn_url,
        "success_url": success_url,
        "cancel_url": cancel_url,
    })


def init_crypto_tables():
    db = get_db()
    try:
        db.execute(
            """CREATE TABLE IF NOT EXISTS crypto_payments (
                   payment_id   TEXT PRIMARY KEY,
                   order_id     TEXT NOT NULL,
                   org_id       TEXT NOT NULL,
                   tier         TEXT NOT NULL,
                   cycle        TEXT NOT NULL,
                   amount_usd   REAL NOT NULL,
                   customer_email TEXT,
                   status       TEXT NOT NULL DEFAULT 'invoiced',
                   created_at   TEXT NOT NULL,
                   fulfilled_at TEXT
               )""")
        db.commit()
    finally:
        db.close()


def record_invoice(payment_ref, order_id, org_id, tier, cycle,
                   amount_usd, customer_email=None):
    """Persist an issued invoice. payment_ref = NOWPayments invoice/payment id."""
    init_crypto_tables()
    db = get_db()
    try:
        db.execute(
            """INSERT OR IGNORE INTO crypto_payments
               (payment_id, order_id, org_id, tier, cycle, amount_usd,
                customer_email, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (str(payment_ref), order_id, org_id, tier, cycle, amount_usd,
             customer_email, "invoiced", _now()))
        db.commit()
    finally:
        db.close()


def already_fulfilled(payment_id):
    db = get_db()
    try:
        row = db.execute(
            "SELECT status FROM crypto_payments WHERE payment_id=?",
            (str(payment_id),)).fetchone()
        return row is not None and row["status"] == "fulfilled"
    finally:
        db.close()


def evaluate_ipn(payload):
    """Pure decision on an IPN payload.

    Returns (verdict, info) where verdict is one of:
      fulfill  - payment completed, safe to activate
      ignore   - not a terminal success state (waiting/confirming/...)
      reject   - looks wrong or unsafe (never fulfill)
    """
    status = payload.get("payment_status")
    if payload.get("parent_payment_id"):
        return ("reject", "parent_payment_id present: wrong-asset deposit")
    if status not in FULFILL_STATUSES:
        return ("ignore", f"non-terminal status: {status}")
    order = parse_order_id(payload.get("order_id"))
    if not order:
        return ("reject", "unparseable order_id")
    expected_usd, _plan = CRYPTO_CATALOG[(order["tier"], order["cycle"])]
    try:
        paid = float(payload.get("price_amount"))
    except (TypeError, ValueError):
        return ("reject", "missing price_amount")
    if abs(paid - expected_usd) > 0.009:
        return ("reject",
                f"amount mismatch: paid {paid} != expected {expected_usd}")
    if str(payload.get("price_currency", "")).lower() != "usd":
        return ("reject", "unexpected price_currency")
    return ("fulfill", order)


def fulfill_ipn(payload):
    """Activate the subscription for a vetted IPN. Idempotent on payment_id."""
    from billing import set_subscription_plan  # lazy: avoids import cycles
    if not isinstance(payload, dict):
        return ("reject", "payload is not an object")
    payment_id = str(payload.get("payment_id"))
    if already_fulfilled(payment_id):
        return ("duplicate", payment_id)
    verdict, info = evaluate_ipn(payload)
    if verdict != "fulfill":
        return (verdict, info)
    expected_usd, plan_id = CRYPTO_CATALOG[(info["tier"], info["cycle"])]
    # Defense in depth: never create phantom orgs from a forged order_id.
    db0 = get_db()
    try:
        exists = db0.execute("SELECT 1 FROM organizations WHERE id=?",
                             (info["org_id"],)).fetchone()
    finally:
        db0.close()
    if not exists:
        return ("reject", f"unknown org: {info['org_id']}")
    set_subscription_plan(info["org_id"], plan_id, "active",
                          provider="nowpayments", external_id=payment_id,
                          period_end=period_end_for_cycle(info["cycle"]))
    db = get_db()
    try:
        db.execute(
            """UPDATE crypto_payments
               SET status='fulfilled', fulfilled_at=?
               WHERE payment_id=?""", (_now(), payment_id))
        # Invoice was recorded under the invoice id; the IPN may carry the
        # payment id instead — record either way so fulfillment is idempotent.
        if db.total_changes == 0:
            db.execute(
                """INSERT INTO crypto_payments
                   (payment_id, order_id, org_id, tier, cycle, amount_usd,
                    status, created_at, fulfilled_at)
                   VALUES (?,?,?,?,?,?,'fulfilled',?,?)""",
                (payment_id, payload.get("order_id"), info["org_id"],
                 info["tier"], info["cycle"], expected_usd, _now(), _now()))
        db.commit()
    finally:
        db.close()
    return ("fulfilled", {"org_id": info["org_id"], "plan": plan_id,
                          "payment_id": payment_id})
