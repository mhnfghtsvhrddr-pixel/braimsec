"""Dodo Payments (card) subscription webhooks for BraimSec.

Dodo is a Merchant of Record like Paddle: it becomes the legal seller,
handles global tax, and pays out to us. No registered company is needed
to start, which fits a solo founder.

Flow:
  1. POST /api/checkout/dodo {tier, cycle, email}  (public, 10/min)
     -> reuses the org for a known email (renewal) or creates a free org +
        provisions an API key (raw key returned once — the buyer saves it
        before paying). Creates a Dodo checkout session for the mapped
        product and returns its checkout_url; metadata stamps
        {org_id, tier, cycle, email} so the webhook can attribute the
        subscription back to this org.
     -> 503 when Dodo checkout is not configured on the server.
  2. Customer pays on Dodo's hosted checkout.
  3. Dodo POSTs to /api/webhooks/dodo.
  4. Signature verified per the Standard Webhooks spec: headers
     webhook-id / webhook-timestamp / webhook-signature, digest is
     HMAC-SHA256 over ``{webhook_id}.{timestamp}.{raw_body}`` keyed by
     the webhook secret (``whsec_`` prefix stripped, base64-decoded).
     Compared constant-time; any v1 signature may match (Dodo sends
     several during secret rotation). The timestamp must be within 300s
     of now (replay window).
  5. Events handled, idempotent on the webhook-id header:
       subscription.active    -> activate the mapped plan
       subscription.renewed   -> plan / status / period re-sync
       subscription.updated   -> plan / status / period re-sync
       subscription.past_due  -> past_due (grace: quotas stay on)
       subscription.paused    -> treated as canceled: there is no local
                                 paused state, so access continues until
                                 the paid period ends, then run_expiry()
                                 retires it
       subscription.on_hold   -> treated as canceled (access revoked by
                                 Dodo; graceful local downgrade instead
                                 of a hard cut)
       subscription.cancelled -> canceled (access until period end)
       subscription.expired   -> expired
       payment.*              -> logged only; subscription events are the
                                 source of truth for entitlements
       anything else          -> ignored (200, no retry storm)
     The tier/cycle ALWAYS comes from the Dodo-reported product_id via
     DODO_PRODUCT_MAP (what was actually paid). metadata only attributes
     the org; a browser claim disagreeing with the paid product is
     rejected as tampering (same lesson as the Paddle webhook).
  6. run_expiry() never auto-expires an active card subscription: card
     subs stay webhook-driven, so a missed renewal webhook must not cut
     off a paying customer (see billing.run_expiry).

Org attribution: the checkout endpoint stamps metadata with
{org_id, tier, cycle, email}. The webhook trusts ONLY an org_id that
already exists — unknown orgs are rejected, never created (defense in
depth: forged metadata must not mint phantom orgs).

Tier -> internal plan mapping is derived from
nowpayments_pay.CRYPTO_CATALOG (single source of truth); Dodo
product ids -> (tier, cycle) come from the DODO_PRODUCT_MAP env var.

Deploy-time env:
  DODO_API_KEY        test (dodo_test_...) or live (dodo_live_...) key
  DODO_API_BASE       https://test.dodopayments.com (default) or
                      https://live.dodopayments.com
  DODO_WEBHOOK_SECRET webhook signing secret from Dodo dashboard ->
                      Developer -> Webhooks (whsec_...)
  DODO_PRODUCT_MAP    JSON object: {"prod_xxx": ["starter","monthly"], ...}
  PUBLIC_BASE_URL     e.g. https://api.braimsec.world (return_url base)
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import billing  # noqa: E402
from database import get_db  # noqa: E402
from nowpayments_pay import CRYPTO_CATALOG, period_end_for_cycle  # noqa: E402

# (public tier, billing cycle) -> internal plan_id. Single source of truth
# lives in nowpayments_pay.CRYPTO_CATALOG; the USD column is crypto-only.
PLAN_FOR_TIER_CYCLE = {(t, c): plan for (t, c), (_usd, plan)
                       in CRYPTO_CATALOG.items()}

# Dodo subscription.status -> local subscription status.
DODO_STATUS_MAP = {
    "active": "active",
    "past_due": "past_due",
    "cancelled": "canceled",
    "expired": "expired",
    # No local paused/on_hold states: graceful downgrade — access runs
    # until the paid period ends, then run_expiry() retires it.
    "paused": "canceled",
    "on_hold": "canceled",
}

# Events that never carry entitlements.
IGNORED_EVENTS = {
    "payment.succeeded", "payment.failed", "payment.cancelled",
    "payment.disputed", "refund.succeeded", "refund.failed",
    "dispute.opened", "dispute.expired", "dispute.won", "dispute.lost",
    "license_key.created",
}

REPLAY_WINDOW_S = 300


def _now():
    return datetime.now(timezone.utc).isoformat()


def api_base():
    return os.environ.get("DODO_API_BASE",
                          "https://test.dodopayments.com").rstrip("/")


def api_key():
    return os.environ.get("DODO_API_KEY", "")


def webhook_secret():
    return os.environ.get("DODO_WEBHOOK_SECRET", "")


def product_map():
    """{dodo_product_id: [tier, cycle]} from DODO_PRODUCT_MAP env JSON."""
    raw = os.environ.get("DODO_PRODUCT_MAP", "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    out = {}
    if isinstance(data, dict):
        for pid, tc in data.items():
            if (isinstance(tc, (list, tuple)) and len(tc) == 2
                    and tc[0] in ("starter", "pro", "advanced")
                    and tc[1] in ("monthly", "annual")):
                out[str(pid)] = [tc[0], tc[1]]
    return out


def entry_for_tier_cycle(tier, cycle, pmap=None):
    """Reverse lookup: (tier, cycle) -> (product_id, plan_id)."""
    pmap = product_map() if pmap is None else pmap
    for pid, (t, c) in pmap.items():
        if t == tier and c == cycle:
            return pid, PLAN_FOR_TIER_CYCLE[(tier, cycle)]
    return None


def _dodo_request(method, path, body=None):
    key = api_key()
    if not key:
        raise RuntimeError("DODO_API_KEY is not configured")
    url = api_base() + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + key)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"Dodo API {e.code} on {path}: {detail}")


def create_checkout_session(product_id, customer_email, metadata,
                            return_url):
    """Create a Dodo checkout session; returns (checkout_url, session_id)."""
    payload = {
        "product_cart": [{"product_id": product_id, "quantity": 1}],
        "customer": {"email": customer_email},
        "return_url": return_url,
        "metadata": metadata,
    }
    resp = _dodo_request("POST", "/checkouts", payload)
    url = resp.get("checkout_url")
    sid = resp.get("session_id")
    if not url:
        raise RuntimeError(f"Dodo checkout missing checkout_url: {resp!r}"[:300])
    return url, sid


# ---------------------------------------------------------------------------
# Webhook signature verification (Standard Webhooks spec, pure stdlib).
# ---------------------------------------------------------------------------

def _decode_secret(secret):
    if secret.startswith("whsec_"):
        secret = secret[len("whsec_"):]
    # b64decode tolerates missing padding only with help; add it.
    return base64.b64decode(secret + "==")


def verify_webhook_signature(raw_body: bytes, headers: dict,
                             secret: str | None = None,
                             now: float | None = None) -> bool:
    """Verify Standard Webhooks HMAC-SHA256 signature.

    headers must carry webhook-id, webhook-timestamp, webhook-signature.
    The digest is HMAC-SHA256 over ``{id}.{ts}.{raw_body}``. Timestamp
    must be within REPLAY_WINDOW_S of now. Constant-time compare; any
    v1 signature in the header may match (secret rotation).
    """
    secret = webhook_secret() if secret is None else secret
    if not secret:
        return False
    get = {str(k).lower(): v for k, v in (headers or {}).items()}.get
    msg_id = get("webhook-id")
    msg_ts = get("webhook-timestamp")
    msg_sig = get("webhook-signature")
    if not (msg_id and msg_ts and msg_sig):
        return False
    try:
        ts = float(msg_ts)
    except (TypeError, ValueError):
        return False
    now = time.time() if now is None else now
    if abs(now - ts) > REPLAY_WINDOW_S:
        return False
    try:
        key = _decode_secret(secret)
    except Exception:
        return False
    # Standard Webhooks signs the exact header bytes: {id}.{timestamp}.{body}
    # where timestamp is the raw webhook-timestamp header string, NOT a
    # normalized integer (truncating a fractional ts would break verify).
    signed = f"{msg_id}.{msg_ts}.".encode() + raw_body
    expected = hmac.new(key, signed, hashlib.sha256).digest()
    for part in str(msg_sig).split(" "):
        if "," not in part:
            continue
        version, sig = part.split(",", 1)
        if version != "v1":
            continue
        try:
            candidate = base64.b64decode(sig)
        except Exception:
            continue
        if hmac.compare_digest(expected, candidate):
            return True
    return False


def _sign_for_test(msg_id, ts, raw_body: bytes, secret: str) -> str:
    """Test helper: produce a valid webhook-signature header value."""
    key = _decode_secret(secret)
    signed = f"{msg_id}.{ts}.".encode() + raw_body
    sig = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest())
    return "v1," + sig.decode()


# ---------------------------------------------------------------------------
# Webhook event tables + evaluation + fulfillment.
# ---------------------------------------------------------------------------

def init_dodo_tables():
    db = get_db()
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS dodo_events(
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            org_id TEXT,
            subscription_id TEXT,
            verdict TEXT NOT NULL DEFAULT 'received',
            note TEXT,
            created_at TEXT NOT NULL)""")
        db.commit()
    finally:
        db.close()


def already_processed(event_id):
    db = get_db()
    try:
        row = db.execute("SELECT 1 FROM dodo_events WHERE event_id=?",
                         (event_id,)).fetchone()
        return row is not None
    finally:
        db.close()


def _record_event(event_id, event_type, org_id, subscription_id,
                  verdict, note):
    db = get_db()
    try:
        try:
            db.execute(
                """INSERT INTO dodo_events
                   (event_id, event_type, org_id, subscription_id,
                    verdict, note, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (event_id, event_type, org_id, subscription_id,
                 verdict, note, _now()))
            db.commit()
            return True
        except Exception:
            return False
    finally:
        db.close()


def _org_exists(org_id):
    if not org_id:
        return False
    db = get_db()
    try:
        row = db.execute("SELECT 1 FROM organizations WHERE id=?",
                         (org_id,)).fetchone()
        return row is not None
    finally:
        db.close()


def evaluate_event(event):
    """Pure decision on a Dodo webhook event dict.

    Returns (verdict, info) where verdict is one of:
      fulfill  - safe to apply to the subscription
      ignore   - observed but not entitlement-bearing
      reject   - looks wrong or unsafe (never apply)
    """
    if not isinstance(event, dict):
        return ("reject", "event is not a JSON object")
    event_type = event.get("type")
    if not event_type:
        return ("reject", "missing event type")
    if event_type in IGNORED_EVENTS:
        return ("ignore",
                "payment/license event: entitlements are subscription-driven")
    if not event_type.startswith("subscription."):
        return ("ignore", f"unhandled event type: {event_type}")
    data = event.get("data") or {}
    if not isinstance(data, dict):
        return ("reject", "missing data object")
    sub_id = data.get("subscription_id")
    if not sub_id:
        return ("reject", "missing subscription_id")
    # The product_id Dodo reports is authoritative: it reflects what was
    # actually paid. metadata is stamped by the customer's browser via the
    # checkout page, so it may only *attribute* the org — it must never
    # decide the tier on its own (else a buyer could pay for starter while
    # claiming pro).
    product_id = data.get("product_id")
    paid_tc = product_map().get(str(product_id)) if product_id else None
    if not paid_tc:
        return ("reject",
                f"unmapped or missing Dodo product_id: {product_id}")
    tier, cycle = paid_tc
    meta = data.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    org_id = meta.get("org_id")
    claimed = (meta.get("tier"), meta.get("cycle"))
    if claimed != (None, None) and claimed != (tier, cycle):
        return ("reject",
                f"metadata claim {claimed[0]}/{claimed[1]} disagrees "
                f"with paid product {product_id} ({tier}/{cycle})")
    plan_id = PLAN_FOR_TIER_CYCLE[(tier, cycle)]
    if not _org_exists(org_id):
        return ("reject", f"unknown org: {org_id}")
    dodo_status = str(data.get("status", "")).lower()
    if dodo_status in ("failed", "pending"):
        return ("ignore", f"subscription not yet billable: {dodo_status}")
    mapped = DODO_STATUS_MAP.get(dodo_status)
    if not mapped:
        return ("reject", f"unknown Dodo status: {dodo_status!r}")
    period_end = data.get("next_billing_date")
    if not period_end:
        # Fall back to a cycle-aware local estimate (same as crypto).
        period_end = period_end_for_cycle(cycle)
    return ("fulfill", {
        "org_id": org_id,
        "plan_id": plan_id,
        "status": mapped,
        "dodo_status": dodo_status,
        "subscription_id": str(sub_id),
        "tier": tier,
        "cycle": cycle,
        "period_end": period_end,
        "event_type": event_type,
    })


def fulfill_event(event, webhook_id):
    """Apply a vetted Dodo event. Idempotent on the webhook-id header."""
    if not webhook_id:
        return ("reject", "missing webhook id")
    webhook_id = str(webhook_id)
    event_type = event.get("type", "") if isinstance(event, dict) else ""
    inserted = _record_event(webhook_id, event_type, None, None,
                             "received", None)
    if not inserted:
        return ("duplicate", webhook_id)
    verdict, info = evaluate_event(event)
    if verdict != "fulfill":
        _update_event(webhook_id, verdict,
                      info if isinstance(info, str) else event_type)
        return (verdict, info)
    org_id = info["org_id"]
    sub_id = info["subscription_id"]
    if info["status"] == "canceled":
        # Access until the paid period ends; run_expiry() retires it after.
        billing.cancel_subscription(org_id)
        db = get_db()
        try:
            db.execute(
                """UPDATE subscriptions
                   SET payment_provider='dodo',
                       external_subscription_id=?
                   WHERE org_id=?""",
                (sub_id, org_id))
            db.commit()
        finally:
            db.close()
    else:
        billing.set_subscription_plan(
            org_id, info["plan_id"], info["status"],
            provider="dodo", external_id=sub_id,
            period_end=info["period_end"])
    _update_event(webhook_id, "fulfilled", info["status"])
    db = get_db()
    try:
        db.execute(
            "UPDATE dodo_events SET org_id=?, subscription_id=? "
            "WHERE event_id=?",
            (org_id, sub_id, webhook_id))
        db.commit()
    finally:
        db.close()
    return ("fulfilled", {"org_id": org_id, "plan": info["plan_id"],
                          "status": info["status"],
                          "subscription_id": sub_id})


def _update_event(event_id, verdict, note):
    db = get_db()
    try:
        db.execute("UPDATE dodo_events SET verdict=?, note=? "
                   "WHERE event_id=?",
                   (verdict, note, event_id))
        db.commit()
    finally:
        db.close()


def get_event(event_id):
    db = get_db()
    try:
        row = db.execute("SELECT event_id, event_type, org_id, "
                         "subscription_id, verdict, note, created_at "
                         "FROM dodo_events WHERE event_id=?",
                         (event_id,)).fetchone()
        if not row:
            return None
        keys = ("event_id", "event_type", "org_id", "subscription_id",
                "verdict", "note", "created_at")
        return dict(zip(keys, row))
    finally:
        db.close()
