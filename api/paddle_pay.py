"""Paddle Billing (card) subscription webhooks for BraimSec.

Paddle is the primary card processor. The backend had no Paddle code at
all — no webhook receiver, no card checkout — so an approved Paddle
account could not have activated a single subscription. This module
closes that gap.

Flow:
  1. POST /api/checkout/paddle {tier, cycle, email}  (public, 10/min)
     -> reuses the org for a known email (renewal) or creates a free org +
        provisions an API key (raw key returned once — the buyer saves it
        before paying). Returns the Paddle price id plus the custom_data
        payload the site hands to the Paddle.js checkout overlay, so the
        webhook can attribute the subscription back to this org.
     -> 503 when Paddle checkout is not configured on the server.
  2. Customer pays on Paddle's hosted checkout (Paddle.js overlay).
  3. Paddle POSTs to /api/webhooks/paddle.
  4. Signature verified: the Paddle-Signature header looks like
     ``ts=<unix>;h1=<hex>[;h1=<hex>...]`` and the digest is HMAC-SHA256
     over ``{ts}:{raw_body}`` keyed by the notification destination
     secret. Compared constant-time; any h1 may match (Paddle sends
     several during secret rotation). The ts must be within 300s of now
     (replay window).
  5. Events handled, idempotent on event_id:
       subscription.created / activated -> activate the mapped plan
       subscription.updated            -> plan / status / period re-sync
       subscription.trialing           -> trialing
       subscription.past_due           -> past_due (grace: quotas stay on)
       subscription.paused             -> treated as canceled: there is no
                                          local paused state, so access
                                          continues until the paid period
                                          ends, then run_expiry() retires it
       subscription.canceled           -> canceled (access until period end)
       transaction.completed           -> logged only; subscription events
                                          are the source of truth for
                                          entitlements (a transaction has no
                                          period to grant)
       anything else                   -> ignored (200, no retry storm)
  6. run_expiry() never auto-expires an active card subscription: card
     subs stay webhook-driven, so a missed renewal webhook must not cut
     off a paying customer (see billing.run_expiry).

Org attribution: the checkout endpoint stamps custom_data with
{org_id, tier, cycle, email}. The webhook trusts ONLY an org_id that
already exists — unknown orgs are rejected, never created (defense in
depth: a forged custom_data must not mint phantom orgs).

Tier -> internal plan mapping is derived from
nowpayments_pay.CRYPTO_CATALOG (single source of truth); Paddle price
ids -> (tier, cycle) come from the PADDLE_PRICE_MAP env var, built from
the paddle_catalog.py output at deploy time.

Deploy-time env:
  PADDLE_WEBHOOK_SECRET  notification destination secret (pdl_ntfset_...)
  PADDLE_PRICE_MAP       JSON object: {"pri_xxx": ["starter","monthly"], ...}
  PUBLIC_BASE_URL        e.g. https://api.braimsec.world (informational)
"""
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import billing  # noqa: E402
from database import get_db  # noqa: E402
from nowpayments_pay import CRYPTO_CATALOG  # noqa: E402

# (public tier, billing cycle) -> internal plan_id. Single source of truth
# lives in nowpayments_pay.CRYPTO_CATALOG; the USD column is crypto-only.
PLAN_FOR_TIER_CYCLE = {(t, c): plan for (t, c), (_usd, plan)
                       in CRYPTO_CATALOG.items()}

# Paddle subscription.status -> local subscription status.
PADDLE_STATUS_MAP = {
    "active": "active",
    "trialing": "trialing",
    "past_due": "past_due",
    # No local "paused": treat as cancel-at-period-end. Access continues
    # until current_period_end, then run_expiry() retires the sub.
    "paused": "canceled",
    "canceled": "canceled",
}

SUBSCRIPTION_EVENTS = (
    "subscription.created",
    "subscription.activated",
    "subscription.updated",
    "subscription.trialing",
    "subscription.past_due",
    "subscription.paused",
    "subscription.canceled",
)

# Observed but not entitlement-bearing: logged, never fulfill.
TRANSACTION_EVENTS = (
    "transaction.created",
    "transaction.updated",
    "transaction.completed",
    "transaction.paid",
    "transaction.payment_failed",
    "transaction.billed",
    "transaction.canceled",
    "transaction.past_due",
    "transaction.ready",
    "transaction.revised",
)

REPLAY_WINDOW_SECS = 300


def _now():
    return datetime.now(timezone.utc).isoformat()


def price_map():
    """PADDLE_PRICE_MAP env -> {price_id: (tier, cycle)}. Invalid entries
    are dropped; returns {} when unconfigured (callers answer 503)."""
    raw = os.environ.get("PADDLE_PRICE_MAP", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    out = {}
    if isinstance(data, dict):
        for price_id, tc in data.items():
            if (isinstance(tc, (list, tuple)) and len(tc) == 2
                    and (str(tc[0]), str(tc[1])) in PLAN_FOR_TIER_CYCLE):
                out[str(price_id)] = (str(tc[0]), str(tc[1]))
    return out


def entry_for_tier_cycle(tier, cycle, pmap=None):
    """Return (price_id, plan_id) for a public tier/cycle, or None."""
    pmap = price_map() if pmap is None else pmap
    for price_id, (t, c) in pmap.items():
        if t == tier and c == cycle:
            return (price_id, PLAN_FOR_TIER_CYCLE[(t, c)])
    return None


def parse_signature_header(header):
    """Parse 'ts=<unix>;h1=<hex>[;h1=<hex>...]' -> (ts_str, [digests]).

    Raises ValueError on anything malformed. The raw ts string is kept so
    the signed material is byte-exact (no int round-trip).
    """
    if not header or not isinstance(header, str):
        raise ValueError("missing signature header")
    ts_str = None
    digests = []
    for part in header.split(";"):
        part = part.strip()
        if part.startswith("ts="):
            ts_str = part[3:].strip()
        elif part.startswith("h1="):
            d = part[3:].strip().lower()
            if d:
                digests.append(d)
    if ts_str is None or not digests:
        raise ValueError("signature header lacks ts= or h1=")
    int(ts_str)  # validates; the raw string is still what gets signed
    return ts_str, digests


def verify_webhook_signature(raw_body: bytes, header: str | None,
                             secret: str,
                             max_age_secs: int = REPLAY_WINDOW_SECS) -> bool:
    """Verify a Paddle-Signature header against the raw request body.

    Signed material is ``{ts}:{raw_body}`` (ts verbatim from the header),
    HMAC-SHA256 keyed by the notification destination secret, hex digest,
    constant-time compare. Any listed h1 may match (secret rotation).
    Rejects timestamps outside the replay window.
    """
    if not secret:
        return False
    if raw_body is None:
        return False
    try:
        ts_str, digests = parse_signature_header(header)
    except ValueError:
        return False
    try:
        age = abs(int(time.time()) - int(ts_str))
    except ValueError:
        return False
    if age > max_age_secs:
        return False
    signed = ts_str.encode() + b":" + raw_body
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, d) for d in digests)


def init_paddle_tables():
    db = get_db()
    try:
        db.execute(
            """CREATE TABLE IF NOT EXISTS paddle_events (
                   event_id        TEXT PRIMARY KEY,
                   event_type      TEXT NOT NULL,
                   org_id          TEXT,
                   subscription_id TEXT,
                   verdict         TEXT NOT NULL DEFAULT 'received',
                   note            TEXT,
                   received_at     TEXT NOT NULL,
                   processed_at    TEXT
               )""")
        db.commit()
    finally:
        db.close()


def already_processed(event_id):
    db = get_db()
    try:
        row = db.execute(
            "SELECT verdict FROM paddle_events WHERE event_id=?",
            (str(event_id),)).fetchone()
        return row is not None
    finally:
        db.close()


def _record_event(event_id, event_type, org_id, subscription_id,
                  verdict, note):
    init_paddle_tables()
    db = get_db()
    try:
        db.execute(
            """INSERT OR IGNORE INTO paddle_events
               (event_id, event_type, org_id, subscription_id, verdict,
                note, received_at, processed_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (str(event_id), event_type, org_id, subscription_id, verdict,
             note if isinstance(note, str) else json.dumps(note),
             _now(), _now()))
        db.commit()
        return db.total_changes > 0
    finally:
        db.close()


def _org_exists(org_id):
    if not org_id:
        return False
    db = get_db()
    try:
        row = db.execute(
            "SELECT 1 FROM organizations WHERE id=? AND status='active'",
            (org_id,)).fetchone()
        return row is not None
    finally:
        db.close()


def _period_end_for(data, cycle):
    """Paddle's current billing period wins; cycle-based fallback."""
    try:
        ends_at = (data.get("current_billing_period") or {}).get("ends_at")
    except AttributeError:
        ends_at = None
    if ends_at:
        return str(ends_at)
    days = 365 if cycle == "annual" else 30
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def evaluate_event(event):
    """Pure decision on a Paddle webhook event dict.

    Returns (verdict, info) where verdict is one of:
      fulfill  - safe to apply to the subscription
      ignore   - observed but not entitlement-bearing
      reject   - looks wrong or unsafe (never apply)
    """
    if not isinstance(event, dict):
        return ("reject", "event is not a JSON object")
    event_type = event.get("event_type")
    if not event_type:
        return ("reject", "missing event_type")
    if event_type in TRANSACTION_EVENTS:
        return ("ignore",
                "transaction event: entitlements are subscription-driven")
    if event_type not in SUBSCRIPTION_EVENTS:
        return ("ignore", f"unhandled event type: {event_type}")
    data = event.get("data") or {}
    if not isinstance(data, dict):
        return ("reject", "missing data object")
    sub_id = data.get("id")
    if not sub_id:
        return ("reject", "missing subscription id")
    custom = data.get("custom_data") or {}
    if not isinstance(custom, dict):
        custom = {}
    org_id = custom.get("org_id")
    tier, cycle = custom.get("tier"), custom.get("cycle")
    if (tier, cycle) not in PLAN_FOR_TIER_CYCLE:
        # Fall back to the price id on the first item.
        price_id = None
        try:
            price_id = (data.get("items") or [])[0]["price"]["id"]
        except (IndexError, KeyError, TypeError):
            price_id = None
        tc = price_map().get(str(price_id)) if price_id else None
        if not tc:
            return ("reject",
                    "cannot map subscription to a tier/cycle "
                    f"(custom_data={tier}/{cycle}, price={price_id})")
        tier, cycle = tc
    plan_id = PLAN_FOR_TIER_CYCLE[(tier, cycle)]
    if not _org_exists(org_id):
        return ("reject", f"unknown org: {org_id}")
    paddle_status = str(data.get("status", "")).lower()
    mapped = PADDLE_STATUS_MAP.get(paddle_status)
    if not mapped:
        return ("reject", f"unknown Paddle status: {paddle_status!r}")
    return ("fulfill", {
        "org_id": org_id,
        "plan_id": plan_id,
        "status": mapped,
        "paddle_status": paddle_status,
        "subscription_id": str(sub_id),
        "tier": tier,
        "cycle": cycle,
        "period_end": _period_end_for(data, cycle),
        "event_type": event_type,
    })


def fulfill_event(event):
    """Apply a vetted Paddle event. Idempotent on event_id."""
    event_id = event.get("event_id") if isinstance(event, dict) else None
    if not event_id:
        return ("reject", "missing event_id")
    event_id = str(event_id)
    event_type = event.get("event_type", "")
    inserted = _record_event(event_id, event_type, None, None,
                             "received", None)
    if not inserted:
        return ("duplicate", event_id)
    verdict, info = evaluate_event(event)
    if verdict != "fulfill":
        _update_event(event_id, verdict,
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
                   SET payment_provider='paddle',
                       external_subscription_id=?
                   WHERE org_id=?""",
                (sub_id, org_id))
            db.commit()
        finally:
            db.close()
    else:
        billing.set_subscription_plan(
            org_id, info["plan_id"], info["status"],
            provider="paddle", external_id=sub_id,
            period_end=info["period_end"])
    _update_event(event_id, "fulfilled", info["status"])
    db = get_db()
    try:
        db.execute(
            "UPDATE paddle_events SET org_id=?, subscription_id=? "
            "WHERE event_id=?",
            (org_id, sub_id, event_id))
        db.commit()
    finally:
        db.close()
    return ("fulfilled", {"org_id": org_id, "plan": info["plan_id"],
                          "status": info["status"],
                          "subscription_id": sub_id})


def _update_event(event_id, verdict, note):
    db = get_db()
    try:
        db.execute(
            "UPDATE paddle_events SET verdict=?, note=?, processed_at=? "
            "WHERE event_id=?",
            (verdict, note if isinstance(note, str) else json.dumps(note),
             _now(), str(event_id)))
        db.commit()
    finally:
        db.close()


def get_event(event_id):
    """Inspect a recorded webhook event (support/debugging)."""
    init_paddle_tables()
    db = get_db()
    try:
        row = db.execute("SELECT * FROM paddle_events WHERE event_id=?",
                         (str(event_id),)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()
