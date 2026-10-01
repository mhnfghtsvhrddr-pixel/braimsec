"""HMAC-SHA256 signing for outgoing alert webhooks.

Scheduled/VCS alert webhooks (``scheduler.send_alert``) are POSTed to
customer-owned URLs. Without a signature, a receiver cannot tell a
genuine BraimSec alert from a forged one, so every org gets a
**signing secret**: generated server-side, Fernet-encrypted at rest
(same scheme as the other alert-channel secrets), and used to sign each
outgoing payload Stripe-style::

    X-BraimSec-Signature: t=<unix_ts>,v1=<hex_hmac_sha256>
    X-BraimSec-Timestamp: <unix_ts>

The HMAC covers the canonical string ``"<ts>.<raw_json_body>"``, binding
both the body and its freshness; receivers should reject payloads whose
timestamp is older than 5 minutes (replay protection).

The secret is shown **once**, at rotation time (``POST
/api/webhook-signing/rotate``), and is never returned again — ``GET
/api/webhook-signing`` only reports whether one is configured.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

SIGNATURE_HEADER = "X-BraimSec-Signature"
TIMESTAMP_HEADER = "X-BraimSec-Timestamp"
REPLAY_TOLERANCE_S = 300
SECRET_PREFIX = "whsec_"


def generate_signing_secret() -> tuple[bytes, str]:
    """Return ``(raw_secret, display_secret)``; the display form is shown
    to the org owner exactly once."""
    raw = secrets.token_bytes(32)
    display = SECRET_PREFIX + base64.urlsafe_b64encode(raw).rstrip(
        b"=").decode("ascii")
    return raw, display


def parse_display_secret(display: str) -> bytes:
    """Recover the raw secret bytes from its ``whsec_...`` display form."""
    if not display.startswith(SECRET_PREFIX):
        raise ValueError("bad signing-secret format")
    b64 = display[len(SECRET_PREFIX):]
    return base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))


def sign_payload(secret: bytes, body: bytes,
                 ts: int | None = None) -> tuple[str, str]:
    """Return ``(ts_str, hex_signature)`` for ``body``.

    The signed message is ``"<ts>.<body>"`` so the signature binds the
    payload to its timestamp.
    """
    ts = int(time.time()) if ts is None else int(ts)
    msg = f"{ts}.".encode("ascii") + body
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return str(ts), sig


def signing_headers(secret: bytes, body: bytes) -> dict:
    """Headers to attach to an outgoing alert webhook POST."""
    ts, sig = sign_payload(secret, body)
    return {SIGNATURE_HEADER: f"t={ts},v1={sig}",
            TIMESTAMP_HEADER: ts}


def verify_signature(secret: bytes, body: bytes, ts: str | int,
                     sig: str, tolerance_s: int = REPLAY_TOLERANCE_S,
                     now: int | None = None) -> bool:
    """Verify a received signature (constant-time compare) and reject
    replays older than ``tolerance_s`` seconds."""
    try:
        ts_int = int(ts)
    except (TypeError, ValueError):
        return False
    now = int(time.time()) if now is None else int(now)
    if abs(now - ts_int) > tolerance_s:
        return False
    expected = sign_payload(secret, body, ts_int)[1]
    return hmac.compare_digest(expected, sig)


def get_org_signing_secret(db, org_id: str) -> bytes | None:
    """Return the org's raw signing secret, or None if not configured.

    A corrupt row is treated as unconfigured (logged, never fatal —
    alert delivery is best-effort).
    """
    import logging
    row = db.execute(
        "SELECT secret_enc FROM webhook_signing_secrets WHERE org_id=?",
        (org_id,)).fetchone()
    if not row:
        return None
    try:
        from vcs import decrypt_secret
        return parse_display_secret(decrypt_secret(row["secret_enc"]))
    except Exception:  # noqa: BLE001 - best effort by design
        logging.getLogger(__name__).warning(
            "webhook signing secret for org %s is corrupt; sending unsigned",
            org_id)
        return None


def rotate_org_signing_secret(db, org_id: str) -> str:
    """Generate, persist (encrypted) and return the new display secret.

    The caller must show the returned value to the org owner exactly
    once — it is never retrievable again.
    """
    from datetime import datetime, timezone
    from vcs import encrypt_secret
    raw, display = generate_signing_secret()
    db.execute(
        "INSERT INTO webhook_signing_secrets (org_id, secret_enc, created_at)"
        " VALUES (?,?,?)"
        " ON CONFLICT(org_id) DO UPDATE SET secret_enc=excluded.secret_enc,"
        " created_at=excluded.created_at",
        (org_id, encrypt_secret(display),
         datetime.now(timezone.utc).isoformat()))
    db.commit()
    return display
