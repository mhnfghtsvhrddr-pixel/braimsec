"""Customer accounts: email + password login for the BraimSec dashboard.

API keys remain the machine credential. This module adds the human
credential: a customer registers/logs in with email + password and
receives a session token (``bss_`` prefix) that the api_key_gate accepts
everywhere an API key works, carrying the user's org + role. The
dashboard stores it in the same localStorage slot and sends it in the
same X-API-Key header, so no dashboard request code changes.

Security properties:
- passwords: scrypt (stdlib) with a per-user 16-byte salt; the raw
  password is never logged or stored. Verification is constant-time.
- session tokens: 32 random bytes, stored as SHA-256 hashes, 7-day
  expiry, revocable. The raw token is shown once at login/register.
- login failures say "Invalid email or password" (no account oracle).
- register/login are public and rate-limited (10/min) in main.py.

Tables: users, user_sessions (created by init_auth_tables()).
"""
import hashlib
import hmac
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import get_db  # noqa: E402

SESSION_PREFIX = "bss_"
SESSION_DAYS = 7
RESET_PREFIX = "bsr_"
RESET_HOURS = 1
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128

# scrypt work factors: ~50ms per verification on commodity hardware.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64


def _now():
    return datetime.now(timezone.utc).isoformat()


def init_auth_tables():
    db = get_db()
    try:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id         TEXT PRIMARY KEY,
                   org_id     TEXT NOT NULL,
                   email      TEXT NOT NULL,
                   password_hash TEXT NOT NULL,
                   role       TEXT NOT NULL DEFAULT 'owner',
                   created_at TEXT NOT NULL
               )""")
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
            "ON users (email)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS user_sessions (
                   token_hash  TEXT PRIMARY KEY,
                   user_id     TEXT NOT NULL,
                   org_id      TEXT NOT NULL,
                   created_at  TEXT NOT NULL,
                   expires_at  TEXT NOT NULL,
                   last_seen_at TEXT,
                   revoked     INTEGER NOT NULL DEFAULT 0
               )""")
        db.execute(
            """CREATE TABLE IF NOT EXISTS password_resets (
                   token_hash  TEXT PRIMARY KEY,
                   user_id     TEXT NOT NULL,
                   org_id      TEXT NOT NULL,
                   created_at  TEXT NOT NULL,
                   expires_at  TEXT NOT NULL,
                   used        INTEGER NOT NULL DEFAULT 0
               )""")
        db.commit()
    finally:
        db.close()


def normalize_email(email):
    return str(email or "").strip().lower()


def valid_email(email):
    e = normalize_email(email)
    return "@" in e and 3 <= len(e) <= 254 and "." in e.split("@")[-1]


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N,
                        r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return (f"scrypt$n={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}"
            f"${salt.hex()}${dk.hex()}")


def verify_password(password: str, stored: str) -> bool:
    try:
        _alg, params, salt_hex, dk_hex = stored.split("$")
        kv = dict(p.split("=") for p in params.split(","))
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.scrypt(password.encode(), salt=salt,
                            n=int(kv["n"]), r=int(kv["r"]),
                            p=int(kv["p"]), dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# Precomputed once at import so failed logins for unknown accounts cost
# the same scrypt work as real verifications (no timing oracle).
_DUMMY_HASH = hash_password("dummy-password-for-timing")


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def find_user_by_email(email):
    init_auth_tables()
    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE email=?",
                         (normalize_email(email),)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def create_user(org_id, email, password, role="owner"):
    """Insert a user row. Returns the user dict. Raises ValueError on
    bad input, KeyError if the email is taken."""
    email_n = normalize_email(email)
    if not valid_email(email_n):
        raise ValueError("A valid email is required")
    if not isinstance(password, str) or not (
            MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise ValueError(
            f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} chars")
    if role not in ("owner", "admin", "member", "viewer"):
        raise ValueError(f"Unknown role: {role}")
    if find_user_by_email(email_n):
        raise KeyError("Email already registered")
    import sqlite3
    import uuid
    user_id = "user_" + uuid.uuid4().hex[:12]
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (id, org_id, email, password_hash, role,"
            " created_at) VALUES (?,?,?,?,?,?)",
            (user_id, org_id, email_n, hash_password(password), role,
             _now()))
        db.commit()
    except sqlite3.IntegrityError:
        # Lost a registration race: the email is taken after all.
        raise KeyError("Email already registered")
    finally:
        db.close()
    return {"id": user_id, "org_id": org_id, "email": email_n, "role": role}


def create_session(user_id, org_id):
    """Mint a session token. Returns the RAW token (shown once)."""
    init_auth_tables()
    raw = SESSION_PREFIX + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db = get_db()
    try:
        db.execute(
            """INSERT INTO user_sessions
               (token_hash, user_id, org_id, created_at, expires_at,
                last_seen_at, revoked)
               VALUES (?,?,?,?,?,?,0)""",
            (_token_hash(raw), user_id, org_id, now.isoformat(),
             (now + timedelta(days=SESSION_DAYS)).isoformat(),
             now.isoformat()))
        db.commit()
    finally:
        db.close()
    return raw


def verify_session(raw):
    """Validate a presented session token.

    Returns {org_id, plan, key_id, key_prefix, role, project_id, user_id,
    email} — the same shape as billing.verify_key — or None.
    """
    if not raw or not raw.startswith(SESSION_PREFIX):
        return None
    init_auth_tables()
    db = get_db()
    try:
        row = db.execute(
            """SELECT s.token_hash, s.user_id, s.org_id, s.expires_at,
                      u.email, u.role, o.plan
               FROM user_sessions s
               JOIN users u ON u.id = s.user_id
               JOIN organizations o ON o.id = s.org_id
               WHERE s.token_hash=? AND s.revoked=0
                     AND o.status='active'""",
            (_token_hash(raw),)).fetchone()
        if not row:
            return None
        if row["expires_at"] <= _now():
            return None
        db.execute("UPDATE user_sessions SET last_seen_at=? "
                   "WHERE token_hash=?", (_now(), row["token_hash"]))
        db.commit()
        return {"org_id": row["org_id"], "plan": row["plan"],
                "key_id": row["token_hash"][:16],
                "key_prefix": raw[:8], "role": row["role"] or "member",
                "project_id": None, "user_id": row["user_id"],
                "email": row["email"]}
    finally:
        db.close()


def revoke_session(raw):
    """Revoke one session token. Returns True when something was revoked."""
    if not raw or not raw.startswith(SESSION_PREFIX):
        return False
    init_auth_tables()
    db = get_db()
    try:
        cur = db.execute("UPDATE user_sessions SET revoked=1 "
                         "WHERE token_hash=? AND revoked=0",
                         (_token_hash(raw),))
        db.commit()
        return cur.rowcount > 0
    finally:
        db.close()


def register_account(email, password):
    """Register a new customer: org + owner user + session.

    Returns (user_dict, raw_session_token). Raises ValueError / KeyError.
    """
    from billing import create_org, ensure_subscription  # lazy: no cycles
    from audit import log_event
    email_n = normalize_email(email)
    if find_user_by_email(email_n):
        raise KeyError("Email already registered")
    org_id = create_org(email_n)
    ensure_subscription(org_id)
    user = create_user(org_id, email_n, password, role="owner")
    token = create_session(user["id"], org_id)
    log_event(org_id, "user:" + email_n, "user.registered", "user",
              user["id"], {"email": email_n})
    return user, token


def login_account(email, password):
    """Verify credentials and mint a session.

    Returns (user_dict, raw_session_token). Raises KeyError on any
    failure (generic message at the HTTP layer: no account oracle).
    A dummy scrypt verification runs when the account is missing so
    failures take the same time either way (no timing oracle).
    """
    from audit import log_event
    user = find_user_by_email(email)
    if user is None:
        # Same cost as a real check: burn one scrypt.
        verify_password("dummy-password-for-timing", _DUMMY_HASH)
        raise KeyError("bad credentials")
    if not isinstance(password, str) or not verify_password(
            password, user["password_hash"]):
        raise KeyError("bad credentials")
    token = create_session(user["id"], user["org_id"])
    log_event(user["org_id"], "user:" + user["email"], "user.login",
              "user", user["id"], {})
    return ({"id": user["id"], "org_id": user["org_id"],
             "email": user["email"], "role": user["role"]}, token)


def _create_reset_token(user_id, org_id):
    """Mint a raw password-reset token (single active token per user).

    Returns the RAW token (emailed once, shown never)."""
    init_auth_tables()
    raw = RESET_PREFIX + secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    db = get_db()
    try:
        db.execute("UPDATE password_resets SET used=1 "
                   "WHERE user_id=? AND used=0", (user_id,))
        db.execute(
            """INSERT INTO password_resets
               (token_hash, user_id, org_id, created_at, expires_at, used)
               VALUES (?,?,?,?,?,0)""",
            (_token_hash(raw), user_id, org_id, now.isoformat(),
             (now + timedelta(hours=RESET_HOURS)).isoformat()))
        db.commit()
    finally:
        db.close()
    return raw


def request_password_reset(email):
    """Email a password-reset link. Always silent (no account oracle):
    returns True only when a reset email was actually dispatched.

    Without SMTP configured the token is still minted (single-use,
    1-hour) but undeliverable — the operator resends it manually.
    """
    from audit import log_event
    from email_alerts import send_email  # lazy: avoids import cycles
    user = find_user_by_email(email)
    if not user:
        return False
    raw = _create_reset_token(user["id"], user["org_id"])
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    link = f"{base}/?reset_token={raw}" if base else ""
    lines = [
        "Someone requested a password reset for your BraimSec account.",
        "This link is valid for 1 hour and can be used once:",
        "",
        link or f"Reset token (paste it in the dashboard): {raw}",
        "",
        "If you did not request this, ignore this email — your password "
        "is unchanged.",
    ]
    text = "\n".join(lines)
    html = "<p>Someone requested a password reset for your BraimSec " \
           "account.</p><p>This link is valid for 1 hour and can be used " \
           "once:</p><p>" + (f'<a href="{link}">{link}</a>' if link
                             else f"<code>{raw}</code>") + "</p><p>If you " \
           "did not request this, ignore this email — your password is " \
           "unchanged.</p>"
    ok, _, _ = send_email(user["email"], "BraimSec — password reset",
                          text, html)
    log_event(user["org_id"], "user:" + user["email"],
              "user.password_reset_requested", "user", user["id"], {})
    return ok


def reset_password(token, new_password):
    """Consume a reset token and set the new password.

    Raises KeyError on a bad/expired/used token, ValueError on a bad new
    password. All of the user's sessions are revoked: a password change
    must kill every live session.
    """
    from audit import log_event
    if not isinstance(token, str) or not token.startswith(RESET_PREFIX):
        raise KeyError("bad token")
    if not isinstance(new_password, str) or not (
            MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):
        raise ValueError(
            f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} chars")
    init_auth_tables()
    db = get_db()
    try:
        row = db.execute(
            "SELECT user_id, org_id, expires_at FROM password_resets "
            "WHERE token_hash=? AND used=0",
            (_token_hash(token),)).fetchone()
        if not row or row["expires_at"] <= _now():
            raise KeyError("bad token")
        db.execute("UPDATE users SET password_hash=? WHERE id=?",
                   (hash_password(new_password), row["user_id"]))
        db.execute("UPDATE password_resets SET used=1 WHERE token_hash=?",
                   (_token_hash(token),))
        db.execute("UPDATE user_sessions SET revoked=1 WHERE user_id=?",
                   (row["user_id"],))
        db.commit()
        user_id, org_id = row["user_id"], row["org_id"]
    finally:
        db.close()
    user = find_user_by_email_row(user_id)
    log_event(org_id, "user:" + (user["email"] if user else "?"),
              "user.password_reset", "user", user_id, {})
    return True


def find_user_by_email_row(user_id):
    init_auth_tables()
    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE id=?",
                         (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()
