"""SQLite-backed attempt limits shared by application workers and sessions."""

import hashlib
import hmac
import time

from flask import current_app
from werkzeug.exceptions import TooManyRequests

from database import get_db


def initialize_auth_limits(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS auth_rate_limits (
            scope TEXT NOT NULL,
            bucket_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (scope, bucket_hash)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS auth_limits_expiry ON auth_rate_limits(expires_at)")
    db.commit()


def limit_attempts(buckets):
    """Count attempts atomically; identities are HMACed, never stored verbatim.

    Each bucket is (scope, identity, allowed_attempts). Counts survive restarts
    and cookie resets. Only the socket peer is used for address-based limits.
    """
    now = int(time.time())
    window = current_app.config["AUTH_RATE_WINDOW_SECONDS"]
    if type(window) is not int or window <= 0:
        raise ValueError("AUTH_RATE_WINDOW_SECONDS must be a positive integer")
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    retry_after = 0
    db = get_db()
    with db:
        db.execute("DELETE FROM auth_rate_limits WHERE expires_at <= ?", (now,))
        for scope, identity, allowed in buckets:
            if type(allowed) is not int or allowed <= 0:
                raise ValueError("Authentication rate limits must be positive integers")
            digest = hmac.new(secret, (scope + "\0" + identity).encode("utf-8"), hashlib.sha256).hexdigest()
            db.execute("""
                INSERT INTO auth_rate_limits (scope, bucket_hash, attempts, expires_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(scope, bucket_hash) DO UPDATE SET
                    attempts = MIN(auth_rate_limits.attempts + 1, ?)
            """, (scope, digest, now + window, allowed + 1))
            record = db.execute(
                "SELECT attempts, expires_at FROM auth_rate_limits WHERE scope=? AND bucket_hash=?",
                (scope, digest),
            ).fetchone()
            if record["attempts"] > allowed:
                retry_after = max(retry_after, record["expires_at"] - now)
                # Once the address bucket is blocked, do not create more
                # username buckets from attacker-supplied names.
                break
    if retry_after:
        raise TooManyRequests(
            description="Too many attempts. Please wait before trying again.", retry_after=retry_after,
        )
