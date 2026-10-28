"""HMAC signatures so receivers can prove a payload came from us (Stripe-style)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

SIGNATURE_VERSION = "v1"
TOLERANCE_SECONDS = 300


def canonical_body(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON: key order and spacing must not change the signature."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign(secret: str, body: bytes, timestamp: int) -> str:
    message = f"{timestamp}.".encode() + body
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"t={timestamp},{SIGNATURE_VERSION}={digest}"


def verify(secret: str, body: bytes, header: str, *, tolerance: int = TOLERANCE_SECONDS, now: int | None = None) -> bool:
    try:
        parts = dict(part.split("=", 1) for part in header.split(","))
        timestamp = int(parts["t"])
        provided = parts[SIGNATURE_VERSION]
    except (ValueError, KeyError):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance:
        return False  # replay protection
    expected = sign(secret, body, timestamp).split(f"{SIGNATURE_VERSION}=", 1)[1]
    return hmac.compare_digest(expected, provided)
