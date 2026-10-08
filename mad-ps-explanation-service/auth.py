"""
Authentication & Multi-Tenant Identity Module for MAD-PS Ecosystem.
Supports password hashing (bcrypt with PBKDF2 fallback), JWT signing & validation,
and secure API key generation/hashing (mk_live_...).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
import os
import secrets
from typing import Any, Dict, Optional
import jwt

logger = logging.getLogger("mad_ps.auth")

JWT_SECRET_KEY = os.environ.get("MAD_PS_JWT_SECRET", "madps_production_secret_key_sec1_inspired_mesh_2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("MAD_PS_JWT_EXPIRY_HOURS", "72"))

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


def hash_password(password: str) -> str:
    """Hash password using bcrypt or robust PBKDF2-SHA256."""
    if HAS_BCRYPT:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2:sha256:100000${salt}${dk.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hashed password."""
    try:
        if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
            if HAS_BCRYPT:
                return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
            return False
        if hashed_password.startswith("pbkdf2:sha256:"):
            parts = hashed_password.split("$")
            if len(parts) == 3:
                salt = parts[1]
                expected_hash = parts[2]
                dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100_000)
                return hmac.compare_digest(dk.hex(), expected_hash)
    except Exception as exc:
        logger.error("Password verification error: %s", exc)
    return False


def generate_api_key() -> str:
    """Generate high-entropy live production API key format: mk_live_<48 hex chars>."""
    return f"mk_live_{secrets.token_hex(24)}"


def hash_api_key(api_key: str) -> str:
    """Produce deterministic SHA-256 hash for secure storage and constant-time lookup."""
    return hashlib.sha256(api_key.strip().encode("utf-8")).hexdigest()


def create_access_token(data: Dict[str, Any], expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Create signed JWT access token for session state."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire, "iat": datetime.datetime.now(datetime.timezone.utc)})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate signed JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError as exc:
        logger.debug("Invalid JWT token: %s", exc)
        return None
