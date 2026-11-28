"""Password hashing and verification."""
import base64
import hashlib
import secrets

from .config import PBKDF2_ITERATIONS, PBKDF2_PREFIX


def hash_password(plain: str) -> str:
    """Return a self-describing hash string: pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>."""
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "{}${}${}${}".format(
        PBKDF2_PREFIX,
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(h).decode("ascii"),
    )


def verify_password(plain: str, expected_hash: str) -> tuple[bool, bool]:
    """Return (ok, needs_rehash). Supports legacy unsalted SHA-256 for migration."""
    if not expected_hash:
        return False, False
    if expected_hash.startswith(PBKDF2_PREFIX + "$"):
        try:
            _, iters_s, salt_b64, hash_b64 = expected_hash.split("$", 3)
            iters = int(iters_s)
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
        except Exception:
            return False, False
        h = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iters)
        ok = secrets.compare_digest(h, expected)
        return ok, ok and iters < PBKDF2_ITERATIONS
    # Legacy unsalted SHA-256 — accept once, then rehash
    legacy = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    ok = secrets.compare_digest(legacy, expected_hash)
    return ok, ok