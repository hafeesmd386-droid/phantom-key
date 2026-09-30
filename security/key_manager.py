"""Password-based key derivation (PBKDF2-HMAC-SHA256) and salt generation."""
import base64
import hashlib
import secrets

SALT_LEN = 16
DEFAULT_ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256


def generate_salt() -> bytes:
    """Cryptographically secure random salt."""
    return secrets.token_bytes(SALT_LEN)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive a 32-byte key from password+salt, returned in Fernet's base64 format.

    The password is never used directly as a key.
    """
    raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(raw)
