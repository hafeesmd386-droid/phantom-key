"""Integrity verification for .phkey files."""
import hashlib
from pathlib import Path

from .encryption import AuthenticationError, InvalidFormatError, decrypt_bytes, parse_header


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_with_password(path, password: str) -> tuple[bool, str]:
    """Full check: authenticated decryption (detects tampering AND wrong password)."""
    try:
        decrypt_bytes(Path(path).read_bytes(), password)
        return True, "Integrity verified: data is authentic and unmodified."
    except InvalidFormatError as e:
        return False, str(e)
    except AuthenticationError:
        return False, ("Verification FAILED: wrong password, or the file was modified/corrupted. "
                       "(Authenticated encryption cannot tell these two cases apart.)")


def verify_against_record(path, recorded_hash: str) -> tuple[bool, str]:
    """Password-free check: compare SHA-256 with the hash recorded when it was protected."""
    try:
        parse_header(Path(path).read_bytes())
    except InvalidFormatError as e:
        return False, str(e)
    if sha256_file(path) == recorded_hash:
        return True, "File matches the fingerprint recorded at protection time."
    return False, "Fingerprint MISMATCH: the protected file was modified or corrupted."
