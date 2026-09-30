"""File protection using Fernet (AES-128-CBC + HMAC-SHA256, authenticated encryption).

.phkey file layout:
    MAGIC (6 bytes) | iterations (4 bytes, big-endian) | salt (16 bytes) | Fernet token

Encrypted payload layout:
    name length (2 bytes) | original file name (UTF-8) | file bytes
"""
import os
import struct
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .key_manager import DEFAULT_ITERATIONS, SALT_LEN, derive_key, generate_salt

MAGIC = b"PHKEY\x01"
HEADER_LEN = len(MAGIC) + 4 + SALT_LEN
EXTENSION = ".phkey"


class AuthenticationError(Exception):
    """Wrong password OR the protected data was modified/corrupted."""


class InvalidFormatError(Exception):
    """File is not a valid Phantom Key file."""


def parse_header(blob: bytes):
    if len(blob) <= HEADER_LEN or not blob.startswith(MAGIC):
        raise InvalidFormatError("Not a valid .phkey file (bad header).")
    iterations = struct.unpack(">I", blob[len(MAGIC):len(MAGIC) + 4])[0]
    salt = blob[len(MAGIC) + 4:HEADER_LEN]
    return iterations, salt, blob[HEADER_LEN:]


def _unique_path(path: Path) -> Path:
    """Never overwrite existing files: add ' (1)', ' (2)' ... if needed."""
    if not path.exists():
        return path
    n = 1
    while True:
        candidate = path.with_name(f"{path.stem} ({n}){path.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def decrypt_bytes(blob: bytes, password: str) -> tuple[str, bytes]:
    iterations, salt, token = parse_header(blob)
    key = derive_key(password, salt, iterations)
    try:
        payload = Fernet(key).decrypt(token)
    except InvalidToken:
        raise AuthenticationError("Authentication failed: wrong password or file modified.")
    name_len = struct.unpack(">H", payload[:2])[0]
    name = payload[2:2 + name_len].decode("utf-8")
    return name, payload[2 + name_len:]


def protect_file(src, password: str, out_dir=None, iterations: int = DEFAULT_ITERATIONS) -> Path:
    """Encrypt `src` into `<name>.phkey`. The original file is left untouched."""
    src = Path(src)
    if not password:
        raise ValueError("Password must not be empty.")
    if not src.is_file():
        raise FileNotFoundError(f"File not found: {src}")
    name = src.name.encode("utf-8")
    payload = struct.pack(">H", len(name)) + name + src.read_bytes()
    salt = generate_salt()
    key = derive_key(password, salt, iterations)
    token = Fernet(key).encrypt(payload)
    blob = MAGIC + struct.pack(">I", iterations) + salt + token
    out_path = _unique_path(Path(out_dir or src.parent) / (src.name + EXTENSION))
    _write_atomic(out_path, blob)
    return out_path


def restore_file(src, password: str, out_dir=None) -> Path:
    """Decrypt a .phkey file and write the original file (never overwrites)."""
    src = Path(src)
    if not password:
        raise ValueError("Password must not be empty.")
    name, data = decrypt_bytes(src.read_bytes(), password)
    safe_name = Path(name).name  # strip any path components -> no path traversal
    out_path = _unique_path(Path(out_dir or src.parent) / safe_name)
    _write_atomic(out_path, data)
    return out_path
