import hashlib
import secrets


def new_api_key(prefix: str) -> tuple[str, str, str]:
    """Return (key, display_prefix, sha256_hash). Only the hash is ever stored."""
    key = f"{prefix}_{secrets.token_urlsafe(32)}"
    return key, key[: len(prefix) + 5], hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()
