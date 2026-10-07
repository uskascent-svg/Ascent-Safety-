from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()
# Used to equalise timing when the email does not exist.
_DUMMY_HASH = _hasher.hash("ascent-safety-dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if password_hash is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except (VerificationError, InvalidHashError):
            pass
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False
