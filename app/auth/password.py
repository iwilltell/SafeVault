
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)

password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2
)


def hash_password(password: str) -> str:
    """Generate a secure Argon2 password hash."""

    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against its stored hash."""

    try:
        return password_hasher.verify(password_hash, password)

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Check whether the password hash needs updating."""

    try:
        return password_hasher.check_needs_rehash(password_hash)

    except (VerificationError, InvalidHashError):
        return True
