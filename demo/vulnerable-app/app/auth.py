import hashlib


def hash_password(password: str) -> str:
    # VULNERABLE: unsalted MD5 is not a password hash.
    return hashlib.md5(password.encode()).hexdigest()
