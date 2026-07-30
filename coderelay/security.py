from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from coderelay.config import SecuritySettings

_PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=2, hash_len=32, salt_len=16)
_API_HASH_PREFIX = "sha256$"
_SESSION_VERSION = 1


class SecretFileError(ValueError):
    pass


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def read_secret(path: Path, *, strict_permissions: bool, max_bytes: int = 16_384) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SecretFileError(f"cannot access secret file {path}: {exc.strerror or exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SecretFileError(f"secret path is not a regular file: {path}")
        if strict_permissions and os.name == "posix" and info.st_mode & 0o077:
            raise SecretFileError(f"secret file must not be accessible by group/others: {path}")
        if info.st_size > max_bytes:
            raise SecretFileError(f"secret file is too large: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = handle.read(max_bytes + 1).strip()
    except SecretFileError:
        raise
    except (OSError, UnicodeError) as exc:
        raise SecretFileError(f"cannot read secret file {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value.encode("utf-8")) > max_bytes:
        raise SecretFileError(f"secret file is too large: {path}")
    if not value:
        raise SecretFileError(f"secret file is empty: {path}")
    return value


def write_secret(path: Path, value: str, *, overwrite: bool = False) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | (os.O_TRUNC if overwrite else os.O_EXCL)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise SecretFileError(f"refusing to overwrite existing secret file: {path}") from None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def generate_api_token() -> str:
    return f"cr_live_{secrets.token_urlsafe(32)}"


def hash_api_token(token: str) -> str:
    if not token.startswith("cr_live_") or len(token) < 40:
        raise ValueError("API token does not have the expected CodeRelay format")
    return _API_HASH_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_api_token(token: str, stored_hashes: Iterable[str]) -> bool:
    if not token or len(token) > 512:
        return False
    candidate = _API_HASH_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched = False
    for stored_hash in stored_hashes:
        matched = hmac.compare_digest(candidate, stored_hash.strip()) or matched
    return matched


def hash_ui_password(password: str) -> str:
    if len(password) < 14:
        raise ValueError("UI password must contain at least 14 characters")
    if len(password) > 1_024:
        raise ValueError("UI password is too long")
    return _PASSWORD_HASHER.hash(password)


def verify_ui_password(password: str, stored_hash: str) -> bool:
    if not password or len(password) > 1_024:
        return False
    try:
        return _PASSWORD_HASHER.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def generate_key_material() -> str:
    return _b64encode(secrets.token_bytes(32))


def decode_key_material(value: str) -> bytes:
    try:
        decoded = _b64decode(value.strip())
    except Exception as exc:
        raise SecretFileError("key material is not valid URL-safe base64") from exc
    if len(decoded) != 32:
        raise SecretFileError("key material must decode to exactly 32 bytes")
    return decoded


@dataclass(frozen=True, slots=True)
class SessionClaims:
    issued_at: int
    expires_at: int
    nonce: str


class SessionSigner:
    def __init__(self, secret: bytes, lifetime_seconds: int) -> None:
        if len(secret) < 32:
            raise ValueError("session signing key must be at least 32 bytes")
        self._secret = secret
        self._lifetime_seconds = lifetime_seconds

    def issue(self, *, now: int | None = None) -> str:
        now = int(time.time() if now is None else now)
        payload = {
            "v": _SESSION_VERSION,
            "iat": now,
            "exp": now + self._lifetime_seconds,
            "nonce": secrets.token_urlsafe(18),
        }
        encoded = _b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signature = _b64encode(hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest())
        return f"{encoded}.{signature}"

    def verify(self, token: str, *, now: int | None = None) -> SessionClaims | None:
        if not token or len(token) > 2_048 or token.count(".") != 1:
            return None
        encoded, signature = token.split(".", 1)
        expected = _b64encode(hmac.new(self._secret, encoded.encode("ascii", "ignore"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            payload = json.loads(_b64decode(encoded))
            issued_at = int(payload["iat"])
            expires_at = int(payload["exp"])
            nonce = str(payload["nonce"])
            version = int(payload["v"])
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return None
        current = int(time.time() if now is None else now)
        if version != _SESSION_VERSION or issued_at > current + 60 or expires_at <= current:
            return None
        if expires_at - issued_at > self._lifetime_seconds + 60 or not (16 <= len(nonce) <= 128):
            return None
        return SessionClaims(issued_at=issued_at, expires_at=expires_at, nonce=nonce)


@dataclass(slots=True)
class SecurityContext:
    api_token_hashes: tuple[str, ...]
    ui_password_hash: str
    session_signer: SessionSigner

    @classmethod
    def from_settings(cls, settings: SecuritySettings) -> SecurityContext:
        strict = settings.strict_secret_permissions
        hashes = tuple(
            read_secret(path, strict_permissions=strict, max_bytes=1_024) for path in settings.api_token_hash_files
        )
        for value in hashes:
            if not value.startswith(_API_HASH_PREFIX) or len(value) != len(_API_HASH_PREFIX) + 64:
                raise SecretFileError("an API token hash file contains an unsupported hash")
            try:
                int(value[len(_API_HASH_PREFIX) :], 16)
            except ValueError as exc:
                raise SecretFileError("an API token hash file contains malformed hex") from exc
        password_hash = read_secret(settings.ui_password_hash_file, strict_permissions=strict, max_bytes=2_048)
        if not password_hash.startswith("$argon2id$"):
            raise SecretFileError("UI password hash must use Argon2id")
        session_value = read_secret(settings.session_secret_file, strict_permissions=strict, max_bytes=1_024)
        signer = SessionSigner(decode_key_material(session_value), settings.session_hours * 3_600)
        return cls(api_token_hashes=hashes, ui_password_hash=password_hash, session_signer=signer)


def principal_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def mask_email(value: str) -> str:
    local, separator, domain = value.partition("@")
    if not separator:
        return "***"
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}***@{domain}"
