from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from coderelay.config import SecuritySettings

_API_HASH_PREFIX = "sha256$"


class SecretFileError(ValueError):
    pass


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


@dataclass(slots=True)
class SecurityContext:
    api_token_hashes: tuple[str, ...]

    @classmethod
    def from_settings(cls, settings: SecuritySettings) -> SecurityContext:
        hashes = tuple(
            read_secret(path, strict_permissions=settings.strict_secret_permissions, max_bytes=1_024)
            for path in settings.api_token_hash_files
        )
        for value in hashes:
            if not value.startswith(_API_HASH_PREFIX) or len(value) != len(_API_HASH_PREFIX) + 64:
                raise SecretFileError("an API token hash file contains an unsupported hash")
            try:
                int(value[len(_API_HASH_PREFIX) :], 16)
            except ValueError as exc:
                raise SecretFileError("an API token hash file contains malformed hex") from exc
        return cls(api_token_hashes=hashes)


def principal_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
