from __future__ import annotations

import os
import stat
import tempfile
import threading
from pathlib import Path

import msal
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from coderelay.security import decode_key_material, read_secret

_MAGIC = b"CRMSAL1\x00"
_NONCE_BYTES = 12
_MAX_CACHE_BYTES = 10 * 1024 * 1024


class TokenCacheError(ValueError):
    pass


class EncryptedMsalCacheStore:
    def __init__(
        self,
        cache_file: Path,
        key_file: Path,
        *,
        source_id: str,
        strict_permissions: bool,
    ) -> None:
        self.cache_file = cache_file
        self._strict_permissions = strict_permissions
        key_value = read_secret(key_file, strict_permissions=strict_permissions, max_bytes=1_024)
        self._cipher = AESGCM(decode_key_material(key_value))
        self._aad = f"coderelay-msal-cache-v1:{source_id}".encode()
        self._lock = threading.RLock()

    def create_cache(self) -> msal.SerializableTokenCache:
        cache = msal.SerializableTokenCache()
        state = self.load()
        if state:
            try:
                cache.deserialize(state)
            except Exception as exc:
                raise TokenCacheError("MSAL token cache contains invalid serialized data") from exc
        return cache

    def load(self) -> str | None:
        with self._lock:
            if not self.cache_file.exists():
                return None
            descriptor = -1
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(self.cache_file, flags)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise TokenCacheError("MSAL token cache is not a regular file")
                if self._strict_permissions and os.name == "posix" and info.st_mode & 0o077:
                    raise TokenCacheError("MSAL token cache must have mode 0600")
                if info.st_size > _MAX_CACHE_BYTES:
                    raise TokenCacheError("MSAL token cache is unexpectedly large")
                with os.fdopen(descriptor, "rb") as handle:
                    descriptor = -1
                    payload = handle.read(_MAX_CACHE_BYTES + 1)
            except TokenCacheError:
                raise
            except OSError as exc:
                raise TokenCacheError("cannot read MSAL token cache") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            if len(payload) > _MAX_CACHE_BYTES:
                raise TokenCacheError("MSAL token cache is unexpectedly large")
            if len(payload) < len(_MAGIC) + _NONCE_BYTES + 16 or not payload.startswith(_MAGIC):
                raise TokenCacheError("MSAL token cache has an unsupported format")
            nonce_start = len(_MAGIC)
            nonce = payload[nonce_start : nonce_start + _NONCE_BYTES]
            ciphertext = payload[nonce_start + _NONCE_BYTES :]
            try:
                plaintext = self._cipher.decrypt(nonce, ciphertext, self._aad)
                return plaintext.decode("utf-8")
            except (InvalidTag, UnicodeDecodeError) as exc:
                raise TokenCacheError("MSAL token cache authentication failed") from exc

    def save_if_changed(self, cache: msal.SerializableTokenCache) -> None:
        if not cache.has_state_changed:
            return
        state = cache.serialize()
        try:
            self.save(state)
        except Exception:
            cache.has_state_changed = True
            raise

    def save(self, state: str) -> None:
        encoded = state.encode("utf-8")
        if len(encoded) > _MAX_CACHE_BYTES:
            raise TokenCacheError("refusing to save an unexpectedly large MSAL token cache")
        nonce = os.urandom(_NONCE_BYTES)
        payload = _MAGIC + nonce + self._cipher.encrypt(nonce, encoded, self._aad)
        with self._lock:
            self._atomic_write(payload)

    def _atomic_write(self, payload: bytes) -> None:
        parent = self.cache_file.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(parent, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.cache_file.name}.", dir=parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.cache_file)
            os.chmod(self.cache_file, 0o600)
            if os.name == "posix":
                directory_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
