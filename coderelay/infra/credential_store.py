from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from coderelay.security import decode_key_material, read_secret

_MAGIC = b"CRCRED1\x00"
_NONCE_BYTES = 12
_MAX_FILE_BYTES = 128 * 1024
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class CredentialStoreError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OutlookCredential:
    email: str
    client_id: str
    refresh_token: str

    def with_refresh_token(self, refresh_token: str) -> OutlookCredential:
        return replace(self, refresh_token=_validate_refresh_token(refresh_token))


def parse_four_part_credential(value: str) -> OutlookCredential:
    parts = value.rstrip("\r\n").split("----", 3)
    if len(parts) != 4:
        raise CredentialStoreError("Outlook credential must use email----password----client_id----refresh_token format")
    email, password, client_id, refresh_token = (part.strip() for part in parts)
    if not password:
        raise CredentialStoreError("Outlook credential password field is empty")
    # The password is intentionally validated only for presence and then discarded.
    password = ""
    return OutlookCredential(
        email=_validate_email(email),
        client_id=_validate_client_id(client_id),
        refresh_token=_validate_refresh_token(refresh_token),
    )


class EncryptedOutlookCredentialStore:
    def __init__(
        self,
        credential_file: Path,
        key_file: Path,
        *,
        source_id: str,
        strict_permissions: bool,
    ) -> None:
        self.credential_file = credential_file
        self._strict_permissions = strict_permissions
        key_value = read_secret(key_file, strict_permissions=strict_permissions, max_bytes=1_024)
        self._cipher = AESGCM(decode_key_material(key_value))
        self._aad = f"coderelay-outlook-credential-v1:{source_id}".encode()
        self._lock = threading.RLock()

    def load(self) -> OutlookCredential:
        with self._lock:
            payload = self._read_payload()
            if len(payload) < len(_MAGIC) + _NONCE_BYTES + 16 or not payload.startswith(_MAGIC):
                raise CredentialStoreError("Outlook credential file has an unsupported format")
            nonce_start = len(_MAGIC)
            nonce = payload[nonce_start : nonce_start + _NONCE_BYTES]
            ciphertext = payload[nonce_start + _NONCE_BYTES :]
            try:
                plaintext = self._cipher.decrypt(nonce, ciphertext, self._aad)
                value = json.loads(plaintext)
            except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CredentialStoreError("Outlook credential authentication failed") from exc
            if not isinstance(value, dict) or value.get("version") != 1:
                raise CredentialStoreError("Outlook credential payload has an unsupported schema")
            return OutlookCredential(
                email=_validate_email(value.get("email")),
                client_id=_validate_client_id(value.get("client_id")),
                refresh_token=_validate_refresh_token(value.get("refresh_token")),
            )

    def save(self, credential: OutlookCredential, *, overwrite: bool = False) -> None:
        credential = OutlookCredential(
            email=_validate_email(credential.email),
            client_id=_validate_client_id(credential.client_id),
            refresh_token=_validate_refresh_token(credential.refresh_token),
        )
        encoded = json.dumps(
            {
                "version": 1,
                "email": credential.email,
                "client_id": credential.client_id,
                "refresh_token": credential.refresh_token,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        if len(encoded) > _MAX_FILE_BYTES:
            raise CredentialStoreError("Outlook credential payload is unexpectedly large")
        nonce = os.urandom(_NONCE_BYTES)
        payload = _MAGIC + nonce + self._cipher.encrypt(nonce, encoded, self._aad)
        with self._lock:
            if self.credential_file.exists() and not overwrite:
                raise CredentialStoreError(
                    f"refusing to overwrite existing Outlook credential file: {self.credential_file}"
                )
            self._atomic_write(payload)

    def _read_payload(self) -> bytes:
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.credential_file, flags)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise CredentialStoreError("Outlook credential path is not a regular file")
            if self._strict_permissions and os.name == "posix" and info.st_mode & 0o077:
                raise CredentialStoreError("Outlook credential file must have mode 0600")
            if info.st_size > _MAX_FILE_BYTES:
                raise CredentialStoreError("Outlook credential file is unexpectedly large")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                payload = handle.read(_MAX_FILE_BYTES + 1)
        except CredentialStoreError:
            raise
        except OSError as exc:
            raise CredentialStoreError(
                "cannot read Outlook credential file; run 'coderelay outlook-import' first"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(payload) > _MAX_FILE_BYTES:
            raise CredentialStoreError("Outlook credential file is unexpectedly large")
        return payload

    def _atomic_write(self, payload: bytes) -> None:
        parent = self.credential_file.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(parent, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.credential_file.name}.", dir=parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.credential_file)
            os.chmod(self.credential_file, 0o600)
            if os.name == "posix":
                directory_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise


def _validate_email(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialStoreError("Outlook credential email must be a string")
    normalized = value.strip().casefold()
    if len(normalized) > 320 or not _EMAIL_RE.fullmatch(normalized):
        raise CredentialStoreError("Outlook credential email is invalid")
    return normalized


def _validate_client_id(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialStoreError("Outlook credential client_id must be a string")
    try:
        return str(uuid.UUID(value.strip()))
    except ValueError as exc:
        raise CredentialStoreError("Outlook credential client_id is invalid") from exc


def _validate_refresh_token(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialStoreError("Outlook refresh token must be a string")
    normalized = value.strip()
    if not 100 <= len(normalized) <= 65_536 or any(character.isspace() for character in normalized):
        raise CredentialStoreError("Outlook refresh token has an invalid shape")
    return normalized
