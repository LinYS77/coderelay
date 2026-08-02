from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ConfigError(ValueError):
    """Raised when the service configuration cannot be loaded safely."""


def _validate_re2_subset(pattern: str) -> None:
    """Reject Python regexp constructs that Go's RE2 engine cannot compile."""
    unsupported_groups = ("(?=", "(?!", "(?<=", "(?<!", "(?P=", "(?>", "(?#", "(?(")
    escaped = False
    in_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if escaped:
            if character in "123456789" or character in {"k", "g"}:
                raise ValueError("extractor patterns must use the common RE2 subset")
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if character == "[":
            in_class = True
            index += 1
            continue
        if character == "]" and in_class:
            in_class = False
            index += 1
            continue
        if not in_class:
            if any(pattern.startswith(prefix, index) for prefix in unsupported_groups):
                raise ValueError("extractor patterns must use the common RE2 subset")
            if character in "*+?" and index + 1 < len(pattern) and pattern[index + 1] == "+":
                raise ValueError("extractor patterns must use the common RE2 subset")
            if character == "}" and index + 1 < len(pattern) and pattern[index + 1] == "+":
                raise ValueError("extractor patterns must use the common RE2 subset")
        index += 1


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = Field(default=8787, ge=1, le=65535)
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    cors_origins: list[str] = Field(default_factory=list)
    forwarded_allow_ips: str = "127.0.0.1"
    access_log: bool = False
    log_level: Literal["debug", "info", "warning", "error", "critical"] = "info"
    max_wait_seconds: int = Field(default=30, ge=0, le=60)
    http_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    http_read_timeout_seconds: float = Field(default=20.0, gt=0, le=60)
    http_max_connections: int = Field(default=20, ge=1, le=100)
    max_concurrent_code_requests: int = Field(default=10, ge=1, le=100)

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("allowed_hosts must contain at least one host")
        if any(not value.strip() or value == "*" for value in values):
            raise ValueError("allowed_hosts cannot be blank or '*'")
        return list(dict.fromkeys(value.strip() for value in values))

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            parsed = urlparse(value)
            if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.path not in {"", "/"}:
                raise ValueError(f"invalid CORS origin: {value!r}")
            if value == "*":
                raise ValueError("wildcard CORS origins are not allowed")
            normalized.append(value.rstrip("/"))
        return list(dict.fromkeys(normalized))


class SecuritySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_token_hash_files: list[Path] = Field(min_length=1)
    strict_secret_permissions: bool = True
    api_rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)


class ExtractorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    senders: list[str] = Field(default_factory=list, max_length=100)
    sender_domains: list[str] = Field(default_factory=list, max_length=100)
    subject_keywords: list[str] = Field(default_factory=list, max_length=100)
    patterns: list[str] = Field(default_factory=list, max_length=20)
    max_age_seconds: int = Field(default=600, ge=30, le=86_400)
    allow_generic_fallback: bool = True
    generic_requires_keyword: bool = True
    max_text_chars: int = Field(default=100_000, ge=1_000, le=1_000_000)

    @field_validator("senders")
    @classmethod
    def normalize_senders(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip().casefold() for value in values if value.strip()))

    @field_validator("sender_domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            domain = value.strip().casefold().lstrip("@")
            if not domain or "." not in domain or any(character.isspace() for character in domain):
                raise ValueError(f"invalid sender domain: {value!r}")
            normalized.append(domain)
        return list(dict.fromkeys(normalized))

    @field_validator("subject_keywords")
    @classmethod
    def normalize_keywords(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip().casefold() for value in values if value.strip()))

    @field_validator("patterns")
    @classmethod
    def validate_patterns(cls, values: list[str]) -> list[str]:
        for pattern in values:
            if len(pattern) > 512:
                raise ValueError("extractor patterns cannot exceed 512 characters")
            _validate_re2_subset(pattern)
            try:
                compiled = re.compile(pattern, re.ASCII)
            except re.error as exc:
                raise ValueError(f"invalid extractor regex: {exc}") from exc
            if "code" not in compiled.groupindex:
                raise ValueError("every extractor regex must define a named group '(?P<code>...)'")
        return values


class OutlookProviderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token_url: Literal["https://login.microsoftonline.com/common/oauth2/v2.0/token"] = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    )
    imap_host: Literal["outlook.office365.com"] = "outlook.office365.com"
    imap_port: Literal[993] = 993
    imap_timeout_seconds: float = Field(default=15.0, ge=3.0, le=60.0)
    poll_interval_seconds: float = Field(default=2.0, ge=1.0, le=10.0)
    max_messages: int = Field(default=10, ge=1, le=50)
    max_message_bytes: int = Field(default=262_144, ge=32_768, le=1_048_576)
    extractor: ExtractorSettings = Field(default_factory=ExtractorSettings)


class FlySmsProviderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: Literal["https://flysms.xyz/icloud/api/pickup/messages"] = "https://flysms.xyz/icloud/api/pickup/messages"
    poll_interval_seconds: float = Field(default=2.0, ge=1.0, le=10.0)
    history_limit: int = Field(default=30, ge=1, le=50)
    max_detail_messages: int = Field(default=5, ge=0, le=10)
    extractor: ExtractorSettings = Field(default_factory=ExtractorSettings)


class ProviderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outlook: OutlookProviderSettings = Field(default_factory=OutlookProviderSettings)
    flysms: FlySmsProviderSettings = Field(default_factory=FlySmsProviderSettings)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerSettings = Field(default_factory=ServerSettings)
    security: SecuritySettings
    providers: ProviderSettings = Field(default_factory=ProviderSettings)
    config_path: Path | None = Field(default=None, exclude=True)


def _resolve(path: Path, base: Path) -> Path:
    path = path.expanduser()
    return path if path.is_absolute() else (base / path).resolve()


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {config_path}: {exc.strerror or exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc
    try:
        config = AppConfig.model_validate(data)
    except Exception as exc:
        raise ConfigError(f"invalid configuration in {config_path}: {exc}") from exc
    security = config.security.model_copy(
        update={
            "api_token_hash_files": [
                _resolve(secret_path, config_path.parent) for secret_path in config.security.api_token_hash_files
            ]
        }
    )
    return config.model_copy(update={"security": security, "config_path": config_path})
