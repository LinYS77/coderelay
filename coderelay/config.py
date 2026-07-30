from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


class ConfigError(ValueError):
    """Raised when the application configuration is invalid."""


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

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("allowed_hosts must contain at least one host")
        if any(not value.strip() or value == "*" for value in values):
            raise ValueError("allowed_hosts cannot be blank or '*' in CodeRelay")
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
    ui_password_hash_file: Path
    session_secret_file: Path
    session_cookie_name: str = "coderelay_session"
    session_hours: int = Field(default=8, ge=1, le=168)
    cookie_secure: bool = True
    strict_secret_permissions: bool = True
    api_rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)
    login_rate_limit_per_minute: int = Field(default=5, ge=1, le=100)
    login_global_rate_limit_per_minute: int = Field(default=30, ge=1, le=1_000)

    @field_validator("session_cookie_name")
    @classmethod
    def validate_cookie_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("session_cookie_name contains unsupported characters")
        return value


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
        normalized = [value.strip().casefold() for value in values if value.strip()]
        return list(dict.fromkeys(normalized))

    @field_validator("sender_domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            domain = value.strip().casefold().lstrip("@")
            if not domain or "." not in domain or any(char.isspace() for char in domain):
                raise ValueError(f"invalid sender domain: {value!r}")
            normalized.append(domain)
        return list(dict.fromkeys(normalized))

    @field_validator("subject_keywords")
    @classmethod
    def normalize_keywords(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().casefold() for value in values if value.strip()]
        return list(dict.fromkeys(normalized))

    @field_validator("patterns")
    @classmethod
    def validate_patterns(cls, values: list[str]) -> list[str]:
        for pattern in values:
            if len(pattern) > 512:
                raise ValueError("extractor patterns cannot exceed 512 characters")
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid extractor regex: {exc}") from exc
            if "code" not in compiled.groupindex:
                raise ValueError("every extractor regex must define a named group '(?P<code>...)'")
        return values


class SourceBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    display_name: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    extractor: ExtractorSettings = Field(default_factory=ExtractorSettings)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _SOURCE_ID_RE.fullmatch(value):
            raise ValueError("source id must match ^[a-z][a-z0-9_-]{1,63}$")
        return value


class TotpSourceSettings(SourceBase):
    type: Literal["totp"]
    secret_file: Path
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"
    period_seconds: int = Field(default=30, ge=15, le=300)
    digits: Literal[6] = 6
    default_min_ttl_seconds: int = Field(default=5, ge=0, le=30)

    @model_validator(mode="after")
    def validate_min_ttl(self) -> TotpSourceSettings:
        if self.default_min_ttl_seconds >= self.period_seconds:
            raise ValueError("default_min_ttl_seconds must be less than period_seconds")
        return self


class OutlookImapSourceSettings(SourceBase):
    type: Literal["outlook_imap"]
    credential_file: Path
    credential_key_file: Path
    token_url: str = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    imap_host: str = "outlook.office365.com"
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_timeout_seconds: float = Field(default=15.0, ge=3.0, le=60.0)
    poll_interval_seconds: float = Field(default=2.0, ge=1.0, le=10.0)
    max_messages: int = Field(default=10, ge=1, le=50)
    max_message_bytes: int = Field(default=262_144, ge=32_768, le=1_048_576)

    @field_validator("token_url")
    @classmethod
    def validate_token_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "login.microsoftonline.com"
            or not parsed.path.endswith("/oauth2/v2.0/token")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Outlook token_url must be a Microsoft v2 token endpoint")
        return value

    @field_validator("imap_host")
    @classmethod
    def validate_imap_host(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if not normalized or len(normalized) > 253 or not re.fullmatch(r"[a-z0-9.-]+", normalized):
            raise ValueError("imap_host is invalid")
        return normalized


class FlySmsSourceSettings(SourceBase):
    type: Literal["flysms"]
    email_file: Path
    token_file: Path
    base_url: str = "https://flysms.xyz/icloud/api/pickup/messages"
    poll_interval_seconds: float = Field(default=2.0, ge=1.0, le=10.0)
    history_limit: int = Field(default=30, ge=1, le=50)
    max_detail_messages: int = Field(default=5, ge=0, le=10)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("FlySMS base_url must be an absolute HTTPS URL")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("FlySMS base_url cannot contain credentials, query, or fragment")
        return value.rstrip("/")


SourceSettings = Annotated[
    TotpSourceSettings | OutlookImapSourceSettings | FlySmsSourceSettings,
    Field(discriminator="type"),
]


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerSettings = Field(default_factory=ServerSettings)
    security: SecuritySettings
    sources: list[SourceSettings] = Field(min_length=1)
    config_path: Path | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def validate_source_ids(self) -> AppConfig:
        ids = [source.id for source in self.sources]
        if len(ids) != len(set(ids)):
            raise ValueError("source ids must be unique")
        if not any(source.enabled for source in self.sources):
            raise ValueError("at least one source must be enabled")
        return self

    def source_by_id(self, source_id: str) -> SourceSettings:
        for source in self.sources:
            if source.id == source_id:
                return source
        raise KeyError(source_id)


def _resolve(path: Path, base: Path) -> Path:
    path = path.expanduser()
    return path if path.is_absolute() else (base / path).resolve()


def _resolve_paths(config: AppConfig, base: Path) -> AppConfig:
    security = config.security.model_copy(
        update={
            "api_token_hash_files": [_resolve(path, base) for path in config.security.api_token_hash_files],
            "ui_password_hash_file": _resolve(config.security.ui_password_hash_file, base),
            "session_secret_file": _resolve(config.security.session_secret_file, base),
        }
    )
    sources: list[SourceSettings] = []
    for source in config.sources:
        if isinstance(source, TotpSourceSettings):
            source = source.model_copy(update={"secret_file": _resolve(source.secret_file, base)})
        elif isinstance(source, OutlookImapSourceSettings):
            source = source.model_copy(
                update={
                    "credential_file": _resolve(source.credential_file, base),
                    "credential_key_file": _resolve(source.credential_key_file, base),
                }
            )
        elif isinstance(source, FlySmsSourceSettings):
            source = source.model_copy(
                update={
                    "email_file": _resolve(source.email_file, base),
                    "token_file": _resolve(source.token_file, base),
                }
            )
        sources.append(source)
    return config.model_copy(
        update={"security": security, "sources": sources, "config_path": (base / "config.toml").resolve()}
    )


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
    resolved = _resolve_paths(config, config_path.parent)
    return resolved.model_copy(update={"config_path": config_path})
