from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from coderelay.domain.errors import UpstreamSchemaChanged


def parse_retry_after(value: str | None, *, default: int = 0, maximum: int = 3_600) -> int:
    if not value:
        return default
    value = value.strip()
    if value.isdigit():
        return min(maximum, max(0, int(value)))
    try:
        target = parsedate_to_datetime(value)
        if target.tzinfo is None:
            target = target.replace(tzinfo=UTC)
        seconds = math.ceil((target.astimezone(UTC) - datetime.now(UTC)).total_seconds())
        return min(maximum, max(0, seconds))
    except (TypeError, ValueError, OverflowError):
        return default


def bounded_json(content: bytes, *, max_bytes: int = 2 * 1024 * 1024) -> Any:
    if len(content) > max_bytes:
        raise UpstreamSchemaChanged()
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamSchemaChanged() from exc


def parse_iso_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise UpstreamSchemaChanged()
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise UpstreamSchemaChanged() from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def require_text(value: object, *, maximum: int, nullable: bool = False) -> str:
    if value is None and nullable:
        return ""
    if not isinstance(value, str) or len(value) > maximum:
        raise UpstreamSchemaChanged()
    return value
