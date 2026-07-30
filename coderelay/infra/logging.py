from __future__ import annotations

import contextvars
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_REDACTIONS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)\b(cr_live_|tok_)[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(refresh[_ -]?token\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bM\.[A-Za-z0-9!*$._-]{80,}"),
)


def redact(value: str) -> str:
    result = value
    for pattern in _REDACTIONS:
        if pattern.groups:
            result = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
        else:
            result = pattern.sub("[REDACTED]", result)
    return result


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    key: redact(value) if isinstance(value, str) else value for key, value in record.args.items()
                }
            else:
                record.args = tuple(redact(value) if isinstance(value, str) else value for value in record.args)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact(record.getMessage()),
            "request_id": request_id_var.get(),
        }
        if record.exc_info:
            payload["exception"] = record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str = "info") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for name in ("uvicorn", "uvicorn.error", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
        if name in {"httpx", "httpcore"}:
            logger.setLevel(logging.WARNING)
