from __future__ import annotations

import logging

from coderelay.infra.logging import JsonFormatter, RedactingFilter, redact


def test_redact_hides_bearer_and_provider_tokens() -> None:
    refresh_token = "M." + "x" * 120
    value = redact(
        f"Authorization: Bearer secret-value tok_abcdefghijklmnopqrstuvwxyz {refresh_token} "
        "credential=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    )
    assert "secret-value" not in value
    assert "abcdefghijklmnopqrstuvwxyz" not in value
    assert refresh_token not in value
    assert "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" not in value
    assert "[REDACTED]" in value


def test_logging_filter_preserves_numeric_format_arguments() -> None:
    record = logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        "count=%d token=%s",
        (7, "cr_live_abcdefghijklmnopqrstuvwxyz0123456789"),
        None,
    )
    assert RedactingFilter().filter(record)
    rendered = JsonFormatter().format(record)
    assert "count=7" in rendered
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in rendered
