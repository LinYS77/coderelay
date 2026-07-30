from __future__ import annotations

from datetime import UTC, datetime

import pytest

from coderelay.domain.errors import UpstreamSchemaChanged
from coderelay.providers.http_utils import parse_iso_datetime, parse_retry_after


def test_parse_iso_datetime_accepts_graph_and_rfc2822() -> None:
    expected = datetime(2026, 7, 30, 3, 0, tzinfo=UTC)
    assert parse_iso_datetime("2026-07-30T03:00:00Z") == expected
    assert parse_iso_datetime("Thu, 30 Jul 2026 03:00:00 GMT") == expected


def test_parse_iso_datetime_rejects_invalid_value() -> None:
    with pytest.raises(UpstreamSchemaChanged):
        parse_iso_datetime("not-a-date")


def test_parse_retry_after_seconds() -> None:
    assert parse_retry_after("17", default=2) == 17
    assert parse_retry_after("invalid", default=2) == 2
    assert parse_retry_after(None, default=3) == 3
