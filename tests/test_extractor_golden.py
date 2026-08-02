from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from coderelay.config import ExtractorSettings
from coderelay.domain.errors import AmbiguousCode
from coderelay.domain.extractor import CodeExtractor
from coderelay.domain.models import MailMessage

_FIXTURES = json.loads((Path(__file__).parents[1] / "testdata" / "extractor_golden.json").read_text(encoding="utf-8"))


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@pytest.mark.parametrize("case", _FIXTURES["cases"], ids=lambda case: case["name"])
def test_python_extractor_matches_language_neutral_golden(case: dict[str, object]) -> None:
    raw_settings = case["settings"]
    if isinstance(raw_settings, str):
        raw_settings = _FIXTURES["settings_profiles"][raw_settings]
    settings = ExtractorSettings.model_validate(raw_settings)
    messages = [
        MailMessage(
            provider_message_id=item["id"],
            provider_sequence=item.get("uid", 0),
            subject=item.get("subject", ""),
            sender=item.get("sender", ""),
            received_at=_time(item["received_at"]),
            preview=item.get("preview", ""),
            text=item.get("text", ""),
            html=item.get("html", ""),
        )
        for item in case["messages"]
    ]
    not_before = _time(case["not_before"]) if case.get("not_before") is not None else None
    expected = case["expected"]
    try:
        result = CodeExtractor(settings).extract(messages, not_before=not_before, now=_time(case["now"]))
    except AmbiguousCode:
        actual = {"code": None, "error": "AMBIGUOUS_CODE"}
    else:
        actual = {"code": result.code if result is not None else None, "error": None}
    assert actual == expected
