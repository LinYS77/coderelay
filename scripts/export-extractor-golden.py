#!/usr/bin/env python3
"""Export Python 0.3 extractor outcomes into language-neutral JSON golden data."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from coderelay.config import ExtractorSettings  # noqa: E402
from coderelay.domain.errors import AmbiguousCode  # noqa: E402
from coderelay.domain.extractor import CodeExtractor  # noqa: E402
from coderelay.domain.models import MailMessage  # noqa: E402

DEFAULT_PATH = ROOT / "testdata" / "extractor_golden.json"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate(case: dict[str, Any], profiles: dict[str, Any]) -> dict[str, str | None]:
    raw_settings = case["settings"]
    if isinstance(raw_settings, str):
        raw_settings = profiles[raw_settings]
    settings = ExtractorSettings.model_validate(raw_settings)
    messages = [
        MailMessage(
            provider_message_id=item["id"],
            provider_sequence=item.get("uid", 0),
            subject=item.get("subject", ""),
            sender=item.get("sender", ""),
            received_at=parse_time(item["received_at"]),
            preview=item.get("preview", ""),
            text=item.get("text", ""),
            html=item.get("html", ""),
        )
        for item in case["messages"]
    ]
    not_before = parse_time(case["not_before"]) if case.get("not_before") is not None else None
    try:
        result = CodeExtractor(settings).extract(messages, not_before=not_before, now=parse_time(case["now"]))
    except AmbiguousCode:
        return {"code": None, "error": "AMBIGUOUS_CODE"}
    return {"code": result.code if result is not None else None, "error": None}


def render(path: Path) -> bytes:
    document = json.loads(path.read_text(encoding="utf-8"))
    profiles = document.get("settings_profiles")
    if (
        document.get("schema_version") != 1
        or not isinstance(document.get("cases"), list)
        or not isinstance(profiles, dict)
    ):
        raise ValueError("unsupported extractor fixture schema")
    names: set[str] = set()
    for case in document["cases"]:
        name = case.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("fixture names must be unique non-empty strings")
        names.add(name)
        case["expected"] = evaluate(case, profiles)
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(args.path)
    if args.check:
        if args.path.read_bytes() != expected:
            print(f"{args.path}: golden output is stale", file=sys.stderr)
            return 1
        return 0
    args.path.write_bytes(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
