from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from coderelay.config import ExtractorSettings
from coderelay.domain.errors import AmbiguousCode
from coderelay.domain.extractor import CodeExtractor, html_to_text
from coderelay.domain.models import MailMessage

NOW = datetime(2026, 7, 30, 3, 0, tzinfo=UTC)


def message(
    message_id: str,
    *,
    subject: str = "",
    sender: str = "no-reply@example.com",
    age_seconds: int = 5,
    preview: str = "",
    text: str = "",
    html: str = "",
) -> MailMessage:
    return MailMessage(
        provider_message_id=message_id,
        subject=subject,
        sender=sender,
        received_at=NOW - timedelta(seconds=age_seconds),
        preview=preview,
        text=text,
        html=html,
    )


def test_newest_matching_message_wins() -> None:
    extractor = CodeExtractor(ExtractorSettings())
    result = extractor.extract(
        [
            message("old", subject="Verification code 111111", age_seconds=50),
            message("new", subject="Verification code 222222", age_seconds=5),
        ],
        not_before=NOW - timedelta(minutes=2),
        now=NOW,
    )
    assert result is not None
    assert result.code == "222222"
    assert result.redacted_subject == "Verification code ••••••"
    assert result.message_fingerprint.startswith("sha256:")


def test_not_before_rejects_stale_mail() -> None:
    extractor = CodeExtractor(ExtractorSettings(max_age_seconds=600))
    result = extractor.extract(
        [message("old", subject="Code 111111", age_seconds=120)],
        not_before=NOW - timedelta(seconds=30),
        now=NOW,
    )
    assert result is None


def test_sender_domain_allowlist() -> None:
    extractor = CodeExtractor(ExtractorSettings(sender_domains=["trusted.example"]))
    result = extractor.extract(
        [
            message("bad", sender="attacker@example.com", subject="Code 111111"),
            message("good", sender="Service <mail.eu.trusted.example>", subject="Code 222222"),
        ],
        not_before=None,
        now=NOW,
    )
    assert result is None  # malformed sender is not treated as an email address

    result = extractor.extract(
        [message("good", sender="Service <mail@mail.eu.trusted.example>", subject="Code 222222")],
        not_before=None,
        now=NOW,
    )
    assert result is not None and result.code == "222222"


def test_custom_pattern_beats_unrelated_number() -> None:
    settings = ExtractorSettings(
        patterns=[r"(?i)verification\s+code:\s*(?P<code>\d{6})"],
        allow_generic_fallback=True,
    )
    extractor = CodeExtractor(settings)
    result = extractor.extract(
        [message("one", text="Order 999999. Verification code: 123456")],
        not_before=None,
        now=NOW,
    )
    assert result is not None
    assert result.code == "123456"


def test_equal_candidates_are_ambiguous() -> None:
    extractor = CodeExtractor(ExtractorSettings())
    with pytest.raises(AmbiguousCode):
        extractor.extract(
            [message("one", subject="Verification code 123456 and security code 654321")],
            not_before=None,
            now=NOW,
        )


def test_unrelated_six_digit_number_is_not_a_code() -> None:
    extractor = CodeExtractor(ExtractorSettings())
    result = extractor.extract(
        [message("order", subject="Your order 999999 has shipped")],
        not_before=None,
        now=NOW,
    )
    assert result is None


def test_script_and_urls_do_not_supply_codes() -> None:
    extractor = CodeExtractor(ExtractorSettings())
    result = extractor.extract(
        [
            message(
                "one",
                html='<script>const code="111111"</script><p>No code here</p>',
                text="Visit https://example.com/reset/222222",
            )
        ],
        not_before=None,
        now=NOW,
    )
    assert result is None


def test_html_to_text_omits_active_content() -> None:
    assert html_to_text("<style>.x{content:'123456'}</style><p>Hello&nbsp;world</p>") == "Hello world"
