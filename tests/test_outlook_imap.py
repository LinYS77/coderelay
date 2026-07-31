from __future__ import annotations

from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs

import httpx
import pytest

from coderelay.config import OutlookProviderSettings
from coderelay.domain.credentials import OutlookCredential
from coderelay.domain.errors import SourceReauthRequired
from coderelay.domain.models import CodeRequest
from coderelay.providers.outlook_imap import OutlookImapProvider, _extract_message_content, _parse_internal_date

CLIENT_ID = "11111111-2222-4333-8444-555555555555"
REFRESH_TOKEN = "M." + "a" * 240
ROTATED_TOKEN = "M." + "b" * 240
ACCESS_TOKEN = "access-token-value"
IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All"
NOW = datetime(2026, 7, 30, 4, 0, tzinfo=UTC)


class FakeImap:
    def __init__(self, raw_message: bytes, *, expected_access_token: str = ACCESS_TOKEN) -> None:
        self.raw_message = raw_message
        self.expected_access_token = expected_access_token
        self.readonly = False
        self.logged_out = False

    def authenticate(self, mechanism: str, callback):
        assert mechanism == "XOAUTH2"
        authentication = callback(None)
        assert f"auth=Bearer {self.expected_access_token}".encode() in authentication
        return "OK", [b"authenticated"]

    def select(self, mailbox: str, readonly: bool = False):
        assert mailbox == "INBOX"
        self.readonly = readonly
        return "OK", [b"1"]

    def fetch(self, sequence: str, query: str):
        assert sequence == "1"
        assert "BODY.PEEK[]" in query
        metadata = (
            b'1 (UID 42 INTERNALDATE "30-Jul-2026 03:00:00 +0000" ' + f"BODY[]<0> {{{len(self.raw_message)}}}".encode()
        )
        return "OK", [(metadata, self.raw_message), b")"]

    def logout(self):
        self.logged_out = True
        return "BYE", [b"logout"]


@pytest.fixture
def raw_verification_email() -> bytes:
    return (
        b"From: Service <no-reply@example.com>\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Your verification code 123456\r\n"
        b"Date: Thu, 30 Jul 2026 03:00:00 +0000\r\n"
        b"Message-ID: <message-one@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Use verification code 123456 to continue.\r\n"
    )


@pytest.fixture
def outlook_settings() -> OutlookProviderSettings:
    return OutlookProviderSettings(extractor={"max_age_seconds": 86_400})


@pytest.fixture
def outlook_credential() -> OutlookCredential:
    return OutlookCredential("user@example.com", CLIENT_ID, REFRESH_TOKEN)


@pytest.mark.asyncio
async def test_outlook_imap_returns_code_and_request_scoped_rotation(
    outlook_settings: OutlookProviderSettings,
    outlook_credential: OutlookCredential,
    raw_verification_email: bytes,
) -> None:
    token_requests = 0
    fake_imap = FakeImap(raw_verification_email)

    def token_handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests
        token_requests += 1
        form = parse_qs(request.content.decode())
        assert form["client_id"] == [CLIENT_ID]
        assert form["grant_type"] == ["refresh_token"]
        assert form["refresh_token"] == [REFRESH_TOKEN]
        assert "scope" not in form
        return httpx.Response(
            200,
            json={
                "access_token": ACCESS_TOKEN,
                "refresh_token": ROTATED_TOKEN,
                "expires_in": 3600,
                "scope": IMAP_SCOPE,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(token_handler)) as client:
        provider = OutlookImapProvider(
            outlook_settings,
            client,
            outlook_credential,
            imap_factory=lambda *args, **kwargs: fake_imap,
            now=lambda: NOW,
        )
        result = await provider.fetch_code(CodeRequest(not_before=datetime(2026, 7, 30, 2, 59, tzinfo=UTC)))
        second = await provider.fetch_code(CodeRequest())
        update = provider.credential_update
        provider.close()

    assert result is not None and result.code == "123456"
    assert second is not None and second.code == "123456"
    assert fake_imap.readonly is True
    assert fake_imap.logged_out is True
    assert token_requests == 1
    assert update is not None and update.refresh_token == ROTATED_TOKEN
    assert provider.credential_update is None


@pytest.mark.asyncio
async def test_outlook_imap_respects_not_before(
    outlook_settings: OutlookProviderSettings,
    outlook_credential: OutlookCredential,
    raw_verification_email: bytes,
) -> None:
    def token_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": ACCESS_TOKEN, "expires_in": 3600, "scope": IMAP_SCOPE})

    async with httpx.AsyncClient(transport=httpx.MockTransport(token_handler)) as client:
        provider = OutlookImapProvider(
            outlook_settings,
            client,
            outlook_credential,
            imap_factory=lambda *args, **kwargs: FakeImap(raw_verification_email),
            now=lambda: NOW,
        )
        result = await provider.fetch_code(CodeRequest(not_before=datetime(2026, 7, 30, 3, 1, tzinfo=UTC)))
    assert result is None


@pytest.mark.asyncio
async def test_outlook_invalid_grant_requires_new_credential(
    outlook_settings: OutlookProviderSettings,
    outlook_credential: OutlookCredential,
) -> None:
    def token_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant", "error_codes": [70000]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(token_handler)) as client:
        provider = OutlookImapProvider(
            outlook_settings,
            client,
            outlook_credential,
            imap_factory=lambda *args, **kwargs: None,
            now=lambda: NOW,
        )
        with pytest.raises(SourceReauthRequired):
            await provider.fetch_code(CodeRequest())


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        (
            b'1 (UID 42 INTERNALDATE "30-Jul-2026 03:00:00 +0000")',
            datetime(2026, 7, 30, 3, 0, tzinfo=UTC),
        ),
        (
            b'1 (UID 42 INTERNALDATE "30-Jul-2026 11:00:00 +0800")',
            datetime(2026, 7, 30, 3, 0, tzinfo=UTC),
        ),
    ],
)
def test_parse_internal_date(metadata: bytes, expected: datetime) -> None:
    assert _parse_internal_date(metadata) == expected


def test_mime_extraction_ignores_attachments() -> None:
    raw = (
        b"Content-Type: multipart/mixed; boundary=boundary\r\n"
        b"\r\n"
        b"--boundary\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>Verification code <strong>222222</strong></p>\r\n"
        b"--boundary\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Disposition: attachment; filename=order.txt\r\n"
        b"\r\n"
        b"Order 999999\r\n"
        b"--boundary--\r\n"
    )
    message = BytesParser(policy=policy.default).parsebytes(raw)
    text, html = _extract_message_content(message, 100_000)
    assert text == ""
    assert "222222" in html
    assert "999999" not in html
