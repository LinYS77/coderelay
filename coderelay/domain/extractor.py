from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import ClassVar

from coderelay.config import ExtractorSettings
from coderelay.domain.errors import AmbiguousCode
from coderelay.domain.models import ExtractedCode, MailMessage

_GENERIC_CODE_RE = re.compile(r"(?<![0-9])([0-9]{6})(?![0-9])")
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
_WHITESPACE_RE = re.compile(r"\s+")
_DEFAULT_KEYWORDS = (
    "验证码",
    "校验码",
    "动态码",
    "安全码",
    "一次性密码",
    "verification code",
    "security code",
    "authentication code",
    "one-time code",
    "one time code",
    "passcode",
    "code",
    "otp",
)


class _PlainTextHTMLParser(HTMLParser):
    _SKIPPED: ClassVar[frozenset[str]] = frozenset({"script", "style", "head", "noscript", "svg", "template"})
    _BLOCKS: ClassVar[frozenset[str]] = frozenset(
        {"p", "div", "br", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6"}
    )

    def __init__(self, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self._limit = limit
        self._skip_depth = 0
        self._chunks: list[str] = []
        self._length = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in self._SKIPPED:
            self._skip_depth += 1
        elif not self._skip_depth and tag in self._BLOCKS:
            self._append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag in self._SKIPPED and self._skip_depth:
            self._skip_depth -= 1
        elif not self._skip_depth and tag in self._BLOCKS:
            self._append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._append(data)

    def _append(self, value: str) -> None:
        if self._length >= self._limit:
            return
        value = value[: self._limit - self._length]
        self._chunks.append(value)
        self._length += len(value)

    def text(self) -> str:
        return _WHITESPACE_RE.sub(" ", "".join(self._chunks)).strip()


def html_to_text(value: str, limit: int = 100_000) -> str:
    parser = _PlainTextHTMLParser(limit)
    try:
        parser.feed(value[:limit])
        parser.close()
    except Exception:
        return ""
    return parser.text()


def normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class _Candidate:
    code: str
    score: int
    position: int


class CodeExtractor:
    def __init__(self, settings: ExtractorSettings) -> None:
        self.settings = settings
        self._patterns = [re.compile(pattern, re.ASCII) for pattern in settings.patterns]
        self._keywords = tuple(dict.fromkeys((*_DEFAULT_KEYWORDS, *settings.subject_keywords)))

    def extract(
        self,
        messages: list[MailMessage],
        *,
        not_before: datetime | None,
        now: datetime,
    ) -> ExtractedCode | None:
        now = normalize_datetime(now)
        lower_bound = now - timedelta(seconds=self.settings.max_age_seconds)
        if not_before is not None:
            lower_bound = max(lower_bound, normalize_datetime(not_before))

        ordered = sorted(
            messages,
            key=lambda item: (normalize_datetime(item.received_at), item.provider_sequence),
            reverse=True,
        )
        for message in ordered:
            received_at = normalize_datetime(message.received_at)
            if received_at < lower_bound or received_at > now + timedelta(minutes=5):
                continue
            if not self._sender_allowed(message.sender):
                continue
            candidates = self._message_candidates(message)
            if not candidates:
                continue
            ranked = sorted(candidates.values(), key=lambda item: (-item.score, item.position, item.code))
            if len(ranked) > 1 and ranked[0].score == ranked[1].score:
                raise AmbiguousCode()
            chosen = ranked[0]
            fingerprint = hashlib.sha256(message.provider_message_id.encode("utf-8", "replace")).hexdigest()[:24]
            return ExtractedCode(
                code=chosen.code,
                message=message,
                redacted_subject=_GENERIC_CODE_RE.sub("••••••", message.subject)[:300],
                message_fingerprint=f"sha256:{fingerprint}",
            )
        return None

    def _sender_allowed(self, sender: str) -> bool:
        if not self.settings.senders and not self.settings.sender_domains:
            return True
        _, address = parseaddr(sender)
        normalized = (address or sender).strip().casefold()
        if normalized in self.settings.senders:
            return True
        if "@" not in normalized:
            return False
        domain = normalized.rsplit("@", 1)[1]
        return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in self.settings.sender_domains)

    def _message_candidates(self, message: MailMessage) -> dict[str, _Candidate]:
        subject = message.subject[:2_000]
        body_parts = [message.preview, message.text]
        if message.html:
            body_parts.append(html_to_text(message.html, self.settings.max_text_chars))
        body = " ".join(part for part in body_parts if part)[: self.settings.max_text_chars]
        subject = _URL_RE.sub(" ", subject)
        body = _URL_RE.sub(" ", body)

        candidates: dict[str, _Candidate] = {}
        self._collect_custom(subject, is_subject=True, candidates=candidates)
        self._collect_custom(body, is_subject=False, candidates=candidates)
        if self.settings.allow_generic_fallback:
            self._collect_generic(subject, is_subject=True, candidates=candidates)
            self._collect_generic(body, is_subject=False, candidates=candidates)
        return candidates

    def _collect_custom(self, text: str, *, is_subject: bool, candidates: dict[str, _Candidate]) -> None:
        for pattern_index, pattern in enumerate(self._patterns):
            for match in pattern.finditer(text):
                code = match.groupdict().get("code") or ""
                if not re.fullmatch(r"[0-9]{6}", code, flags=re.ASCII):
                    continue
                score = (140 if is_subject else 110) + self._context_score(text, match.start()) - pattern_index
                self._keep_best(candidates, _Candidate(code=code, score=score, position=match.start()))

    def _collect_generic(self, text: str, *, is_subject: bool, candidates: dict[str, _Candidate]) -> None:
        for match in _GENERIC_CODE_RE.finditer(text):
            code = match.group(1)
            context_score = self._context_score(text, match.start())
            if self.settings.generic_requires_keyword and context_score == 0:
                continue
            score = (70 if is_subject else 40) + context_score
            self._keep_best(candidates, _Candidate(code=code, score=score, position=match.start()))

    def _context_score(self, text: str, position: int) -> int:
        start = max(0, position - 80)
        end = min(len(text), position + 80)
        context = text[start:end].casefold()
        score = 0
        for keyword in self._keywords:
            folded_keyword = keyword.casefold()
            if self._contains_keyword(context, folded_keyword):
                score += 30
                break
        subject_folded = text.casefold()
        for keyword in self.settings.subject_keywords:
            if self._contains_keyword(subject_folded, keyword):
                score += 15
                break
        return score

    @staticmethod
    def _contains_keyword(text: str, keyword: str) -> bool:
        if keyword.isascii() and all(character.isalnum() or character.isspace() for character in keyword):
            return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", text) is not None
        return keyword in text

    @staticmethod
    def _keep_best(candidates: dict[str, _Candidate], candidate: _Candidate) -> None:
        current = candidates.get(candidate.code)
        if current is None or (candidate.score, -candidate.position) > (current.score, -current.position):
            candidates[candidate.code] = candidate
