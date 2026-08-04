package outlook

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	codeextractor "github.com/LinYS77/coderelay/internal/extractor"
)

func TestParseMIMEExtractsTextHTMLAndSkipsAttachment(t *testing.T) {
	raw := []byte("MIME-Version: 1.0\r\nSubject: =?UTF-8?B?VGVzdCDkuK3lm73mloc=?=\r\nFrom: Sender <sender@example.com>\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour verification code is 123456.\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Use <b>654321</b></p>\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\n\r\n123456\r\n--b--\r\n")
	subject, sender, text, html, err := parseMIME(raw)
	if err != nil {
		t.Fatalf("parseMIME() error = %v", err)
	}
	if !strings.Contains(subject, "中国") || !strings.Contains(sender, "sender@example.com") {
		t.Fatalf("headers = subject %q sender %q", subject, sender)
	}
	if !strings.Contains(text, "123456") || !strings.Contains(html, "654321") {
		t.Fatalf("body = text %q html %q", text, html)
	}
}

func TestJapaneseBase64MIMEFeedsDefaultExtractor(t *testing.T) {
	body := "この一時検証コードを入力して続行してください:\r\n\r\n123456\r\n\r\n検証コードをリクエストしていない場合、このメールは無視してください。"
	raw := []byte("MIME-Version: 1.0\r\n" +
		"Subject: =?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("一時検証コード")) + "?=\r\n" +
		"From: Service <service@example.com>\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(body)) + "\r\n")
	subject, sender, text, html, err := parseMIME(raw)
	if err != nil {
		t.Fatalf("parseMIME() error = %v", err)
	}
	engine, err := codeextractor.New(codeextractor.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC)
	code, err := engine.Extract([]codeextractor.Message{{
		UID:        1,
		Subject:    subject,
		Sender:     sender,
		ReceivedAt: now,
		Text:       text,
		HTML:       html,
	}}, nil, now)
	if err != nil || code != "123456" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func TestPortugueseBase64MIMEFeedsDefaultExtractor(t *testing.T) {
	body := "OpenAI\r\n\r\nInforme este código de verificação temporário para continuar:\r\n\r\n470213\r\n\r\nIgnore este e-mail se não é você que está tentando criar uma conta ChatGPT."
	raw := []byte("MIME-Version: 1.0\r\n" +
		"Subject: =?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("Código de verificação")) + "?=\r\n" +
		"From: Service <service@example.com>\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(body)) + "\r\n")
	subject, sender, text, html, err := parseMIME(raw)
	if err != nil {
		t.Fatalf("parseMIME() error = %v", err)
	}
	engine, err := codeextractor.New(codeextractor.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC)
	code, err := engine.Extract([]codeextractor.Message{{
		UID:        1,
		Subject:    subject,
		Sender:     sender,
		ReceivedAt: now,
		Text:       text,
		HTML:       html,
	}}, nil, now)
	if err != nil || code != "470213" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func TestParseMIMERejectsMalformed(t *testing.T) {
	if _, _, _, _, err := parseMIME([]byte("not an RFC 5322 message")); err == nil {
		t.Fatal("parseMIME accepted malformed message")
	}
}

func TestParseMIMEBoundsSender(t *testing.T) {
	raw := "From: " + strings.Repeat("a", maxSenderRunes+100) + "@example.com\r\n\r\nhello"
	_, sender, _, _, err := parseMIME([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(sender)) > maxSenderRunes {
		t.Fatalf("sender runes = %d", len([]rune(sender)))
	}
}
