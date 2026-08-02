package outlook

import (
	"strings"
	"testing"
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
