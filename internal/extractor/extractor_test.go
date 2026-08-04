package extractor

import (
	"errors"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestExtractFreshCodeFromTextSubjectAndHTML(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	extractor := mustNew(t, DefaultSettings())
	cases := []Message{
		{UID: 1, ReceivedAt: now.Add(-time.Second), Subject: "Notice", Text: "Your verification code is 123456"},
		{UID: 2, ReceivedAt: now.Add(-time.Second), Subject: "Security code 654321"},
		{UID: 3, ReceivedAt: now.Add(-time.Second), Subject: "Notice", HTML: `<script>code 999999</script><p>One-time code: <b>112233</b></p>`},
	}
	expected := []string{"123456", "654321", "112233"}
	for i, message := range cases {
		code, err := extractor.Extract([]Message{message}, nil, now)
		if err != nil || code != expected[i] {
			t.Fatalf("case %d code=%q error=%v", i, code, err)
		}
	}
}

func TestExtractJapaneseVerificationKeywords(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	extractor := mustNew(t, DefaultSettings())
	cases := []Message{
		{UID: 1, ReceivedAt: now, Text: "この一時検証コードを入力して続行してください:\n\n123456\n\n検証コードをリクエストしていない場合、このメールは無視してください。"},
		{UID: 2, ReceivedAt: now, Subject: "認証コードは 234567 です"},
		{UID: 3, ReceivedAt: now, Text: "確認コード: 345678"},
		{UID: 4, ReceivedAt: now, HTML: `<p>セキュリティコード：<strong>456789</strong></p>`},
		{UID: 5, ReceivedAt: now, Text: "ワンタイムコード 567890"},
		{UID: 6, ReceivedAt: now, Text: "ワンタイムパスワードは 678901 です"},
		{UID: 7, ReceivedAt: now, Text: "パスコード: 789012"},
	}
	for index, message := range cases {
		want := []string{"123456", "234567", "345678", "456789", "567890", "678901", "789012"}[index]
		code, err := extractor.Extract([]Message{message}, nil, now)
		if err != nil || code != want {
			t.Errorf("case %d code=%q error=%v, want %q", index, code, err, want)
		}
	}
}

func TestExtractPortugueseVerificationKeywords(t *testing.T) {
	now := time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC)
	extractor := mustNew(t, DefaultSettings())
	cases := []Message{
		{UID: 1, ReceivedAt: now, Text: "OpenAI\n\nInforme este código de verificação temporário para continuar:\n\n470213\n\nIgnore este e-mail se não é você que está tentando criar uma conta ChatGPT."},
		{UID: 2, ReceivedAt: now, Text: "Informe este codigo de verificacao temporario para continuar: 571324"},
		{UID: 3, ReceivedAt: now, Subject: "CÓDIGO DE VERIFICAÇÃO 672435"},
		{UID: 4, ReceivedAt: now, Text: "Seu código de segurança é 773546"},
		{UID: 5, ReceivedAt: now, Text: "Codigo de confirmacao: 874657"},
	}
	for index, message := range cases {
		want := []string{"470213", "571324", "672435", "773546", "874657"}[index]
		code, err := extractor.Extract([]Message{message}, nil, now)
		if err != nil || code != want {
			t.Errorf("case %d code=%q error=%v, want %q", index, code, err, want)
		}
	}
}

func TestExtractHonorsFreshnessKeywordsURLsAndASCII(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	extractor := mustNew(t, DefaultSettings())
	notBefore := now.Add(-time.Minute)
	messages := []Message{
		{UID: 4, ReceivedAt: now.Add(-2 * time.Minute), Subject: "Verification code 111111"},
		{UID: 3, ReceivedAt: now.Add(-time.Second), Text: "number 222222 without keyword"},
		{UID: 2, ReceivedAt: now.Add(-time.Second), Text: "verification code https://example.test/333333"},
		{UID: 1, ReceivedAt: now.Add(-time.Second), Text: "verification code １２３４５６"},
	}
	code, err := extractor.Extract(messages, &notBefore, now)
	if err != nil || code != "" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func TestExtractRejectsEqualScoreAmbiguity(t *testing.T) {
	now := time.Now().UTC()
	extractor := mustNew(t, DefaultSettings())
	_, err := extractor.Extract([]Message{{ReceivedAt: now, Subject: "verification code 123456 or 654321"}}, nil, now)
	if !errors.Is(err, domain.ErrAmbiguousCode) {
		t.Fatalf("error=%v", err)
	}
}

func TestNewestMessageAndUIDWin(t *testing.T) {
	now := time.Now().UTC()
	extractor := mustNew(t, DefaultSettings())
	code, err := extractor.Extract([]Message{
		{UID: 1, ReceivedAt: now.Add(-time.Second), Subject: "verification code 111111"},
		{UID: 2, ReceivedAt: now.Add(-time.Second), Subject: "verification code 222222"},
	}, nil, now)
	if err != nil || code != "222222" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func mustNew(t *testing.T, settings Settings) *Extractor {
	t.Helper()
	extractor, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	return extractor
}
