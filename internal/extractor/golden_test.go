package extractor

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

type goldenDocument struct {
	SchemaVersion    int                       `json:"schema_version"`
	SettingsProfiles map[string]goldenSettings `json:"settings_profiles"`
	Cases            []goldenCase              `json:"cases"`
}

type goldenSettings struct {
	Senders                []string `json:"senders"`
	SenderDomains          []string `json:"sender_domains"`
	SubjectKeywords        []string `json:"subject_keywords"`
	Patterns               []string `json:"patterns"`
	MaxAgeSeconds          *int     `json:"max_age_seconds"`
	AllowGenericFallback   *bool    `json:"allow_generic_fallback"`
	GenericRequiresKeyword *bool    `json:"generic_requires_keyword"`
	MaxTextChars           *int     `json:"max_text_chars"`
}

type goldenCase struct {
	Name      string          `json:"name"`
	Settings  json.RawMessage `json:"settings"`
	Now       string          `json:"now"`
	NotBefore *string         `json:"not_before"`
	Messages  []goldenMessage `json:"messages"`
	Expected  goldenExpected  `json:"expected"`
}

type goldenMessage struct {
	ID         string `json:"id"`
	UID        int64  `json:"uid"`
	Subject    string `json:"subject"`
	Sender     string `json:"sender"`
	ReceivedAt string `json:"received_at"`
	Preview    string `json:"preview"`
	Text       string `json:"text"`
	HTML       string `json:"html"`
}

type goldenExpected struct {
	Code  *string `json:"code"`
	Error *string `json:"error"`
}

func TestGoExtractorMatchesPythonGolden(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/extractor_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var document goldenDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != 1 || len(document.Cases) == 0 {
		t.Fatal("unsupported or empty golden fixture")
	}
	for _, test := range document.Cases {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			settings := resolveGoldenSettings(t, document.SettingsProfiles, test.Settings)
			extractor, err := New(settings)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			now := parseGoldenTime(t, test.Now)
			var notBefore *time.Time
			if test.NotBefore != nil {
				value := parseGoldenTime(t, *test.NotBefore)
				notBefore = &value
			}
			messages := make([]Message, len(test.Messages))
			for index, item := range test.Messages {
				messages[index] = Message{
					ID:         item.ID,
					UID:        item.UID,
					Subject:    item.Subject,
					Sender:     item.Sender,
					ReceivedAt: parseGoldenTime(t, item.ReceivedAt),
					Preview:    item.Preview,
					Text:       item.Text,
					HTML:       item.HTML,
				}
			}
			code, extractErr := extractor.Extract(messages, notBefore, now)
			if test.Expected.Error != nil {
				if *test.Expected.Error != "AMBIGUOUS_CODE" || !errors.Is(extractErr, domain.ErrAmbiguousCode) || code != "" {
					t.Fatalf("code=%q error=%v, want error=%q", code, extractErr, *test.Expected.Error)
				}
				return
			}
			if extractErr != nil {
				t.Fatalf("Extract: %v", extractErr)
			}
			want := ""
			if test.Expected.Code != nil {
				want = *test.Expected.Code
			}
			if code != want {
				t.Fatalf("code=%q, want %q", code, want)
			}
		})
	}
}

func resolveGoldenSettings(t *testing.T, profiles map[string]goldenSettings, raw json.RawMessage) Settings {
	t.Helper()
	var profileName string
	var value goldenSettings
	if err := json.Unmarshal(raw, &profileName); err == nil {
		var ok bool
		value, ok = profiles[profileName]
		if !ok {
			t.Fatalf("unknown settings profile %q", profileName)
		}
	} else if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("settings: %v", err)
	}
	settings := DefaultSettings()
	if value.Senders != nil {
		settings.Senders = value.Senders
	}
	if value.SenderDomains != nil {
		settings.SenderDomains = value.SenderDomains
	}
	if value.SubjectKeywords != nil {
		settings.SubjectKeywords = value.SubjectKeywords
	}
	if value.Patterns != nil {
		settings.Patterns = value.Patterns
	}
	if value.MaxAgeSeconds != nil {
		settings.MaxAge = time.Duration(*value.MaxAgeSeconds) * time.Second
	}
	if value.AllowGenericFallback != nil {
		settings.AllowGenericFallback = *value.AllowGenericFallback
	}
	if value.GenericRequiresKeyword != nil {
		settings.GenericRequiresKeyword = *value.GenericRequiresKeyword
	}
	if value.MaxTextChars != nil {
		settings.MaxTextChars = *value.MaxTextChars
	}
	return settings
}

func parseGoldenTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("time %q: %v", value, err)
	}
	return parsed
}
