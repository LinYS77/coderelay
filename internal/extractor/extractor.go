// Package extractor finds fresh six-digit verification codes in bounded messages.
package extractor

import (
	"errors"
	"html"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/domain"
)

const (
	DefaultMaxAge  = 10 * time.Minute
	DefaultMaxText = 100_000
)

var (
	urlPattern   = regexp.MustCompile(`(?i)\b(?:https?://|www\.)\S+`)
	tagPattern   = regexp.MustCompile(`(?is)<[^>]*>`)
	skipPattern  = regexp.MustCompile(`(?is)<(?:script|style|head|noscript|svg|template)\b[^>]*>.*?</(?:script|style|head|noscript|svg|template)>`)
	defaultWords = []string{
		"验证码", "校验码", "动态码", "安全码", "一次性密码",
		"verification code", "security code", "authentication code",
		"one-time code", "one time code", "passcode", "code", "otp",
	}
)

type Message struct {
	ID         string
	Mailbox    string
	UID        int64
	Subject    string
	Sender     string
	ReceivedAt time.Time
	Preview    string
	Text       string
	HTML       string
}

func (m *Message) Destroy() {
	if m == nil {
		return
	}
	m.ID = ""
	m.Mailbox = ""
	m.Subject = ""
	m.Sender = ""
	m.Preview = ""
	m.Text = ""
	m.HTML = ""
	m.UID = 0
	m.ReceivedAt = time.Time{}
}

type Settings struct {
	MaxAge          time.Duration
	MaxTextChars    int
	AllowGeneric    bool
	RequireKeyword  bool
	SubjectKeywords []string
}

func DefaultSettings() Settings {
	return Settings{
		MaxAge:         DefaultMaxAge,
		MaxTextChars:   DefaultMaxText,
		AllowGeneric:   true,
		RequireKeyword: true,
	}
}

type Extractor struct {
	settings Settings
	keywords []string
}

func New(settings Settings) *Extractor {
	if settings.MaxAge <= 0 {
		settings.MaxAge = DefaultMaxAge
	}
	if settings.MaxTextChars <= 0 || settings.MaxTextChars > 1_000_000 {
		settings.MaxTextChars = DefaultMaxText
	}
	keywords := make([]string, 0, len(defaultWords)+len(settings.SubjectKeywords))
	seen := make(map[string]struct{}, len(defaultWords)+len(settings.SubjectKeywords))
	for _, word := range append(append([]string{}, defaultWords...), settings.SubjectKeywords...) {
		word = strings.ToLower(strings.TrimSpace(word))
		if word == "" {
			continue
		}
		if _, ok := seen[word]; ok {
			continue
		}
		seen[word] = struct{}{}
		keywords = append(keywords, word)
	}
	return &Extractor{settings: settings, keywords: keywords}
}

func (e *Extractor) Extract(messages []Message, notBefore *time.Time, now time.Time) (string, error) {
	if e == nil {
		return "", errors.New("extractor is not initialized")
	}
	now = now.UTC()
	lower := now.Add(-e.settings.MaxAge)
	if notBefore != nil {
		bound := notBefore.UTC()
		if bound.After(lower) {
			lower = bound
		}
	}
	ordered := append([]Message(nil), messages...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i].ReceivedAt.UTC(), ordered[j].ReceivedAt.UTC()
		if !left.Equal(right) {
			return left.After(right)
		}
		if ordered[i].UID != ordered[j].UID {
			return ordered[i].UID > ordered[j].UID
		}
		return ordered[i].ID > ordered[j].ID
	})
	for _, message := range ordered {
		received := message.ReceivedAt.UTC()
		if received.Before(lower) || received.After(now.Add(5*time.Minute)) {
			continue
		}
		candidates := e.candidates(message)
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].score != candidates[j].score {
				return candidates[i].score > candidates[j].score
			}
			if candidates[i].position != candidates[j].position {
				return candidates[i].position < candidates[j].position
			}
			return candidates[i].code < candidates[j].code
		})
		if len(candidates) > 1 && candidates[0].score == candidates[1].score && candidates[0].code != candidates[1].code {
			return "", domain.ErrAmbiguousCode
		}
		return candidates[0].code, nil
	}
	return "", nil
}

type candidate struct {
	code     string
	score    int
	position int
}

func (e *Extractor) candidates(message Message) []candidate {
	subject := truncateRunes(urlPattern.ReplaceAllString(message.Subject, " "), 2_000)
	body := strings.Join(nonEmpty(
		message.Preview,
		message.Text,
		htmlToText(message.HTML, e.settings.MaxTextChars),
	), " ")
	body = truncateRunes(urlPattern.ReplaceAllString(body, " "), e.settings.MaxTextChars)
	found := make(map[string]candidate)
	if e.settings.AllowGeneric {
		e.collect(subject, true, found)
		e.collect(body, false, found)
	}
	result := make([]candidate, 0, len(found))
	for _, item := range found {
		result = append(result, item)
	}
	return result
}

func (e *Extractor) collect(text string, subject bool, found map[string]candidate) {
	for position := 0; position+6 <= len(text); position++ {
		if position > 0 && isDigit(text[position-1]) {
			continue
		}
		code := text[position : position+6]
		if !allDigits(code) || position+6 < len(text) && isDigit(text[position+6]) {
			continue
		}
		context := e.contextScore(text, position)
		if e.settings.RequireKeyword && context == 0 {
			continue
		}
		score := 40 + context
		if subject {
			score = 70 + context
		}
		item := candidate{code: code, score: score, position: position}
		if old, ok := found[code]; !ok || item.score > old.score || item.score == old.score && item.position < old.position {
			found[code] = item
		}
	}
}

func (e *Extractor) contextScore(text string, position int) int {
	start := position - 80
	if start < 0 {
		start = 0
	}
	end := position + 80
	if end > len(text) {
		end = len(text)
	}
	context := strings.ToLower(text[start:end])
	score := 0
	for _, keyword := range e.keywords {
		if containsKeyword(context, keyword) {
			score += 30
			break
		}
	}
	return score
}

func containsKeyword(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	if strings.IndexFunc(keyword, func(r rune) bool { return r > 127 }) >= 0 {
		return strings.Contains(text, keyword)
	}
	for offset := 0; ; {
		index := strings.Index(text[offset:], keyword)
		if index < 0 {
			return false
		}
		index += offset
		beforeOK := index == 0 || !asciiWord(text[index-1])
		after := index + len(keyword)
		afterOK := after == len(text) || !asciiWord(text[after])
		if beforeOK && afterOK {
			return true
		}
		offset = index + 1
		if offset >= len(text) {
			return false
		}
	}
}

func htmlToText(value string, limit int) string {
	if value == "" {
		return ""
	}
	value = truncateRunes(value, limit)
	value = skipPattern.ReplaceAllString(value, " ")
	value = tagPattern.ReplaceAllString(value, " ")
	return truncateRunes(strings.Join(strings.Fields(html.UnescapeString(value)), " "), limit)
}

func nonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(value) <= limit {
		return value
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index]
		}
		count++
	}
	return value
}

func allDigits(value string) bool {
	for i := 0; i < len(value); i++ {
		if !isDigit(value[i]) {
			return false
		}
	}
	return true
}

func isDigit(value byte) bool { return value >= '0' && value <= '9' }
func asciiWord(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
