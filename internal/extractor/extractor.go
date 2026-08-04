// Package extractor finds fresh six-digit verification codes according to the
// frozen language-neutral golden contract.
package extractor

import (
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/domain"
	xhtml "golang.org/x/net/html"
	"golang.org/x/text/cases"
)

const (
	DefaultMaxAge   = 10 * time.Minute
	DefaultMaxText  = 100_000
	maxListItems    = 100
	maxPatterns     = 20
	maxPatternRunes = 512
)

var (
	ErrInvalidSettings = errors.New("invalid extractor settings")
	unicodeFold        = cases.Fold()
	defaultWords       = []string{
		"验证码", "校验码", "动态码", "安全码", "一次性密码",
		"検証コード", "認証コード", "確認コード", "セキュリティコード", "セキュリティ コード",
		"ワンタイムコード", "ワンタイム コード", "ワンタイムパスワード", "ワンタイム パスワード", "パスコード",
		"verification code", "security code", "authentication code",
		"one-time code", "one time code", "passcode", "code", "otp",
		"código de verificação", "codigo de verificacao",
		"código de segurança", "codigo de seguranca",
		"código de confirmação", "codigo de confirmacao",
	}
	skippedHTMLTags = map[string]struct{}{
		"script": {}, "style": {}, "head": {}, "noscript": {}, "svg": {}, "template": {},
	}
	blockHTMLTags = map[string]struct{}{
		"p": {}, "div": {}, "br": {}, "li": {}, "tr": {}, "td": {}, "th": {},
		"h1": {}, "h2": {}, "h3": {}, "h4": {}, "h5": {}, "h6": {},
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
	Senders                []string
	SenderDomains          []string
	SubjectKeywords        []string
	Patterns               []string
	MaxAge                 time.Duration
	MaxTextChars           int
	AllowGenericFallback   bool
	GenericRequiresKeyword bool
}

func DefaultSettings() Settings {
	return Settings{
		MaxAge:                 DefaultMaxAge,
		MaxTextChars:           DefaultMaxText,
		AllowGenericFallback:   true,
		GenericRequiresKeyword: true,
	}
}

type compiledPattern struct {
	expression *regexp.Regexp
	codeGroup  int
}

type Extractor struct {
	settings Settings
	patterns []compiledPattern
	keywords []string
}

func New(settings Settings) (*Extractor, error) {
	if settings.MaxAge == 0 {
		settings.MaxAge = DefaultMaxAge
	}
	if settings.MaxTextChars == 0 {
		settings.MaxTextChars = DefaultMaxText
	}
	if settings.MaxAge < 30*time.Second || settings.MaxAge > 24*time.Hour || settings.MaxTextChars < 1_000 || settings.MaxTextChars > 1_000_000 {
		return nil, ErrInvalidSettings
	}
	if len(settings.Senders) > maxListItems || len(settings.SenderDomains) > maxListItems || len(settings.SubjectKeywords) > maxListItems || len(settings.Patterns) > maxPatterns {
		return nil, ErrInvalidSettings
	}
	settings.Senders = normalizeList(settings.Senders)
	var err error
	if settings.SenderDomains, err = normalizeDomains(settings.SenderDomains); err != nil {
		return nil, err
	}
	settings.SubjectKeywords = normalizeList(settings.SubjectKeywords)
	patterns := make([]compiledPattern, 0, len(settings.Patterns))
	for _, source := range settings.Patterns {
		if utf8.RuneCountInString(source) > maxPatternRunes {
			return nil, ErrInvalidSettings
		}
		expression, compileErr := regexp.Compile(source)
		if compileErr != nil {
			return nil, fmt.Errorf("%w: custom pattern is not valid RE2", ErrInvalidSettings)
		}
		codeGroup := expression.SubexpIndex("code")
		if codeGroup < 1 || countSubexpression(expression.SubexpNames(), "code") != 1 {
			return nil, fmt.Errorf("%w: custom pattern must define one named code group", ErrInvalidSettings)
		}
		patterns = append(patterns, compiledPattern{expression: expression, codeGroup: codeGroup})
	}
	settings.Patterns = append([]string(nil), settings.Patterns...)
	keywords := make([]string, 0, len(defaultWords)+len(settings.SubjectKeywords))
	seen := make(map[string]struct{}, len(defaultWords)+len(settings.SubjectKeywords))
	for _, word := range append(append([]string(nil), defaultWords...), settings.SubjectKeywords...) {
		word = fold(strings.TrimSpace(word))
		if word == "" {
			continue
		}
		if _, duplicate := seen[word]; duplicate {
			continue
		}
		seen[word] = struct{}{}
		keywords = append(keywords, word)
	}
	return &Extractor{settings: settings, patterns: patterns, keywords: keywords}, nil
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
		return ordered[i].UID > ordered[j].UID
	})
	for _, message := range ordered {
		received := message.ReceivedAt.UTC()
		if received.Before(lower) || received.After(now.Add(5*time.Minute)) {
			continue
		}
		if !e.senderAllowed(message.Sender) {
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
		if len(candidates) > 1 && candidates[0].score == candidates[1].score {
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

type preparedText struct {
	value      string
	runes      []rune
	folded     string
	byteToRune []int
}

func prepareText(value string) preparedText {
	runes := []rune(value)
	byteToRune := make([]int, len(value)+1)
	runePosition := 0
	for bytePosition := range value {
		byteToRune[bytePosition] = runePosition
		runePosition++
	}
	byteToRune[len(value)] = len(runes)
	return preparedText{value: value, runes: runes, folded: fold(value), byteToRune: byteToRune}
}

func (e *Extractor) candidates(message Message) []candidate {
	subject := truncateRunes(message.Subject, 2_000)
	bodyParts := nonEmpty(message.Preview, message.Text)
	if message.HTML != "" {
		if visible := htmlToText(message.HTML, e.settings.MaxTextChars); visible != "" {
			bodyParts = append(bodyParts, visible)
		}
	}
	body := truncateRunes(strings.Join(bodyParts, " "), e.settings.MaxTextChars)
	subject = stripURLs(subject)
	body = stripURLs(body)

	found := make(map[string]candidate)
	subjectText := prepareText(subject)
	bodyText := prepareText(body)
	e.collectCustom(subjectText, true, found)
	e.collectCustom(bodyText, false, found)
	if e.settings.AllowGenericFallback {
		e.collectGeneric(subjectText, true, found)
		e.collectGeneric(bodyText, false, found)
	}
	result := make([]candidate, 0, len(found))
	for _, item := range found {
		result = append(result, item)
	}
	return result
}

func (e *Extractor) collectCustom(text preparedText, subject bool, found map[string]candidate) {
	for patternIndex, pattern := range e.patterns {
		for _, match := range pattern.expression.FindAllStringSubmatchIndex(text.value, -1) {
			groupOffset := pattern.codeGroup * 2
			if len(match) <= groupOffset+1 || match[groupOffset] < 0 || match[groupOffset+1] < 0 {
				continue
			}
			code := text.value[match[groupOffset]:match[groupOffset+1]]
			if !sixASCIIDigits(code) {
				continue
			}
			position := text.byteToRune[match[0]]
			baseScore := 110
			if subject {
				baseScore = 140
			}
			score := baseScore + e.contextScore(text, position) - patternIndex
			keepBest(found, candidate{code: code, score: score, position: position})
		}
	}
}

func (e *Extractor) collectGeneric(text preparedText, subject bool, found map[string]candidate) {
	for position := 0; position+6 <= len(text.runes); position++ {
		if position > 0 && isASCIIDigitRune(text.runes[position-1]) {
			continue
		}
		if position+6 < len(text.runes) && isASCIIDigitRune(text.runes[position+6]) {
			continue
		}
		valid := true
		for offset := 0; offset < 6; offset++ {
			if !isASCIIDigitRune(text.runes[position+offset]) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		contextScore := e.contextScore(text, position)
		if e.settings.GenericRequiresKeyword && contextScore == 0 {
			continue
		}
		score := 40 + contextScore
		if subject {
			score = 70 + contextScore
		}
		keepBest(found, candidate{code: string(text.runes[position : position+6]), score: score, position: position})
	}
}

func (e *Extractor) contextScore(text preparedText, position int) int {
	start := position - 80
	if start < 0 {
		start = 0
	}
	end := position + 80
	if end > len(text.runes) {
		end = len(text.runes)
	}
	context := fold(string(text.runes[start:end]))
	score := 0
	for _, keyword := range e.keywords {
		if containsKeyword(context, keyword) {
			score += 30
			break
		}
	}
	for _, keyword := range e.settings.SubjectKeywords {
		if containsKeyword(text.folded, keyword) {
			score += 15
			break
		}
	}
	return score
}

func (e *Extractor) senderAllowed(sender string) bool {
	if len(e.settings.Senders) == 0 && len(e.settings.SenderDomains) == 0 {
		return true
	}
	normalized := sender
	if parsed, err := mail.ParseAddress(sender); err == nil && parsed != nil {
		normalized = parsed.Address
	}
	normalized = fold(strings.TrimSpace(normalized))
	for _, allowed := range e.settings.Senders {
		if normalized == allowed {
			return true
		}
	}
	separator := strings.LastIndexByte(normalized, '@')
	if separator < 0 || separator == len(normalized)-1 {
		return false
	}
	domain := normalized[separator+1:]
	for _, allowed := range e.settings.SenderDomains {
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

func keepBest(found map[string]candidate, item candidate) {
	old, exists := found[item.code]
	if !exists || item.score > old.score || item.score == old.score && item.position < old.position {
		found[item.code] = item
	}
}

func containsKeyword(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	if !isASCIIAlnumSpace(keyword) {
		return strings.Contains(text, keyword)
	}
	for offset := 0; offset <= len(text); {
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
	}
	return false
}

func htmlToText(value string, limit int) string {
	if value == "" || limit <= 0 {
		return ""
	}
	source := truncateRunes(value, limit)
	tokenizer := xhtml.NewTokenizer(strings.NewReader(source))
	var output strings.Builder
	output.Grow(min(len(source), limit))
	length := 0
	skipDepth := 0
	appendVisible := func(value string) {
		if length >= limit || value == "" {
			return
		}
		for _, current := range value {
			if length >= limit {
				break
			}
			output.WriteRune(current)
			length++
		}
	}
	for {
		switch tokenType := tokenizer.Next(); tokenType {
		case xhtml.ErrorToken:
			if errors.Is(tokenizer.Err(), io.EOF) {
				return strings.Join(strings.Fields(output.String()), " ")
			}
			return ""
		case xhtml.TextToken:
			if skipDepth == 0 {
				appendVisible(tokenizer.Token().Data)
			}
		case xhtml.StartTagToken:
			tag := strings.ToLower(tokenizer.Token().Data)
			if _, skipped := skippedHTMLTags[tag]; skipped {
				skipDepth++
			} else if skipDepth == 0 {
				if _, block := blockHTMLTags[tag]; block {
					appendVisible(" ")
				}
			}
		case xhtml.SelfClosingTagToken:
			tag := strings.ToLower(tokenizer.Token().Data)
			if _, block := blockHTMLTags[tag]; block && skipDepth == 0 {
				appendVisible("  ")
			}
		case xhtml.EndTagToken:
			tag := strings.ToLower(tokenizer.Token().Data)
			if _, skipped := skippedHTMLTags[tag]; skipped && skipDepth > 0 {
				skipDepth--
			} else if skipDepth == 0 {
				if _, block := blockHTMLTags[tag]; block {
					appendVisible(" ")
				}
			}
		}
	}
}

func stripURLs(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	var output strings.Builder
	output.Grow(len(value))
	for position := 0; position < len(runes); {
		matched := 0
		if (position == 0 || !regexWord(runes[position-1])) && asciiRunesHavePrefixFold(runes[position:], "https://") {
			matched = len([]rune("https://"))
		} else if (position == 0 || !regexWord(runes[position-1])) && asciiRunesHavePrefixFold(runes[position:], "http://") {
			matched = len([]rune("http://"))
		} else if (position == 0 || !regexWord(runes[position-1])) && asciiRunesHavePrefixFold(runes[position:], "www.") {
			matched = len([]rune("www."))
		}
		if matched == 0 {
			output.WriteRune(runes[position])
			position++
			continue
		}
		position += matched
		for position < len(runes) && !unicode.IsSpace(runes[position]) {
			position++
		}
		output.WriteByte(' ')
	}
	return output.String()
}

func normalizeList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = fold(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeDomains(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimLeft(fold(strings.TrimSpace(value)), "@")
		if value == "" || !strings.Contains(value, ".") || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
			return nil, ErrInvalidSettings
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func countSubexpression(names []string, expected string) int {
	count := 0
	for _, name := range names {
		if name == expected {
			count++
		}
	}
	return count
}

func fold(value string) string { return unicodeFold.String(value) }

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

func sixASCIIDigits(value string) bool {
	if len(value) != 6 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func isASCIIDigitRune(value rune) bool { return value >= '0' && value <= '9' }

func isASCIIAlnumSpace(value string) bool {
	for _, current := range value {
		if current > unicode.MaxASCII || !(current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || unicode.IsSpace(current)) {
			return false
		}
	}
	return true
}

func asciiWord(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func regexWord(value rune) bool {
	return value == '_' || unicode.IsLetter(value) || unicode.IsNumber(value)
}

func asciiRunesHavePrefixFold(value []rune, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index, expected := range []byte(prefix) {
		current := value[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		if current != rune(expected) {
			return false
		}
	}
	return true
}
