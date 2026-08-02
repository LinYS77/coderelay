package flysms

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const pickupURLPrefix = "https://flysms.xyz/icloud/pickup#"

var tokenPattern = regexp.MustCompile(`^tok_[A-Za-z0-9_-]{16,512}$`)

var ErrInvalidCredential = errors.New("invalid FlySMS credential")

type Credential struct {
	Email string
	Token []byte
}

func (c *Credential) Destroy() {
	if c == nil {
		return
	}
	c.Email = ""
	clear(c.Token)
	c.Token = nil
}

func ParseCredential(source []byte) (Credential, error) {
	var empty Credential
	if len(source) == 0 || len(source) > 16_384 || utf8.RuneCount(source) > 4_096 {
		return empty, ErrInvalidCredential
	}
	raw := strings.TrimRight(string(source), "\r\n")
	separator := "---"
	first := strings.Index(raw, separator)
	if first <= 0 {
		return empty, ErrInvalidCredential
	}
	remainder := raw[first+len(separator):]
	marker := "---" + pickupURLPrefix
	urlStart := strings.Index(remainder, marker)
	if urlStart <= 0 {
		return empty, ErrInvalidCredential
	}
	emailPart := raw[:first]
	tokenPart := remainder[:urlStart]
	pickupURL := pickupURLPrefix + remainder[urlStart+len(marker):]
	email, ok := normalizeEmail(emailPart)
	if !ok || !tokenPattern.MatchString(strings.TrimSpace(tokenPart)) {
		return empty, ErrInvalidCredential
	}
	token := []byte(strings.TrimSpace(tokenPart))
	parsed, err := url.Parse(pickupURL)
	if err != nil || !canonicalPickupURL(parsed) {
		clear(token)
		return empty, ErrInvalidCredential
	}
	pairs, err := parseFragment(strings.SplitN(pickupURL, "#", 2)[1])
	if err != nil {
		clear(token)
		return empty, ErrInvalidCredential
	}
	fragmentEmail, ok := normalizeEmail(pairs.Get("email"))
	if !ok || fragmentEmail != email {
		clear(token)
		return empty, ErrInvalidCredential
	}
	fragmentToken := []byte(pairs.Get("key"))
	leftHash := sha256.Sum256(fragmentToken)
	rightHash := sha256.Sum256(token)
	matches := subtle.ConstantTimeCompare(leftHash[:], rightHash[:])
	clear(leftHash[:])
	clear(rightHash[:])
	clear(fragmentToken)
	if matches != 1 {
		clear(token)
		return empty, ErrInvalidCredential
	}
	return Credential{Email: email, Token: token}, nil
}

func canonicalPickupURL(parsed *url.URL) bool {
	return parsed != nil &&
		parsed.Scheme == "https" &&
		strings.EqualFold(parsed.Hostname(), "flysms.xyz") &&
		parsed.Port() == "" &&
		parsed.User == nil &&
		!strings.Contains(parsed.Host, ":") &&
		parsed.Opaque == "" &&
		parsed.RawPath == "" &&
		parsed.Path == "/icloud/pickup" &&
		parsed.RawQuery == "" &&
		!parsed.ForceQuery &&
		parsed.Fragment != ""
}

func parseFragment(raw string) (url.Values, error) {
	if raw == "" || strings.Contains(raw, ";") {
		return nil, ErrInvalidCredential
	}
	parts := strings.Split(raw, "&")
	if len(parts) != 2 {
		return nil, ErrInvalidCredential
	}
	values := make(url.Values, 2)
	for _, part := range parts {
		if strings.Count(part, "=") != 1 {
			return nil, ErrInvalidCredential
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil || key == "" {
			return nil, ErrInvalidCredential
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, ErrInvalidCredential
		}
		if key != "email" && key != "key" || values.Has(key) {
			return nil, ErrInvalidCredential
		}
		values.Add(key, value)
	}
	if len(values["email"]) != 1 || len(values["key"]) != 1 {
		return nil, ErrInvalidCredential
	}
	return values, nil
}

func normalizeEmail(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || utf8.RuneCountInString(value) > 320 || strings.Count(value, "@") != 1 || strings.IndexFunc(value, invalidEmailRune) >= 0 {
		return "", false
	}
	at := strings.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return "", false
	}
	domain := value[at+1:]
	dot := strings.IndexByte(domain, '.')
	if dot <= 0 || dot == len(domain)-1 {
		return "", false
	}
	return strings.Clone(value), true
}

func invalidEmailRune(value rune) bool {
	return unicode.IsSpace(value) || value < 0x20 || value == 0x7f
}
