// Package totp implements RFC 6238 using only the Go standard library.
package totp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/credential"
)

const attemptTimeout = 35 * time.Second

var (
	ErrInvalidCredential = errors.New("invalid TOTP credential")
	ErrInvalidMinTTL     = errors.New("invalid TOTP minimum TTL")
)

type algorithm uint8

const (
	algorithmSHA1 algorithm = iota
	algorithmSHA256
	algorithmSHA512
)

type parsedCredential struct {
	secret []byte
	algo   algorithm
	period int64
}

func (p *parsedCredential) destroy() {
	clear(p.secret)
	p.secret = nil
}

type Generator struct {
	now  func() time.Time
	wait func(context.Context, time.Duration) error
}

func New() *Generator {
	return NewWithClock(time.Now)
}

// NewWithClock is used by deterministic tests and offline verification tools.
func NewWithClock(now func() time.Time) *Generator {
	if now == nil {
		now = time.Now
	}
	return &Generator{now: now, wait: waitContext}
}

func (g *Generator) Resolve(ctx context.Context, source *credential.Secret, minTTL int) ([6]byte, error) {
	var empty [6]byte
	if g == nil || source == nil || ctx == nil {
		return empty, ErrInvalidCredential
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	nowFn := g.now
	if nowFn == nil {
		nowFn = time.Now
	}
	waitFn := g.wait
	if waitFn == nil {
		waitFn = waitContext
	}
	parsed, err := parse(source.Bytes())
	if err != nil {
		return empty, err
	}
	defer parsed.destroy()
	if minTTL < 0 || int64(minTTL) >= parsed.period {
		return empty, ErrInvalidMinTTL
	}

	operationCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	now := nowFn().UTC()
	for minTTL > 0 {
		remaining := remainingInPeriod(now, parsed.period)
		if remaining >= time.Duration(minTTL)*time.Second {
			break
		}
		if err := waitFn(operationCtx, remaining+time.Millisecond); err != nil {
			return empty, err
		}
		now = nowFn().UTC()
	}
	if err := operationCtx.Err(); err != nil {
		return empty, err
	}
	return generate(parsed, now), nil
}

func parse(source []byte) (*parsedCredential, error) {
	raw := bytes.TrimSpace(source)
	if len(raw) == 0 || len(raw) > 8_192 {
		return nil, ErrInvalidCredential
	}
	if len(raw) >= len("otpauth://") && bytes.EqualFold(raw[:len("otpauth://")], []byte("otpauth://")) {
		return parseURI(raw)
	}
	secret, err := decodeBase32(raw)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	return &parsedCredential{secret: secret, algo: algorithmSHA1, period: 30}, nil
}

func parseURI(raw []byte) (*parsedCredential, error) {
	uri, err := url.Parse(string(raw))
	if err != nil || !strings.EqualFold(uri.Scheme, "otpauth") || uri.User != nil || uri.Fragment != "" || uri.Port() != "" {
		return nil, ErrInvalidCredential
	}
	if !strings.EqualFold(uri.Hostname(), "totp") {
		return nil, ErrInvalidCredential
	}
	labelIssuer, account, err := parseLabel(uri.EscapedPath())
	if err != nil || account == "" {
		return nil, ErrInvalidCredential
	}

	query, err := url.ParseQuery(uri.RawQuery)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	for _, values := range query {
		if len(values) != 1 {
			return nil, ErrInvalidCredential
		}
	}
	if query.Has("counter") || query.Has("encoder") {
		return nil, ErrInvalidCredential
	}
	issuer := query.Get("issuer")
	if issuer != "" && labelIssuer != "" && issuer != labelIssuer {
		return nil, ErrInvalidCredential
	}
	if query.Has("issuer") && strings.TrimSpace(issuer) == "" {
		return nil, ErrInvalidCredential
	}

	secretValue, ok := onlyValue(query, "secret")
	if !ok || secretValue == "" {
		return nil, ErrInvalidCredential
	}
	secret, err := decodeBase32([]byte(secretValue))
	if err != nil {
		return nil, ErrInvalidCredential
	}

	algo := algorithmSHA1
	if query.Has("algorithm") {
		value := query.Get("algorithm")
		switch strings.ToUpper(value) {
		case "SHA1":
			algo = algorithmSHA1
		case "SHA256":
			algo = algorithmSHA256
		case "SHA512":
			algo = algorithmSHA512
		default:
			clear(secret)
			return nil, ErrInvalidCredential
		}
	}
	if query.Has("digits") && query.Get("digits") != "6" {
		clear(secret)
		return nil, ErrInvalidCredential
	}
	period := int64(30)
	if query.Has("period") {
		value := query.Get("period")
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil || parsed < 1 || parsed > 86_400 {
			clear(secret)
			return nil, ErrInvalidCredential
		}
		period = parsed
	}
	return &parsedCredential{secret: secret, algo: algo, period: period}, nil
}

func parseLabel(escapedPath string) (issuer, account string, err error) {
	if !strings.HasPrefix(escapedPath, "/") {
		return "", "", ErrInvalidCredential
	}
	label := strings.TrimPrefix(escapedPath, "/")
	if label == "" || strings.Contains(label, "/") {
		return "", "", ErrInvalidCredential
	}
	issuerPart, accountPart, hasIssuer := strings.Cut(label, ":")
	if !hasIssuer {
		accountPart = issuerPart
		issuerPart = ""
	}
	issuer, err = url.PathUnescape(issuerPart)
	if err != nil {
		return "", "", ErrInvalidCredential
	}
	account, err = url.PathUnescape(accountPart)
	if err != nil || strings.TrimSpace(account) == "" || (hasIssuer && strings.TrimSpace(issuer) == "") {
		return "", "", ErrInvalidCredential
	}
	return issuer, account, nil
}

func onlyValue(values url.Values, key string) (string, bool) {
	items, ok := values[key]
	return first(items), ok && len(items) == 1
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func decodeBase32(source []byte) ([]byte, error) {
	normalized := make([]byte, 0, len(source)+8)
	defer clear(normalized)
	paddingStarted := false
	for len(source) > 0 {
		r, size := utf8.DecodeRune(source)
		if r == utf8.RuneError && size == 1 {
			return nil, ErrInvalidCredential
		}
		source = source[size:]
		if unicode.IsSpace(r) {
			continue
		}
		if r == '=' {
			paddingStarted = true
			normalized = append(normalized, '=')
			continue
		}
		if paddingStarted || r > unicode.MaxASCII {
			return nil, ErrInvalidCredential
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		if !((r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7')) {
			return nil, ErrInvalidCredential
		}
		normalized = append(normalized, byte(r))
	}
	if len(normalized) == 0 {
		return nil, ErrInvalidCredential
	}
	if bytes.IndexByte(normalized, '=') < 0 {
		if remainder := len(normalized) % 8; remainder != 0 {
			for padding := 8 - remainder; padding > 0; padding-- {
				normalized = append(normalized, '=')
			}
		}
	}
	decoded := make([]byte, base32.StdEncoding.DecodedLen(len(normalized)))
	n, err := base32.StdEncoding.Decode(decoded, normalized)
	if err != nil || n == 0 {
		clear(decoded)
		return nil, ErrInvalidCredential
	}
	return decoded[:n], nil
}

func generate(parsed *parsedCredential, now time.Time) [6]byte {
	counter := uint64(now.Unix() / parsed.period)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	var digest func() hash.Hash
	switch parsed.algo {
	case algorithmSHA256:
		digest = sha256.New
	case algorithmSHA512:
		digest = sha512.New
	default:
		digest = sha1.New
	}
	mac := hmac.New(digest, parsed.secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	value %= 1_000_000
	clear(sum)
	clear(message[:])
	var code [6]byte
	for i := len(code) - 1; i >= 0; i-- {
		code[i] = byte('0' + value%10)
		value /= 10
	}
	return code
}

func remainingInPeriod(now time.Time, period int64) time.Duration {
	periodDuration := time.Duration(period) * time.Second
	elapsed := time.Duration(now.UnixNano() % periodDuration.Nanoseconds())
	if elapsed < 0 {
		elapsed += periodDuration
	}
	return periodDuration - elapsed
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
