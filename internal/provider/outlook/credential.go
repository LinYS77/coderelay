// Package outlook implements request-scoped Outlook OAuth with explicit IMAP
// and Microsoft Graph mailbox-access modes.
package outlook

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

const (
	maxCredentialBytes   = 128 << 10
	maxRefreshTokenBytes = 256 << 10
)

var ErrInvalidCredential = errors.New("invalid Outlook credential")

type Credential struct {
	Email        []byte
	ClientID     []byte
	RefreshToken []byte
}

func (c *Credential) Destroy() {
	if c == nil {
		return
	}
	clear(c.Email)
	clear(c.ClientID)
	clear(c.RefreshToken)
	c.Email = nil
	c.ClientID = nil
	c.RefreshToken = nil
}

func (c Credential) WithRefreshToken(value []byte) (Credential, error) {
	if err := validateRefreshToken(value); err != nil {
		return Credential{}, err
	}
	updated := Credential{
		Email:        bytes.Clone(c.Email),
		ClientID:     bytes.Clone(c.ClientID),
		RefreshToken: bytes.Clone(value),
	}
	return updated, nil
}

func ParseCredential(source []byte) (Credential, error) {
	var empty Credential
	if len(source) == 0 || len(source) > maxCredentialBytes || !utf8.Valid(source) {
		return empty, ErrInvalidCredential
	}
	trimmed := bytes.TrimRight(source, "\r\n")
	parts := bytes.SplitN(trimmed, []byte("----"), 4)
	if len(parts) != 4 || len(bytes.TrimSpace(parts[1])) == 0 {
		return empty, ErrInvalidCredential
	}
	email, err := normalizeEmail(parts[0])
	if err != nil {
		return empty, err
	}
	clientID, err := normalizeClientID(parts[2])
	if err != nil {
		clear(email)
		return empty, err
	}
	refresh := bytes.TrimSpace(parts[3])
	if err := validateRefreshToken(refresh); err != nil {
		clear(email)
		clear(clientID)
		return empty, err
	}
	return Credential{Email: email, ClientID: clientID, RefreshToken: bytes.Clone(refresh)}, nil
}

func normalizeEmail(value []byte) ([]byte, error) {
	value = bytes.TrimSpace(value)
	if len(value) == 0 || len(value) > 320 || bytes.Count(value, []byte{'@'}) != 1 {
		return nil, ErrInvalidCredential
	}
	for remaining := value; len(remaining) > 0; {
		r, size := utf8.DecodeRune(remaining)
		if r == utf8.RuneError && size == 1 || unicode.IsSpace(r) || unicode.IsControl(r) {
			return nil, ErrInvalidCredential
		}
		remaining = remaining[size:]
	}
	at := bytes.IndexByte(value, '@')
	domainPart := value[at+1:]
	dot := bytes.IndexByte(domainPart, '.')
	if at <= 0 || len(domainPart) == 0 || dot <= 0 || dot == len(domainPart)-1 {
		return nil, ErrInvalidCredential
	}
	result := cases.Fold().String(string(value))
	if utf8.RuneCountInString(result) > 320 {
		result = ""
		return nil, ErrInvalidCredential
	}
	return []byte(result), nil
}

func normalizeClientID(value []byte) ([]byte, error) {
	text := strings.TrimSpace(string(value))
	text = strings.TrimPrefix(strings.TrimSuffix(text, "}"), "{")
	text = strings.ReplaceAll(text, "-", "")
	if len(text) != 32 {
		return nil, ErrInvalidCredential
	}
	decoded := make([]byte, 16)
	if _, err := hex.Decode(decoded, []byte(text)); err != nil {
		clear(decoded)
		return nil, ErrInvalidCredential
	}
	clear(decoded)
	text = strings.ToLower(text)
	return []byte(text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]), nil
}

func validateRefreshToken(value []byte) error {
	if len(value) > maxRefreshTokenBytes || !utf8.Valid(value) {
		return ErrInvalidCredential
	}
	count := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 || unicode.IsSpace(r) || unicode.IsControl(r) {
			return ErrInvalidCredential
		}
		count++
		value = value[size:]
	}
	if count < 100 || count > 65_536 {
		return ErrInvalidCredential
	}
	return nil
}
