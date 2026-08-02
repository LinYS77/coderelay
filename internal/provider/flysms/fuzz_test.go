package flysms

import (
	"testing"
	"unicode/utf8"
)

func FuzzCredentialParser(f *testing.F) {
	f.Add([]byte(validCredential(testEmail, testToken)))
	f.Add([]byte("invalid"))
	f.Add([]byte("a@b.example---tok_1234567890123456---https://example.com/icloud/pickup#email=a%40b.example&key=tok_1234567890123456"))
	f.Fuzz(func(t *testing.T, value []byte) {
		parsed, err := ParseCredential(value)
		if err != nil {
			return
		}
		defer parsed.Destroy()
		if !utf8.ValidString(parsed.Email) || !tokenPattern.Match(parsed.Token) {
			t.Fatal("successful parse violated credential invariants")
		}
	})
}
