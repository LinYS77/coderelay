package totp

import (
	"bytes"
	"context"
	"testing"

	"github.com/LinYS77/coderelay/internal/credential"
)

func FuzzCredentialParser(f *testing.F) {
	f.Add([]byte(rfcSHA1Base32))
	f.Add([]byte("otpauth://totp/Test?secret=" + rfcSHA1Base32))
	f.Add([]byte("otpauth://hotp/Test?secret=ABC&counter=0"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 8_192 {
			t.Skip()
		}
		owned := append([]byte(nil), input...)
		secret := credential.NewOwned(owned)
		_, err := New().Resolve(context.Background(), secret, 0)
		secret.Destroy()
		if err != nil && len(input) >= 8 && bytes.Contains([]byte(err.Error()), input) {
			t.Fatal("parser error echoed input")
		}
	})
}
