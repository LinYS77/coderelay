package outlook

import (
	"bytes"
	"strings"
	"testing"
)

func testRefreshToken(prefix byte) []byte {
	return []byte(strings.Repeat(string(prefix), 120))
}

func TestParseCredentialDiscardsPasswordAndNormalizes(t *testing.T) {
	refresh := testRefreshToken('r')
	source := []byte(" User@Example.COM ---- compatibility-password ---- {550e8400-e29b-41d4-a716-446655440000} ---- " + string(refresh) + "\r\n")
	parsed, err := ParseCredential(source)
	if err != nil {
		t.Fatalf("ParseCredential() error = %v", err)
	}
	defer parsed.Destroy()
	if got, want := string(parsed.Email), "user@example.com"; got != want {
		t.Fatalf("email = %q, want %q", got, want)
	}
	if got, want := string(parsed.ClientID), "550e8400-e29b-41d4-a716-446655440000"; got != want {
		t.Fatalf("client ID = %q, want %q", got, want)
	}
	if !bytes.Equal(parsed.RefreshToken, refresh) {
		t.Fatal("refresh token changed")
	}
	if bytes.Contains(parsed.Email, []byte("password")) || bytes.Contains(parsed.RefreshToken, []byte("password")) {
		t.Fatal("compatibility password entered parsed credential")
	}
}

func TestParseCredentialUsesUnicodeCasefold(t *testing.T) {
	refresh := testRefreshToken('u')
	parsed, err := ParseCredential([]byte("Straße@Example.COM----pw----550e8400-e29b-41d4-a716-446655440000----" + string(refresh)))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	if string(parsed.Email) != "strasse@example.com" {
		t.Fatalf("email = %q", parsed.Email)
	}
}

func TestParseCredentialPreservesRefreshTokenSeparators(t *testing.T) {
	refresh := append(testRefreshToken('x'), []byte("----tail")...)
	value := []byte("a@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + string(refresh))
	parsed, err := ParseCredential(value)
	if err != nil {
		t.Fatalf("ParseCredential() error = %v", err)
	}
	defer parsed.Destroy()
	if !bytes.Equal(parsed.RefreshToken, refresh) {
		t.Fatalf("refresh token = %q, want %q", parsed.RefreshToken, refresh)
	}
}

func TestParseCredentialRejectsInvalidRefreshWhitespace(t *testing.T) {
	base := "a@example.com----pw----550e8400-e29b-41d4-a716-446655440000----"
	for _, whitespace := range []string{"\t", "\u00a0", "\u2003"} {
		value := []byte(base + strings.Repeat("x", 110) + whitespace + "x")
		if _, err := ParseCredential(value); err == nil {
			t.Fatalf("ParseCredential accepted whitespace %q", whitespace)
		}
	}
}

func TestCredentialWithRefreshTokenCopies(t *testing.T) {
	old := testRefreshToken('a')
	credential, err := ParseCredential([]byte("a@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + string(old)))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	newToken := testRefreshToken('b')
	updated, err := credential.WithRefreshToken(newToken)
	if err != nil {
		t.Fatal(err)
	}
	newToken[0] = 'z'
	if updated.RefreshToken[0] != 'b' {
		t.Fatal("updated credential aliases caller token")
	}
	updated.Destroy()
}
