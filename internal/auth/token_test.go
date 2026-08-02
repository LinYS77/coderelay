package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LinYS77/coderelay/internal/config"
)

func TestGenerateHashAndVerify(t *testing.T) {
	token, stored, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	defer clear(stored)
	if !strings.HasPrefix(string(token), "cr_live_") || len(token) < 40 {
		t.Fatal("generated token shape is invalid")
	}
	parsed, err := parseHash(stored)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &Verifier{hashes: [][32]byte{parsed, {}}}
	principal, valid := verifier.Verify(token)
	if !valid || len(principal) != 16 {
		t.Fatalf("valid=%v principal length=%d", valid, len(principal))
	}
	invalid := append([]byte(nil), token...)
	invalid[len(invalid)-1] ^= 1
	defer clear(invalid)
	if _, valid := verifier.Verify(invalid); valid {
		t.Fatal("invalid token was accepted")
	}
}

const testAPIToken = "cr_" + "live_" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func TestLoadVerifierFromSecureFiles(t *testing.T) {
	token := []byte(testAPIToken)
	hash, err := HashToken(token)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	defer clear(hash)
	path := filepath.Join(t.TempDir(), "api.sha256")
	if err := os.WriteFile(path, append(hash, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := LoadVerifier(config.SecurityConfig{
		APITokenHashFiles:       []string{path},
		StrictSecretPermissions: true,
	})
	if err != nil {
		t.Fatalf("LoadVerifier: %v", err)
	}
	candidate := []byte(testAPIToken)
	defer clear(candidate)
	if _, valid := verifier.Verify(candidate); !valid {
		t.Fatal("loaded verifier rejected token")
	}
}

func TestMalformedHashIsRejectedWithoutEcho(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(path, []byte("sha256$not-a-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadVerifier(config.SecurityConfig{APITokenHashFiles: []string{path}, StrictSecretPermissions: true})
	if err == nil {
		t.Fatal("malformed hash was accepted")
	}
	if strings.Contains(err.Error(), "not-a-hash") {
		t.Fatal("malformed secret was echoed in error")
	}
}
