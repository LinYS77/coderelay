// Package auth handles CodeRelay API token generation and constant-time verification.
package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/secretfile"
)

const hashPrefix = "sha256$"

var ErrInvalidHash = errors.New("invalid CodeRelay API token hash")

type Verifier struct {
	hashes [][sha256.Size]byte
}

func LoadVerifier(settings config.SecurityConfig) (*Verifier, error) {
	hashes := make([][sha256.Size]byte, 0, len(settings.APITokenHashFiles))
	for _, path := range settings.APITokenHashFiles {
		raw, err := secretfile.Read(path, settings.StrictSecretPermissions, 1<<10)
		if err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(raw)
		hash, err := parseHash(trimmed)
		clear(raw)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("%w: no hashes loaded", ErrInvalidHash)
	}
	return &Verifier{hashes: hashes}, nil
}

// Verify hashes every candidate and compares against every configured hash.
// It never stops after the first match. The returned principal is a truncated
// SHA-256 fingerprint, never the raw bearer token.
func (v *Verifier) Verify(token []byte) (principal string, valid bool) {
	candidate := sha256.Sum256(token)
	matched := 0
	if v != nil {
		for i := range v.hashes {
			matched |= subtle.ConstantTimeCompare(candidate[:], v.hashes[i][:])
		}
	}
	principal = hex.EncodeToString(candidate[:8])
	clear(candidate[:])
	return principal, matched == 1
}

func GenerateToken() (token []byte, storedHash []byte, err error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, nil, err
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(random)))
	base64.RawURLEncoding.Encode(encoded, random)
	clear(random)
	token = make([]byte, 0, len("cr_live_")+len(encoded))
	token = append(token, "cr_live_"...)
	token = append(token, encoded...)
	clear(encoded)
	hash := sha256.Sum256(token)
	storedHash = make([]byte, 0, len(hashPrefix)+hex.EncodedLen(len(hash)))
	storedHash = append(storedHash, hashPrefix...)
	storedHash = hex.AppendEncode(storedHash, hash[:])
	clear(hash[:])
	return token, storedHash, nil
}

func HashToken(token []byte) ([]byte, error) {
	if !bytes.HasPrefix(token, []byte("cr_live_")) || len(token) < 40 || len(token) > 512 {
		return nil, errors.New("API token does not have the expected CodeRelay format")
	}
	hash := sha256.Sum256(token)
	encoded := make([]byte, 0, len(hashPrefix)+64)
	encoded = append(encoded, hashPrefix...)
	encoded = hex.AppendEncode(encoded, hash[:])
	clear(hash[:])
	return encoded, nil
}

func parseHash(value []byte) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != len(hashPrefix)+sha256.Size*2 || !bytes.HasPrefix(value, []byte(hashPrefix)) {
		return result, ErrInvalidHash
	}
	if _, err := hex.Decode(result[:], value[len(hashPrefix):]); err != nil {
		clear(result[:])
		return result, ErrInvalidHash
	}
	return result, nil
}
