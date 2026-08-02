package probe

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

const maxCredentialBytes = 70_000

// Credential contains only the three Outlook fields used by OAuth/IMAP. The
// compatibility password is validated and discarded during parsing.
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

func ReadCredentialFile(path string) (*Credential, error) {
	if path == "" {
		return nil, stageError("credential", "FILE_REQUIRED", errors.New("credential file is required"))
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, stageError("credential", "FILE_OPEN_FAILED", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, stageError("credential", "FILE_NOT_REGULAR", errors.New("credential file must be a regular non-symlink file"))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, stageError("credential", "FILE_PERMISSIONS", errors.New("credential file permissions are too broad"))
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, stageError("credential", "FILE_OWNER", errors.New("credential file is not owned by the current user"))
	}
	if info.Size() <= 0 || info.Size() > maxCredentialBytes {
		return nil, stageError("credential", "FILE_SIZE", errors.New("credential file size is invalid"))
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, stageError("credential", "FILE_OPEN_FAILED", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, stageError("credential", "FILE_OPEN_FAILED", errors.New("failed to create file handle"))
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, stageError("credential", "FILE_CHANGED", errors.New("credential file changed while opening"))
	}

	raw := make([]byte, info.Size())
	if _, err := io.ReadFull(f, raw); err != nil {
		clear(raw)
		return nil, stageError("credential", "FILE_READ_FAILED", err)
	}
	var extra [1]byte
	n, readErr := f.Read(extra[:])
	if n != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		clear(extra[:])
		clear(raw)
		return nil, stageError("credential", "FILE_CHANGED", errors.New("credential file changed while reading"))
	}
	clear(extra[:])
	defer clear(raw)
	return ParseCredential(raw)
}

func ParseCredential(raw []byte) (*Credential, error) {
	trimmed := bytes.TrimRight(raw, "\r\n")
	parts := bytes.SplitN(trimmed, []byte("----"), 4)
	if len(parts) != 4 {
		return nil, stageError("credential", "INVALID_FORMAT", errors.New("expected four fields"))
	}

	email := bytes.TrimSpace(parts[0])
	passwordField := parts[1]
	password := bytes.TrimSpace(passwordField)
	clientID := bytes.TrimSpace(parts[2])
	refreshToken := bytes.TrimSpace(parts[3])
	if len(password) == 0 {
		return nil, stageError("credential", "EMPTY_PASSWORD_FIELD", errors.New("compatibility password is empty"))
	}
	defer clear(passwordField)

	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}
	normalizedClientID, err := normalizeUUID(clientID)
	if err != nil {
		clear(normalizedEmail)
		return nil, err
	}
	if err := validateRefreshToken(refreshToken); err != nil {
		clear(normalizedEmail)
		clear(normalizedClientID)
		return nil, err
	}

	return &Credential{
		Email:        normalizedEmail,
		ClientID:     normalizedClientID,
		RefreshToken: bytes.Clone(refreshToken),
	}, nil
}

func normalizeEmail(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > 320 || !utf8.Valid(value) || bytes.Count(value, []byte{'@'}) != 1 {
		return nil, stageError("credential", "INVALID_EMAIL", errors.New("email has invalid shape"))
	}
	for remaining := value; len(remaining) > 0; {
		r, size := utf8.DecodeRune(remaining)
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return nil, stageError("credential", "INVALID_EMAIL", errors.New("email has invalid shape"))
		}
		remaining = remaining[size:]
	}
	at := bytes.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 || bytes.IndexByte(value[at+1:], '.') < 0 {
		return nil, stageError("credential", "INVALID_EMAIL", errors.New("email has invalid shape"))
	}
	out := bytes.Clone(value)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		}
	}
	return out, nil
}

func normalizeUUID(value []byte) ([]byte, error) {
	s := strings.TrimSpace(string(value))
	s = strings.TrimPrefix(strings.TrimSuffix(s, "}"), "{")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return nil, stageError("credential", "INVALID_CLIENT_ID", errors.New("client ID is not a UUID"))
	}
	decoded := make([]byte, 16)
	if _, err := hex.Decode(decoded, []byte(s)); err != nil {
		clear(decoded)
		return nil, stageError("credential", "INVALID_CLIENT_ID", errors.New("client ID is not a UUID"))
	}
	clear(decoded)
	s = strings.ToLower(s)
	normalized := fmt.Sprintf("%s-%s-%s-%s-%s", s[:8], s[8:12], s[12:16], s[16:20], s[20:])
	return []byte(normalized), nil
}

func validateRefreshToken(value []byte) error {
	if !utf8.Valid(value) {
		return stageError("credential", "INVALID_REFRESH_TOKEN", errors.New("refresh token is not valid UTF-8"))
	}
	count := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			return stageError("credential", "INVALID_REFRESH_TOKEN", errors.New("refresh token is not valid UTF-8"))
		}
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return stageError("credential", "INVALID_REFRESH_TOKEN", errors.New("refresh token contains whitespace or control characters"))
		}
		count++
		value = value[size:]
	}
	if count < 100 || count > 65_536 {
		return stageError("credential", "INVALID_REFRESH_TOKEN", errors.New("refresh token length is invalid"))
	}
	return nil
}

// ValidateSecretOutputPath verifies the rotation sink before OAuth can rotate
// a token. It creates and removes a 0600 probe file in the target directory,
// but never truncates or replaces the target.
func ValidateSecretOutputPath(path string) error {
	if err := validateSecretTarget(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	probe, err := os.CreateTemp(dir, ".coderelay-phase0-preflight-*")
	if err != nil {
		return stageError("rotation", "OUTPUT_CREATE_FAILED", err)
	}
	probePath := probe.Name()
	defer os.Remove(probePath)
	if err := probe.Chmod(0o600); err != nil {
		_ = probe.Close()
		return stageError("rotation", "OUTPUT_CHMOD_FAILED", err)
	}
	if err := probe.Close(); err != nil {
		return stageError("rotation", "OUTPUT_CLOSE_FAILED", err)
	}
	return nil
}

func validateSecretTarget(path string) error {
	if path == "" {
		return stageError("rotation", "OUTPUT_REQUIRED", errors.New("rotation output path is required"))
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return stageError("rotation", "OUTPUT_UNSAFE", errors.New("existing rotation output is unsafe"))
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
			return stageError("rotation", "OUTPUT_UNSAFE", errors.New("existing rotation output has a different owner"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return stageError("rotation", "OUTPUT_CHECK_FAILED", err)
	}
	return nil
}

// WriteSecretAtomic writes a caller-managed secret without following a target
// symlink. Existing targets must already satisfy the same owner/mode checks.
func WriteSecretAtomic(path string, secret []byte) error {
	if err := validateSecretTarget(path); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".coderelay-phase0-rotation-*")
	if err != nil {
		return stageError("rotation", "OUTPUT_CREATE_FAILED", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return stageError("rotation", "OUTPUT_CHMOD_FAILED", err)
	}
	payload := make([]byte, len(secret)+1)
	copy(payload, secret)
	payload[len(payload)-1] = '\n'
	defer clear(payload)
	if _, err := tmp.Write(payload); err != nil {
		return stageError("rotation", "OUTPUT_WRITE_FAILED", err)
	}
	if err := tmp.Sync(); err != nil {
		return stageError("rotation", "OUTPUT_SYNC_FAILED", err)
	}
	if err := tmp.Close(); err != nil {
		return stageError("rotation", "OUTPUT_CLOSE_FAILED", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return stageError("rotation", "OUTPUT_RENAME_FAILED", err)
	}
	committed = true
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}
