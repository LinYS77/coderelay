// Package secretfile provides no-follow, bounded secret file I/O for Linux.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrUnsafe = errors.New("unsafe secret file")

func Read(path string, strictPermissions bool, maxBytes int64) ([]byte, error) {
	if path == "" || maxBytes <= 0 {
		return nil, fmt.Errorf("%w: invalid secret file parameters", ErrUnsafe)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open secret file", ErrUnsafe)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w: cannot create secret file handle", ErrUnsafe)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: secret path is not a regular file", ErrUnsafe)
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: secret file size is invalid", ErrUnsafe)
	}
	if strictPermissions {
		permissions := info.Mode().Perm()
		if permissions != 0o400 && permissions != 0o600 {
			return nil, fmt.Errorf("%w: secret file must use mode 0400 or 0600", ErrUnsafe)
		}
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%w: secret file owner does not match service user", ErrUnsafe)
	}

	value, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		clear(value)
		return nil, fmt.Errorf("%w: cannot read secret file", ErrUnsafe)
	}
	if int64(len(value)) > maxBytes {
		clear(value)
		return nil, fmt.Errorf("%w: secret file exceeds limit", ErrUnsafe)
	}
	return value, nil
}

func WriteExclusive(path string, value []byte) error {
	if path == "" || len(value) == 0 {
		return fmt.Errorf("%w: invalid secret output", ErrUnsafe)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%w: invalid secret output path", ErrUnsafe)
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("%w: cannot create secret directory", ErrUnsafe)
	}
	fd, err := syscall.Open(absolute, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("%w: refusing to overwrite or follow secret output", ErrUnsafe)
	}
	file := os.NewFile(uintptr(fd), absolute)
	if file == nil {
		_ = syscall.Close(fd)
		_ = os.Remove(absolute)
		return fmt.Errorf("%w: cannot create secret output handle", ErrUnsafe)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(absolute)
		}
	}()
	payload := make([]byte, len(value)+1)
	copy(payload, value)
	payload[len(payload)-1] = '\n'
	defer clear(payload)
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("%w: cannot write secret output", ErrUnsafe)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: cannot sync secret output", ErrUnsafe)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("%w: cannot set secret output permissions", ErrUnsafe)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: cannot close secret output", ErrUnsafe)
	}
	committed = true
	if dir, err := os.Open(directory); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
