// Package credential contains request-scoped secret containers.
package credential

import (
	"encoding/json"
	"errors"
	"log/slog"
)

var ErrSecretSerialization = errors.New("secret serialization is forbidden")

type Secret struct {
	value []byte
}

// NewOwned takes ownership of value. Callers must not retain or mutate it.
func NewOwned(value []byte) *Secret {
	return &Secret{value: value}
}

// Bytes returns the request-scoped bytes for immediate provider use. Callers
// must not retain the slice beyond the call.
func (s *Secret) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.value
}

func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	clear(s.value)
	s.value = nil
}

func (*Secret) String() string   { return "[REDACTED]" }
func (*Secret) GoString() string { return "[REDACTED]" }

func (*Secret) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

func (*Secret) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func (*Secret) MarshalText() ([]byte, error) {
	return nil, ErrSecretSerialization
}

var _ json.Marshaler = (*Secret)(nil)
var _ slog.LogValuer = (*Secret)(nil)
