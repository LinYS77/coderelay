// Package domain defines provider-neutral request and result types.
package domain

import (
	"errors"

	"github.com/LinYS77/coderelay/internal/credential"
)

type Provider string

const ProviderTOTP Provider = "totp"

var ErrInvalidCodeRequest = errors.New("invalid verification-code request")

type Command struct {
	Provider   Provider
	Credential *credential.Secret
	MinTTL     int
}

func (c *Command) Destroy() {
	if c == nil {
		return
	}
	c.Credential.Destroy()
	c.Credential = nil
	c.Provider = ""
	c.MinTTL = 0
}

type Result struct {
	Code [6]byte
}

func (r *Result) Destroy() {
	if r == nil {
		return
	}
	clear(r.Code[:])
}
