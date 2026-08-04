// Package domain defines provider-neutral request and result types.
package domain

import (
	"errors"
	"time"

	"github.com/LinYS77/coderelay/internal/credential"
)

type Provider string

type OutlookMailAccess string

const (
	ProviderTOTP    Provider = "totp"
	ProviderFlySMS  Provider = "flysms"
	ProviderOutlook Provider = "outlook"

	OutlookMailAccessIMAP  OutlookMailAccess = "imap"
	OutlookMailAccessGraph OutlookMailAccess = "graph"
)

var ErrInvalidCodeRequest = errors.New("invalid verification-code request")

type Command struct {
	Provider          Provider
	Credential        *credential.Secret
	MinTTL            int
	NotBefore         *time.Time
	WaitSeconds       int
	OutlookMailAccess OutlookMailAccess
}

func (c *Command) Destroy() {
	if c == nil {
		return
	}
	c.Credential.Destroy()
	c.Credential = nil
	c.Provider = ""
	c.MinTTL = 0
	c.NotBefore = nil
	c.WaitSeconds = 0
	c.OutlookMailAccess = ""
}

type OutlookRequest struct {
	Credential  *credential.Secret
	NotBefore   *time.Time
	WaitSeconds int
	MailAccess  OutlookMailAccess
}

type Result struct {
	Code             [6]byte
	CredentialUpdate *CredentialUpdate
}

func (r *Result) Destroy() {
	if r == nil {
		return
	}
	clear(r.Code[:])
	if r.CredentialUpdate != nil {
		r.CredentialUpdate.Destroy()
		r.CredentialUpdate = nil
	}
}
