package service

import (
	"context"
	"errors"

	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/totp"
)

type TOTPProvider interface {
	Resolve(context.Context, *credential.Secret, int) ([6]byte, error)
}

type Resolver struct {
	totp TOTPProvider
}

func NewResolver(totpProvider TOTPProvider) *Resolver {
	return &Resolver{totp: totpProvider}
}

func (r *Resolver) Resolve(ctx context.Context, command *domain.Command) (domain.Result, error) {
	if r == nil || r.totp == nil || command == nil || command.Provider != domain.ProviderTOTP {
		return domain.Result{}, domain.ErrInvalidCodeRequest
	}
	code, err := r.totp.Resolve(ctx, command.Credential, command.MinTTL)
	if err != nil {
		clear(code[:])
		if errors.Is(err, totp.ErrInvalidCredential) || errors.Is(err, totp.ErrInvalidMinTTL) {
			return domain.Result{}, domain.ErrInvalidCodeRequest
		}
		return domain.Result{}, err
	}
	return domain.Result{Code: code}, nil
}
