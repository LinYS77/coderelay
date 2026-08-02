package service

import (
	"context"
	"errors"
	"time"

	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/totp"
)

type TOTPProvider interface {
	Resolve(context.Context, *credential.Secret, int) ([6]byte, error)
}

type FlySMSProvider interface {
	Resolve(context.Context, *credential.Secret, *time.Time, int) ([6]byte, error)
}

type OutlookProvider interface {
	Resolve(context.Context, *credential.Secret, *time.Time, int) ([6]byte, *domain.CredentialUpdate, error)
}

type Resolver struct {
	totp    TOTPProvider
	flysms  FlySMSProvider
	outlook OutlookProvider
}

func NewResolver(totpProvider TOTPProvider, providers ...any) *Resolver {
	resolver := &Resolver{totp: totpProvider}
	for _, raw := range providers {
		if provider, ok := raw.(FlySMSProvider); ok {
			resolver.flysms = provider
		}
		if provider, ok := raw.(OutlookProvider); ok {
			resolver.outlook = provider
		}
	}
	return resolver
}

func (r *Resolver) Resolve(ctx context.Context, command *domain.Command) (domain.Result, error) {
	if r == nil || command == nil {
		return domain.Result{}, domain.ErrInvalidCodeRequest
	}
	if command.Provider == domain.ProviderTOTP {
		if r.totp == nil {
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
	if command.Provider == domain.ProviderFlySMS {
		if r.flysms == nil {
			return domain.Result{}, domain.ErrInvalidCodeRequest
		}
		code, err := r.flysms.Resolve(ctx, command.Credential, command.NotBefore, command.WaitSeconds)
		if err != nil {
			clear(code[:])
			return domain.Result{}, err
		}
		return domain.Result{Code: code}, nil
	}
	if command.Provider == domain.ProviderOutlook {
		if r.outlook == nil {
			return domain.Result{}, domain.ErrInvalidCodeRequest
		}
		code, update, err := r.outlook.Resolve(ctx, command.Credential, command.NotBefore, command.WaitSeconds)
		if err != nil {
			clear(code[:])
			if update != nil {
				wrapped := domain.WithCredentialUpdate(err, update.RefreshToken)
				update.Destroy()
				return domain.Result{}, wrapped
			}
			return domain.Result{}, err
		}
		return domain.Result{Code: code, CredentialUpdate: update}, nil
	}
	return domain.Result{}, domain.ErrInvalidCodeRequest
}
