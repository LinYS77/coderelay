package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/totp"
)

func TestResolverMapsTOTPAndDomainErrors(t *testing.T) {
	provider := totp.NewWithClock(func() time.Time { return time.Unix(1_111_111_111, 0) })
	resolver := NewResolver(provider)
	command := &domain.Command{
		Provider:   domain.ProviderTOTP,
		Credential: credential.NewOwned([]byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
		MinTTL:     0,
	}
	defer command.Destroy()
	result, err := resolver.Resolve(context.Background(), command)
	if err != nil || string(result.Code[:]) != "050471" {
		t.Fatalf("result=%q error=%v", result.Code, err)
	}
	result.Destroy()

	invalid := &domain.Command{Provider: domain.ProviderTOTP, Credential: credential.NewOwned([]byte("invalid!"))}
	defer invalid.Destroy()
	if _, err := resolver.Resolve(context.Background(), invalid); !errors.Is(err, domain.ErrInvalidCodeRequest) {
		t.Fatalf("invalid credential error=%v", err)
	}
	unsupported := &domain.Command{Provider: "outlook", Credential: credential.NewOwned([]byte("request-secret"))}
	defer unsupported.Destroy()
	if _, err := resolver.Resolve(context.Background(), unsupported); !errors.Is(err, domain.ErrInvalidCodeRequest) {
		t.Fatalf("unsupported provider error=%v", err)
	}
}
