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

func TestResolverMapsFlySMSRequest(t *testing.T) {
	provider := &fakeFlySMSProvider{code: [6]byte{'6', '5', '4', '3', '2', '1'}}
	resolver := NewResolver(totp.New(), provider)
	notBefore := time.Now().UTC().Add(-time.Second)
	command := &domain.Command{
		Provider:    domain.ProviderFlySMS,
		Credential:  credential.NewOwned([]byte("fly-request-secret")),
		NotBefore:   &notBefore,
		WaitSeconds: 7,
	}
	defer command.Destroy()
	result, err := resolver.Resolve(context.Background(), command)
	if err != nil || string(result.Code[:]) != "654321" || provider.wait != 7 || provider.notBefore == nil {
		t.Fatalf("result=%q error=%v wait=%d", result.Code, err, provider.wait)
	}
	result.Destroy()
}

type fakeFlySMSProvider struct {
	code      [6]byte
	wait      int
	notBefore *time.Time
}

func (p *fakeFlySMSProvider) Resolve(_ context.Context, _ *credential.Secret, notBefore *time.Time, wait int) ([6]byte, error) {
	p.wait = wait
	p.notBefore = notBefore
	return p.code, nil
}
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
