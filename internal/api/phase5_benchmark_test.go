package api

import (
	"net/http"
	"testing"

	"github.com/LinYS77/coderelay/internal/ratelimit"
	"github.com/LinYS77/coderelay/internal/totp"
)

// BenchmarkPhase5TOTPHandler is the synthetic, credential-safe workload used
// for CPU and heap pprof capture. Rate limiting is made effectively infinite in
// this benchmark only so the profile measures the full authenticated handler.
func BenchmarkPhase5TOTPHandler(b *testing.B) {
	handler, token, cancel := newTestHandler(b, totp.New(), nil)
	defer cancel()
	handler.ipLimiter = ratelimit.New(1_000_000_000, 1_000_000_000, 1)
	handler.principalLimiter = ratelimit.New(1_000_000_000, 1_000_000_000, 1)
	payload := []byte(`{"type":"totp","credential":"` + testTOTPSecret + `","min_ttl":0}`)
	authorization := string(token)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(iterations *testing.PB) {
		for iterations.Next() {
			response := perform(handler, http.MethodPost, "/api/v1/code", payload, authorization)
			if response.Code != http.StatusOK {
				b.Errorf("status=%d body=%s", response.Code, response.Body.String())
				return
			}
		}
	})
}
