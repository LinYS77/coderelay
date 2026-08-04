package outlook

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestGraphHTTPErrorMapping(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		want       error
		retryAfter int
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, want: domain.ErrSourceCredentials},
		{name: "forbidden", status: http.StatusForbidden, want: domain.ErrSourceReauthRequired},
		{name: "rate limited", status: http.StatusTooManyRequests, want: domain.ErrSourceRateLimited, retryAfter: 7},
		{name: "upstream", status: http.StatusBadGateway, want: domain.ErrUpstreamFailure},
		{name: "unsupported client response", status: http.StatusBadRequest, want: domain.ErrUpstreamSchemaChanged},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := mapGraphHTTPError(test.status, "7", stageOutlookGraphList)
			if !errors.Is(err, test.want) || domain.SourceStageOf(err) != stageOutlookGraphList {
				t.Fatalf("error=%v stage=%q", err, domain.SourceStageOf(err))
			}
			if domain.RetryAfter(err) != test.retryAfter {
				t.Fatalf("retry-after=%d", domain.RetryAfter(err))
			}
		})
	}
}

func TestDecodeGraphJSONRejectsDuplicateNestedAndTrailingValues(t *testing.T) {
	for _, raw := range []string{
		`{"value":[{"id":"a","id":"b"}]}`,
		`{"value":[]} {}`,
		strings.Repeat("[", 34) + strings.Repeat("]", 34),
	} {
		var result any
		if err := decodeGraphJSON([]byte(raw), &result); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestGraphLowerBoundUsesNotBeforeWhenStricter(t *testing.T) {
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	notBefore := now.Add(-time.Minute)
	if got := graphLowerBound(now, &notBefore, 600); !got.Equal(notBefore) {
		t.Fatalf("lower=%s want=%s", got, notBefore)
	}
	if got := graphLowerBound(now, nil, 600); !got.Equal(now.Add(-10 * time.Minute)) {
		t.Fatalf("default lower=%s", got)
	}
}

func FuzzGraphJSON(f *testing.F) {
	f.Add([]byte(`{"value":[]}`))
	f.Add([]byte(`{"value":[{"id":"a","id":"b"}]}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var destination any
		_ = decodeGraphJSON(input, &destination)
	})
}
