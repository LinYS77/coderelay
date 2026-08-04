package outlook

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOAuthRefreshRequestBodyIsNotReplayable(t *testing.T) {
	var inspected bool
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		inspected = true
		if request.GetBody != nil {
			t.Fatal("OAuth request unexpectedly exposes a replay body")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if request.ContentLength != int64(len(body)) || !strings.Contains(string(body), "refresh_token=") {
			t.Fatalf("content length=%d body length=%d", request.ContentLength, len(body))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"access","expires_in":3600}`)),
			Request:    request,
		}, nil
	})}
	oauth := newOAuthClientForTest("https://login.microsoftonline.com/common/oauth2/v2.0/token", client, time.Second)
	credential := oauthCredential(t, 'r')
	defer credential.Destroy()
	result, err := oauth.Refresh(t.Context(), &credential)
	if err != nil {
		t.Fatal(err)
	}
	result.Destroy()
	if !inspected {
		t.Fatal("transport was not called")
	}
}

func TestOAuthGraphRefreshRequestBodyIsNotReplayable(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.GetBody != nil {
			t.Fatal("Graph OAuth request unexpectedly exposes a replay body")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "scope=") || !strings.Contains(string(body), "refresh_token=") {
			t.Fatalf("Graph OAuth form=%q", body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"access","expires_in":3600,"scope":"User.Read Mail.Read"}`)),
			Request:    request,
		}, nil
	})}
	oauth := newOAuthClientForTest("https://login.microsoftonline.com/common/oauth2/v2.0/token", client, time.Second)
	credential := oauthCredential(t, 'g')
	defer credential.Destroy()
	result, err := oauth.RefreshFor(t.Context(), &credential, oauthTargetGraph)
	if err != nil {
		t.Fatal(err)
	}
	result.Destroy()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
