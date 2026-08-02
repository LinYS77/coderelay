package flysms

import (
	"net/url"
	"strings"
	"testing"
)

const (
	testEmail = "box.name@icloud.com"
	testToken = "tok_test-token_with-safe-characters_123456"
)

func validCredential(email, token string) string {
	return email + "---" + token + "---https://flysms.xyz/icloud/pickup#email=" + url.QueryEscape(email) + "&key=" + url.QueryEscape(token)
}

func TestParseCredentialValidatesAllThreeComponents(t *testing.T) {
	parsed, err := ParseCredential([]byte(validCredential("Box.Name@iCloud.com", testToken)))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	if parsed.Email != testEmail || string(parsed.Token) != testToken {
		t.Fatal("credential was not normalized correctly")
	}
	reversed := testEmail + "---" + testToken + "---https://flysms.xyz/icloud/pickup#key=" + url.QueryEscape(testToken) + "&email=" + url.QueryEscape(testEmail)
	other, err := ParseCredential([]byte(reversed))
	if err != nil {
		t.Fatalf("reversed fragment order: %v", err)
	}
	other.Destroy()
}

func TestParseCredentialRejectsSSRFAndAmbiguousFragments(t *testing.T) {
	valid := validCredential(testEmail, testToken)
	cases := []string{
		"missing-separators",
		strings.Replace(valid, "https://", "http://", 1),
		strings.Replace(valid, "flysms.xyz", "example.com", 1),
		strings.Replace(valid, "flysms.xyz", "flysms.xyz:443", 1),
		strings.Replace(valid, "flysms.xyz", "flysms.xyz:", 1),
		strings.Replace(valid, "flysms.xyz", "user@flysms.xyz", 1),
		strings.Replace(valid, "/icloud/pickup", "/icloud/other", 1),
		strings.Replace(valid, "/icloud/pickup", "/icloud/%70ickup", 1),
		strings.Replace(valid, "/icloud/pickup#", "/icloud/pickup?next=evil#", 1),
		valid + "&extra=value",
		valid + "&email=" + url.QueryEscape(testEmail),
		strings.Replace(valid, "&key=", ";key=", 1),
		strings.Replace(valid, "email=", "email=%ZZ", 1),
		strings.Replace(valid, "key="+testToken, "key=tok_different-safe-token_123456", 1),
		strings.Replace(valid, testEmail+"---", "not-an-email---", 1),
		strings.Replace(valid, testToken+"---", "token-without-prefix---", 1),
	}
	for _, value := range cases {
		if parsed, err := ParseCredential([]byte(value)); err == nil {
			parsed.Destroy()
			t.Fatalf("invalid credential accepted")
		} else if strings.Contains(err.Error(), testEmail) || strings.Contains(err.Error(), testToken) {
			t.Fatal("credential entered parser error")
		}
	}
}
