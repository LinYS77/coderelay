package outlook

import (
	"encoding/json"
	"testing"
)

func TestParseExpiresRejectsWrongJSONTypesAndClamps(t *testing.T) {
	for _, raw := range []string{`"3600"`, `null`, `1.5`, `{}`} {
		if _, ok := parseExpires(json.RawMessage(raw)); ok {
			t.Fatalf("parseExpires accepted %s", raw)
		}
	}
	if got, ok := parseExpires(json.RawMessage(`1`)); !ok || got != 60 {
		t.Fatalf("low expires = %d/%v", got, ok)
	}
	if got, ok := parseExpires(json.RawMessage(`999999`)); !ok || got != 86400 {
		t.Fatalf("high expires = %d/%v", got, ok)
	}
}
