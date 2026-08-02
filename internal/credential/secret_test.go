package credential

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretRedactsAndRefusesSerialization(t *testing.T) {
	value := []byte("sensitive-value")
	secret := NewOwned(value)
	if secret.String() != "[REDACTED]" || secret.GoString() != "[REDACTED]" {
		t.Fatal("secret string representation is not redacted")
	}
	if secret.LogValue().String() != "[REDACTED]" {
		t.Fatal("secret slog representation is not redacted")
	}
	if _, err := json.Marshal(secret); err == nil {
		t.Fatal("secret JSON serialization unexpectedly succeeded")
	}
	var output strings.Builder
	logger := slog.New(slog.NewTextHandler(&output, nil))
	logger.Info("test", "secret", secret)
	if strings.Contains(output.String(), "sensitive-value") {
		t.Fatal("secret entered slog output")
	}
	secret.Destroy()
	for _, current := range value {
		if current != 0 {
			t.Fatal("owned secret bytes were not cleared")
		}
	}
}
