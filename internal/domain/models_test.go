package domain

import (
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/credential"
)

func TestCommandAndResultDestroy(t *testing.T) {
	raw := []byte("request-secret")
	now := time.Now()
	command := &Command{Provider: ProviderFlySMS, Credential: credential.NewOwned(raw), MinTTL: 5, NotBefore: &now, WaitSeconds: 20}
	command.Destroy()
	for _, value := range raw {
		if value != 0 {
			t.Fatal("command credential was not cleared")
		}
	}
	if command.Credential != nil || command.Provider != "" || command.MinTTL != 0 || command.NotBefore != nil || command.WaitSeconds != 0 {
		t.Fatal("command references were not released")
	}
	result := Result{Code: [6]byte{'1', '2', '3', '4', '5', '6'}}
	result.Destroy()
	if result.Code != [6]byte{} {
		t.Fatal("result code was not cleared")
	}
}
