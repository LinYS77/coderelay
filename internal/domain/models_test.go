package domain

import (
	"testing"

	"github.com/LinYS77/coderelay/internal/credential"
)

func TestCommandAndResultDestroy(t *testing.T) {
	raw := []byte("request-secret")
	command := &Command{Provider: ProviderTOTP, Credential: credential.NewOwned(raw), MinTTL: 5}
	command.Destroy()
	for _, value := range raw {
		if value != 0 {
			t.Fatal("command credential was not cleared")
		}
	}
	if command.Credential != nil || command.Provider != "" || command.MinTTL != 0 {
		t.Fatal("command references were not released")
	}
	result := Result{Code: [6]byte{'1', '2', '3', '4', '5', '6'}}
	result.Destroy()
	if result.Code != [6]byte{} {
		t.Fatal("result code was not cleared")
	}
}
