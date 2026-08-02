package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestDecodeOutlookCommand(t *testing.T) {
	fields, err := decodeRootObject([]byte(`{"type":"outlook","credential":"user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----` + strings.Repeat("r", 120) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer clearRawFields(fields)
	command, err := decodeOutlookCommand(fields, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer command.Destroy()
	if command.Provider != domain.ProviderOutlook || command.WaitSeconds != 20 || command.Credential == nil {
		t.Fatalf("command = %+v", command)
	}
}

func TestDecodeOutlookDefaultWaitHonorsMax(t *testing.T) {
	fields := map[string]json.RawMessage{
		"type":       json.RawMessage(`"outlook"`),
		"credential": json.RawMessage(`"user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"`),
	}
	if _, err := decodeOutlookCommand(fields, 10, time.Now()); err == nil {
		t.Fatal("default wait exceeded max was accepted")
	}
	for key, value := range fields {
		clear(value)
		delete(fields, key)
	}
}
