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

func TestDecodeOutlookMailAccess(t *testing.T) {
	credential := `"user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----` + strings.Repeat("r", 120) + `"`
	for _, test := range []struct {
		name    string
		value   json.RawMessage
		want    domain.OutlookMailAccess
		wantErr bool
	}{
		{name: "omitted defaults to imap", want: domain.OutlookMailAccessIMAP},
		{name: "explicit imap", value: json.RawMessage(`"imap"`), want: domain.OutlookMailAccessIMAP},
		{name: "explicit graph", value: json.RawMessage(`"graph"`), want: domain.OutlookMailAccessGraph},
		{name: "auto is rejected", value: json.RawMessage(`"auto"`), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{
				"type":       json.RawMessage(`"outlook"`),
				"credential": json.RawMessage(credential),
			}
			if test.value != nil {
				fields["mail_access"] = test.value
			}
			command, err := decodeOutlookCommand(fields, 30, time.Now())
			defer clearRawFields(fields)
			if test.wantErr {
				if err == nil {
					command.Destroy()
					t.Fatal("unsupported mail_access was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer command.Destroy()
			if command.OutlookMailAccess != test.want {
				t.Fatalf("mail access=%q, want %q", command.OutlookMailAccess, test.want)
			}
		})
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
