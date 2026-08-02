package outlook

import (
	"bytes"
	"testing"
)

func TestXOAUTH2StartAndDestroyDoNotClearCallerBuffers(t *testing.T) {
	email := []byte("user@example.com")
	token := []byte("access-token")
	client := newXOAUTH2Client(email, token)
	mechanism, response, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	if mechanism != "XOAUTH2" {
		t.Fatalf("mechanism = %q", mechanism)
	}
	want := []byte("user=user@example.com\x01auth=Bearer access-token\x01\x01")
	if !bytes.Equal(response, want) {
		t.Fatalf("response = %q, want %q", response, want)
	}
	client.Destroy()
	if string(email) != "user@example.com" || string(token) != "access-token" {
		t.Fatal("Destroy cleared caller-owned buffers")
	}
	if !bytes.Equal(response, make([]byte, len(response))) {
		t.Fatal("response buffer was not cleared")
	}
}

func TestXOAUTH2ChallengeReturnsEmptyResponse(t *testing.T) {
	client := newXOAUTH2Client([]byte("u@example.com"), []byte("token"))
	defer client.Destroy()
	response, err := client.Next([]byte(`{"status":"401"}`))
	if err != nil || len(response) != 0 {
		t.Fatalf("Next() = %q, %v", response, err)
	}
}
