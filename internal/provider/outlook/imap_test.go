package outlook

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
)

func TestIMAPSessionXOAUTH2ReadonlyBatchPeek(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	conn := newCappedDeadlineConn(clientConn, deadline)
	client := imapclient.New(conn, &imapclient.Options{})
	session := &imapSession{conn: conn, client: client, stageLimit: 2 * time.Second}
	defer session.Abort()

	email := []byte("user@example.com")
	token := []byte("access-token")
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveScriptedIMAP(serverConn, email, token, []byte("From: Service <service@example.com>\r\nSubject: Verification code\r\nContent-Type: text/plain\r\n\r\nYour code is 123456\r\n"))
	}()
	if err := client.WaitGreeting(); err != nil {
		t.Fatalf("WaitGreeting() = %v", err)
	}
	if err := session.authenticate(t.Context(), email, token); err != nil {
		select {
		case serverErr := <-serverDone:
			t.Fatalf("authenticate() = %v (server: %v)", err, serverErr)
		default:
			t.Fatalf("authenticate() = %v", err)
		}
	}
	if string(email) != "user@example.com" || string(token) != "access-token" {
		t.Fatal("XOAUTH2 destroyed caller buffers")
	}
	selected, err := session.selectReadOnly(t.Context())
	if err != nil {
		select {
		case serverErr := <-serverDone:
			t.Fatalf("selectReadOnly() = %v (server: %v)", err, serverErr)
		default:
			t.Fatalf("selectReadOnly() = %v", err)
		}
	}
	if selected.NumMessages != 1 || session.selectedMessages != 1 {
		t.Fatalf("NumMessages=%d stored=%d", selected.NumMessages, session.selectedMessages)
	}
	messages, err := session.fetchBatch(t.Context(), 10, 64<<10)
	if err != nil {
		select {
		case serverErr := <-serverDone:
			t.Fatalf("fetchBatch() = %v (server: %v)", err, serverErr)
		default:
			t.Fatalf("fetchBatch() = %v", err)
		}
	}
	if len(messages) != 1 || messages[0].UID != 1 || !strings.Contains(messages[0].Text, "123456") {
		t.Fatalf("messages = %+v", messages)
	}
	for i := range messages {
		messages[i].Destroy()
	}
	session.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestMailboxCountFallsBackToSelectDataWhenSnapshotIsNil(t *testing.T) {
	session := &imapSession{selectedMessages: 42}
	if count := session.captureMailboxCount(); count != 42 {
		t.Fatalf("count=%d, want selected fallback 42", count)
	}
}

func serveScriptedIMAP(conn net.Conn, email, accessToken, raw []byte) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(value string) error {
		_, err := io.WriteString(conn, value)
		return err
	}
	if err := write("* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2] ready\r\n"); err != nil {
		return err
	}
	readCommand := func() (string, error) {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", err
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 && strings.EqualFold(parts[1], "CAPABILITY") {
				if err := write("* CAPABILITY IMAP4rev1 AUTH=XOAUTH2\r\n" + parts[0] + " OK capability\r\n"); err != nil {
					return "", err
				}
				continue
			}
			return line, nil
		}
	}
	line, err := readCommand()
	if err != nil {
		return err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 || !strings.EqualFold(parts[1], "AUTHENTICATE") {
		return fmt.Errorf("unexpected auth command %q", line)
	}
	tag := parts[0]
	if err := write("+ \r\n"); err != nil {
		return err
	}
	encoded, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return err
	}
	want := append([]byte("user="), email...)
	want = append(want, '\x01')
	want = append(want, "auth=Bearer "...)
	want = append(want, accessToken...)
	want = append(want, '\x01', '\x01')
	if !bytes.Equal(decoded, want) {
		return fmt.Errorf("XOAUTH2 response mismatch: %q", decoded)
	}
	clear(want)
	if err := write(tag + " OK authenticated\r\n"); err != nil {
		return err
	}
	line, err = readCommand()
	if err != nil {
		return err
	}
	parts = strings.Fields(line)
	if len(parts) < 3 || !strings.EqualFold(parts[1], "EXAMINE") || !strings.Contains(line, "INBOX") {
		return fmt.Errorf("unexpected examine command %q", line)
	}
	tag = parts[0]
	if err := write("* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n" + tag + " OK [READ-ONLY] selected\r\n"); err != nil {
		return err
	}
	line, err = readCommand()
	if err != nil {
		return err
	}
	parts = strings.Fields(line)
	if len(parts) < 3 || !strings.EqualFold(parts[1], "FETCH") || !strings.Contains(line, "BODY.PEEK") || !strings.Contains(line, "INTERNALDATE") || !strings.Contains(line, "UID") {
		return fmt.Errorf("unexpected fetch command %q", line)
	}
	tag = parts[0]
	date := "01-Jan-2026 00:00:00 +0000"
	response := fmt.Sprintf("* 1 FETCH (UID 1 INTERNALDATE \"%s\" BODY[]<0> {%d}\r\n%s)\r\n%s OK fetch done\r\n", date, len(raw), raw, tag)
	if err := write(response); err != nil {
		return err
	}
	line, err = readCommand()
	if err != nil {
		return err
	}
	parts = strings.Fields(line)
	if len(parts) >= 2 && strings.EqualFold(parts[1], "LOGOUT") {
		return write(parts[0] + " OK logout\r\n")
	}
	return nil
}
