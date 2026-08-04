package outlook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestProviderPollingReusesSessionAndReturnsRotation(t *testing.T) {
	rotated := testRefreshToken('z')
	oauthServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"access_token":"access","expires_in":3600,"scope":"https://outlook.office.com/imap.accessasuser.all","refresh_token":"` + string(rotated) + `"}`))
	}))
	defer oauthServer.Close()
	oauth := newOAuthClientForTest(oauthServer.URL, oauthServer.Client(), time.Second)
	provider := newProviderForTest(config.OutlookConfig{PollIntervalSeconds: 0.01, MaxMessages: 1, MaxMessageBytes: 64 << 10}, oauth)
	var opens atomic.Int32
	var serverDone <-chan error
	provider.openOverride = func(ctx context.Context, parsed *Credential, access []byte) (*imapSession, error) {
		opens.Add(1)
		if string(access) != "access" {
			return nil, fmt.Errorf("unexpected access token")
		}
		session, done, err := newPreselectedSession(ctx, parsed.Email, access, [][]byte{
			[]byte("From: Service <service@example.com>\r\nSubject: Old\r\nContent-Type: text/plain\r\n\r\nNo code here\r\n"),
			[]byte("From: Service <service@example.com>\r\nSubject: Verification\r\nContent-Type: text/plain\r\n\r\nYour verification code is 654321\r\n"),
		})
		serverDone = done
		return session, err
	}
	secret := credential.NewOwned([]byte("user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + strings.Repeat("r", 120)))
	defer secret.Destroy()
	code, update, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, WaitSeconds: 1, MailAccess: domain.OutlookMailAccessIMAP})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if string(code[:]) != "654321" || update == nil || string(update.RefreshToken) != string(rotated) {
		t.Fatalf("result code=%q update=%q", code, update.RefreshToken)
	}
	update.Destroy()
	if opens.Load() != 1 {
		t.Fatalf("session opens = %d, want 1", opens.Load())
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func newPreselectedSession(ctx context.Context, email, access []byte, rawMessages [][]byte) (*imapSession, <-chan error, error) {
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	conn := newCappedDeadlineConn(clientConn, deadline)
	client := imapclient.New(conn, &imapclient.Options{})
	session := &imapSession{conn: conn, client: client, stageLimit: 2 * time.Second}
	done := make(chan error, 1)
	go func() { done <- servePreselectedIMAP(serverConn, email, access, rawMessages) }()
	if err := client.WaitGreeting(); err != nil {
		session.Abort()
		return nil, done, err
	}
	if err := session.authenticate(ctx, email, access); err != nil {
		session.Abort()
		return nil, done, err
	}
	if _, err := session.selectReadOnly(ctx); err != nil {
		session.Abort()
		return nil, done, err
	}
	return session, done, nil
}

func servePreselectedIMAP(conn net.Conn, email, access []byte, rawMessages [][]byte) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(value string) error { _, err := io.WriteString(conn, value); return err }
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
	if err := write("* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2] ready\r\n"); err != nil {
		return err
	}
	line, err := readCommand()
	if err != nil {
		return err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 || !strings.EqualFold(parts[1], "AUTHENTICATE") {
		return fmt.Errorf("unexpected auth %q", line)
	}
	tag := parts[0]
	if err := write("+ \r\n"); err != nil {
		return err
	}
	encoded, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return err
	}
	want := append([]byte("user="), email...)
	want = append(want, '\x01')
	want = append(want, "auth=Bearer "...)
	want = append(want, access...)
	want = append(want, '\x01', '\x01')
	if !bytes.Equal(got, want) {
		return imapserver.ErrAuthFailed
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
	if len(parts) < 3 || !strings.EqualFold(parts[1], "EXAMINE") {
		return fmt.Errorf("unexpected select %q", line)
	}
	tag = parts[0]
	if err := write("* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n" + tag + " OK [READ-ONLY] selected\r\n"); err != nil {
		return err
	}
	for _, raw := range rawMessages {
		line, err = readCommand()
		if err != nil {
			return err
		}
		parts = strings.Fields(line)
		if len(parts) < 2 {
			return fmt.Errorf("unexpected command %q", line)
		}
		tag = parts[0]
		if strings.EqualFold(parts[1], "NOOP") {
			if err := write(tag + " OK noop\r\n"); err != nil {
				return err
			}
			line, err = readCommand()
			if err != nil {
				return err
			}
			parts = strings.Fields(line)
			tag = parts[0]
		}
		if len(parts) < 2 || !strings.EqualFold(parts[1], "FETCH") {
			return fmt.Errorf("unexpected fetch %q", line)
		}
		response := fmt.Sprintf("* 1 FETCH (UID 1 INTERNALDATE \"%s\" BODY[]<0> {%d}\r\n%s)\r\n%s OK fetch\r\n", time.Now().UTC().Format("02-Jan-2006 15:04:05 +0000"), len(raw), raw, tag)
		if err := write(response); err != nil {
			return err
		}
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
