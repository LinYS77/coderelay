package probe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/emersion/go-sasl"
)

type testLiteral struct {
	*bytes.Reader
}

func newTestLiteral(raw []byte) *testLiteral {
	return &testLiteral{Reader: bytes.NewReader(raw)}
}

func (l *testLiteral) Size() int64 {
	return l.Reader.Size()
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...interface{}) {}

type imapTracker struct {
	email []byte
	token []byte

	activeSessions  atomic.Int64
	totalSessions   atomic.Int64
	bodyFetchCalls  atomic.Int64
	flagFetchCalls  atomic.Int64
	noopPollCalls   atomic.Int64
	readonlySelects atomic.Int64
	violations      atomic.Int64

	stallBodyFetch bool
	oversizeBody   bool
	fetchStarted   chan struct{}
	fetchRelease   chan struct{}
	startOnce      sync.Once
	releaseOnce    sync.Once
}

func (t *imapTracker) releaseBlockedFetch() {
	t.releaseOnce.Do(func() { close(t.fetchRelease) })
}

type trackingSession struct {
	*imapmemserver.UserSession
	tracker   *imapTracker
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *trackingSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.tracker.activeSessions.Add(-1)
	})
	return s.UserSession.Close()
}

func (s *trackingSession) AuthenticateMechanisms() []string {
	return []string{"XOAUTH2"}
}

func (s *trackingSession) Authenticate(mechanism string) (sasl.Server, error) {
	if mechanism != "XOAUTH2" {
		return nil, imapserver.ErrAuthFailed
	}
	return &xoauth2TestServer{email: s.tracker.email, token: s.tracker.token}, nil
}

func (s *trackingSession) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if mailbox != "INBOX" || options == nil || !options.ReadOnly {
		s.tracker.violations.Add(1)
	} else {
		s.tracker.readonlySelects.Add(1)
	}
	return s.UserSession.Select(mailbox, options)
}

func (s *trackingSession) Fetch(writer *imapserver.FetchWriter, set imap.NumSet, options *imap.FetchOptions) error {
	if len(options.BodySection) > 0 {
		s.tracker.bodyFetchCalls.Add(1)
		if !options.UID || !options.InternalDate || !options.Flags || len(options.BodySection) != 1 {
			s.tracker.violations.Add(1)
		}
		section := options.BodySection[0]
		if !section.Peek || section.Partial == nil || section.Partial.Offset != 0 || section.Partial.Size != defaultMaxMessageSize {
			s.tracker.violations.Add(1)
		}
		if set.String() != "1:2" {
			s.tracker.violations.Add(1)
		}
		if s.tracker.stallBodyFetch {
			s.tracker.startOnce.Do(func() { close(s.tracker.fetchStarted) })
			<-s.tracker.fetchRelease
			return net.ErrClosed
		}
		if s.tracker.oversizeBody {
			response := writer.CreateMessage(1)
			response.WriteUID(1)
			response.WriteFlags(nil)
			response.WriteInternalDate(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
			oversized := bytes.Repeat([]byte{'x'}, int(defaultMaxMessageSize+1))
			literal := response.WriteBodySection(section, int64(len(oversized)))
			_, writeErr := literal.Write(oversized)
			clear(oversized)
			closeErr := literal.Close()
			responseErr := response.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
			return responseErr
		}
	} else {
		s.tracker.flagFetchCalls.Add(1)
	}
	return s.UserSession.Fetch(writer, set, options)
}

func (s *trackingSession) Poll(writer *imapserver.UpdateWriter, allowExpunge bool) error {
	s.tracker.noopPollCalls.Add(1)
	return s.UserSession.Poll(writer, allowExpunge)
}

type xoauth2TestServer struct {
	email []byte
	token []byte
	done  bool
}

func (s *xoauth2TestServer) Next(response []byte) ([]byte, bool, error) {
	if s.done {
		return nil, false, errors.New("unexpected extra XOAUTH2 response")
	}
	s.done = true
	expected := make([]byte, 0, len(s.email)+len(s.token)+20)
	expected = append(expected, "user="...)
	expected = append(expected, s.email...)
	expected = append(expected, '\x01')
	expected = append(expected, "auth=Bearer "...)
	expected = append(expected, s.token...)
	expected = append(expected, '\x01', '\x01')
	defer clear(expected)
	if !bytes.Equal(response, expected) {
		return nil, false, imapserver.ErrAuthFailed
	}
	return nil, true, nil
}

type mockIMAPServer struct {
	server   *imapserver.Server
	listener net.Listener
	tracker  *imapTracker
	config   IMAPConfig
}

func startMockIMAPServer(t *testing.T, stallBodyFetch bool) *mockIMAPServer {
	t.Helper()
	serverTLS, roots := makeTestTLS(t)
	email := []byte("user@example.com")
	token := []byte("test-access-token-not-a-real-secret")
	tracker := &imapTracker{
		email:          email,
		token:          token,
		stallBodyFetch: stallBodyFetch,
		fetchStarted:   make(chan struct{}),
		fetchRelease:   make(chan struct{}),
	}
	user := imapmemserver.NewUser(string(email), "unused")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	appendTestMessage(t, user, multipartMessage(), time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC), nil)
	appendTestMessage(t, user, plainMessage(), time.Date(2026, 8, 1, 12, 1, 0, 0, time.UTC), []imap.Flag{imap.FlagSeen})

	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			tracker.activeSessions.Add(1)
			tracker.totalSessions.Add(1)
			return &trackingSession{
				UserSession: imapmemserver.NewUserSession(user),
				tracker:     tracker,
				closed:      make(chan struct{}),
			}, nil, nil
		},
		Caps:   imap.CapSet{imap.CapIMAP4rev1: {}},
		Logger: discardLogger{},
	})
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(rawListener, serverTLS)
	go func() { _ = server.Serve(tlsListener) }()

	mock := &mockIMAPServer{
		server:   server,
		listener: tlsListener,
		tracker:  tracker,
		config: IMAPConfig{
			Address:         rawListener.Addr().String(),
			ServerName:      "localhost",
			RootCAs:         roots,
			MaxMessages:     10,
			MaxMessageBytes: defaultMaxMessageSize,
			StageTimeout:    2 * time.Second,
			DialTimeout:     time.Second,
		},
	}
	t.Cleanup(func() {
		_ = mock.server.Close()
	})
	return mock
}

func (m *mockIMAPServer) waitForNoSessions(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.tracker.activeSessions.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("active sessions did not return to zero: %d", m.tracker.activeSessions.Load())
}

func appendTestMessage(t *testing.T, user *imapmemserver.User, raw []byte, date time.Time, flags []imap.Flag) {
	t.Helper()
	literal := newTestLiteral(raw)
	if _, err := user.Append("INBOX", literal, &imap.AppendOptions{Flags: flags, Time: date}); err != nil {
		t.Fatalf("append message: %v", err)
	}
}

func makeTestTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, roots
}

func multipartMessage() []byte {
	return []byte("From: Service <no-reply@example.com>\r\n" +
		"To: user@example.com\r\n" +
		"Subject: =?UTF-8?Q?Verification_=E2=9C=93?=\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=mixed\r\n\r\n" +
		"--mixed\r\n" +
		"Content-Type: multipart/alternative; boundary=alt\r\n\r\n" +
		"--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlain verification content 654321.\r\n" +
		"--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>HTML verification content.</p>\r\n" +
		"--alt--\r\n" +
		"--mixed\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=secret.txt\r\n\r\nAttachment must be ignored.\r\n" +
		"--mixed--\r\n")
}

func plainMessage() []byte {
	return []byte("From: Service <no-reply@example.com>\r\n" +
		"To: user@example.com\r\n" +
		"Subject: Plain message\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"Decoded=20plain=20content.\r\n")
}

var _ io.Reader = (*testLiteral)(nil)
