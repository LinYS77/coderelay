package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
)

const (
	OutlookIMAPAddress    = "outlook.office365.com:993"
	OutlookIMAPServerName = "outlook.office365.com"
	defaultMaxMessages    = uint32(10)
	defaultMaxMessageSize = int64(256 << 10)
	defaultStageTimeout   = 30 * time.Second
)

type IMAPConfig struct {
	Address         string
	ServerName      string
	RootCAs         *x509.CertPool
	MaxMessages     uint32
	MaxMessageBytes int64
	StageTimeout    time.Duration
	DialTimeout     time.Duration
}

func DefaultIMAPConfig() IMAPConfig {
	return IMAPConfig{
		Address:         OutlookIMAPAddress,
		ServerName:      OutlookIMAPServerName,
		MaxMessages:     defaultMaxMessages,
		MaxMessageBytes: defaultMaxMessageSize,
		StageTimeout:    defaultStageTimeout,
		DialTimeout:     10 * time.Second,
	}
}

type MessageReport struct {
	Sequence     uint32     `json:"sequence"`
	UID          string     `json:"uid"`
	InternalDate string     `json:"internal_date"`
	Seen         bool       `json:"seen"`
	LiteralBytes int        `json:"literal_bytes"`
	MIME         MIMEReport `json:"mime"`
}

type CycleReport struct {
	Cycle         int             `json:"cycle"`
	SequenceRange string          `json:"sequence_range"`
	Messages      []MessageReport `json:"messages"`
}

type IMAPReport struct {
	TLSVersion              string        `json:"tls_version"`
	XOAUTH2                 bool          `json:"xoauth2"`
	ReadOnlySelectRequested bool          `json:"readonly_select_requested"`
	NumMessages             uint32        `json:"num_messages"`
	SessionCount            int           `json:"session_count"`
	NoopCount               int           `json:"noop_count"`
	BodyFetchCommands       int           `json:"body_fetch_commands"`
	SingleBatchPerCycle     bool          `json:"single_batch_per_cycle"`
	SeenChecked             int           `json:"seen_checked"`
	SeenPreserved           bool          `json:"seen_preserved"`
	Cycles                  []CycleReport `json:"cycles"`
}

type imapSession struct {
	conn       *cappedDeadlineConn
	tlsConn    *tls.Conn
	client     *imapclient.Client
	cancelStop func() bool
	stageLimit time.Duration
	closeOnce  sync.Once
	tlsVersion string
}

func dialIMAP(ctx context.Context, config IMAPConfig) (*imapSession, error) {
	config = normalizeIMAPConfig(config)
	dialer := &net.Dialer{Timeout: config.DialTimeout, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", config.Address)
	if err != nil {
		return nil, stageError("imap_dial", "DIAL_FAILED", err)
	}

	capDeadline := deadlineFor(ctx, config.StageTimeout)
	conn := newCappedDeadlineConn(rawConn, capDeadline)
	cancelStop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: config.ServerName,
		RootCAs:    config.RootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"imap"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		cancelStop()
		_ = rawConn.Close()
		if ctx.Err() != nil {
			return nil, stageError("imap_tls", "CANCELED_OR_TIMEOUT", ctx.Err())
		}
		return nil, stageError("imap_tls", "HANDSHAKE_FAILED", err)
	}

	client := imapclient.New(tlsConn, imapOptions())
	session := &imapSession{
		conn:       conn,
		tlsConn:    tlsConn,
		client:     client,
		cancelStop: cancelStop,
		stageLimit: config.StageTimeout,
		tlsVersion: tlsVersionName(tlsConn.ConnectionState().Version),
	}
	if err := session.runStage(ctx, "imap_greeting", func() error {
		return client.WaitGreeting()
	}); err != nil {
		session.Abort()
		return nil, err
	}
	return session, nil
}

func imapOptions() *imapclient.Options {
	return &imapclient.Options{
		WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader},
		// DebugWriter deliberately remains nil: it can expose XOAUTH2 and mail.
	}
}

func normalizeIMAPConfig(config IMAPConfig) IMAPConfig {
	if config.Address == "" {
		config.Address = OutlookIMAPAddress
	}
	if config.ServerName == "" {
		config.ServerName = OutlookIMAPServerName
	}
	if config.MaxMessages == 0 {
		config.MaxMessages = defaultMaxMessages
	}
	if config.MaxMessageBytes <= 0 {
		config.MaxMessageBytes = defaultMaxMessageSize
	}
	if config.StageTimeout <= 0 {
		config.StageTimeout = defaultStageTimeout
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	return config
}

func (s *imapSession) runStage(ctx context.Context, stage string, operation func() error) error {
	stageCtx, cancel := context.WithTimeout(ctx, s.stageLimit)
	deadline := deadlineFor(stageCtx, s.stageLimit)
	s.conn.SetCap(deadline)
	stop := context.AfterFunc(stageCtx, func() { _ = s.conn.Close() })
	err := operation()
	stageErr := stageCtx.Err()
	stopped := stop()
	cancel()
	if stageErr != nil || !stopped {
		cause := stageErr
		if cause == nil {
			cause = context.Canceled
		}
		return stageError(stage, "CANCELED_OR_TIMEOUT", cause)
	}
	if err != nil {
		return stageError(stage, "COMMAND_FAILED", err)
	}
	return nil
}

func (s *imapSession) Authenticate(ctx context.Context, email, accessToken []byte) error {
	return s.runStage(ctx, "imap_xoauth2", func() error {
		caps := s.client.Caps()
		if caps == nil || !caps.Has(imap.AuthCap("XOAUTH2")) {
			return errors.New("server does not advertise AUTH=XOAUTH2")
		}
		xoauth := newXOAUTH2Client(email, accessToken)
		defer xoauth.Destroy()
		return s.client.Authenticate(xoauth)
	})
}

func (s *imapSession) SelectReadOnly(ctx context.Context) (*imap.SelectData, error) {
	var data *imap.SelectData
	err := s.runStage(ctx, "imap_select", func() error {
		var err error
		data, err = s.client.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
		return err
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, stageError("imap_select", "MISSING_SELECT_DATA", errors.New("Select returned no data"))
	}
	return data, nil
}

func (s *imapSession) Noop(ctx context.Context) error {
	return s.runStage(ctx, "imap_noop", func() error {
		return s.client.Noop().Wait()
	})
}

func (s *imapSession) Abort() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if s.cancelStop != nil {
			s.cancelStop()
		}
		if s.client != nil {
			_ = s.client.Close()
		} else if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

func (s *imapSession) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		canLogout := true
		if s.cancelStop != nil && !s.cancelStop() {
			canLogout = false
		}
		if canLogout && s.client != nil {
			cleanupDeadline := time.Now().Add(time.Second)
			s.conn.SetCap(cleanupDeadline)
			_ = s.conn.SetDeadline(cleanupDeadline)
			_ = s.client.Logout().Wait()
		}
		if s.client != nil {
			_ = s.client.Close()
		} else if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

func ProbeIMAP(ctx context.Context, config IMAPConfig, email, accessToken []byte, cycles int) (IMAPReport, error) {
	config = normalizeIMAPConfig(config)
	ctx, cancel := context.WithTimeout(ctx, config.StageTimeout)
	defer cancel()
	if cycles < 1 {
		cycles = 1
	}
	var report IMAPReport
	report.SessionCount = 1
	report.ReadOnlySelectRequested = true
	report.SingleBatchPerCycle = true
	report.SeenPreserved = true

	session, err := dialIMAP(ctx, config)
	if err != nil {
		return report, err
	}
	defer session.Close()
	report.TLSVersion = session.tlsVersion

	if err := session.Authenticate(ctx, email, accessToken); err != nil {
		session.Abort()
		return report, err
	}
	report.XOAUTH2 = true
	selectData, err := session.SelectReadOnly(ctx)
	if err != nil {
		session.Abort()
		return report, err
	}
	report.NumMessages = selectData.NumMessages

	initialSet, initialRange := recentSequenceSet(selectData.NumMessages, config.MaxMessages)
	before, err := session.fetchFlags(ctx, initialSet)
	if err != nil {
		session.Abort()
		return report, err
	}

	for cycle := 1; cycle <= cycles; cycle++ {
		if cycle > 1 {
			if err := session.Noop(ctx); err != nil {
				session.Abort()
				return report, err
			}
			report.NoopCount++
		}
		count := report.NumMessages
		if mailbox := session.client.Mailbox(); mailbox != nil {
			count = mailbox.NumMessages
		}
		sequenceSet, sequenceRange := recentSequenceSet(count, config.MaxMessages)
		if sequenceRange == "" {
			sequenceRange = initialRange
		}
		messages, err := session.fetchBatch(ctx, sequenceSet, config.MaxMessageBytes)
		if err != nil {
			session.Abort()
			return report, err
		}
		if sequenceRange != "" {
			report.BodyFetchCommands++
		}
		report.Cycles = append(report.Cycles, CycleReport{
			Cycle:         cycle,
			SequenceRange: sequenceRange,
			Messages:      messages,
		})
	}

	currentCount := report.NumMessages
	if mailbox := session.client.Mailbox(); mailbox != nil {
		currentCount = mailbox.NumMessages
	}
	finalSet, _ := recentSequenceSet(currentCount, config.MaxMessages)
	after, err := session.fetchFlags(ctx, finalSet)
	if err != nil {
		session.Abort()
		return report, err
	}
	for uid, wasSeen := range before {
		isSeen, ok := after[uid]
		if !ok {
			continue
		}
		report.SeenChecked++
		if !wasSeen && isSeen {
			report.SeenPreserved = false
		}
	}
	if !report.SeenPreserved {
		return report, stageError("imap_seen", "MESSAGE_MARKED_SEEN", errors.New("BODY.PEEK changed a message to seen"))
	}
	return report, nil
}

func SmokeIMAP(ctx context.Context, config IMAPConfig, email, accessToken []byte) error {
	config = normalizeIMAPConfig(config)
	ctx, cancel := context.WithTimeout(ctx, config.StageTimeout)
	defer cancel()
	session, err := dialIMAP(ctx, config)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.Authenticate(ctx, email, accessToken); err != nil {
		session.Abort()
		return err
	}
	if _, err := session.SelectReadOnly(ctx); err != nil {
		session.Abort()
		return err
	}
	if err := session.Noop(ctx); err != nil {
		session.Abort()
		return err
	}
	return nil
}

func (s *imapSession) fetchBatch(ctx context.Context, sequenceSet imap.SeqSet, maxBytes int64) ([]MessageReport, error) {
	if sequenceSet.String() == "" {
		return []MessageReport{}, nil
	}
	bodySection := &imap.FetchItemBodySection{
		Peek:    true,
		Partial: &imap.SectionPartial{Offset: 0, Size: maxBytes},
	}
	options := &imap.FetchOptions{
		UID:          true,
		Flags:        true,
		InternalDate: true,
		BodySection:  []*imap.FetchItemBodySection{bodySection},
	}
	var reports []MessageReport
	err := s.runStage(ctx, "imap_fetch", func() error {
		command := s.client.Fetch(sequenceSet, options)
		for message := command.Next(); message != nil; message = command.Next() {
			var uid imap.UID
			var internalDate time.Time
			var flags []imap.Flag
			var raw []byte
			bodyCount := 0
			for item := message.Next(); item != nil; item = message.Next() {
				switch value := item.(type) {
				case imapclient.FetchItemDataUID:
					uid = value.UID
				case imapclient.FetchItemDataInternalDate:
					internalDate = value.Time
				case imapclient.FetchItemDataFlags:
					flags = value.Flags
				case imapclient.FetchItemDataBodySection:
					bodyCount++
					if value.Literal == nil {
						return errors.New("FETCH body literal is nil")
					}
					if value.Literal.Size() > maxBytes {
						s.abortLiteral(value.Literal)
						return errors.New("FETCH body literal exceeds requested partial size")
					}
					var readErr error
					raw, readErr = io.ReadAll(io.LimitReader(value.Literal, maxBytes+1))
					if readErr != nil {
						clear(raw)
						return readErr
					}
					if int64(len(raw)) > maxBytes {
						clear(raw)
						s.abortLiteral(value.Literal)
						return errors.New("FETCH body exceeded requested partial size")
					}
				}
			}
			if uid == 0 || internalDate.IsZero() || bodyCount != 1 || raw == nil {
				clear(raw)
				return errors.New("FETCH response is missing UID, INTERNALDATE, or body")
			}
			mimeReport, parseErr := parseMIME(raw)
			literalBytes := len(raw)
			clear(raw)
			if parseErr != nil {
				return parseErr
			}
			reports = append(reports, MessageReport{
				Sequence:     message.SeqNum,
				UID:          strconv.FormatUint(uint64(uid), 10),
				InternalDate: internalDate.UTC().Format(time.RFC3339Nano),
				Seen:         hasSeenFlag(flags),
				LiteralBytes: literalBytes,
				MIME:         mimeReport,
			})
		}
		return command.Close()
	})
	if err != nil {
		return nil, err
	}
	return reports, nil
}

func (s *imapSession) abortLiteral(literal imap.LiteralReader) {
	// beta.8's decoder waits for the application to finish the current
	// streaming literal. Closing Client without touching the literal can
	// therefore deadlock. Close the transport first, then read until the
	// resulting transport error releases the library's internal done channel.
	_ = s.conn.Close()
	buffer := make([]byte, 32<<10)
	for {
		n, err := literal.Read(buffer)
		if err != nil {
			break
		}
		if n == 0 {
			break
		}
	}
	clear(buffer)
}

func (s *imapSession) fetchFlags(ctx context.Context, sequenceSet imap.SeqSet) (map[string]bool, error) {
	result := make(map[string]bool)
	if sequenceSet.String() == "" {
		return result, nil
	}
	err := s.runStage(ctx, "imap_flags", func() error {
		command := s.client.Fetch(sequenceSet, &imap.FetchOptions{UID: true, Flags: true})
		for message := command.Next(); message != nil; message = command.Next() {
			var uid imap.UID
			var flags []imap.Flag
			for item := message.Next(); item != nil; item = message.Next() {
				switch value := item.(type) {
				case imapclient.FetchItemDataUID:
					uid = value.UID
				case imapclient.FetchItemDataFlags:
					flags = value.Flags
				}
			}
			if uid != 0 {
				result[strconv.FormatUint(uint64(uid), 10)] = hasSeenFlag(flags)
			}
		}
		return command.Close()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func recentSequenceSet(messageCount, maxMessages uint32) (imap.SeqSet, string) {
	var set imap.SeqSet
	if messageCount == 0 || maxMessages == 0 {
		return set, ""
	}
	first := uint32(1)
	if messageCount > maxMessages {
		first = messageCount - maxMessages + 1
	}
	set.AddRange(first, messageCount)
	return set, fmt.Sprintf("%d:%d", first, messageCount)
}

func hasSeenFlag(flags []imap.Flag) bool {
	for _, flag := range flags {
		if flag == imap.FlagSeen {
			return true
		}
	}
	return false
}

func deadlineFor(ctx context.Context, fallback time.Duration) time.Time {
	deadline := time.Now().Add(fallback)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
