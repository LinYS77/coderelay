package outlook

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/extractor"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
)

type imapAuthError struct{}

func (imapAuthError) Error() string { return "Outlook IMAP authentication failed" }

type imapSession struct {
	conn       *cappedDeadlineConn
	tlsConn    *tls.Conn
	client     *imapclient.Client
	cancelStop func() bool
	stageLimit time.Duration
	closeOnce  sync.Once
}

func readMessages(ctx context.Context, settings config.OutlookConfig, credential *Credential, accessToken []byte) ([]extractor.Message, error) {
	if credential == nil || len(accessToken) == 0 {
		return nil, domain.ErrSourceCredentials
	}
	session, err := dialIMAP(ctx, settings)
	if err != nil {
		return nil, err
	}
	completed := false
	defer func() {
		if !completed {
			session.Abort()
		} else {
			session.Close()
		}
	}()
	if err := session.authenticate(ctx, credential.Email, accessToken); err != nil {
		return nil, err
	}
	_, err = session.selectReadOnly(ctx)
	if err != nil {
		return nil, err
	}
	messages, err := session.fetchBatch(ctx, settings.MaxMessages, settings.MaxMessageBytes)
	if err != nil {
		return nil, err
	}
	completed = true
	return messages, nil
}

var (
	_ = readMessages
	_ = parseFetchedMessage
)

func dialIMAP(ctx context.Context, settings config.OutlookConfig) (*imapSession, error) {
	stageLimit := duration(settings.IMAPTimeoutSeconds)
	if stageLimit <= 0 {
		stageLimit = 15 * time.Second
	}
	dialer := &net.Dialer{Timeout: stageLimit, KeepAlive: 30 * time.Second}
	address := net.JoinHostPort(settings.IMAPHost, strconv.Itoa(settings.IMAPPort))
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, domain.ErrUpstreamFailure
	}
	deadline := deadlineFor(ctx, stageLimit)
	conn := newCappedDeadlineConn(raw, deadline)
	cancelStop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	tlsConn := tls.Client(conn, &tls.Config{ServerName: settings.IMAPHost, MinVersion: tls.VersionTLS12, NextProtos: []string{"imap"}})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		cancelStop()
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, domain.ErrUpstreamFailure
	}
	client := imapclient.New(tlsConn, &imapclient.Options{WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader}})
	session := &imapSession{conn: conn, tlsConn: tlsConn, client: client, cancelStop: cancelStop, stageLimit: stageLimit}
	if err := session.runStage(ctx, func() error { return client.WaitGreeting() }); err != nil {
		session.Abort()
		return nil, err
	}
	return session, nil
}

func (s *imapSession) runStage(ctx context.Context, operation func() error) error {
	if s == nil || s.conn == nil || s.client == nil || ctx == nil || operation == nil {
		return domain.ErrUpstreamFailure
	}
	stageCtx, cancel := context.WithTimeout(ctx, s.stageLimit)
	defer cancel()
	deadline := deadlineFor(stageCtx, s.stageLimit)
	s.conn.SetCap(deadline)
	stop := context.AfterFunc(stageCtx, func() { _ = s.conn.Close() })
	err := operation()
	stageErr := stageCtx.Err()
	stopped := stop()
	if stageErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return domain.ErrUpstreamTimeout
	}
	if !stopped {
		return domain.ErrUpstreamTimeout
	}
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, domain.ErrUpstreamSchemaChanged) || errors.Is(err, domain.ErrSourceCredentials) || errors.Is(err, domain.ErrSourceReauthRequired) || isIMAPAuthError(err) {
		return err
	}
	return domain.ErrUpstreamFailure
}

func (s *imapSession) authenticate(ctx context.Context, email, token []byte) error {
	if s == nil || s.client == nil || len(email) == 0 || len(token) == 0 {
		return domain.ErrSourceCredentials
	}
	return s.runStage(ctx, func() error {
		caps := s.client.Caps()
		if caps == nil || !caps.Has(imap.AuthCap("XOAUTH2")) {
			return domain.ErrUpstreamSchemaChanged
		}
		xoauth := newXOAUTH2Client(email, token)
		defer xoauth.Destroy()
		if err := s.client.Authenticate(xoauth); err != nil {
			if isIMAPAuthResponse(err) {
				return imapAuthError{}
			}
			return err
		}
		return nil
	})
}

func isIMAPAuthResponse(err error) bool {
	var status *imap.Error
	if !errors.As(err, &status) || status == nil {
		return false
	}
	switch status.Code {
	case imap.ResponseCodeAuthenticationFailed, imap.ResponseCodeAuthorizationFailed, imap.ResponseCodeExpired, imap.ResponseCodeNoPerm:
		return true
	default:
		return status.Type == imap.StatusResponseTypeNo && strings.Contains(strings.ToLower(status.Text), "auth")
	}
}

func (s *imapSession) selectReadOnly(ctx context.Context) (*imap.SelectData, error) {
	if s == nil || s.client == nil {
		return nil, domain.ErrUpstreamFailure
	}
	var selected *imap.SelectData
	err := s.runStage(ctx, func() error {
		var err error
		selected, err = s.client.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil || selected == nil {
			return domain.ErrUpstreamFailure
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return selected, nil
}

func (s *imapSession) noop(ctx context.Context) error {
	return s.runStage(ctx, func() error { return s.client.Noop().Wait() })
}

func (s *imapSession) fetchBatch(ctx context.Context, maxMessages int, maxBytes int64) ([]extractor.Message, error) {
	if s == nil || s.client == nil || maxMessages < 1 || maxBytes < 1 {
		return nil, domain.ErrUpstreamFailure
	}
	mailbox := s.client.Mailbox()
	if mailbox == nil {
		return nil, domain.ErrUpstreamFailure
	}
	sequenceSet := recentSequenceSet(mailbox.NumMessages, maxMessages)
	if sequenceSet.String() == "" {
		return []extractor.Message{}, nil
	}
	var messages []extractor.Message
	err := s.runStage(ctx, func() error {
		section := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: maxBytes}}
		command := s.client.Fetch(sequenceSet, &imap.FetchOptions{UID: true, InternalDate: true, BodySection: []*imap.FetchItemBodySection{section}})
		for item := command.Next(); item != nil; item = command.Next() {
			var uid imap.UID
			var internalDate time.Time
			var raw []byte
			bodyCount := 0
			for data := item.Next(); data != nil; data = item.Next() {
				switch value := data.(type) {
				case imapclient.FetchItemDataUID:
					uid = value.UID
				case imapclient.FetchItemDataInternalDate:
					internalDate = value.Time
				case imapclient.FetchItemDataBodySection:
					bodyCount++
					if value.Literal == nil || value.Literal.Size() > maxBytes {
						if value.Literal != nil {
							s.abortLiteral(value.Literal)
						}
						clear(raw)
						destroyMessages(messages)
						return domain.ErrUpstreamSchemaChanged
					}
					var readErr error
					raw, readErr = io.ReadAll(io.LimitReader(value.Literal, maxBytes+1))
					if readErr != nil || int64(len(raw)) > maxBytes {
						clear(raw)
						s.abortLiteral(value.Literal)
						destroyMessages(messages)
						if ctx.Err() != nil {
							return ctx.Err()
						}
						return domain.ErrUpstreamSchemaChanged
					}
				}
			}
			if uid == 0 || internalDate.IsZero() || bodyCount != 1 || len(raw) == 0 {
				clear(raw)
				continue
			}
			message, parseErr := parseFetchedMessageWithLimit(raw, uid, internalDate.UTC(), maxBytes)
			clear(raw)
			if parseErr == nil {
				messages = append(messages, message)
			}
		}
		return command.Close()
	})
	if err != nil {
		destroyMessages(messages)
		return nil, err
	}
	return messages, nil
}

func parseFetchedMessage(raw []byte, uid imap.UID, internalDate time.Time) (extractor.Message, error) {
	return parseFetchedMessageWithLimit(raw, uid, internalDate, 0)
}

func parseFetchedMessageWithLimit(raw []byte, uid imap.UID, internalDate time.Time, maxBytes int64) (extractor.Message, error) {
	subject, sender, text, html, err := parseMIMEWithPartial(raw, maxBytes > 0 && int64(len(raw)) >= maxBytes)
	if err != nil {
		return extractor.Message{}, err
	}
	return extractor.Message{
		ID:         "imap:" + strconv.FormatUint(uint64(uid), 10),
		UID:        int64(uid),
		Subject:    subject,
		Sender:     sender,
		ReceivedAt: internalDate,
		Text:       text,
		HTML:       html,
	}, nil
}

func (s *imapSession) abortLiteral(literal imap.LiteralReader) {
	if s == nil || literal == nil {
		return
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	buffer := make([]byte, 32<<10)
	for {
		n, err := literal.Read(buffer)
		if err != nil || n == 0 {
			break
		}
	}
	clear(buffer)
}

func (s *imapSession) Abort() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if s.cancelStop != nil {
			s.cancelStop()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
		if s.client != nil {
			_ = s.client.Close()
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
		if canLogout {
			deadline := time.Now().Add(time.Second)
			if s.conn != nil {
				s.conn.SetCap(deadline)
				_ = s.conn.SetDeadline(deadline)
			}
		}
		if canLogout && s.client != nil {
			_ = s.client.Logout().Wait()
			_ = s.client.Close()
		} else if s.client != nil {
			_ = s.client.Close()
		} else if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

func recentSequenceSet(count uint32, maximum int) imap.SeqSet {
	var set imap.SeqSet
	if count == 0 || maximum <= 0 {
		return set
	}
	first := uint32(1)
	if int(count) > maximum {
		first = count - uint32(maximum) + 1
	}
	set.AddRange(first, count)
	return set
}

func deadlineFor(ctx context.Context, fallback time.Duration) time.Time {
	deadline := time.Now().Add(fallback)
	if existing, ok := ctx.Deadline(); ok && existing.Before(deadline) {
		return existing
	}
	return deadline
}

func destroyMessages(messages []extractor.Message) {
	for i := range messages {
		messages[i].Destroy()
	}
	clear(messages)
}
