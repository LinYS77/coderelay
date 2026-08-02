package outlook

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/domain"
	message "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

const (
	maxMIMEParts    = 100
	maxMIMEDepth    = 10
	maxMIMEText     = 100_000
	maxSubjectRunes = 10_000
	maxSenderRunes  = 4_096
)

func parseMIME(raw []byte) (subject, sender, text, html string, err error) {
	return parseMIMEWithPartial(raw, false)
}

func parseMIMEWithPartial(raw []byte, allowPartial bool) (subject, sender, text, html string, err error) {
	if structureErr := validateMIMEStructure(raw, allowPartial); structureErr != nil {
		return "", "", "", "", structureErr
	}
	reader, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && !(message.IsUnknownCharset(err) && reader != nil) {
		return "", "", "", "", domainSchemaError()
	}
	defer reader.Close()
	subject, _ = reader.Header.Subject()
	if utf8.RuneCountInString(subject) > maxSubjectRunes {
		subject = truncateRunes(subject, maxSubjectRunes)
	}
	if senders, senderErr := reader.Header.AddressList("From"); senderErr == nil && len(senders) > 0 {
		sender = senders[0].String()
	} else {
		sender = reader.Header.Get("From")
	}
	if utf8.RuneCountInString(sender) > maxSenderRunes {
		sender = truncateRunes(sender, maxSenderRunes)
	}
	var plainParts, htmlParts []string
	plainLength, htmlLength := 0, 0
	for partCount := 0; ; partCount++ {
		if partCount > maxMIMEParts {
			return subject, sender, strings.Join(plainParts, "\n"), strings.Join(htmlParts, "\n"), domainSchemaError()
		}
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) || allowPartial && isPartialMIMEEOF(nextErr) {
			break
		}
		if nextErr != nil && part == nil {
			if message.IsUnknownCharset(nextErr) || allowPartial && isPartialMIMEEOF(nextErr) {
				break
			}
			return subject, sender, strings.Join(plainParts, "\n"), strings.Join(htmlParts, "\n"), domainSchemaError()
		}
		if part == nil {
			break
		}
		if isMIMEAttachment(part.Header) {
			_, _ = io.CopyN(io.Discard, part.Body, int64(maxMIMEText))
			continue
		}
		contentType := "text/plain"
		if value := part.Header.Get("Content-Type"); value != "" {
			parsed, _, parseErr := mime.ParseMediaType(value)
			if parseErr != nil {
				_, _ = io.CopyN(io.Discard, part.Body, int64(maxMIMEText))
				continue
			}
			contentType = strings.ToLower(parsed)
		}
		if contentType != "text/plain" && contentType != "text/html" {
			_, _ = io.CopyN(io.Discard, part.Body, int64(maxMIMEText))
			continue
		}
		limit := maxMIMEText
		if contentType == "text/plain" {
			limit -= plainLength
		} else {
			limit -= htmlLength
		}
		if limit <= 0 {
			_, _ = io.CopyN(io.Discard, part.Body, int64(maxMIMEText))
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(part.Body, int64(limit)+1))
		if readErr != nil {
			if allowPartial && errors.Is(readErr, io.ErrUnexpectedEOF) {
				readErr = nil
			} else {
				clear(content)
				return subject, sender, strings.Join(plainParts, "\n"), strings.Join(htmlParts, "\n"), domainSchemaError()
			}
		}
		if len(content) > limit {
			content = content[:limit]
			_, _ = io.CopyN(io.Discard, part.Body, int64(limit))
		}
		value := string(content)
		clear(content)
		if contentType == "text/plain" {
			plainParts = append(plainParts, value)
			plainLength += len(value)
		} else {
			htmlParts = append(htmlParts, value)
			htmlLength += len(value)
		}
	}
	return subject, sender, strings.Join(plainParts, "\n"), strings.Join(htmlParts, "\n"), nil
}

func validateMIMEStructure(raw []byte, allowPartial bool) error {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && !(message.IsUnknownCharset(err) && entity != nil) {
		return domainSchemaError()
	}
	partCount := 0
	err = entity.Walk(func(path []int, _ *message.Entity, walkErr error) error {
		if walkErr != nil && !message.IsUnknownCharset(walkErr) {
			return domainSchemaError()
		}
		if len(path) > maxMIMEDepth {
			return domainSchemaError()
		}
		if len(path) > 0 {
			partCount++
			if partCount > maxMIMEParts {
				return domainSchemaError()
			}
		}
		return nil
	})
	if err == nil {
		return nil
	}
	if allowPartial && isPartialMIMEEOF(err) {
		return nil
	}
	return domainSchemaError()
}

func isMIMEAttachment(header mail.PartHeader) bool {
	if header == nil {
		return false
	}
	disposition := header.Get("Content-Disposition")
	if parsed, parameters, err := mime.ParseMediaType(disposition); err == nil {
		if strings.EqualFold(parsed, "attachment") || parameters["filename"] != "" {
			return true
		}
	} else if strings.HasPrefix(strings.ToLower(strings.TrimSpace(disposition)), "attachment") {
		return true
	}
	if _, parameters, err := mime.ParseMediaType(header.Get("Content-Type")); err == nil && parameters["name"] != "" {
		return true
	}
	return false
}

func domainSchemaError() error { return domain.ErrUpstreamSchemaChanged }

func isPartialMIMEEOF(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.HasSuffix(strings.ToLower(err.Error()), ": eof")
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(value) <= limit {
		return value
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index]
		}
		count++
	}
	return value
}
