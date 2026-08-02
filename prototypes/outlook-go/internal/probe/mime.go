package probe

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"unicode/utf8"

	message "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

const (
	maxMIMEParts    = 100
	maxTextBytes    = 100_000
	maxSubjectRunes = 10_000
)

type MIMEReport struct {
	Parsed             bool `json:"parsed"`
	SubjectRunes       int  `json:"subject_runes"`
	SenderCount        int  `json:"sender_count"`
	PartCount          int  `json:"part_count"`
	PlainBytes         int  `json:"plain_bytes"`
	HTMLBytes          int  `json:"html_bytes"`
	AttachmentCount    int  `json:"attachment_count"`
	TextLimitReached   bool `json:"text_limit_reached"`
	PartialOrMalformed bool `json:"partial_or_malformed"`
	UnknownCharsetSeen bool `json:"unknown_charset_seen"`
}

func parseMIME(raw []byte) (MIMEReport, error) {
	var report MIMEReport
	reader, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		if message.IsUnknownCharset(err) && reader != nil {
			report.UnknownCharsetSeen = true
		} else {
			return report, stageError("mime", "HEADER_PARSE_FAILED", err)
		}
	}
	defer reader.Close()

	subject, subjectErr := reader.Header.Subject()
	if subjectErr != nil {
		report.PartialOrMalformed = true
	}
	report.SubjectRunes = utf8.RuneCountInString(subject)
	if report.SubjectRunes > maxSubjectRunes {
		report.SubjectRunes = maxSubjectRunes
		report.TextLimitReached = true
	}
	subject = ""
	if senders, senderErr := reader.Header.AddressList("From"); senderErr == nil {
		report.SenderCount = len(senders)
	} else {
		report.PartialOrMalformed = true
	}

	for {
		part, nextErr := reader.NextPart()
		if nextErr != nil {
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if message.IsUnknownCharset(nextErr) && part != nil {
				report.UnknownCharsetSeen = true
			} else if errors.Is(nextErr, io.ErrUnexpectedEOF) {
				report.PartialOrMalformed = true
				break
			} else {
				return report, stageError("mime", "PART_PARSE_FAILED", nextErr)
			}
		}
		if part == nil {
			break
		}
		report.PartCount++
		if report.PartCount > maxMIMEParts {
			return report, stageError("mime", "TOO_MANY_PARTS", errors.New("MIME part count exceeds limit"))
		}

		switch header := part.Header.(type) {
		case *mail.AttachmentHeader:
			report.AttachmentCount++
			_, _ = io.Copy(io.Discard, part.Body)
		case *mail.InlineHeader:
			contentType := header.Get("Content-Type")
			mediaType := "text/plain"
			var mediaErr error
			if contentType != "" {
				mediaType, _, mediaErr = mime.ParseMediaType(contentType)
			}
			if mediaErr != nil {
				report.PartialOrMalformed = true
				_, _ = io.Copy(io.Discard, part.Body)
				continue
			}
			if mediaType != "text/plain" && mediaType != "text/html" {
				_, _ = io.Copy(io.Discard, part.Body)
				continue
			}
			content, readErr := io.ReadAll(io.LimitReader(part.Body, maxTextBytes+1))
			if readErr != nil {
				clear(content)
				return report, stageError("mime", "PART_READ_FAILED", readErr)
			}
			if len(content) > maxTextBytes {
				report.TextLimitReached = true
				content = content[:maxTextBytes]
				_, _ = io.Copy(io.Discard, part.Body)
			}
			if mediaType == "text/plain" {
				report.PlainBytes += len(content)
			} else {
				report.HTMLBytes += len(content)
			}
			clear(content)
		default:
			_, _ = io.Copy(io.Discard, part.Body)
		}
	}
	report.Parsed = true
	return report, nil
}
