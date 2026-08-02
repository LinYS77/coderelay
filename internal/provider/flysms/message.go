package flysms

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/extractor"
)

func decodeDetail(payload []byte, expectedEmail string, expected *extractor.Message) (extractor.Message, error) {
	fields, err := decodeObject(payload)
	if err != nil {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	defer clearFields(fields)
	if err := checkResponseEmail(fields, expectedEmail); err != nil {
		return extractor.Message{}, err
	}
	if err := checkEntitlement(fields); err != nil {
		return extractor.Message{}, err
	}
	rawMessage, ok := fields["message"]
	if !ok {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	message, err := decodeMessage(rawMessage, false)
	if err != nil {
		return extractor.Message{}, err
	}
	if expected != nil && (message.Mailbox != expected.Mailbox || message.UID != expected.UID) {
		message.Destroy()
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	return message, nil
}

func decodeHistory(payload []byte, expectedEmail string) ([]extractor.Message, error) {
	fields, err := decodeObject(payload)
	if err != nil {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	defer clearFields(fields)
	if err := checkResponseEmail(fields, expectedEmail); err != nil {
		return nil, err
	}
	if err := checkEntitlement(fields); err != nil {
		return nil, err
	}
	rawMessages, ok := fields["messages"]
	if !ok {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	var items []json.RawMessage
	if err := json.Unmarshal(rawMessages, &items); err != nil || items == nil || len(items) > 50 {
		clearRawMessages(items)
		return nil, domain.ErrUpstreamSchemaChanged
	}
	defer clearRawMessages(items)
	messages := make([]extractor.Message, 0, len(items))
	for _, item := range items {
		message, err := decodeMessage(item, true)
		if err != nil {
			destroyMessages(messages)
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func decodeMessage(payload []byte, summary bool) (extractor.Message, error) {
	fields, err := decodeObject(payload)
	if err != nil {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	defer clearFields(fields)
	mailbox, err := requiredString(fields, "mailbox", 512)
	if err != nil || mailbox == "" {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	uid, err := requiredPositiveInt(fields, "uid")
	if err != nil {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	subject, err := requiredString(fields, "subject", 10_000)
	if err != nil {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	sender, err := requiredString(fields, "from", 4_096)
	if err != nil {
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	message := extractor.Message{
		ID:      "flysms:" + mailbox + ":" + strconv.FormatInt(uid, 10),
		Mailbox: mailbox,
		UID:     uid,
		Subject: subject,
		Sender:  sender,
	}
	if summary {
		dateValue, err := requiredString(fields, "date", 128)
		if err != nil {
			message.Destroy()
			return extractor.Message{}, domain.ErrUpstreamSchemaChanged
		}
		message.ReceivedAt, err = parseDate(dateValue)
		if err != nil {
			message.Destroy()
			return extractor.Message{}, domain.ErrUpstreamSchemaChanged
		}
		message.Preview, err = requiredString(fields, "preview", 100_000)
		if err != nil {
			message.Destroy()
			return extractor.Message{}, domain.ErrUpstreamSchemaChanged
		}
		return message, nil
	}

	dateValue, err := firstDateValue(fields, "mailboxReceivedAt", "date", "sentAt", "ingestedAt")
	if err != nil {
		message.Destroy()
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	message.ReceivedAt, err = parseDate(dateValue)
	if err != nil {
		message.Destroy()
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	message.Text, err = requiredString(fields, "text", 1_000_000)
	if err != nil {
		message.Destroy()
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	message.HTML, err = nullableString(fields, "html", 2_000_000)
	if err != nil {
		message.Destroy()
		return extractor.Message{}, domain.ErrUpstreamSchemaChanged
	}
	return message, nil
}

func checkResponseEmail(fields map[string]json.RawMessage, expected string) error {
	value, err := requiredString(fields, "email", 320)
	if err != nil {
		return domain.ErrUpstreamSchemaChanged
	}
	normalized, ok := normalizeEmail(value)
	if !ok || normalized != expected {
		return domain.ErrUpstreamSchemaChanged
	}
	return nil
}

func checkEntitlement(fields map[string]json.RawMessage) error {
	raw, ok := fields["entitlementStatus"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var status string
	if err := json.Unmarshal(raw, &status); err != nil {
		return domain.ErrUpstreamSchemaChanged
	}
	switch status {
	case "expired":
		return domain.ErrSourceExpired
	case "pending":
		return domain.WithRetryAfter(domain.ErrSourceSyncing, 2)
	case "active", "unlimited":
		return nil
	default:
		return domain.ErrUpstreamSchemaChanged
	}
}

func decodeObject(payload []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	fields := make(map[string]json.RawMessage)
	valid := false
	defer func() {
		if !valid {
			clearFields(fields)
		}
	}()
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, domain.ErrUpstreamSchemaChanged
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, domain.ErrUpstreamSchemaChanged
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			clear(value)
			return nil, err
		}
		fields[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	valid = true
	return fields, nil
}

func requiredString(fields map[string]json.RawMessage, key string, maximum int) (string, error) {
	raw, ok := fields[key]
	if !ok {
		return "", domain.ErrUpstreamSchemaChanged
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || utf8.RuneCountInString(value) > maximum {
		return "", domain.ErrUpstreamSchemaChanged
	}
	return value, nil
}

func nullableString(fields map[string]json.RawMessage, key string, maximum int) (string, error) {
	raw, ok := fields[key]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", nil
	}
	return requiredString(fields, key, maximum)
}

func requiredPositiveInt(fields map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := fields[key]
	if !ok {
		return 0, domain.ErrUpstreamSchemaChanged
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < 1 {
		return 0, domain.ErrUpstreamSchemaChanged
	}
	return value, nil
}

func firstDateValue(fields map[string]json.RawMessage, keys ...string) (string, error) {
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", domain.ErrUpstreamSchemaChanged
		}
		if value != "" {
			if utf8.RuneCountInString(value) > 128 {
				return "", domain.ErrUpstreamSchemaChanged
			}
			return value, nil
		}
	}
	return "", domain.ErrUpstreamSchemaChanged
}

func parseDate(value string) (time.Time, error) {
	if value == "" || len(value) > 128 {
		return time.Time{}, domain.ErrUpstreamSchemaChanged
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999"} {
		if parsed, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return parsed.UTC(), nil
		}
	}
	parsed, err := mail.ParseDate(value)
	if err != nil {
		return time.Time{}, domain.ErrUpstreamSchemaChanged
	}
	return parsed.UTC(), nil
}

func clearFields(fields map[string]json.RawMessage) {
	for key, value := range fields {
		clear(value)
		delete(fields, key)
	}
}

func clearRawMessages(messages []json.RawMessage) {
	for i := range messages {
		clear(messages[i])
		messages[i] = nil
	}
}

func destroyMessages(messages []extractor.Message) {
	for i := range messages {
		messages[i].Destroy()
	}
	clear(messages)
}
