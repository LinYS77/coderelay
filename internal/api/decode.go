package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
)

func readCodeCommand(writer http.ResponseWriter, request *http.Request, maxBytes int64) (*domain.Command, error) {
	if request.Body == nil {
		return nil, validationError()
	}
	if request.ContentLength > maxBytes {
		return nil, requestTooLarge()
	}
	limited := http.MaxBytesReader(writer, request.Body, maxBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		clear(body)
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, requestTooLarge()
		}
		if request.Context().Err() != nil {
			return nil, request.Context().Err()
		}
		return nil, validationError()
	}
	defer clear(body)
	if len(body) == 0 || !utf8.Valid(body) {
		return nil, validationError()
	}

	fields, err := decodeRootObject(body)
	if err != nil {
		return nil, validationError()
	}
	defer clearRawFields(fields)
	rawType, ok := fields["type"]
	if !ok {
		return nil, validationError()
	}
	var provider string
	if err := json.Unmarshal(rawType, &provider); err != nil {
		return nil, validationError()
	}
	switch provider {
	case "outlook", "flysms":
		provider = ""
		return nil, invalidCodeRequest()
	case "totp":
	default:
		provider = ""
		return nil, validationError()
	}

	for key := range fields {
		if key != "type" && key != "credential" && key != "min_ttl" {
			provider = ""
			return nil, validationError()
		}
	}
	rawCredential, ok := fields["credential"]
	if !ok {
		provider = ""
		return nil, validationError()
	}
	minimumTTL := 5
	if rawTTL, exists := fields["min_ttl"]; exists {
		if err := json.Unmarshal(rawTTL, &minimumTTL); err != nil || minimumTTL < 0 || minimumTTL > 30 {
			provider = ""
			return nil, validationError()
		}
	}
	var value string
	if err := json.Unmarshal(rawCredential, &value); err != nil || value == "" || utf8.RuneCountInString(value) > 8_192 {
		value = ""
		provider = ""
		return nil, validationError()
	}
	owned := []byte(value)
	value = ""
	return &domain.Command{
		Provider:   domain.ProviderTOTP,
		Credential: credential.NewOwned(owned),
		MinTTL:     minimumTTL,
	}, nil
}

func decodeRootObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("JSON root is not an object")
	}
	fields := make(map[string]json.RawMessage)
	valid := false
	defer func() {
		if !valid {
			clearRawFields(fields)
		}
	}()
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("JSON object key is invalid")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("duplicate JSON root key")
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
		return nil, errors.New("JSON object is not closed")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON contains trailing data")
	}
	valid = true
	return fields, nil
}

func clearRawFields(fields map[string]json.RawMessage) {
	for key, value := range fields {
		clear(value)
		delete(fields, key)
	}
}
