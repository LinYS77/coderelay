package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/LinYS77/coderelay/internal/domain"
)

type credentialUpdateBody struct {
	RefreshToken string `json:"refresh_token"`
}

type errorEnvelope struct {
	Error            errorBody             `json:"error"`
	CredentialUpdate *credentialUpdateBody `json:"credential_update,omitempty"`
}

type errorBody struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	Retryable         bool   `json:"retryable"`
	RetryAfterSeconds *int   `json:"retry_after_seconds"`
	RequestID         string `json:"request_id"`
}

func writePublicError(writer http.ResponseWriter, requestID string, problem *publicError) {
	writePublicErrorWithUpdate(writer, requestID, problem, nil)
}

func writePublicErrorWithUpdate(writer http.ResponseWriter, requestID string, problem *publicError, update *domain.CredentialUpdate) {
	if problem == nil {
		problem = internalError()
	}
	var retry *int
	if problem.RetryAfter > 0 {
		value := problem.RetryAfter
		retry = &value
		writer.Header().Set("Retry-After", strconv.Itoa(value))
	}
	if problem.Status == http.StatusUnauthorized {
		writer.Header().Set("WWW-Authenticate", "Bearer")
	}
	var updateBody *credentialUpdateBody
	if update != nil && len(update.RefreshToken) > 0 {
		updateBody = &credentialUpdateBody{RefreshToken: string(update.RefreshToken)}
	}
	payload := errorEnvelope{Error: errorBody{
		Code:              problem.Code,
		Message:           problem.Message,
		Retryable:         problem.Retryable,
		RetryAfterSeconds: retry,
		RequestID:         requestID,
	}, CredentialUpdate: updateBody}
	writeJSON(writer, problem.Status, payload)
}

func writeSuccess(writer http.ResponseWriter, code [6]byte, updates ...*domain.CredentialUpdate) error {
	var update *domain.CredentialUpdate
	if len(updates) > 0 {
		update = updates[0]
	}
	payload := make([]byte, 0, 64+len(updateBytes(update)))
	payload = append(payload, `{"code":"`...)
	payload = append(payload, code[:]...)
	payload = append(payload, '"')
	if update != nil && len(update.RefreshToken) > 0 {
		payload = append(payload, `,"credential_update":{"refresh_token":`...)
		encoded, _ := json.Marshal(string(update.RefreshToken))
		payload = append(payload, encoded...)
		clear(encoded)
		payload = append(payload, '}')
	}
	payload = append(payload, '}')
	defer clear(payload)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(payload)
	return err
}

func updateBytes(update *domain.CredentialUpdate) []byte {
	if update == nil {
		return nil
	}
	return update.RefreshToken
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		payload = []byte(`{"error":{"code":"INTERNAL_ERROR","message":"An internal error occurred","retryable":false,"retry_after_seconds":null,"request_id":"unknown"}}`)
		status = http.StatusInternalServerError
	}
	defer clear(payload)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}
