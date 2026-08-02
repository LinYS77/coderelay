package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	Retryable         bool   `json:"retryable"`
	RetryAfterSeconds *int   `json:"retry_after_seconds"`
	RequestID         string `json:"request_id"`
}

func writePublicError(writer http.ResponseWriter, requestID string, problem *publicError) {
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
	payload := errorEnvelope{Error: errorBody{
		Code:              problem.Code,
		Message:           problem.Message,
		Retryable:         problem.Retryable,
		RetryAfterSeconds: retry,
		RequestID:         requestID,
	}}
	writeJSON(writer, problem.Status, payload)
}

func writeSuccess(writer http.ResponseWriter, code [6]byte) error {
	payload := make([]byte, 0, 17)
	payload = append(payload, `{"code":"`...)
	payload = append(payload, code[:]...)
	payload = append(payload, '"', '}')
	defer clear(payload)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(payload)
	return err
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
