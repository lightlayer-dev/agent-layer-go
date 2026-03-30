package core

import (
	"encoding/json"
	"testing"
)

func TestFormatError_Defaults(t *testing.T) {
	env := FormatError(AgentErrorOptions{Message: "something broke"})
	if env.Status != 500 {
		t.Errorf("expected status 500, got %d", env.Status)
	}
	if env.Type != "api_error" {
		t.Errorf("expected type api_error, got %s", env.Type)
	}
	if env.Message != "something broke" {
		t.Errorf("expected message 'something broke', got %s", env.Message)
	}
}

func TestFormatError_AutoStatusTypeMapping(t *testing.T) {
	tests := []struct {
		status   int
		expected string
	}{
		{400, "invalid_request_error"},
		{401, "authentication_error"},
		{403, "permission_error"},
		{404, "not_found_error"},
		{409, "conflict_error"},
		{422, "validation_error"},
		{429, "rate_limit_error"},
		{500, "api_error"},
		{418, "api_error"}, // unknown status falls back to api_error
	}

	for _, tt := range tests {
		env := FormatError(AgentErrorOptions{Status: tt.status, Message: "test"})
		if env.Type != tt.expected {
			t.Errorf("status %d: expected type %s, got %s", tt.status, tt.expected, env.Type)
		}
	}
}

func TestFormatError_TypeOverride(t *testing.T) {
	env := FormatError(AgentErrorOptions{
		Status:  400,
		Type:    "custom_error",
		Message: "test",
	})
	if env.Type != "custom_error" {
		t.Errorf("expected custom_error, got %s", env.Type)
	}
}

func TestFormatError_OptionalFields(t *testing.T) {
	retryAfter := 30
	env := FormatError(AgentErrorOptions{
		Status:     429,
		Message:    "rate limited",
		RetryAfter: &retryAfter,
		Param:      "api_key",
		DocsURL:    "https://docs.example.com/errors",
	})

	if env.RetryAfter == nil || *env.RetryAfter != 30 {
		t.Errorf("expected retry_after 30, got %v", env.RetryAfter)
	}
	if env.Param != "api_key" {
		t.Errorf("expected param api_key, got %s", env.Param)
	}
	if env.DocsURL != "https://docs.example.com/errors" {
		t.Errorf("expected docs_url, got %s", env.DocsURL)
	}
}

func TestFormatError_RetriableFlag(t *testing.T) {
	// 429 should be retriable by default
	env429 := FormatError(AgentErrorOptions{Status: 429, Message: "rate limited"})
	if !env429.IsRetriable {
		t.Error("429 should be retriable")
	}

	// 500 should be retriable by default
	env500 := FormatError(AgentErrorOptions{Status: 500, Message: "server error"})
	if !env500.IsRetriable {
		t.Error("500 should be retriable")
	}

	// 503 should be retriable by default
	env503 := FormatError(AgentErrorOptions{Status: 503, Message: "unavailable"})
	if !env503.IsRetriable {
		t.Error("503 should be retriable")
	}

	// 400 should NOT be retriable by default
	env400 := FormatError(AgentErrorOptions{Status: 400, Message: "bad request"})
	if env400.IsRetriable {
		t.Error("400 should not be retriable")
	}

	// Explicit override: mark 400 as retriable
	retriable := true
	env400r := FormatError(AgentErrorOptions{Status: 400, Message: "bad request", IsRetriable: &retriable})
	if !env400r.IsRetriable {
		t.Error("explicit override should make 400 retriable")
	}

	// Explicit override: mark 500 as not retriable
	notRetriable := false
	env500nr := FormatError(AgentErrorOptions{Status: 500, Message: "fatal", IsRetriable: &notRetriable})
	if env500nr.IsRetriable {
		t.Error("explicit override should make 500 not retriable")
	}
}

func TestAgentError_Creation(t *testing.T) {
	err := NewAgentError(AgentErrorOptions{
		Code:    "test_error",
		Message: "test message",
		Status:  422,
	})

	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Envelope.Status != 422 {
		t.Errorf("expected status 422, got %d", err.Envelope.Status)
	}
	if err.Envelope.Code != "test_error" {
		t.Errorf("expected code test_error, got %s", err.Envelope.Code)
	}
}

func TestAgentError_ErrorString(t *testing.T) {
	err := NewAgentError(AgentErrorOptions{
		Message: "something went wrong",
		Status:  500,
	})

	if err.Error() != "something went wrong" {
		t.Errorf("expected 'something went wrong', got '%s'", err.Error())
	}
}

func TestAgentError_ToJSON(t *testing.T) {
	err := NewAgentError(AgentErrorOptions{
		Code:    "bad_input",
		Message: "invalid field",
		Status:  400,
	})

	j := err.ToJSON()
	envelope, ok := j["error"]
	if !ok {
		t.Fatal("expected 'error' key in JSON")
	}

	// Verify it's serializable
	data, marshalErr := json.Marshal(envelope)
	if marshalErr != nil {
		t.Fatalf("failed to marshal: %v", marshalErr)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestAgentError_StatusGetter(t *testing.T) {
	err := NewAgentError(AgentErrorOptions{
		Message: "forbidden",
		Status:  403,
	})
	if err.Envelope.Status != 403 {
		t.Errorf("expected status 403, got %d", err.Envelope.Status)
	}
}

func TestNotFoundError_DefaultMessage(t *testing.T) {
	env := NotFoundError("")
	if env.Status != 404 {
		t.Errorf("expected status 404, got %d", env.Status)
	}
	if env.Message != "The requested resource was not found." {
		t.Errorf("expected default message, got '%s'", env.Message)
	}
	if env.Code != "not_found" {
		t.Errorf("expected code not_found, got %s", env.Code)
	}
	if env.Type != "not_found_error" {
		t.Errorf("expected type not_found_error, got %s", env.Type)
	}
}

func TestNotFoundError_CustomMessage(t *testing.T) {
	env := NotFoundError("User not found")
	if env.Message != "User not found" {
		t.Errorf("expected 'User not found', got '%s'", env.Message)
	}
}

func TestRateLimitError_RetryAfter(t *testing.T) {
	env := RateLimitError(60)
	if env.Status != 429 {
		t.Errorf("expected status 429, got %d", env.Status)
	}
	if env.RetryAfter == nil || *env.RetryAfter != 60 {
		t.Errorf("expected retry_after 60, got %v", env.RetryAfter)
	}
	if env.Code != "rate_limit_exceeded" {
		t.Errorf("expected code rate_limit_exceeded, got %s", env.Code)
	}
}

func TestRateLimitError_IsRetriable(t *testing.T) {
	env := RateLimitError(30)
	if !env.IsRetriable {
		t.Error("rate limit error should be retriable")
	}
}
