package core

import "fmt"

var statusTypes = map[int]string{
	400: "invalid_request_error",
	401: "authentication_error",
	403: "permission_error",
	404: "not_found_error",
	409: "conflict_error",
	422: "validation_error",
	429: "rate_limit_error",
	500: "api_error",
}

func typeForStatus(status int) string {
	if t, ok := statusTypes[status]; ok {
		return t
	}
	return "api_error"
}

// FormatError formats an error into the standard agent-friendly envelope.
func FormatError(opts AgentErrorOptions) AgentErrorEnvelope {
	status := opts.Status
	if status == 0 {
		status = 500
	}

	typ := opts.Type
	if typ == "" {
		typ = typeForStatus(status)
	}

	isRetriable := status == 429 || status >= 500
	if opts.IsRetriable != nil {
		isRetriable = *opts.IsRetriable
	}

	return AgentErrorEnvelope{
		Type:        typ,
		Code:        opts.Code,
		Message:     opts.Message,
		Status:      status,
		IsRetriable: isRetriable,
		RetryAfter:  opts.RetryAfter,
		Param:       opts.Param,
		DocsURL:     opts.DocsURL,
	}
}

// AgentError is a custom error that carries the agent error envelope.
type AgentError struct {
	Envelope AgentErrorEnvelope
}

func (e *AgentError) Error() string {
	return e.Envelope.Message
}

// NewAgentError creates a new AgentError from options.
func NewAgentError(opts AgentErrorOptions) *AgentError {
	return &AgentError{Envelope: FormatError(opts)}
}

// ToJSON returns the error in the standard JSON format.
func (e *AgentError) ToJSON() map[string]interface{} {
	return map[string]interface{}{
		"error": e.Envelope,
	}
}

// NotFoundError creates a 404 Not Found error envelope.
func NotFoundError(message string) AgentErrorEnvelope {
	if message == "" {
		message = "The requested resource was not found."
	}
	return FormatError(AgentErrorOptions{Code: "not_found", Message: message, Status: 404})
}

// RateLimitError creates a 429 Rate Limit error envelope.
func RateLimitError(retryAfter int) AgentErrorEnvelope {
	isRetriable := true
	return FormatError(AgentErrorOptions{
		Code:        "rate_limit_exceeded",
		Message:     fmt.Sprintf("Too many requests. Please retry after the specified time."),
		Status:      429,
		IsRetriable: &isRetriable,
		RetryAfter:  &retryAfter,
	})
}
