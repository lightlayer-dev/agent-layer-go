package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	supportedCredentialTypes = []string{"api_key", "oauth2_client_credentials", "bearer"}
	exemptOnboardingPaths    = map[string]struct{}{
		"/agent/register": {},
		"/llms.txt":       {},
		"/llms-full.txt":  {},
		"/agents.txt":     {},
		"/robots.txt":     {},
	}
)

// OnboardingConfig configures agent self-registration and auth-required responses.
type OnboardingConfig struct {
	ProvisioningWebhook string
	WebhookSecret       string
	WebhookTimeoutMs    int
	RequireIdentity     bool
	AllowedProviders    []string
	AuthDocs            string
	RateLimitMax        int
	RateLimitWindowMs   int64
	HTTPClient          *http.Client
}

// RegistrationRequest is the JSON payload accepted by POST /agent/register.
type RegistrationRequest struct {
	AgentID       string                 `json:"agent_id"`
	AgentName     string                 `json:"agent_name"`
	AgentProvider string                 `json:"agent_provider"`
	IdentityToken string                 `json:"identity_token,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// Credential is a provisioned credential descriptor.
type Credential struct {
	Type          string   `json:"type"`
	Token         string   `json:"token,omitempty"`
	Header        string   `json:"header,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	TokenEndpoint string   `json:"token_endpoint,omitempty"`
	AccessToken   string   `json:"access_token,omitempty"`
	RefreshToken  string   `json:"refresh_token,omitempty"`
	ExpiresIn     int      `json:"expires_in,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
}

// RegistrationResponse is the normalized provisioning response.
type RegistrationResponse struct {
	Status      string      `json:"status"`
	Credentials *Credential `json:"credentials,omitempty"`
	Reason      string      `json:"reason,omitempty"`
}

// HandlerResult is the result returned by the onboarding handler.
type HandlerResult struct {
	Status int
	Body   interface{}
}

type onboardingWebhookRequest struct {
	AgentID          string `json:"agent_id"`
	AgentName        string `json:"agent_name"`
	AgentProvider    string `json:"agent_provider"`
	IdentityVerified bool   `json:"identity_verified"`
	RequestIP        string `json:"request_ip"`
	Timestamp        string `json:"timestamp"`
}

type rateLimitWindow struct {
	Count   int
	ResetAt time.Time
}

// OnboardingHandler is a stateless registration handler plus auth-required helper.
type OnboardingHandler struct {
	config  OnboardingConfig
	client  *http.Client
	mu      sync.Mutex
	windows map[string]rateLimitWindow
}

// CreateOnboardingHandler creates an onboarding handler from config.
func CreateOnboardingHandler(config OnboardingConfig) *OnboardingHandler {
	timeout := time.Duration(config.WebhookTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	} else if client.Timeout == 0 {
		client.Timeout = timeout
	}

	return &OnboardingHandler{
		config:  config,
		client:  client,
		windows: map[string]rateLimitWindow{},
	}
}

// SignWebhookPayload computes an HMAC-SHA256 signature for the provisioning webhook body.
func SignWebhookPayload(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature validates a webhook payload signature.
func VerifyWebhookSignature(body, secret, signature string) bool {
	expected := "sha256=" + SignWebhookPayload(body, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// HandleRegister validates a registration request and proxies it to the provisioning webhook.
func (h *OnboardingHandler) HandleRegister(body RegistrationRequest, clientIP string) HandlerResult {
	if !h.checkRateLimit(clientIP) {
		return HandlerResult{
			Status: http.StatusTooManyRequests,
			Body: map[string]interface{}{
				"error": FormatError(AgentErrorOptions{
					Code:        "rate_limit_exceeded",
					Message:     "Too many registration attempts. Try again later.",
					Status:      http.StatusTooManyRequests,
					IsRetriable: onboardingBoolPtr(true),
				}),
			},
		}
	}

	if body.AgentID == "" {
		return h.missingField("agent_id")
	}
	if body.AgentName == "" {
		return h.missingField("agent_name")
	}
	if body.AgentProvider == "" {
		return h.missingField("agent_provider")
	}
	if h.config.RequireIdentity && body.IdentityToken == "" {
		return HandlerResult{
			Status: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": FormatError(AgentErrorOptions{
					Code:    "identity_required",
					Message: "This API requires an identity_token for registration",
					Status:  http.StatusBadRequest,
				}),
			},
		}
	}

	if len(h.config.AllowedProviders) > 0 {
		allowed := false
		for _, provider := range h.config.AllowedProviders {
			if strings.EqualFold(provider, body.AgentProvider) {
				allowed = true
				break
			}
		}
		if !allowed {
			return HandlerResult{
				Status: http.StatusForbidden,
				Body: map[string]interface{}{
					"error": FormatError(AgentErrorOptions{
						Code:    "provider_not_allowed",
						Message: `Agent provider "` + body.AgentProvider + `" is not allowed`,
						Status:  http.StatusForbidden,
					}),
				},
			}
		}
	}

	payload := onboardingWebhookRequest{
		AgentID:          body.AgentID,
		AgentName:        body.AgentName,
		AgentProvider:    body.AgentProvider,
		IdentityVerified: body.IdentityToken != "",
		RequestIP:        clientIP,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}

	webhookBody, err := json.Marshal(payload)
	if err != nil {
		return h.webhookError()
	}

	req, err := http.NewRequest(http.MethodPost, h.config.ProvisioningWebhook, bytes.NewReader(webhookBody))
	if err != nil {
		return h.webhookError()
	}
	req.Header.Set("Content-Type", "application/json")
	if h.config.WebhookSecret != "" {
		req.Header.Set("X-Webhook-Signature", "sha256="+SignWebhookPayload(string(webhookBody), h.config.WebhookSecret))
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return h.webhookError()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return h.webhookError()
	}

	var responseBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return h.webhookError()
	}

	status := http.StatusOK
	if responseBody["status"] == "rejected" {
		status = http.StatusForbidden
	}

	return HandlerResult{Status: status, Body: responseBody}
}

// ShouldReturn401 reports whether the request should receive the auth-required response.
func (h *OnboardingHandler) ShouldReturn401(path string, headers map[string]string) bool {
	if strings.HasPrefix(path, "/.well-known/") {
		return false
	}
	if _, ok := exemptOnboardingPaths[path]; ok {
		return false
	}

	normalized := map[string]string{}
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}

	if normalized["authorization"] != "" {
		return false
	}
	if normalized["x-api-key"] != "" {
		return false
	}
	return true
}

// GetAuthRequiredResponse returns the standard auth-required body.
func (h *OnboardingHandler) GetAuthRequiredResponse() map[string]interface{} {
	return map[string]interface{}{
		"error":                      "auth_required",
		"message":                    "This API requires authentication. Register to get credentials.",
		"register_url":               "/agent/register",
		"auth_docs":                  h.config.AuthDocs,
		"supported_credential_types": append([]string{}, supportedCredentialTypes...),
	}
}

func (h *OnboardingHandler) checkRateLimit(ip string) bool {
	if h.config.RateLimitMax <= 0 {
		return true
	}

	windowMs := h.config.RateLimitWindowMs
	if windowMs <= 0 {
		windowMs = 3600000
	}

	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()

	window, ok := h.windows[ip]
	if !ok || !now.Before(window.ResetAt) {
		h.windows[ip] = rateLimitWindow{
			Count:   1,
			ResetAt: now.Add(time.Duration(windowMs) * time.Millisecond),
		}
		return true
	}

	if window.Count >= h.config.RateLimitMax {
		return false
	}

	window.Count++
	h.windows[ip] = window
	return true
}

func (h *OnboardingHandler) missingField(field string) HandlerResult {
	return HandlerResult{
		Status: http.StatusBadRequest,
		Body: map[string]interface{}{
			"error": FormatError(AgentErrorOptions{
				Code:    "missing_field",
				Message: field + " is required",
				Status:  http.StatusBadRequest,
			}),
		},
	}
}

func (h *OnboardingHandler) webhookError() HandlerResult {
	return HandlerResult{
		Status: http.StatusBadGateway,
		Body: map[string]interface{}{
			"error": FormatError(AgentErrorOptions{
				Code:        "webhook_error",
				Message:     "Failed to provision credentials. Please try again later.",
				Status:      http.StatusBadGateway,
				IsRetriable: onboardingBoolPtr(true),
			}),
		},
	}
}

func onboardingBoolPtr(v bool) *bool {
	return &v
}
