package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestCreateOnboardingHandler_HandleRegister(t *testing.T) {
	var signature string
	handler := CreateOnboardingHandler(OnboardingConfig{
		ProvisioningWebhook: "https://example.com/provision",
		WebhookSecret:       "top-secret",
		HTTPClient: &http.Client{
			Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				signature = r.Header.Get("X-Webhook-Signature")
				defer r.Body.Close()

				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatalf("failed to decode webhook request: %v", err)
				}
				if body["agent_id"] != "agent-1" {
					t.Fatalf("expected agent_id agent-1, got %v", body["agent_id"])
				}

				respBody := `{"status":"provisioned","credentials":{"type":"api_key","token":"secret-token","header":"X-API-Key"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				}, nil
			}),
		},
	})

	result := handler.HandleRegister(RegistrationRequest{
		AgentID:       "agent-1",
		AgentName:     "Agent One",
		AgentProvider: "OpenAI",
		IdentityToken: "jwt",
	}, "127.0.0.1")

	if result.Status != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.Status)
	}
	body := result.Body.(map[string]interface{})
	if body["status"] != "provisioned" {
		t.Fatalf("expected provisioned response, got %v", body["status"])
	}
	if signature == "" {
		t.Fatal("expected webhook signature header")
	}
}

func TestCreateOnboardingHandler_RejectsInvalidRequests(t *testing.T) {
	handler := CreateOnboardingHandler(OnboardingConfig{
		ProvisioningWebhook: "https://example.com/provision",
		RequireIdentity:     true,
		AllowedProviders:    []string{"OpenAI"},
	})

	missingField := handler.HandleRegister(RegistrationRequest{}, "127.0.0.1")
	if missingField.Status != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing field, got %d", missingField.Status)
	}

	missingIdentity := handler.HandleRegister(RegistrationRequest{
		AgentID:       "agent-1",
		AgentName:     "Agent One",
		AgentProvider: "OpenAI",
	}, "127.0.0.1")
	if missingIdentity.Status != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing identity token, got %d", missingIdentity.Status)
	}

	providerDenied := handler.HandleRegister(RegistrationRequest{
		AgentID:       "agent-1",
		AgentName:     "Agent One",
		AgentProvider: "Anthropic",
		IdentityToken: "jwt",
	}, "127.0.0.1")
	if providerDenied.Status != http.StatusForbidden {
		t.Fatalf("expected 403 for denied provider, got %d", providerDenied.Status)
	}
}

func TestCreateOnboardingHandler_RateLimitAndAuthRequired(t *testing.T) {
	handler := CreateOnboardingHandler(OnboardingConfig{
		ProvisioningWebhook: "https://example.com/provision",
		RateLimitMax:        1,
		RateLimitWindowMs:   60000,
	})

	first := handler.HandleRegister(RegistrationRequest{
		AgentID:       "agent-1",
		AgentName:     "Agent One",
		AgentProvider: "OpenAI",
	}, "127.0.0.1")
	if first.Status != http.StatusBadGateway {
		t.Fatalf("expected first request to reach webhook and fail with 502, got %d", first.Status)
	}

	second := handler.HandleRegister(RegistrationRequest{
		AgentID:       "agent-2",
		AgentName:     "Agent Two",
		AgentProvider: "OpenAI",
	}, "127.0.0.1")
	if second.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second request, got %d", second.Status)
	}

	if !handler.ShouldReturn401("/api/private", map[string]string{}) {
		t.Fatal("expected auth-required response for unauthenticated API request")
	}
	if handler.ShouldReturn401("/robots.txt", map[string]string{}) {
		t.Fatal("did not expect auth-required response for robots.txt")
	}
	if handler.ShouldReturn401("/api/private", map[string]string{"Authorization": "Bearer abc"}) {
		t.Fatal("did not expect auth-required response when authorization is present")
	}

	authRequired := handler.GetAuthRequiredResponse()
	if authRequired["register_url"] != "/agent/register" {
		t.Fatalf("unexpected register_url: %v", authRequired["register_url"])
	}
}

func TestVerifyWebhookSignature(t *testing.T) {
	body := `{"agent_id":"agent-1"}`
	signature := "sha256=" + SignWebhookPayload(body, "secret")

	if !VerifyWebhookSignature(body, "secret", signature) {
		t.Fatal("expected signature to verify")
	}
	if VerifyWebhookSignature(body, "wrong", signature) {
		t.Fatal("did not expect signature to verify with wrong secret")
	}
}
