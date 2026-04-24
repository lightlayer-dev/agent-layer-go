package agentlayerchi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lightlayer-dev/agent-layer-go/core"
)

// ── Helpers ─────────────────────────────────────────────────────────────

func setupRouter() *chi.Mux {
	r := chi.NewRouter()
	return r
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func htmlHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<html><head></head><body><main>content</main></body></html>`))
}

func decodeJSONBody(t *testing.T, body *bytes.Buffer) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	return result
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// mockFacilitator is a test double for FacilitatorClient.
type mockFacilitator struct {
	verifyResp *core.VerifyResponse
	verifyErr  error
	settleResp *core.SettleResponse
	settleErr  error
}

func (m *mockFacilitator) Verify(payload core.PaymentPayload, requirements core.PaymentRequirements) (*core.VerifyResponse, error) {
	return m.verifyResp, m.verifyErr
}

func (m *mockFacilitator) Settle(payload core.PaymentPayload, requirements core.PaymentRequirements) (*core.SettleResponse, error) {
	return m.settleResp, m.settleErr
}

// ── TestRateLimits ──────────────────────────────────────────────────────

func TestRateLimits(t *testing.T) {
	r := setupRouter()
	r.Use(RateLimits(core.RateLimitConfig{
		Max:      2,
		WindowMs: 60000,
	}))
	r.Get("/test", okHandler)

	// First request — should succeed
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-RateLimit-Limit") != "2" {
		t.Errorf("expected X-RateLimit-Limit=2, got %s", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "1" {
		t.Errorf("expected X-RateLimit-Remaining=1, got %s", rec.Header().Get("X-RateLimit-Remaining"))
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("expected X-RateLimit-Reset to be set")
	}

	// Second request — should succeed
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}

	// Third request — should be rate limited
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec3.Code)
	}
	if rec3.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header to be set")
	}
	if rec3.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("expected X-RateLimit-Remaining=0, got %s", rec3.Header().Get("X-RateLimit-Remaining"))
	}
}

// ── TestApiKeyAuth ──────────────────────────────────────────────────────

func TestApiKeyAuth(t *testing.T) {
	store := core.NewMemoryApiKeyStore()
	result := core.CreateApiKey(store, core.CreateApiKeyOptions{
		CompanyID: "company1",
		UserID:    "user1",
		Scopes:    []string{"read", "write"},
	})
	validKey := result.RawKey

	r := setupRouter()
	r.Use(ApiKeyAuth(core.ApiKeyConfig{Store: store}))
	r.Get("/protected", okHandler)

	t.Run("valid key via X-API-Key header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("X-API-Key", validKey)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("valid key via Authorization Bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+validKey)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("missing key returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "missing_api_key" {
			t.Errorf("expected code missing_api_key, got %v", errObj["code"])
		}
	})

	t.Run("invalid key returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("X-API-Key", "al_invalid_key_that_does_not_exist")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "invalid_api_key" {
			t.Errorf("expected code invalid_api_key, got %v", errObj["code"])
		}
	})
}

// ── TestRequireScope ────────────────────────────────────────────────────

func TestRequireScope(t *testing.T) {
	store := core.NewMemoryApiKeyStore()
	result := core.CreateApiKey(store, core.CreateApiKeyOptions{
		Scopes: []string{"read"},
	})
	validKey := result.RawKey

	r := setupRouter()
	r.Use(ApiKeyAuth(core.ApiKeyConfig{Store: store}))

	r.With(RequireScope("read")).Get("/readable", okHandler)
	r.With(RequireScope("admin")).Get("/admin-only", okHandler)

	t.Run("valid scope passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/readable", nil)
		req.Header.Set("X-API-Key", validKey)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("missing scope returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		req.Header.Set("X-API-Key", validKey)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "insufficient_scope" {
			t.Errorf("expected code insufficient_scope, got %v", errObj["code"])
		}
	})

	t.Run("no key returns 401", func(t *testing.T) {
		// Use a sub-router with RequireScope only (no ApiKeyAuth) to test nil key path
		r2 := setupRouter()
		r2.Use(RequireScope("read"))
		r2.Get("/test", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		r2.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}

// ── TestLlmsTxtHandler ──────────────────────────────────────────────────

func TestLlmsTxtHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/llms.txt", LlmsTxtHandler(core.LlmsTxtConfig{
		Title:       "Test API",
		Description: "A test API for agents",
	}))

	req := httptest.NewRequest(http.MethodGet, "/llms.txt", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# Test API") {
		t.Errorf("expected body to contain title, got: %s", body)
	}
	if !strings.Contains(body, "A test API for agents") {
		t.Errorf("expected body to contain description, got: %s", body)
	}
}

// ── TestLlmsFullTxtHandler ──────────────────────────────────────────────

func TestLlmsFullTxtHandler(t *testing.T) {
	routes := []core.RouteMetadata{
		{Method: "GET", Path: "/users", Summary: "List users"},
		{Method: "POST", Path: "/users", Summary: "Create user"},
	}
	r := setupRouter()
	r.Get("/llms-full.txt", LlmsFullTxtHandler(core.LlmsTxtConfig{
		Title:       "Full API",
		Description: "Full description",
	}, routes))

	req := httptest.NewRequest(http.MethodGet, "/llms-full.txt", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "GET /users") {
		t.Errorf("expected body to contain route info, got: %s", body)
	}
	if !strings.Contains(body, "POST /users") {
		t.Errorf("expected body to contain route info, got: %s", body)
	}
	if !strings.Contains(body, "API Endpoints") {
		t.Errorf("expected body to contain API Endpoints section, got: %s", body)
	}
}

// ── TestDiscoveryHandler ────────────────────────────────────────────────

func TestDiscoveryHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/.well-known/ai", DiscoveryHandler(core.DiscoveryConfig{
		Manifest: core.AIManifest{
			Name:        "TestAPI",
			Description: "A test API",
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ai", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
	body := decodeJSONBody(t, rec.Body)
	if body["name"] != "TestAPI" {
		t.Errorf("expected name TestAPI, got %v", body["name"])
	}
}

// ── TestA2AHandler ──────────────────────────────────────────────────────

func TestA2AHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/.well-known/agent.json", A2AHandler(core.A2AConfig{
		Card: core.A2AAgentCard{
			Name: "TestAgent",
			URL:  "https://example.com",
			Skills: []core.A2ASkill{
				{ID: "s1", Name: "Skill One"},
			},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent.json", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
	body := decodeJSONBody(t, rec.Body)
	if body["name"] != "TestAgent" {
		t.Errorf("expected name TestAgent, got %v", body["name"])
	}
	skills, ok := body["skills"].([]interface{})
	if !ok || len(skills) != 1 {
		t.Errorf("expected 1 skill, got %v", body["skills"])
	}
}

// ── TestAgentsTxtHandler ────────────────────────────────────────────────

func TestAgentsTxtHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/agents.txt", AgentsTxtHandler(core.AgentsTxtConfig{
		SiteName: "TestSite",
		Rules: []core.AgentsTxtRule{
			{Agent: "*", Allow: []string{"/*"}},
			{Agent: "GPTBot", Deny: []string{"/private"}},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/agents.txt", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Errorf("expected body to contain wildcard agent rule, got: %s", body)
	}
	if !strings.Contains(body, "User-agent: GPTBot") {
		t.Errorf("expected body to contain GPTBot rule, got: %s", body)
	}
	if !strings.Contains(body, "TestSite") {
		t.Errorf("expected body to contain site name, got: %s", body)
	}
}

// ── TestAgentsTxtEnforce ────────────────────────────────────────────────

func TestAgentsTxtEnforce(t *testing.T) {
	config := core.AgentsTxtConfig{
		Rules: []core.AgentsTxtRule{
			{Agent: "*", Allow: []string{"/*"}},
			{Agent: "GPTBot", Deny: []string{"/secret"}},
		},
	}
	r := setupRouter()
	r.Use(AgentsTxtEnforce(config))
	r.Get("/public", okHandler)
	r.Get("/secret", okHandler)

	t.Run("allowed agent passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/public", nil)
		req.Header.Set("User-Agent", "GPTBot/1.0")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("denied agent gets 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/secret", nil)
		req.Header.Set("User-Agent", "GPTBot/1.0")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "agent_not_allowed" {
			t.Errorf("expected code agent_not_allowed, got %v", errObj["code"])
		}
	})

	t.Run("non-agent request passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/secret", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (regular browser)")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

func TestRobotsTxtHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/robots.txt", RobotsTxtHandler(core.RobotsTxtConfig{}))

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "User-agent: GPTBot") {
		t.Fatalf("expected AI-agent robots.txt content, got:\n%s", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=86400" {
		t.Fatalf("unexpected cache-control: %q", rec.Header().Get("Cache-Control"))
	}
}

func TestSecurityHeaders(t *testing.T) {
	r := setupRouter()
	r.Use(SecurityHeaders(core.SecurityHeadersConfig{}))
	r.Get("/test", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("expected HSTS header")
	}
	if rec.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Fatalf("unexpected CSP header: %q", rec.Header().Get("Content-Security-Policy"))
	}
}

func TestAgentOnboarding(t *testing.T) {
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"provisioned","credentials":{"type":"api_key","token":"al_test_key"}}`)),
			}, nil
		}),
	}

	t.Run("register route provisions credentials", func(t *testing.T) {
		r := setupRouter()
		r.Post("/agent/register", AgentOnboardingHandler(core.OnboardingConfig{
			ProvisioningWebhook: "https://example.com/provision",
			HTTPClient:          httpClient,
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/register", strings.NewReader(`{"agent_id":"agent-1","agent_name":"Agent One","agent_provider":"OpenAI"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"provisioned"`) {
			t.Fatalf("expected provisioned response, got: %s", rec.Body.String())
		}
	})

	t.Run("auth middleware returns onboarding 401", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentOnboardingAuth(core.OnboardingConfig{
			ProvisioningWebhook: "https://example.com/provision",
			HTTPClient:          httpClient,
			AuthDocs:            "https://example.com/auth",
		}))
		r.Get("/private", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"register_url":"/agent/register"`) {
			t.Fatalf("expected onboarding response, got: %s", rec.Body.String())
		}
	})
}

// ── TestMcpHandler ──────────────────────────────────────────────────────

func TestMcpHandler(t *testing.T) {
	r := setupRouter()
	r.Post("/mcp", McpHandler(core.McpServerConfig{
		Name:    "TestMCP",
		Version: "1.0.0",
	}))

	t.Run("initialize returns server info", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		if body["jsonrpc"] != "2.0" {
			t.Errorf("expected jsonrpc 2.0, got %v", body["jsonrpc"])
		}
		result := body["result"].(map[string]interface{})
		serverInfo := result["serverInfo"].(map[string]interface{})
		if serverInfo["name"] != "TestMCP" {
			t.Errorf("expected server name TestMCP, got %v", serverInfo["name"])
		}
	})

	t.Run("GET returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rec := httptest.NewRecorder()
		// Mount a handler that accepts GET to test the method check inside McpHandler
		r2 := setupRouter()
		r2.HandleFunc("/mcp", McpHandler(core.McpServerConfig{Name: "TestMCP"}))
		r2.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
	})

	t.Run("invalid JSON returns parse error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("not json"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"].(float64) != -32700 {
			t.Errorf("expected error code -32700, got %v", errObj["code"])
		}
	})

	t.Run("ping returns empty result", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		if body["result"] == nil {
			t.Error("expected non-nil result for ping")
		}
	})

	t.Run("notification (no id) returns 204", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
	})
}

// ── TestAgUiStreamHandler ───────────────────────────────────────────────

func TestAgUiStreamHandler(t *testing.T) {
	r := setupRouter()
	r.Post("/stream", AgUiStreamHandler(func(emitter *core.AgUiEmitter) error {
		emitter.RunStarted("")
		emitter.TextMessage("Hello", "assistant")
		emitter.RunFinished(nil)
		return nil
	}))

	req := httptest.NewRequest(http.MethodPost, "/stream", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: RUN_STARTED") {
		t.Errorf("expected body to contain RUN_STARTED event, got: %s", body)
	}
	if !strings.Contains(body, "event: TEXT_MESSAGE_START") {
		t.Errorf("expected body to contain TEXT_MESSAGE_START event, got: %s", body)
	}
	if !strings.Contains(body, "event: RUN_FINISHED") {
		t.Errorf("expected body to contain RUN_FINISHED event, got: %s", body)
	}
}

// ── TestOAuth2MetadataHandler ───────────────────────────────────────────

func TestOAuth2MetadataHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/.well-known/oauth-authorization-server", OAuth2MetadataHandler(core.OAuth2Config{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		Issuer:                "https://auth.example.com",
		Scopes:                map[string]string{"read": "Read access"},
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
	body := decodeJSONBody(t, rec.Body)
	if body["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Errorf("unexpected authorization_endpoint: %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("unexpected token_endpoint: %v", body["token_endpoint"])
	}
	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("unexpected issuer: %v", body["issuer"])
	}
}

// ── TestAgentAnalytics ──────────────────────────────────────────────────

func TestAgentAnalytics(t *testing.T) {
	var recorded []core.AgentEvent
	r := setupRouter()
	r.Use(AgentAnalytics(core.AnalyticsConfig{
		TrackAll: false,
		OnEvent: func(event core.AgentEvent) {
			recorded = append(recorded, event)
		},
	}))
	r.Get("/test", okHandler)

	t.Run("detects known agent and records event", func(t *testing.T) {
		recorded = nil
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("User-Agent", "ClaudeBot/1.0")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if len(recorded) != 1 {
			t.Fatalf("expected 1 recorded event, got %d", len(recorded))
		}
		if recorded[0].Agent != "ClaudeBot" {
			t.Errorf("expected agent ClaudeBot, got %s", recorded[0].Agent)
		}
		if recorded[0].Path != "/test" {
			t.Errorf("expected path /test, got %s", recorded[0].Path)
		}
		if recorded[0].StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorded[0].StatusCode)
		}
	})

	t.Run("non-agent request is not recorded when TrackAll is false", func(t *testing.T) {
		recorded = nil
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if len(recorded) != 0 {
			t.Errorf("expected 0 recorded events, got %d", len(recorded))
		}
	})

	t.Run("records all when TrackAll is true", func(t *testing.T) {
		var allRecorded []core.AgentEvent
		r2 := setupRouter()
		r2.Use(AgentAnalytics(core.AnalyticsConfig{
			TrackAll: true,
			OnEvent: func(event core.AgentEvent) {
				allRecorded = append(allRecorded, event)
			},
		}))
		r2.Get("/test", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		rec := httptest.NewRecorder()
		r2.ServeHTTP(rec, req)

		if len(allRecorded) != 1 {
			t.Errorf("expected 1 recorded event with TrackAll, got %d", len(allRecorded))
		}
	})
}

// ── TestAgentMeta ───────────────────────────────────────────────────────

func TestAgentMeta(t *testing.T) {
	r := setupRouter()
	r.Use(AgentMeta(core.AgentMetaConfig{
		MetaTags: map[string]string{
			"agent-description": "A test service",
		},
	}))
	r.Get("/page", htmlHandler)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-agent-id="root"`) {
		t.Errorf("expected body to contain data-agent-id attribute, got: %s", body)
	}
	if !strings.Contains(body, `role="main"`) {
		t.Errorf("expected body to contain ARIA landmark, got: %s", body)
	}
	if !strings.Contains(body, "agent-description") {
		t.Errorf("expected body to contain meta tag, got: %s", body)
	}
}

func TestAgentMeta_NonHTML(t *testing.T) {
	r := setupRouter()
	r.Use(AgentMeta(core.AgentMetaConfig{}))
	r.Get("/api", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("expected non-HTML response to pass through unchanged, got: %s", rec.Body.String())
	}
}

// ── TestX402Middleware ───────────────────────────────────────────────────

func TestX402Middleware(t *testing.T) {
	routeConfig := core.X402RouteConfig{
		PayTo:   "0xTestAddress",
		Scheme:  "exact",
		Price:   "$0.01",
		Network: "base-sepolia",
	}

	t.Run("non-matching route passes through", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
		}))
		r.Get("/free", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/free", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("matching route without payment returns 402", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
		}))
		r.Get("/paid", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("expected 402, got %d", rec.Code)
		}
		if rec.Header().Get("Payment-Required") == "" {
			t.Error("expected Payment-Required header to be set")
		}
		body := decodeJSONBody(t, rec.Body)
		if body["x402Version"] == nil {
			t.Error("expected x402Version in response body")
		}
	})

	t.Run("matching route with valid payment and facilitator passes through", func(t *testing.T) {
		fac := &mockFacilitator{
			verifyResp: &core.VerifyResponse{IsValid: true},
			settleResp: &core.SettleResponse{Success: true, TxHash: "0xabc"},
		}

		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: fac,
		}))
		r.Get("/paid", okHandler)

		payload := core.PaymentPayload{
			X402Version: 1,
			Accepted: core.PaymentRequirements{
				Scheme:  "exact",
				Network: "base-sepolia",
				Asset:   "USDC",
				Amount:  "0.01",
				PayTo:   "0xTestAddress",
			},
			Payload: map[string]interface{}{"sig": "test"},
		}
		payloadJSON, _ := json.Marshal(payload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadJSON)

		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		req.Header.Set("Payment-Signature", paymentHeader)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if rec.Header().Get("Payment-Response") != "0xabc" {
			t.Errorf("expected Payment-Response header 0xabc, got %s", rec.Header().Get("Payment-Response"))
		}
	})

	t.Run("invalid payment signature returns 400", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
		}))
		r.Get("/paid", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		req.Header.Set("Payment-Signature", "not-valid-base64!!!")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("facilitator verify failure returns 502", func(t *testing.T) {
		fac := &mockFacilitator{
			verifyErr: fmt.Errorf("network error"),
		}

		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: fac,
		}))
		r.Get("/paid", okHandler)

		payload := core.PaymentPayload{
			X402Version: 1,
			Accepted:    core.PaymentRequirements{Scheme: "exact"},
			Payload:     map[string]interface{}{"sig": "test"},
		}
		payloadJSON, _ := json.Marshal(payload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadJSON)

		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		req.Header.Set("Payment-Signature", paymentHeader)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d", rec.Code)
		}
	})

	t.Run("facilitator verify invalid returns 402", func(t *testing.T) {
		fac := &mockFacilitator{
			verifyResp: &core.VerifyResponse{IsValid: false, InvalidReason: "bad sig"},
		}

		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: fac,
		}))
		r.Get("/paid", okHandler)

		payload := core.PaymentPayload{
			X402Version: 1,
			Accepted:    core.PaymentRequirements{Scheme: "exact"},
			Payload:     map[string]interface{}{"sig": "test"},
		}
		payloadJSON, _ := json.Marshal(payload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadJSON)

		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		req.Header.Set("Payment-Signature", paymentHeader)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("expected 402, got %d", rec.Code)
		}
	})

	t.Run("facilitator settle failure returns 502", func(t *testing.T) {
		fac := &mockFacilitator{
			verifyResp: &core.VerifyResponse{IsValid: true},
			settleErr:  fmt.Errorf("settle network error"),
		}

		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: fac,
		}))
		r.Get("/paid", okHandler)

		payload := core.PaymentPayload{
			X402Version: 1,
			Accepted:    core.PaymentRequirements{Scheme: "exact"},
			Payload:     map[string]interface{}{"sig": "test"},
		}
		payloadJSON, _ := json.Marshal(payload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadJSON)

		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		req.Header.Set("Payment-Signature", paymentHeader)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d", rec.Code)
		}
	})
}

// ── TestGetAgentKey / TestGetAgentIdentity / TestGetX402Payment ─────────

func TestGetAgentKey(t *testing.T) {
	t.Run("returns nil when not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		key := GetAgentKey(req)
		if key != nil {
			t.Error("expected nil when no key in context")
		}
	})

	t.Run("returns key from context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		expected := &core.ScopedApiKey{KeyID: "test-key", Scopes: []string{"read"}}
		ctx := context.WithValue(req.Context(), ctxAgentKey, expected)
		req = req.WithContext(ctx)

		key := GetAgentKey(req)
		if key == nil {
			t.Fatal("expected non-nil key")
		}
		if key.KeyID != "test-key" {
			t.Errorf("expected KeyID test-key, got %s", key.KeyID)
		}
	})
}

func TestGetAgentIdentity(t *testing.T) {
	t.Run("returns nil when not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		identity := GetAgentIdentity(req)
		if identity != nil {
			t.Error("expected nil when no identity in context")
		}
	})

	t.Run("returns identity from context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		expected := &core.AgentIdentityClaims{AgentID: "agent-1", Issuer: "test-issuer"}
		ctx := context.WithValue(req.Context(), ctxAgentIdentity, expected)
		req = req.WithContext(ctx)

		identity := GetAgentIdentity(req)
		if identity == nil {
			t.Fatal("expected non-nil identity")
		}
		if identity.AgentID != "agent-1" {
			t.Errorf("expected AgentID agent-1, got %s", identity.AgentID)
		}
	})
}

func TestGetX402Payment(t *testing.T) {
	t.Run("returns nil when not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		payment := GetX402Payment(req)
		if payment != nil {
			t.Error("expected nil when no payment in context")
		}
	})

	t.Run("returns payment from context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		expected := &core.PaymentPayload{X402Version: 1}
		ctx := context.WithValue(req.Context(), ctxX402Payment, expected)
		req = req.WithContext(ctx)

		payment := GetX402Payment(req)
		if payment == nil {
			t.Fatal("expected non-nil payment")
		}
		if payment.X402Version != 1 {
			t.Errorf("expected X402Version 1, got %d", payment.X402Version)
		}
	})
}

// ── TestAgentLayer ──────────────────────────────────────────────────────

func TestAgentLayer(t *testing.T) {
	store := core.NewMemoryApiKeyStore()
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"provisioned"}`)),
			}, nil
		}),
	}

	config := core.AgentLayerConfig{
		LlmsTxt: &core.LlmsTxtConfig{
			Title:       "Test API",
			Description: "An API",
		},
		Discovery: &core.DiscoveryConfig{
			Manifest: core.AIManifest{
				Name:        "TestAPI",
				Description: "Test",
			},
		},
		A2A: &core.A2AConfig{
			Card: core.A2AAgentCard{
				Name: "TestAgent",
				URL:  "https://example.com",
			},
		},
		AgentsTxt: &core.AgentsTxtMiddlewareConfig{
			AgentsTxtConfig: core.AgentsTxtConfig{
				Rules: []core.AgentsTxtRule{{Agent: "*", Allow: []string{"/*"}}},
			},
		},
		RobotsTxt:       &core.RobotsTxtConfig{},
		SecurityHeaders: &core.SecurityHeadersConfig{},
		AgentOnboarding: &core.OnboardingConfig{
			ProvisioningWebhook: "https://example.com/provision",
			HTTPClient:          httpClient,
		},
		MCP: &core.McpServerConfig{
			Name:    "TestMCP",
			Version: "1.0.0",
		},
		OAuth2: &core.OAuth2Config{
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			TokenEndpoint:         "https://auth.example.com/token",
		},
		ApiKeys: &core.ApiKeyConfig{
			Store: store,
		},
		Routes: []core.RouteMetadata{
			{Method: "GET", Path: "/items", Summary: "List items"},
		},
	}

	router := AgentLayer(config)
	router.Get("/private", okHandler)

	// We need a valid key to pass ApiKeyAuth
	result := core.CreateApiKey(store, core.CreateApiKeyOptions{
		Scopes: []string{"*"},
	})
	apiKey := result.RawKey

	routes := []struct {
		method       string
		path         string
		expectedCode int
		checkBody    func(t *testing.T, body string)
	}{
		{
			method:       http.MethodGet,
			path:         "/llms.txt",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "Test API") {
					t.Error("llms.txt should contain title")
				}
			},
		},
		{
			method:       http.MethodGet,
			path:         "/llms-full.txt",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "Test API") {
					t.Error("llms-full.txt should contain title")
				}
			},
		},
		{
			method:       http.MethodGet,
			path:         "/.well-known/ai",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "TestAPI") {
					t.Error("discovery should contain API name")
				}
			},
		},
		{
			method:       http.MethodGet,
			path:         "/.well-known/agent.json",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "TestAgent") {
					t.Error("agent card should contain agent name")
				}
			},
		},
		{
			method:       http.MethodGet,
			path:         "/agents.txt",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "User-agent: *") {
					t.Error("agents.txt should contain rules")
				}
			},
		},
		{
			method:       http.MethodGet,
			path:         "/robots.txt",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "User-agent: GPTBot") {
					t.Error("robots.txt should contain AI-agent rules")
				}
			},
		},
		{
			method:       http.MethodGet,
			path:         "/.well-known/oauth-authorization-server",
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, "authorization_endpoint") {
					t.Error("oauth2 metadata should contain authorization_endpoint")
				}
			},
		},
	}

	for _, tc := range routes {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.path), func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-API-Key", apiKey)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.expectedCode {
				t.Fatalf("expected %d, got %d; body: %s", tc.expectedCode, rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Strict-Transport-Security") == "" {
				t.Fatalf("expected security headers on %s", tc.path)
			}
			if tc.checkBody != nil {
				tc.checkBody(t, rec.Body.String())
			}
		})
	}

	// Test MCP POST separately
	t.Run("POST /mcp", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("onboarding auth middleware returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"register_url":"/agent/register"`) {
			t.Fatalf("expected onboarding response, got: %s", rec.Body.String())
		}
	})

	t.Run("onboarding register route is wired", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/agent/register", strings.NewReader(`{"agent_id":"agent-1","agent_name":"Agent One","agent_provider":"OpenAI"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ── TestAgentErrors ─────────────────────────────────────────────────────

func TestAgentErrors(t *testing.T) {
	t.Run("catches AgentError panic", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentErrors())
		r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic(core.NewAgentError(core.AgentErrorOptions{
				Code:    "test_error",
				Message: "Something went wrong",
				Status:  422,
			}))
		})

		req := httptest.NewRequest(http.MethodGet, "/panic", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != 422 {
			t.Fatalf("expected 422, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "test_error" {
			t.Errorf("expected code test_error, got %v", errObj["code"])
		}
	})

	t.Run("catches generic panic", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentErrors())
		r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("unexpected failure")
		})

		req := httptest.NewRequest(http.MethodGet, "/panic", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != 500 {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
		body := decodeJSONBody(t, rec.Body)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "internal_error" {
			t.Errorf("expected code internal_error, got %v", errObj["code"])
		}
	})
}

// ── TestJsonLdHandler ───────────────────────────────────────────────────

func TestJsonLdHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/.well-known/ai/json-ld", JsonLdHandler(core.DiscoveryConfig{
		Manifest: core.AIManifest{
			Name:        "TestAPI",
			Description: "A test",
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ai/json-ld", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/ld+json") {
		t.Errorf("expected Content-Type application/ld+json, got %s", ct)
	}
	body := decodeJSONBody(t, rec.Body)
	if body["@context"] != "https://schema.org" {
		t.Errorf("expected @context https://schema.org, got %v", body["@context"])
	}
	if body["name"] != "TestAPI" {
		t.Errorf("expected name TestAPI, got %v", body["name"])
	}
}

// ── TestAgentAuthHandler ────────────────────────────────────────────────

func TestAgentAuthHandler(t *testing.T) {
	r := setupRouter()
	r.Get("/.well-known/agent-auth", AgentAuthHandler(core.AgentAuthConfig{
		Issuer:           "https://auth.example.com",
		AuthorizationURL: "https://auth.example.com/authorize",
		TokenURL:         "https://auth.example.com/token",
		Scopes:           map[string]string{"read": "Read access"},
		Realm:            "myagent",
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent-auth", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `realm="myagent"`) {
		t.Errorf("expected WWW-Authenticate to contain realm, got: %s", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "authorization_uri=") {
		t.Errorf("expected WWW-Authenticate to contain authorization_uri, got: %s", wwwAuth)
	}
	body := decodeJSONBody(t, rec.Body)
	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("expected issuer, got %v", body["issuer"])
	}
}

// ── TestResponseWriter ──────────────────────────────────────────────────

func TestResponseWriter(t *testing.T) {
	t.Run("captures status code and bytes written", func(t *testing.T) {
		base := httptest.NewRecorder()
		rw := newResponseWriter(base)

		rw.WriteHeader(http.StatusCreated)
		n, err := rw.Write([]byte("hello"))
		if err != nil {
			t.Fatal(err)
		}

		if rw.statusCode != http.StatusCreated {
			t.Errorf("expected status 201, got %d", rw.statusCode)
		}
		if rw.bytesWritten != int64(n) {
			t.Errorf("expected bytesWritten %d, got %d", n, rw.bytesWritten)
		}
	})

	t.Run("does not double-write header", func(t *testing.T) {
		base := httptest.NewRecorder()
		rw := newResponseWriter(base)

		rw.WriteHeader(http.StatusCreated)
		rw.WriteHeader(http.StatusBadRequest) // should be ignored

		if rw.statusCode != http.StatusCreated {
			t.Errorf("expected status 201 (first write), got %d", rw.statusCode)
		}
	})

	t.Run("defaults to 200", func(t *testing.T) {
		base := httptest.NewRecorder()
		rw := newResponseWriter(base)

		if rw.statusCode != http.StatusOK {
			t.Errorf("expected default status 200, got %d", rw.statusCode)
		}
	})

	t.Run("Unwrap returns underlying writer", func(t *testing.T) {
		base := httptest.NewRecorder()
		rw := newResponseWriter(base)

		if rw.Unwrap() != base {
			t.Error("Unwrap should return the base ResponseWriter")
		}
	})
}
