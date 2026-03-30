package agentlayerecho

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lightlayer-dev/agent-layer-go/core"
)

// ── Helpers ──────────────────────────────────────────────────────────────

func setupEcho() *echo.Echo {
	e := echo.New()
	return e
}

func doRequest(e *echo.Echo, method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func parseJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON response: %v\nbody: %s", err, rec.Body.String())
	}
	return result
}

// ── TestRateLimits ───────────────────────────────────────────────────────

func TestRateLimits(t *testing.T) {
	e := setupEcho()
	e.Use(RateLimits(core.RateLimitConfig{
		Max:      2,
		WindowMs: 60000,
	}))
	e.GET("/test", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	// First request: allowed
	rec := doRequest(e, "GET", "/test", "", nil)
	if rec.Code != 200 {
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

	// Second request: still allowed
	rec = doRequest(e, "GET", "/test", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("expected X-RateLimit-Remaining=0, got %s", rec.Header().Get("X-RateLimit-Remaining"))
	}

	// Third request: rate limited
	rec = doRequest(e, "GET", "/test", "", nil)
	if rec.Code != 429 {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header to be set")
	}

	body := parseJSON(t, rec)
	errObj, ok := body["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object in response")
	}
	if errObj["code"] != "rate_limit_exceeded" {
		t.Errorf("expected code rate_limit_exceeded, got %v", errObj["code"])
	}
}

// ── TestApiKeyAuth ───────────────────────────────────────────────────────

func TestApiKeyAuth(t *testing.T) {
	store := core.NewMemoryApiKeyStore()
	result := core.CreateApiKey(store, core.CreateApiKeyOptions{
		CompanyID: "test-co",
		UserID:    "user-1",
		Scopes:    []string{"read", "write"},
	})
	validKey := result.RawKey

	config := core.ApiKeyConfig{
		Store:      store,
		HeaderName: "X-API-Key",
	}

	t.Run("valid key via X-API-Key header", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(config))
		e.GET("/secure", func(c echo.Context) error {
			key := c.Get("apiKey")
			if key == nil {
				return c.String(500, "no key in context")
			}
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/secure", "", map[string]string{
			"X-API-Key": validKey,
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("valid key via Bearer token", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(config))
		e.GET("/secure", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/secure", "", map[string]string{
			"Authorization": "Bearer " + validKey,
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing key returns 401", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(config))
		e.GET("/secure", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/secure", "", nil)
		if rec.Code != 401 {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "missing_api_key" {
			t.Errorf("expected code missing_api_key, got %v", errObj["code"])
		}
	})

	t.Run("invalid key returns 401", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(config))
		e.GET("/secure", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/secure", "", map[string]string{
			"X-API-Key": "al_invalid_key_here",
		})
		if rec.Code != 401 {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "invalid_api_key" {
			t.Errorf("expected code invalid_api_key, got %v", errObj["code"])
		}
	})

	t.Run("default header name is X-API-Key", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(core.ApiKeyConfig{Store: store}))
		e.GET("/secure", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/secure", "", map[string]string{
			"X-API-Key": validKey,
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

// ── TestRequireScope ─────────────────────────────────────────────────────

func TestRequireScope(t *testing.T) {
	store := core.NewMemoryApiKeyStore()
	result := core.CreateApiKey(store, core.CreateApiKeyOptions{
		CompanyID: "test-co",
		UserID:    "user-1",
		Scopes:    []string{"read"},
	})
	validKey := result.RawKey

	t.Run("valid scope passes", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(core.ApiKeyConfig{Store: store}))
		e.GET("/admin", func(c echo.Context) error {
			return c.String(200, "ok")
		}, RequireScope("read"))

		rec := doRequest(e, "GET", "/admin", "", map[string]string{
			"X-API-Key": validKey,
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing scope returns 403", func(t *testing.T) {
		e := setupEcho()
		e.Use(ApiKeyAuth(core.ApiKeyConfig{Store: store}))
		e.GET("/admin", func(c echo.Context) error {
			return c.String(200, "ok")
		}, RequireScope("admin"))

		rec := doRequest(e, "GET", "/admin", "", map[string]string{
			"X-API-Key": validKey,
		})
		if rec.Code != 403 {
			t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
		}
		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "insufficient_scope" {
			t.Errorf("expected code insufficient_scope, got %v", errObj["code"])
		}
	})

	t.Run("no apiKey in context returns 401", func(t *testing.T) {
		e := setupEcho()
		// No ApiKeyAuth middleware — so no "apiKey" in context
		e.GET("/admin", func(c echo.Context) error {
			return c.String(200, "ok")
		}, RequireScope("read"))

		rec := doRequest(e, "GET", "/admin", "", nil)
		if rec.Code != 401 {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}

// ── TestLlmsTxtHandler ───────────────────────────────────────────────────

func TestLlmsTxtHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/llms.txt", LlmsTxtHandler(core.LlmsTxtConfig{
		Title:       "Test API",
		Description: "A test API for agents",
		Sections: []core.LlmsTxtSection{
			{Title: "Auth", Content: "Use Bearer tokens."},
		},
	}))

	rec := doRequest(e, "GET", "/llms.txt", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "# Test API") {
		t.Error("expected body to contain title")
	}
	if !strings.Contains(body, "> A test API for agents") {
		t.Error("expected body to contain description")
	}
	if !strings.Contains(body, "## Auth") {
		t.Error("expected body to contain section title")
	}
	if !strings.Contains(body, "Use Bearer tokens.") {
		t.Error("expected body to contain section content")
	}
}

// ── TestLlmsFullTxtHandler ───────────────────────────────────────────────

func TestLlmsFullTxtHandler(t *testing.T) {
	e := setupEcho()
	routes := []core.RouteMetadata{
		{
			Method:  "GET",
			Path:    "/users",
			Summary: "List users",
		},
		{
			Method:      "POST",
			Path:        "/users",
			Summary:     "Create user",
			Description: "Creates a new user account",
			Parameters: []core.RouteParameter{
				{Name: "name", In: "body", Required: true, Description: "User name"},
			},
		},
	}
	e.GET("/llms-full.txt", LlmsFullTxtHandler(core.LlmsTxtConfig{
		Title:       "Test API",
		Description: "Full docs",
	}, routes))

	rec := doRequest(e, "GET", "/llms-full.txt", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "# Test API") {
		t.Error("expected title in output")
	}
	if !strings.Contains(body, "## API Endpoints") {
		t.Error("expected API Endpoints section")
	}
	if !strings.Contains(body, "GET /users") {
		t.Error("expected GET /users route")
	}
	if !strings.Contains(body, "POST /users") {
		t.Error("expected POST /users route")
	}
	if !strings.Contains(body, "name") {
		t.Error("expected parameter name in output")
	}
}

// ── TestDiscoveryHandler ─────────────────────────────────────────────────

func TestDiscoveryHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/.well-known/ai", DiscoveryHandler(core.DiscoveryConfig{
		Manifest: core.AIManifest{
			Name:        "TestAgent",
			Description: "A test agent",
			Capabilities: []string{"search", "summarize"},
		},
	}))

	rec := doRequest(e, "GET", "/.well-known/ai", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := parseJSON(t, rec)
	if body["name"] != "TestAgent" {
		t.Errorf("expected name=TestAgent, got %v", body["name"])
	}
	if body["description"] != "A test agent" {
		t.Errorf("expected description, got %v", body["description"])
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}
}

// ── TestA2AHandler ───────────────────────────────────────────────────────

func TestA2AHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/.well-known/agent.json", A2AHandler(core.A2AConfig{
		Card: core.A2AAgentCard{
			Name: "TestBot",
			URL:  "https://example.com/agent",
			Skills: []core.A2ASkill{
				{ID: "search", Name: "Search"},
			},
		},
	}))

	rec := doRequest(e, "GET", "/.well-known/agent.json", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := parseJSON(t, rec)
	if body["name"] != "TestBot" {
		t.Errorf("expected name=TestBot, got %v", body["name"])
	}
	if body["url"] != "https://example.com/agent" {
		t.Errorf("expected url, got %v", body["url"])
	}
	if body["protocolVersion"] != "1.0.0" {
		t.Errorf("expected protocolVersion=1.0.0, got %v", body["protocolVersion"])
	}

	skills, ok := body["skills"].([]interface{})
	if !ok || len(skills) != 1 {
		t.Fatalf("expected 1 skill, got %v", body["skills"])
	}
	skill := skills[0].(map[string]interface{})
	if skill["id"] != "search" {
		t.Errorf("expected skill id=search, got %v", skill["id"])
	}
}

// ── TestAgentsTxtHandler ─────────────────────────────────────────────────

func TestAgentsTxtHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/agents.txt", AgentsTxtHandler(core.AgentsTxtConfig{
		SiteName: "TestSite",
		Contact:  "admin@test.com",
		Rules: []core.AgentsTxtRule{
			{
				Agent: "GPTBot",
				Allow: []string{"/api/*"},
				Deny:  []string{"/admin/*"},
			},
			{
				Agent: "*",
				Allow: []string{"/public/*"},
			},
		},
	}))

	rec := doRequest(e, "GET", "/agents.txt", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "# agents.txt") {
		t.Error("expected agents.txt header comment")
	}
	if !strings.Contains(body, "# Site: TestSite") {
		t.Error("expected site name")
	}
	if !strings.Contains(body, "User-agent: GPTBot") {
		t.Error("expected GPTBot rule")
	}
	if !strings.Contains(body, "Allow: /api/*") {
		t.Error("expected allow rule")
	}
	if !strings.Contains(body, "Deny: /admin/*") {
		t.Error("expected deny rule")
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", ct)
	}
}

// ── TestAgentsTxtEnforce ─────────────────────────────────────────────────

func TestAgentsTxtEnforce(t *testing.T) {
	config := core.AgentsTxtConfig{
		Rules: []core.AgentsTxtRule{
			{
				Agent: "GPTBot",
				Deny:  []string{"/*"},
			},
			{
				Agent: "ClaudeBot",
				Allow: []string{"/api/*"},
			},
		},
	}

	t.Run("denied agent gets 403", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentsTxtEnforce(config))
		e.GET("/data", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/data", "", map[string]string{
			"User-Agent": "GPTBot/1.0",
		})
		if rec.Code != 403 {
			t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
		}
		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "agent_not_allowed" {
			t.Errorf("expected code agent_not_allowed, got %v", errObj["code"])
		}
	})

	t.Run("allowed agent passes through", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentsTxtEnforce(config))
		e.GET("/api/data", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/api/data", "", map[string]string{
			"User-Agent": "ClaudeBot/1.0",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown agent passes through", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentsTxtEnforce(config))
		e.GET("/data", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/data", "", map[string]string{
			"User-Agent": "Mozilla/5.0",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

// ── TestMcpHandler ───────────────────────────────────────────────────────

func TestMcpHandler(t *testing.T) {
	e := setupEcho()
	e.POST("/mcp", McpHandler(core.McpServerConfig{
		Name:    "TestMCP",
		Version: "1.0.0",
		Tools: []core.McpToolDefinition{
			{
				Name:        "get_weather",
				Description: "Get weather for a location",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
		},
	}))

	t.Run("initialize method", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		rec := doRequest(e, "POST", "/mcp", payload, map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		body := parseJSON(t, rec)
		if body["jsonrpc"] != "2.0" {
			t.Error("expected jsonrpc=2.0")
		}

		result, ok := body["result"].(map[string]interface{})
		if !ok {
			t.Fatal("expected result object")
		}
		serverInfo, ok := result["serverInfo"].(map[string]interface{})
		if !ok {
			t.Fatal("expected serverInfo in result")
		}
		if serverInfo["name"] != "TestMCP" {
			t.Errorf("expected server name=TestMCP, got %v", serverInfo["name"])
		}
		if serverInfo["version"] != "1.0.0" {
			t.Errorf("expected version=1.0.0, got %v", serverInfo["version"])
		}
		if result["protocolVersion"] != "2025-03-26" {
			t.Errorf("expected protocolVersion=2025-03-26, got %v", result["protocolVersion"])
		}
	})

	t.Run("tools/list method", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
		rec := doRequest(e, "POST", "/mcp", payload, map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		body := parseJSON(t, rec)
		result := body["result"].(map[string]interface{})
		tools := result["tools"].([]interface{})
		if len(tools) != 1 {
			t.Fatalf("expected 1 tool, got %d", len(tools))
		}
		tool := tools[0].(map[string]interface{})
		if tool["name"] != "get_weather" {
			t.Errorf("expected tool name=get_weather, got %v", tool["name"])
		}
	})

	t.Run("ping method", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":3,"method":"ping"}`
		rec := doRequest(e, "POST", "/mcp", payload, map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		body := parseJSON(t, rec)
		if body["error"] != nil {
			t.Errorf("expected no error, got %v", body["error"])
		}
	})

	t.Run("notification returns 204", func(t *testing.T) {
		// A notification has no "id" field
		payload := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
		rec := doRequest(e, "POST", "/mcp", payload, map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 204 {
			t.Fatalf("expected 204 for notification, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown method returns error", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":4,"method":"unknown/method"}`
		rec := doRequest(e, "POST", "/mcp", payload, map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"].(float64) != -32601 {
			t.Errorf("expected error code -32601, got %v", errObj["code"])
		}
	})

	t.Run("invalid JSON returns parse error", func(t *testing.T) {
		rec := doRequest(e, "POST", "/mcp", "not json at all", map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"].(float64) != -32700 {
			t.Errorf("expected error code -32700, got %v", errObj["code"])
		}
	})
}

// ── TestAgUiStreamHandler ────────────────────────────────────────────────

func TestAgUiStreamHandler(t *testing.T) {
	e := setupEcho()
	e.POST("/ag-ui", AgUiStreamHandler(func(emitter *core.AgUiEmitter) error {
		emitter.RunStarted("")
		emitter.TextMessage("Hello, agent!", "assistant")
		emitter.RunFinished(nil)
		return nil
	}))

	rec := doRequest(e, "POST", "/ag-ui", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("expected Content-Type=text/event-stream, got %s", ct)
	}

	cacheControl := rec.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-cache") {
		t.Errorf("expected Cache-Control to contain no-cache, got %s", cacheControl)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: RUN_STARTED") {
		t.Error("expected RUN_STARTED event in SSE body")
	}
	if !strings.Contains(body, "event: TEXT_MESSAGE_START") {
		t.Error("expected TEXT_MESSAGE_START event in SSE body")
	}
	if !strings.Contains(body, "event: TEXT_MESSAGE_CONTENT") {
		t.Error("expected TEXT_MESSAGE_CONTENT event in SSE body")
	}
	if !strings.Contains(body, "Hello, agent!") {
		t.Error("expected text content in SSE body")
	}
	if !strings.Contains(body, "event: RUN_FINISHED") {
		t.Error("expected RUN_FINISHED event in SSE body")
	}
}

// ── TestOAuth2MetadataHandler ────────────────────────────────────────────

func TestOAuth2MetadataHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/.well-known/oauth-authorization-server", OAuth2MetadataHandler(core.OAuth2Config{
		ClientID:              "client-123",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		Issuer:                "https://auth.example.com",
		Scopes: map[string]string{
			"read":  "Read access",
			"write": "Write access",
		},
	}))

	rec := doRequest(e, "GET", "/.well-known/oauth-authorization-server", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := parseJSON(t, rec)
	if body["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Errorf("expected authorization_endpoint, got %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("expected token_endpoint, got %v", body["token_endpoint"])
	}
	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("expected issuer, got %v", body["issuer"])
	}

	scopes, ok := body["scopes_supported"].([]interface{})
	if !ok {
		t.Fatal("expected scopes_supported array")
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}
}

// ── TestAgentAnalytics ───────────────────────────────────────────────────

func TestAgentAnalytics(t *testing.T) {
	var recordedEvents []core.AgentEvent

	t.Run("detects known agent and records event", func(t *testing.T) {
		recordedEvents = nil
		e := setupEcho()
		e.Use(AgentAnalytics(core.AnalyticsConfig{
			OnEvent: func(event core.AgentEvent) {
				recordedEvents = append(recordedEvents, event)
			},
		}))
		e.GET("/test", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/test", "", map[string]string{
			"User-Agent": "GPTBot/1.0",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		if len(recordedEvents) != 1 {
			t.Fatalf("expected 1 recorded event, got %d", len(recordedEvents))
		}
		if recordedEvents[0].Agent != "GPTBot" {
			t.Errorf("expected agent=GPTBot, got %s", recordedEvents[0].Agent)
		}
		if recordedEvents[0].Method != "GET" {
			t.Errorf("expected method=GET, got %s", recordedEvents[0].Method)
		}
		if recordedEvents[0].Path != "/test" {
			t.Errorf("expected path=/test, got %s", recordedEvents[0].Path)
		}
	})

	t.Run("skips non-agent request when TrackAll is false", func(t *testing.T) {
		recordedEvents = nil
		e := setupEcho()
		e.Use(AgentAnalytics(core.AnalyticsConfig{
			OnEvent: func(event core.AgentEvent) {
				recordedEvents = append(recordedEvents, event)
			},
			TrackAll: false,
		}))
		e.GET("/test", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/test", "", map[string]string{
			"User-Agent": "Mozilla/5.0",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		if len(recordedEvents) != 0 {
			t.Errorf("expected 0 events for non-agent, got %d", len(recordedEvents))
		}
	})

	t.Run("tracks all when TrackAll is true", func(t *testing.T) {
		recordedEvents = nil
		e := setupEcho()
		e.Use(AgentAnalytics(core.AnalyticsConfig{
			OnEvent: func(event core.AgentEvent) {
				recordedEvents = append(recordedEvents, event)
			},
			TrackAll: true,
		}))
		e.GET("/test", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		rec := doRequest(e, "GET", "/test", "", map[string]string{
			"User-Agent": "Mozilla/5.0",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		if len(recordedEvents) != 1 {
			t.Fatalf("expected 1 event with TrackAll, got %d", len(recordedEvents))
		}
	})
}

// ── TestAgentMeta ────────────────────────────────────────────────────────

func TestAgentMeta(t *testing.T) {
	t.Run("transforms HTML with meta tags and agent-id", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentMeta(core.AgentMetaConfig{
			MetaTags: map[string]string{
				"agent-name": "TestBot",
			},
		}))
		e.GET("/page", func(c echo.Context) error {
			c.Response().Header().Set("Content-Type", "text/html")
			return c.HTML(200, `<html><head></head><body><main><p>Hello</p></main></body></html>`)
		})

		rec := doRequest(e, "GET", "/page", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, `data-agent-id="root"`) {
			t.Error("expected data-agent-id attribute on body tag")
		}
		if !strings.Contains(body, `<meta name="agent-name" content="TestBot">`) {
			t.Error("expected meta tag injection")
		}
		if !strings.Contains(body, `role="main"`) {
			t.Error("expected ARIA role=main on main tag")
		}
	})

	t.Run("does not transform non-HTML content", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentMeta(core.AgentMetaConfig{}))
		e.GET("/api", func(c echo.Context) error {
			return c.JSON(200, map[string]string{"key": "value"})
		})

		rec := doRequest(e, "GET", "/api", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		body := rec.Body.String()
		if strings.Contains(body, "data-agent-id") {
			t.Error("should not inject agent-id into non-HTML responses")
		}
	})
}

// ── TestX402Middleware ────────────────────────────────────────────────────

// mockFacilitator is a mock FacilitatorClient for testing.
type mockFacilitator struct {
	verifyResult *core.VerifyResponse
	settleResult *core.SettleResponse
	verifyErr    error
	settleErr    error
}

func (m *mockFacilitator) Verify(payload core.PaymentPayload, requirements core.PaymentRequirements) (*core.VerifyResponse, error) {
	return m.verifyResult, m.verifyErr
}

func (m *mockFacilitator) Settle(payload core.PaymentPayload, requirements core.PaymentRequirements) (*core.SettleResponse, error) {
	return m.settleResult, m.settleErr
}

func TestX402Middleware(t *testing.T) {
	routeConfig := core.X402RouteConfig{
		PayTo:   "0xRecipient",
		Scheme:  "exact",
		Price:   "$0.01",
		Network: "base-sepolia",
	}

	t.Run("returns 402 when no payment header", func(t *testing.T) {
		e := setupEcho()
		e.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: &mockFacilitator{},
		}))
		e.GET("/paid", func(c echo.Context) error {
			return c.String(200, "premium content")
		})

		rec := doRequest(e, "GET", "/paid", "", nil)
		if rec.Code != 402 {
			t.Fatalf("expected 402, got %d: %s", rec.Code, rec.Body.String())
		}

		if rec.Header().Get("X-Payment-Required") == "" {
			t.Error("expected X-Payment-Required header")
		}

		body := parseJSON(t, rec)
		if body["x402Version"] == nil {
			t.Error("expected x402Version in response")
		}
	})

	t.Run("passes through unmatched routes", func(t *testing.T) {
		e := setupEcho()
		e.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: &mockFacilitator{},
		}))
		e.GET("/free", func(c echo.Context) error {
			return c.String(200, "free content")
		})

		rec := doRequest(e, "GET", "/free", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if rec.Body.String() != "free content" {
			t.Errorf("expected 'free content', got %s", rec.Body.String())
		}
	})

	t.Run("allows request with valid payment", func(t *testing.T) {
		e := setupEcho()
		e.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: &mockFacilitator{
				verifyResult: &core.VerifyResponse{IsValid: true},
				settleResult: &core.SettleResponse{Success: true, TxHash: "0xabc123"},
			},
		}))
		e.GET("/paid", func(c echo.Context) error {
			return c.String(200, "premium content")
		})

		paymentPayload := core.PaymentPayload{
			X402Version: 1,
			Accepted: core.PaymentRequirements{
				Scheme:  "exact",
				Network: "base-sepolia",
				Asset:   "USDC",
				Amount:  "0.01",
				PayTo:   "0xRecipient",
			},
			Payload: map[string]interface{}{"signature": "0xsig"},
		}
		payloadBytes, _ := json.Marshal(paymentPayload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadBytes)

		rec := doRequest(e, "GET", "/paid", "", map[string]string{
			"Payment-Signature": paymentHeader,
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != "premium content" {
			t.Errorf("expected 'premium content', got %s", rec.Body.String())
		}

		if rec.Header().Get("X-Payment-Response") == "" {
			t.Error("expected X-Payment-Response header with settlement data")
		}
	})

	t.Run("returns 402 for invalid payment", func(t *testing.T) {
		e := setupEcho()
		e.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: &mockFacilitator{
				verifyResult: &core.VerifyResponse{IsValid: false, InvalidReason: "insufficient funds"},
			},
		}))
		e.GET("/paid", func(c echo.Context) error {
			return c.String(200, "premium content")
		})

		paymentPayload := core.PaymentPayload{
			X402Version: 1,
			Payload:     map[string]interface{}{"signature": "0xbad"},
		}
		payloadBytes, _ := json.Marshal(paymentPayload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadBytes)

		rec := doRequest(e, "GET", "/paid", "", map[string]string{
			"Payment-Signature": paymentHeader,
		})
		if rec.Code != 402 {
			t.Fatalf("expected 402, got %d: %s", rec.Code, rec.Body.String())
		}

		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "payment_invalid" {
			t.Errorf("expected code payment_invalid, got %v", errObj["code"])
		}
	})

	t.Run("accepts X-Payment-Signature header too", func(t *testing.T) {
		e := setupEcho()
		e.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": routeConfig,
			},
			Facilitator: &mockFacilitator{
				verifyResult: &core.VerifyResponse{IsValid: true},
				settleResult: &core.SettleResponse{Success: true, TxHash: "0xdef"},
			},
		}))
		e.GET("/paid", func(c echo.Context) error {
			return c.String(200, "ok")
		})

		paymentPayload := core.PaymentPayload{
			X402Version: 1,
			Payload:     map[string]interface{}{"signature": "0xsig2"},
		}
		payloadBytes, _ := json.Marshal(paymentPayload)
		paymentHeader := base64.StdEncoding.EncodeToString(payloadBytes)

		rec := doRequest(e, "GET", "/paid", "", map[string]string{
			"X-Payment-Signature": paymentHeader,
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

// ── TestAgentLayer (one-liner setup) ─────────────────────────────────────

func TestAgentLayer(t *testing.T) {
	e := setupEcho()

	store := core.NewMemoryApiKeyStore()
	core.CreateApiKey(store, core.CreateApiKeyOptions{
		CompanyID: "test-co",
		Scopes:    []string{"*"},
	})

	AgentLayer(core.AgentLayerConfig{
		LlmsTxt: &core.LlmsTxtConfig{
			Title:       "My API",
			Description: "API description",
		},
		Discovery: &core.DiscoveryConfig{
			Manifest: core.AIManifest{
				Name: "MyAgent",
			},
		},
		A2A: &core.A2AConfig{
			Card: core.A2AAgentCard{
				Name: "MyBot",
				URL:  "https://example.com",
			},
		},
		MCP: &core.McpServerConfig{
			Name:    "MyMCP",
			Version: "1.0.0",
		},
		OAuth2: &core.OAuth2Config{
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			TokenEndpoint:         "https://auth.example.com/token",
		},
		Routes: []core.RouteMetadata{
			{Method: "GET", Path: "/users", Summary: "List users"},
		},
	}, e)

	t.Run("llms.txt registered", func(t *testing.T) {
		rec := doRequest(e, "GET", "/llms.txt", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200 for /llms.txt, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "My API") {
			t.Error("expected llms.txt to contain title")
		}
	})

	t.Run("llms-full.txt registered", func(t *testing.T) {
		rec := doRequest(e, "GET", "/llms-full.txt", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200 for /llms-full.txt, got %d", rec.Code)
		}
	})

	t.Run("discovery registered", func(t *testing.T) {
		rec := doRequest(e, "GET", "/.well-known/ai", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200 for /.well-known/ai, got %d", rec.Code)
		}
		body := parseJSON(t, rec)
		if body["name"] != "MyAgent" {
			t.Errorf("expected name=MyAgent, got %v", body["name"])
		}
	})

	t.Run("A2A agent card registered", func(t *testing.T) {
		rec := doRequest(e, "GET", "/.well-known/agent.json", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200 for /.well-known/agent.json, got %d", rec.Code)
		}
	})

	t.Run("MCP endpoint registered", func(t *testing.T) {
		payload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		rec := doRequest(e, "POST", "/mcp", payload, map[string]string{
			"Content-Type": "application/json",
		})
		if rec.Code != 200 {
			t.Fatalf("expected 200 for /mcp, got %d", rec.Code)
		}
	})

	t.Run("OAuth2 metadata registered", func(t *testing.T) {
		rec := doRequest(e, "GET", "/.well-known/oauth-authorization-server", "", nil)
		if rec.Code != 200 {
			t.Fatalf("expected 200 for OAuth2 metadata, got %d", rec.Code)
		}
	})
}

// ── TestAgentErrors ──────────────────────────────────────────────────────

func TestAgentErrors(t *testing.T) {
	t.Run("catches panic and returns error envelope", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentErrors())
		e.GET("/panic", func(c echo.Context) error {
			panic("something went wrong")
		})

		rec := doRequest(e, "GET", "/panic", "", nil)
		if rec.Code != 500 {
			t.Fatalf("expected 500, got %d", rec.Code)
		}

		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "internal_error" {
			t.Errorf("expected code internal_error, got %v", errObj["code"])
		}
		if !strings.Contains(errObj["message"].(string), "something went wrong") {
			t.Errorf("expected message to contain 'something went wrong', got %v", errObj["message"])
		}
	})

	t.Run("wraps echo.HTTPError", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentErrors())
		e.GET("/notfound", func(c echo.Context) error {
			return echo.NewHTTPError(http.StatusNotFound, "page not found")
		})

		rec := doRequest(e, "GET", "/notfound", "", nil)
		if rec.Code != 404 {
			t.Fatalf("expected 404, got %d", rec.Code)
		}

		body := parseJSON(t, rec)
		errObj := body["error"].(map[string]interface{})
		if errObj["code"] != "not_found" {
			t.Errorf("expected code not_found, got %v", errObj["code"])
		}
	})

	t.Run("wraps AgentError", func(t *testing.T) {
		e := setupEcho()
		e.Use(AgentErrors())
		e.GET("/custom-err", func(c echo.Context) error {
			return core.NewAgentError(core.AgentErrorOptions{
				Code:    "custom_error",
				Message: "A custom error occurred",
				Status:  422,
			})
		})

		rec := doRequest(e, "GET", "/custom-err", "", nil)
		if rec.Code != 422 {
			t.Fatalf("expected 422, got %d", rec.Code)
		}

		body := parseJSON(t, rec)
		errData := body["error"].(map[string]interface{})
		if errData["code"] != "custom_error" {
			t.Errorf("expected code custom_error, got %v", errData["code"])
		}
	})
}

// ── TestJsonLdHandler ────────────────────────────────────────────────────

func TestJsonLdHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/.well-known/ai/json-ld", JsonLdHandler(core.DiscoveryConfig{
		Manifest: core.AIManifest{
			Name:        "TestAPI",
			Description: "A test API",
		},
	}))

	rec := doRequest(e, "GET", "/.well-known/ai/json-ld", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := parseJSON(t, rec)
	if body["@context"] != "https://schema.org" {
		t.Errorf("expected @context=https://schema.org, got %v", body["@context"])
	}
	if body["@type"] != "WebAPI" {
		t.Errorf("expected @type=WebAPI, got %v", body["@type"])
	}
	if body["name"] != "TestAPI" {
		t.Errorf("expected name=TestAPI, got %v", body["name"])
	}
}

// ── TestAgentAuthHandler ─────────────────────────────────────────────────

func TestAgentAuthHandler(t *testing.T) {
	e := setupEcho()
	e.GET("/.well-known/agent-auth", AgentAuthHandler(core.AgentAuthConfig{
		Issuer:           "https://auth.example.com",
		AuthorizationURL: "https://auth.example.com/authorize",
		TokenURL:         "https://auth.example.com/token",
		Scopes: map[string]string{
			"read":  "Read access",
			"write": "Write access",
		},
		Realm: "test-realm",
	}))

	rec := doRequest(e, "GET", "/.well-known/agent-auth", "", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := parseJSON(t, rec)
	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("expected issuer, got %v", body["issuer"])
	}
	if body["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Errorf("expected authorization_endpoint, got %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("expected token_endpoint, got %v", body["token_endpoint"])
	}
	if body["realm"] != "test-realm" {
		t.Errorf("expected realm=test-realm, got %v", body["realm"])
	}

	scopes, ok := body["scopes_supported"].([]interface{})
	if !ok {
		t.Fatal("expected scopes_supported to be an array")
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}
}
