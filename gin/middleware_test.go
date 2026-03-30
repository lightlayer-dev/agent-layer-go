package agentlayergin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lightlayer-dev/agent-layer-go/core"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

// ── TestRateLimits ──────────────────────────────────────────────────────

func TestRateLimits(t *testing.T) {
	r := setupRouter()
	r.Use(RateLimits(core.RateLimitConfig{
		Max:      2,
		WindowMs: 60000,
	}))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First request should pass
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-RateLimit-Limit") != "2" {
		t.Errorf("expected X-RateLimit-Limit=2, got %s", w.Header().Get("X-RateLimit-Limit"))
	}
	if w.Header().Get("X-RateLimit-Remaining") != "1" {
		t.Errorf("expected X-RateLimit-Remaining=1, got %s", w.Header().Get("X-RateLimit-Remaining"))
	}
	if w.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("expected X-RateLimit-Reset to be set")
	}

	// Second request should pass
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on second request, got %d", w.Code)
	}
	if w.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("expected X-RateLimit-Remaining=0, got %s", w.Header().Get("X-RateLimit-Remaining"))
	}

	// Third request should be rate limited
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header to be set")
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	errObj, ok := body["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object in body")
	}
	if errObj["code"] != "rate_limit_exceeded" {
		t.Errorf("expected code=rate_limit_exceeded, got %v", errObj["code"])
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

	r := setupRouter()
	r.Use(ApiKeyAuth(core.ApiKeyConfig{Store: store}))
	r.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	t.Run("valid key via X-API-Key header", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("X-API-Key", result.RawKey)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("valid key via Authorization Bearer header", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+result.RawKey)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("missing key returns 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		errObj, ok := body["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object in body")
		}
		if errObj["code"] != "missing_api_key" {
			t.Errorf("expected code=missing_api_key, got %v", errObj["code"])
		}
	})

	t.Run("invalid key returns 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("X-API-Key", "invalid_key_12345")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		errObj, ok := body["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object in body")
		}
		if errObj["code"] != "invalid_api_key" {
			t.Errorf("expected code=invalid_api_key, got %v", errObj["code"])
		}
	})
}

// ── TestRequireScope ────────────────────────────────────────────────────

func TestRequireScope(t *testing.T) {
	t.Run("valid scope passes", func(t *testing.T) {
		r := setupRouter()
		// Simulate API key already in context
		r.Use(func(c *gin.Context) {
			c.Set("agentKey", &core.ScopedApiKey{
				Scopes: []string{"read", "write"},
			})
			c.Next()
		})
		r.Use(RequireScope("read"))
		r.GET("/scoped", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/scoped", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("missing scope returns 403", func(t *testing.T) {
		r := setupRouter()
		r.Use(func(c *gin.Context) {
			c.Set("agentKey", &core.ScopedApiKey{
				Scopes: []string{"read"},
			})
			c.Next()
		})
		r.Use(RequireScope("admin"))
		r.GET("/scoped", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/scoped", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		errObj, ok := body["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object in body")
		}
		if errObj["code"] != "insufficient_scope" {
			t.Errorf("expected code=insufficient_scope, got %v", errObj["code"])
		}
	})

	t.Run("no agentKey in context returns 401", func(t *testing.T) {
		r := setupRouter()
		r.Use(RequireScope("read"))
		r.GET("/scoped", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/scoped", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// ── TestLlmsTxtHandler ──────────────────────────────────────────────────

func TestLlmsTxtHandler(t *testing.T) {
	r := setupRouter()
	r.GET("/llms.txt", LlmsTxtHandler(core.LlmsTxtConfig{
		Title:       "Test API",
		Description: "A test API",
		Sections: []core.LlmsTxtSection{
			{Title: "Overview", Content: "This is a test."},
		},
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/llms.txt", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "# Test API") {
		t.Error("expected body to contain '# Test API'")
	}
	if !strings.Contains(body, "> A test API") {
		t.Error("expected body to contain '> A test API'")
	}
	if !strings.Contains(body, "## Overview") {
		t.Error("expected body to contain '## Overview'")
	}
	if !strings.Contains(body, "This is a test.") {
		t.Error("expected body to contain section content")
	}
}

// ── TestLlmsFullTxtHandler ──────────────────────────────────────────────

func TestLlmsFullTxtHandler(t *testing.T) {
	r := setupRouter()
	routes := []core.RouteMetadata{
		{
			Method:  "GET",
			Path:    "/items",
			Summary: "List all items",
		},
	}
	r.GET("/llms-full.txt", LlmsFullTxtHandler(core.LlmsTxtConfig{
		Title:       "Test API",
		Description: "A test API",
	}, routes))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/llms-full.txt", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "# Test API") {
		t.Error("expected body to contain '# Test API'")
	}
	if !strings.Contains(body, "## API Endpoints") {
		t.Error("expected body to contain '## API Endpoints'")
	}
	if !strings.Contains(body, "GET /items") {
		t.Error("expected body to contain route 'GET /items'")
	}
}

// ── TestDiscoveryHandler ────────────────────────────────────────────────

func TestDiscoveryHandler(t *testing.T) {
	r := setupRouter()
	r.GET("/.well-known/ai", DiscoveryHandler(core.DiscoveryConfig{
		Manifest: core.AIManifest{
			Name:        "Test API",
			Description: "A test API",
		},
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/ai", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}
	if body["name"] != "Test API" {
		t.Errorf("expected name=Test API, got %v", body["name"])
	}
	if body["description"] != "A test API" {
		t.Errorf("expected description=A test API, got %v", body["description"])
	}
}

// ── TestA2AHandler ──────────────────────────────────────────────────────

func TestA2AHandler(t *testing.T) {
	r := setupRouter()
	r.GET("/.well-known/agent.json", A2AHandler(core.A2AConfig{
		Card: core.A2AAgentCard{
			Name: "TestAgent",
			URL:  "https://example.com",
			Skills: []core.A2ASkill{
				{ID: "greet", Name: "Greet"},
			},
		},
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/agent.json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}
	if body["name"] != "TestAgent" {
		t.Errorf("expected name=TestAgent, got %v", body["name"])
	}
	if body["protocolVersion"] != "1.0.0" {
		t.Errorf("expected protocolVersion=1.0.0, got %v", body["protocolVersion"])
	}
	skills, ok := body["skills"].([]interface{})
	if !ok || len(skills) != 1 {
		t.Error("expected 1 skill in the agent card")
	}
}

// ── TestAgentsTxtHandler ────────────────────────────────────────────────

func TestAgentsTxtHandler(t *testing.T) {
	r := setupRouter()
	r.GET("/agents.txt", AgentsTxtHandler(core.AgentsTxtConfig{
		SiteName: "TestSite",
		Rules: []core.AgentsTxtRule{
			{
				Agent: "*",
				Allow: []string{"/"},
			},
		},
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/agents.txt", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %s", contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Error("expected body to contain 'User-agent: *'")
	}
	if !strings.Contains(body, "Allow: /") {
		t.Error("expected body to contain 'Allow: /'")
	}
	if !strings.Contains(body, "# Site: TestSite") {
		t.Error("expected body to contain site name")
	}
}

// ── TestAgentsTxtEnforce ────────────────────────────────────────────────

func TestAgentsTxtEnforce(t *testing.T) {
	config := core.AgentsTxtConfig{
		Rules: []core.AgentsTxtRule{
			{
				Agent: "GPTBot",
				Allow: []string{"/public/*"},
				Deny:  []string{"/private/*"},
			},
		},
	}

	t.Run("allowed agent passes", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentsTxtEnforce(config))
		r.GET("/public/data", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/public/data", nil)
		req.Header.Set("User-Agent", "GPTBot/1.0")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("denied agent gets 403", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentsTxtEnforce(config))
		r.GET("/private/data", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/private/data", nil)
		req.Header.Set("User-Agent", "GPTBot/1.0")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		errObj, ok := body["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object in body")
		}
		if errObj["code"] != "agent_not_allowed" {
			t.Errorf("expected code=agent_not_allowed, got %v", errObj["code"])
		}
	})

	t.Run("non-agent request passes through", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentsTxtEnforce(config))
		r.GET("/private/data", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/private/data", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

// ── TestMcpHandler ──────────────────────────────────────────────────────

func TestMcpHandler(t *testing.T) {
	r := setupRouter()
	r.POST("/mcp", McpHandler(core.McpServerConfig{
		Name:    "TestServer",
		Version: "1.0.0",
		Tools: []core.McpToolDefinition{
			{
				Name:        "get_items",
				Description: "Get all items",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
		},
	}))

	t.Run("initialize", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["jsonrpc"] != "2.0" {
			t.Errorf("expected jsonrpc=2.0, got %v", resp["jsonrpc"])
		}

		result, ok := resp["result"].(map[string]interface{})
		if !ok {
			t.Fatal("expected result object")
		}
		serverInfo, ok := result["serverInfo"].(map[string]interface{})
		if !ok {
			t.Fatal("expected serverInfo in result")
		}
		if serverInfo["name"] != "TestServer" {
			t.Errorf("expected name=TestServer, got %v", serverInfo["name"])
		}
	})

	t.Run("tools/list", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		result, ok := resp["result"].(map[string]interface{})
		if !ok {
			t.Fatal("expected result object")
		}
		tools, ok := result["tools"].([]interface{})
		if !ok {
			t.Fatal("expected tools array in result")
		}
		if len(tools) != 1 {
			t.Fatalf("expected 1 tool, got %d", len(tools))
		}
		tool := tools[0].(map[string]interface{})
		if tool["name"] != "get_items" {
			t.Errorf("expected tool name=get_items, got %v", tool["name"])
		}
	})

	t.Run("invalid JSON returns parse error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/mcp", strings.NewReader("{invalid"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		errObj, ok := resp["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object")
		}
		if errObj["code"].(float64) != -32700 {
			t.Errorf("expected error code -32700, got %v", errObj["code"])
		}
	})

	t.Run("notification returns 204", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})
}

// ── TestAgUiStreamHandler ───────────────────────────────────────────────

func TestAgUiStreamHandler(t *testing.T) {
	r := setupRouter()
	r.POST("/ag-ui", AgUiStreamHandler(func(emitter *core.AgUiEmitter) error {
		emitter.RunStarted("")
		emitter.TextMessage("Hello, world!", "assistant")
		emitter.RunFinished(nil)
		return nil
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/ag-ui", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %s", contentType)
	}

	cacheControl := w.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-cache") {
		t.Errorf("expected Cache-Control to include no-cache, got %s", cacheControl)
	}

	body := w.Body.String()
	if !strings.Contains(body, "event: RUN_STARTED") {
		t.Error("expected body to contain RUN_STARTED event")
	}
	if !strings.Contains(body, "event: TEXT_MESSAGE_START") {
		t.Error("expected body to contain TEXT_MESSAGE_START event")
	}
	if !strings.Contains(body, "event: TEXT_MESSAGE_CONTENT") {
		t.Error("expected body to contain TEXT_MESSAGE_CONTENT event")
	}
	if !strings.Contains(body, "Hello, world!") {
		t.Error("expected body to contain message content")
	}
	if !strings.Contains(body, "event: RUN_FINISHED") {
		t.Error("expected body to contain RUN_FINISHED event")
	}
}

// ── TestOAuth2MetadataHandler ───────────────────────────────────────────

func TestOAuth2MetadataHandler(t *testing.T) {
	r := setupRouter()
	r.GET("/.well-known/oauth-authorization-server", OAuth2MetadataHandler(core.OAuth2Config{
		ClientID:              "client123",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		Issuer:                "https://auth.example.com",
		Scopes:                map[string]string{"read": "Read access"},
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}
	if body["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Errorf("expected authorization_endpoint, got %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("expected token_endpoint, got %v", body["token_endpoint"])
	}
	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("expected issuer, got %v", body["issuer"])
	}
}

// ── TestAgentMeta ───────────────────────────────────────────────────────

func TestAgentMeta(t *testing.T) {
	r := setupRouter()
	r.Use(AgentMeta(core.AgentMetaConfig{
		MetaTags: map[string]string{
			"agent-capabilities": "search,chat",
		},
	}))
	r.GET("/page", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<html><head></head><body><main>content</main></body></html>`)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/page", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `data-agent-id="root"`) {
		t.Error("expected body to contain data-agent-id attribute")
	}
	if !strings.Contains(body, `role="main"`) {
		t.Error("expected body to contain ARIA role=main")
	}
	if !strings.Contains(body, `agent-capabilities`) {
		t.Error("expected body to contain meta tag")
	}
}

// ── TestAgentAnalytics ──────────────────────────────────────────────────

func TestAgentAnalytics(t *testing.T) {
	var mu sync.Mutex
	var events []core.AgentEvent

	r := setupRouter()
	r.Use(AgentAnalytics(core.AnalyticsConfig{
		OnEvent: func(event core.AgentEvent) {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		},
	}))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	t.Run("detects agent and calls onEvent", func(t *testing.T) {
		mu.Lock()
		events = nil
		mu.Unlock()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "ClaudeBot/1.0")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
		if events[0].Agent != "ClaudeBot" {
			t.Errorf("expected agent=ClaudeBot, got %s", events[0].Agent)
		}
		if events[0].Path != "/test" {
			t.Errorf("expected path=/test, got %s", events[0].Path)
		}
		if events[0].StatusCode != 200 {
			t.Errorf("expected status=200, got %d", events[0].StatusCode)
		}
	})

	t.Run("non-agent request not tracked by default", func(t *testing.T) {
		mu.Lock()
		events = nil
		mu.Unlock()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(events) != 0 {
			t.Fatalf("expected 0 events for non-agent, got %d", len(events))
		}
	})

	t.Run("trackAll tracks non-agent requests", func(t *testing.T) {
		var trackAllEvents []core.AgentEvent
		var trackAllMu sync.Mutex

		r2 := setupRouter()
		r2.Use(AgentAnalytics(core.AnalyticsConfig{
			TrackAll: true,
			OnEvent: func(event core.AgentEvent) {
				trackAllMu.Lock()
				trackAllEvents = append(trackAllEvents, event)
				trackAllMu.Unlock()
			},
		}))
		r2.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		r2.ServeHTTP(w, req)

		trackAllMu.Lock()
		defer trackAllMu.Unlock()
		if len(trackAllEvents) != 1 {
			t.Fatalf("expected 1 event with trackAll, got %d", len(trackAllEvents))
		}
	})
}

// ── TestAgentErrors ─────────────────────────────────────────────────────

func TestAgentErrors(t *testing.T) {
	t.Run("formats generic error from c.Error", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentErrors())
		r.GET("/fail", func(c *gin.Context) {
			_ = c.Error(fmt.Errorf("something went wrong"))
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/fail", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		errObj, ok := body["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object in body")
		}
		if errObj["code"] != "internal_error" {
			t.Errorf("expected code=internal_error, got %v", errObj["code"])
		}
		if errObj["message"] != "something went wrong" {
			t.Errorf("expected message='something went wrong', got %v", errObj["message"])
		}
	})

	t.Run("formats AgentError with custom envelope", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentErrors())
		r.GET("/fail", func(c *gin.Context) {
			agentErr := core.NewAgentError(core.AgentErrorOptions{
				Code:    "custom_error",
				Message: "custom message",
				Status:  http.StatusBadRequest,
			})
			_ = c.Error(agentErr)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/fail", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		errObj, ok := body["error"].(map[string]interface{})
		if !ok {
			t.Fatal("expected error object in body")
		}
		if errObj["code"] != "custom_error" {
			t.Errorf("expected code=custom_error, got %v", errObj["code"])
		}
	})

	t.Run("no errors does not alter response", func(t *testing.T) {
		r := setupRouter()
		r.Use(AgentErrors())
		r.GET("/ok", func(c *gin.Context) {
			c.String(http.StatusOK, "all good")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ok", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != "all good" {
			t.Errorf("expected body 'all good', got '%s'", w.Body.String())
		}
	})
}

// ── TestX402Middleware ───────────────────────────────────────────────────

func TestX402Middleware(t *testing.T) {
	t.Run("route without payment passes through", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": {
					PayTo:   "0x1234",
					Price:   "$0.01",
					Network: "base",
				},
			},
		}))
		r.GET("/free", func(c *gin.Context) {
			c.String(http.StatusOK, "free content")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/free", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("route with payment returns 402 without signature", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": {
					PayTo:   "0x1234",
					Price:   "$0.01",
					Network: "base",
				},
			},
		}))
		r.GET("/paid", func(c *gin.Context) {
			c.String(http.StatusOK, "paid content")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/paid", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("expected 402, got %d", w.Code)
		}

		if w.Header().Get("Payment-Required") == "" {
			t.Error("expected Payment-Required header to be set")
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["x402Version"] == nil {
			t.Error("expected x402Version in response body")
		}
	})

	t.Run("invalid payment signature returns 400", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": {
					PayTo:   "0x1234",
					Price:   "$0.01",
					Network: "base",
				},
			},
		}))
		r.GET("/paid", func(c *gin.Context) {
			c.String(http.StatusOK, "paid content")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/paid", nil)
		req.Header.Set("Payment-Signature", "not-valid-base64!!!")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("valid payment signature without facilitator sets context", func(t *testing.T) {
		r := setupRouter()
		r.Use(X402Middleware(core.X402Config{
			Routes: map[string]core.X402RouteConfig{
				"GET /paid": {
					PayTo:   "0x1234",
					Price:   "$0.01",
					Network: "base",
				},
			},
		}))
		r.GET("/paid", func(c *gin.Context) {
			payment := GetX402Payment(c)
			if payment == nil {
				c.String(http.StatusInternalServerError, "no payment")
				return
			}
			c.String(http.StatusOK, "paid content")
		})

		// Build a valid base64-encoded payment payload
		payload := core.PaymentPayload{
			X402Version: 1,
			Accepted: core.PaymentRequirements{
				Scheme:  "exact",
				Network: "base",
				Asset:   "USDC",
				Amount:  "0.01",
				PayTo:   "0x1234",
			},
			Payload: map[string]interface{}{"txHash": "0xabc"},
		}
		payloadBytes, _ := json.Marshal(payload)
		encoded := base64.StdEncoding.EncodeToString(payloadBytes)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/paid", nil)
		req.Header.Set("Payment-Signature", encoded)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
		}
	})
}

// ── TestUnifiedDiscoveryRouter ──────────────────────────────────────────

func TestUnifiedDiscoveryRouter(t *testing.T) {
	config := core.UnifiedDiscoveryConfig{
		Name:        "TestAPI",
		Description: "A unified test API",
		URL:         "https://example.com",
	}

	t.Run("serves /.well-known/ai", func(t *testing.T) {
		r := setupRouter()
		RegisterUnifiedDiscovery(r, config)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/.well-known/ai", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var body map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["name"] != "TestAPI" {
			t.Errorf("expected name=TestAPI, got %v", body["name"])
		}
	})

	t.Run("serves /.well-known/agent.json", func(t *testing.T) {
		r := setupRouter()
		RegisterUnifiedDiscovery(r, config)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/.well-known/agent.json", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("serves /llms.txt as text", func(t *testing.T) {
		r := setupRouter()
		RegisterUnifiedDiscovery(r, config)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/llms.txt", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if !strings.Contains(contentType, "text/plain") {
			t.Errorf("expected text/plain content type, got %s", contentType)
		}

		if !strings.Contains(w.Body.String(), "# TestAPI") {
			t.Error("expected llms.txt to contain title")
		}
	})

	t.Run("serves /agents.txt", func(t *testing.T) {
		r := setupRouter()
		RegisterUnifiedDiscovery(r, config)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/agents.txt", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("UnifiedDiscoveryRouter middleware serves paths", func(t *testing.T) {
		r := setupRouter()
		r.Use(UnifiedDiscoveryRouter(config))
		r.GET("/.well-known/ai", func(c *gin.Context) {
			// Fallback should not be reached
			c.String(http.StatusTeapot, "fallback")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/.well-known/ai", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 from middleware, got %d", w.Code)
		}
	})
}

// ── TestAgentLayer ──────────────────────────────────────────────────────

func TestAgentLayer(t *testing.T) {
	r := setupRouter()

	boolTrue := true
	AgentLayer(core.AgentLayerConfig{
		Errors: &boolTrue,
		LlmsTxt: &core.LlmsTxtConfig{
			Title:       "TestAPI",
			Description: "Test",
		},
		Discovery: &core.DiscoveryConfig{
			Manifest: core.AIManifest{
				Name: "TestAPI",
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
				Rules: []core.AgentsTxtRule{
					{Agent: "*", Allow: []string{"/"}},
				},
			},
		},
		OAuth2: &core.OAuth2Config{
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			TokenEndpoint:         "https://auth.example.com/token",
		},
		MCP: &core.McpServerConfig{
			Name:    "TestMCP",
			Version: "1.0.0",
		},
		Routes: []core.RouteMetadata{
			{Method: "GET", Path: "/items", Summary: "List items"},
		},
	}, r)

	// Verify routes are registered by making requests
	paths := map[string]int{
		"/llms.txt":                                http.StatusOK,
		"/llms-full.txt":                           http.StatusOK,
		"/.well-known/ai":                          http.StatusOK,
		"/.well-known/agent.json":                  http.StatusOK,
		"/agents.txt":                              http.StatusOK,
		"/.well-known/oauth-authorization-server":  http.StatusOK,
	}

	for path, expectedStatus := range paths {
		t.Run("GET "+path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", path, nil)
			r.ServeHTTP(w, req)

			if w.Code != expectedStatus {
				t.Errorf("GET %s: expected %d, got %d", path, expectedStatus, w.Code)
			}
		})
	}

	// Verify MCP POST route
	t.Run("POST /mcp", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("POST /mcp: expected 200, got %d", w.Code)
		}
	})
}

// ── TestGetAgentKey ─────────────────────────────────────────────────────

func TestGetAgentKey(t *testing.T) {
	t.Run("returns key when present", func(t *testing.T) {
		r := setupRouter()
		r.GET("/test", func(c *gin.Context) {
			c.Set("agentKey", &core.ScopedApiKey{KeyID: "k1", Scopes: []string{"read"}})
			key := GetAgentKey(c)
			if key == nil {
				t.Error("expected key to be non-nil")
				return
			}
			if key.KeyID != "k1" {
				t.Errorf("expected KeyID=k1, got %s", key.KeyID)
			}
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)
	})

	t.Run("returns nil when not present", func(t *testing.T) {
		r := setupRouter()
		r.GET("/test", func(c *gin.Context) {
			key := GetAgentKey(c)
			if key != nil {
				t.Error("expected key to be nil")
			}
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)
	})
}

// ── TestGetAgentIdentity ────────────────────────────────────────────────

func TestGetAgentIdentity(t *testing.T) {
	t.Run("returns claims when present", func(t *testing.T) {
		r := setupRouter()
		r.GET("/test", func(c *gin.Context) {
			c.Set("agentIdentity", core.AgentIdentityClaims{
				AgentID: "agent-123",
			})
			claims := GetAgentIdentity(c)
			if claims == nil {
				t.Error("expected claims to be non-nil")
				return
			}
			if claims.AgentID != "agent-123" {
				t.Errorf("expected AgentID=agent-123, got %s", claims.AgentID)
			}
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)
	})

	t.Run("returns nil when not present", func(t *testing.T) {
		r := setupRouter()
		r.GET("/test", func(c *gin.Context) {
			claims := GetAgentIdentity(c)
			if claims != nil {
				t.Error("expected claims to be nil")
			}
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)
	})
}

// ── TestJsonLdHandler ───────────────────────────────────────────────────

func TestJsonLdHandler(t *testing.T) {
	r := setupRouter()
	r.GET("/.well-known/ai/json-ld", JsonLdHandler(core.DiscoveryConfig{
		Manifest: core.AIManifest{
			Name:        "Test API",
			Description: "A test API",
		},
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/ai/json-ld", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["@context"] != "https://schema.org" {
		t.Errorf("expected @context=https://schema.org, got %v", body["@context"])
	}
	if body["@type"] != "WebAPI" {
		t.Errorf("expected @type=WebAPI, got %v", body["@type"])
	}
	if body["name"] != "Test API" {
		t.Errorf("expected name=Test API, got %v", body["name"])
	}
}

// ── TestAgentAuth ───────────────────────────────────────────────────────

func TestAgentAuth(t *testing.T) {
	r := setupRouter()
	r.GET("/.well-known/agent-auth", AgentAuth(core.AgentAuthConfig{
		Issuer:           "https://auth.example.com",
		AuthorizationURL: "https://auth.example.com/authorize",
		TokenURL:         "https://auth.example.com/token",
		Scopes:           map[string]string{"read": "Read access"},
		Realm:            "test-realm",
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/agent-auth", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
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
}

// ── TestApiKeyAuthCustomHeader ──────────────────────────────────────────

func TestApiKeyAuthCustomHeader(t *testing.T) {
	store := core.NewMemoryApiKeyStore()
	result := core.CreateApiKey(store, core.CreateApiKeyOptions{
		Scopes: []string{"read"},
	})

	r := setupRouter()
	r.Use(ApiKeyAuth(core.ApiKeyConfig{
		Store:      store,
		HeaderName: "X-Custom-Key",
	}))
	r.GET("/protected", func(c *gin.Context) {
		key := GetAgentKey(c)
		if key == nil {
			t.Error("expected agentKey to be set in context")
		}
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("X-Custom-Key", result.RawKey)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
