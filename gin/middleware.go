// Package agentlayergin provides Gin framework adapters for agent-layer-go.
// It wraps the core package into Gin middleware and route handlers.
package agentlayergin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lightlayer-dev/agent-layer-go/core"
)

// ── Error Handling ──────────────────────────────────────────────────────

// AgentErrors returns middleware that catches errors accumulated via c.Error()
// and formats them as standard agent error envelopes.
func AgentErrors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		lastErr := c.Errors.Last()

		// If it's already an AgentError, use its envelope directly.
		if agentErr, ok := lastErr.Err.(*core.AgentError); ok {
			c.JSON(agentErr.Envelope.Status, gin.H{"error": agentErr.Envelope})
			return
		}

		// Default to 500 unless a status was already set.
		status := c.Writer.Status()
		if status == http.StatusOK || status == 0 {
			status = http.StatusInternalServerError
		}

		envelope := core.FormatError(core.AgentErrorOptions{
			Code:    "internal_error",
			Message: lastErr.Error(),
			Status:  status,
		})
		c.JSON(envelope.Status, gin.H{"error": envelope})
	}
}

// ── Rate Limiting ───────────────────────────────────────────────────────

// RateLimits returns middleware that enforces rate limits.
// It sets X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset
// headers on every response. Returns 429 when the limit is exceeded.
func RateLimits(config core.RateLimitConfig) gin.HandlerFunc {
	limiter := core.CreateRateLimiter(config)

	return func(c *gin.Context) {
		result, err := limiter(c.Request)
		if err != nil {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "rate_limit_error",
				Message: "Rate limit check failed.",
				Status:  http.StatusInternalServerError,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		c.Header("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(result.ResetMs, 10))

		if !result.Allowed {
			retryAfter := int(0)
			if result.RetryAfter != nil {
				retryAfter = int(*result.RetryAfter)
			}
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			envelope := core.RateLimitError(retryAfter)
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		c.Next()
	}
}

// ── Analytics ───────────────────────────────────────────────────────────

// AgentAnalytics returns middleware that records agent request events.
// It detects AI agents from User-Agent headers and records timing, status,
// and content-type information.
func AgentAnalytics(config core.AnalyticsConfig) gin.HandlerFunc {
	analytics := core.CreateAnalytics(config)

	return func(c *gin.Context) {
		start := time.Now()
		userAgent := c.GetHeader("User-Agent")
		agentName := analytics.Detect(userAgent)

		c.Next()

		if agentName == "" && !analytics.Config.TrackAll {
			return
		}

		event := core.AgentEvent{
			Agent:       agentName,
			UserAgent:   userAgent,
			Method:      c.Request.Method,
			Path:        c.Request.URL.Path,
			StatusCode:  c.Writer.Status(),
			DurationMs:  time.Since(start).Milliseconds(),
			Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
			ContentType: c.Writer.Header().Get("Content-Type"),
			ResponseSize: int64(c.Writer.Size()),
		}

		analytics.Record(event)
	}
}

// ── API Key Authentication ──────────────────────────────────────────────

// ApiKeyAuth returns middleware that validates API keys from request headers.
// On success it stores the resolved ScopedApiKey in the context as "agentKey".
func ApiKeyAuth(config core.ApiKeyConfig) gin.HandlerFunc {
	headerName := config.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}

	return func(c *gin.Context) {
		rawKey := c.GetHeader(headerName)
		if rawKey == "" {
			// Also check Authorization: Bearer <key>
			rawKey = core.ExtractBearerToken(c.GetHeader("Authorization"))
		}

		if rawKey == "" {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "missing_api_key",
				Message: fmt.Sprintf("API key is required. Provide it via the %s header.", headerName),
				Status:  http.StatusUnauthorized,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		result, err := core.ValidateApiKey(config.Store, rawKey)
		if err != nil {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "auth_error",
				Message: "Failed to validate API key.",
				Status:  http.StatusInternalServerError,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		if !result.Valid {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    result.Error,
				Message: "Invalid or expired API key.",
				Status:  http.StatusUnauthorized,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		c.Set("agentKey", result.Key)
		c.Next()
	}
}

// ── Scope Enforcement ───────────────────────────────────────────────────

// RequireScope returns middleware that checks whether the authenticated
// API key (stored in context as "agentKey") has the specified scope.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyVal, exists := c.Get("agentKey")
		if !exists {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "missing_api_key",
				Message: "Authentication required.",
				Status:  http.StatusUnauthorized,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		key, ok := keyVal.(*core.ScopedApiKey)
		if !ok {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "auth_error",
				Message: "Invalid authentication state.",
				Status:  http.StatusInternalServerError,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		if !core.HasScope(key, scope) {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "insufficient_scope",
				Message: fmt.Sprintf("Required scope: %s", scope),
				Status:  http.StatusForbidden,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		c.Next()
	}
}

// ── Agent Meta (HTML Transform) ─────────────────────────────────────────

// AgentMeta returns middleware that transforms HTML responses for agent
// consumption by injecting data-agent-id attributes, ARIA landmarks,
// and meta tags.
func AgentMeta(config core.AgentMetaConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use a custom response writer to capture HTML output.
		writer := &agentMetaWriter{
			ResponseWriter: c.Writer,
			config:         config,
			body:           make([]byte, 0),
		}
		c.Writer = writer

		c.Next()

		contentType := writer.Header().Get("Content-Type")
		if strings.Contains(contentType, "text/html") && len(writer.body) > 0 {
			transformed := core.TransformHTML(string(writer.body), config)
			writer.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(transformed)))
			writer.ResponseWriter.Write([]byte(transformed))
		} else if len(writer.body) > 0 {
			writer.ResponseWriter.Write(writer.body)
		}
	}
}

// agentMetaWriter buffers the response body so we can transform HTML.
type agentMetaWriter struct {
	gin.ResponseWriter
	config core.AgentMetaConfig
	body   []byte
}

func (w *agentMetaWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *agentMetaWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// ── LLMs.txt ────────────────────────────────────────────────────────────

// LlmsTxtHandler returns a handler that serves the /llms.txt document.
func LlmsTxtHandler(config core.LlmsTxtConfig) gin.HandlerFunc {
	content := core.GenerateLlmsTxt(config)
	return func(c *gin.Context) {
		c.String(http.StatusOK, content)
	}
}

// LlmsFullTxtHandler returns a handler that serves the /llms-full.txt
// document with route documentation.
func LlmsFullTxtHandler(config core.LlmsTxtConfig, routes []core.RouteMetadata) gin.HandlerFunc {
	content := core.GenerateLlmsFullTxt(config, routes)
	return func(c *gin.Context) {
		c.String(http.StatusOK, content)
	}
}

// ── Discovery (/.well-known/ai) ─────────────────────────────────────────

// DiscoveryHandler returns a handler that serves the /.well-known/ai
// manifest as JSON.
func DiscoveryHandler(config core.DiscoveryConfig) gin.HandlerFunc {
	manifest := core.GenerateAIManifest(config)
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, manifest)
	}
}

// ── JSON-LD ─────────────────────────────────────────────────────────────

// JsonLdHandler returns a handler that serves JSON-LD structured data.
func JsonLdHandler(config core.DiscoveryConfig) gin.HandlerFunc {
	jsonLd := core.GenerateJsonLd(config)
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, jsonLd)
	}
}

// ── A2A Agent Card ──────────────────────────────────────────────────────

// A2AHandler returns a handler that serves the A2A Agent Card JSON at
// /.well-known/agent.json.
func A2AHandler(config core.A2AConfig) gin.HandlerFunc {
	card := core.GenerateAgentCard(config)
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, card)
	}
}

// ── agents.txt ──────────────────────────────────────────────────────────

// AgentsTxtHandler returns a handler that serves the /agents.txt document.
func AgentsTxtHandler(config core.AgentsTxtConfig) gin.HandlerFunc {
	content := core.GenerateAgentsTxt(config)
	return func(c *gin.Context) {
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(content))
	}
}

// AgentsTxtEnforce returns middleware that enforces agents.txt policies.
// It checks the User-Agent to detect known AI agents and denies access
// if the agents.txt rules disallow the request path.
func AgentsTxtEnforce(config core.AgentsTxtConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.GetHeader("User-Agent")
		agentName := core.DetectAgent(userAgent)

		if agentName == "" {
			c.Next()
			return
		}

		allowed := core.IsAgentAllowed(config, agentName, c.Request.URL.Path)
		if allowed != nil && !*allowed {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "agent_not_allowed",
				Message: fmt.Sprintf("Agent %s is not allowed to access %s per agents.txt policy.", agentName, c.Request.URL.Path),
				Status:  http.StatusForbidden,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		c.Next()
	}
}

// ── MCP (Model Context Protocol) ────────────────────────────────────────

// McpHandler returns a handler that accepts POST requests with JSON-RPC
// bodies and processes them via the MCP protocol.
func McpHandler(config core.McpServerConfig) gin.HandlerFunc {
	tools := config.Tools
	if tools == nil && config.Routes != nil {
		tools = core.GenerateToolDefinitions(config.Routes)
	}
	if tools == nil {
		tools = []core.McpToolDefinition{}
	}
	serverInfo := core.GenerateServerInfo(config)

	return func(c *gin.Context) {
		var request core.JsonRpcRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, core.JsonRpcResponse{
				Jsonrpc: "2.0",
				Error: &core.JsonRpcError{
					Code:    -32700,
					Message: "Parse error: invalid JSON",
				},
			})
			return
		}

		response := core.HandleJsonRpc(request, serverInfo, tools, nil)
		if response == nil {
			// Notification — no response needed.
			c.Status(http.StatusNoContent)
			return
		}

		c.JSON(http.StatusOK, response)
	}
}

// ── AG-UI (Server-Sent Events) ──────────────────────────────────────────

// AgUiStreamHandler returns a handler that sets up AG-UI SSE streaming.
// The provided handler function receives an AgUiEmitter that writes
// SSE events to the response.
func AgUiStreamHandler(handler func(*core.AgUiEmitter) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		for k, v := range core.AgUiHeaders {
			c.Header(k, v)
		}
		c.Status(http.StatusOK)

		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "streaming_not_supported",
				Message: "Streaming is not supported by the server.",
				Status:  http.StatusInternalServerError,
			})
			c.JSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		writeFn := func(chunk string) {
			c.Writer.WriteString(chunk)
			flusher.Flush()
		}

		emitter := core.CreateAgUiEmitter(writeFn, core.AgUiEmitterOptions{})

		if err := handler(emitter); err != nil {
			emitter.RunError(err.Error(), "handler_error")
		}
	}
}

// ── OAuth2 Metadata ─────────────────────────────────────────────────────

// OAuth2MetadataHandler returns a handler that serves the OAuth2
// Authorization Server Metadata document (RFC 8414).
func OAuth2MetadataHandler(config core.OAuth2Config) gin.HandlerFunc {
	metadata := core.BuildOAuth2Metadata(config)
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, metadata)
	}
}

// ── Unified Discovery Router ────────────────────────────────────────────

// UnifiedDiscoveryRouter returns a handler function that, when invoked,
// registers all enabled discovery routes on the provided router.
// Use RegisterUnifiedDiscovery for direct registration instead.
func UnifiedDiscoveryRouter(config core.UnifiedDiscoveryConfig) gin.HandlerFunc {
	docs := core.GenerateAllDiscovery(config)

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if doc, ok := docs[path]; ok {
			switch v := doc.(type) {
			case string:
				c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(v))
			default:
				c.JSON(http.StatusOK, v)
			}
			return
		}

		c.Next()
	}
}

// RegisterUnifiedDiscovery registers all enabled discovery routes directly
// onto a Gin router.
func RegisterUnifiedDiscovery(router gin.IRouter, config core.UnifiedDiscoveryConfig) {
	docs := core.GenerateAllDiscovery(config)

	for path, doc := range docs {
		pathCopy := path
		docCopy := doc
		router.GET(pathCopy, func(c *gin.Context) {
			switch v := docCopy.(type) {
			case string:
				c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(v))
			default:
				c.JSON(http.StatusOK, v)
			}
		})
	}
}

// ── X402 Payment Middleware ──────────────────────────────────────────────

// X402Middleware returns middleware that enforces x402 payment requirements.
// For routes configured with payment requirements, it checks for a valid
// payment signature header and verifies/settles with the facilitator.
// On success it stores payment data in the context as "x402".
func X402Middleware(config core.X402Config) gin.HandlerFunc {
	facilitator := config.Facilitator
	if facilitator == nil && config.FacilitatorURL != "" {
		facilitator = &core.HttpFacilitatorClient{URL: config.FacilitatorURL}
	}

	return func(c *gin.Context) {
		routeConfig := core.MatchRoute(c.Request.Method, c.Request.URL.Path, config.Routes)
		if routeConfig == nil {
			c.Next()
			return
		}

		paymentHeader := c.GetHeader("Payment-Signature")
		if paymentHeader == "" {
			paymentHeader = c.GetHeader("X-Payment-Signature")
		}

		if paymentHeader == "" {
			pr, err := core.BuildPaymentRequired(c.Request.URL.String(), *routeConfig, "Payment required")
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_error",
					Message: "Failed to build payment requirements.",
					Status:  http.StatusInternalServerError,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}

			encoded := core.EncodePaymentRequired(*pr)
			c.Header("Payment-Required", encoded)
			c.AbortWithStatusJSON(http.StatusPaymentRequired, pr)
			return
		}

		payload, err := core.DecodePaymentPayload(paymentHeader)
		if err != nil {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "invalid_payment",
				Message: err.Error(),
				Status:  http.StatusBadRequest,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		requirements, err := core.BuildRequirements(*routeConfig)
		if err != nil {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "payment_error",
				Message: "Failed to build payment requirements.",
				Status:  http.StatusInternalServerError,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		if facilitator != nil {
			verifyResult, err := facilitator.Verify(*payload, *requirements)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_verification_failed",
					Message: fmt.Sprintf("Payment verification failed: %s", err.Error()),
					Status:  http.StatusBadRequest,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}

			if !verifyResult.IsValid {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_invalid",
					Message: fmt.Sprintf("Payment invalid: %s", verifyResult.InvalidReason),
					Status:  http.StatusPaymentRequired,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}

			settleResult, err := facilitator.Settle(*payload, *requirements)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_settlement_failed",
					Message: fmt.Sprintf("Payment settlement failed: %s", err.Error()),
					Status:  http.StatusInternalServerError,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}

			if !settleResult.Success {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_settlement_failed",
					Message: fmt.Sprintf("Payment settlement failed: %s", settleResult.ErrorReason),
					Status:  http.StatusPaymentRequired,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}

			c.Header("Payment-Response", settleResult.TxHash)
		}

		c.Set("x402", payload)
		c.Next()
	}
}

// ── Agent Auth (OAuth Discovery) ────────────────────────────────────────

// AgentAuth returns a handler that serves the OAuth2 discovery document
// for agent authentication. It also returns a middleware that validates
// agent identity tokens when the AgentIdentityConfig contains a
// VerifyToken function.
func AgentAuth(config core.AgentAuthConfig) gin.HandlerFunc {
	metadata := map[string]interface{}{
		"issuer":                 config.Issuer,
		"authorization_endpoint": config.AuthorizationURL,
		"token_endpoint":         config.TokenURL,
	}

	if config.Scopes != nil {
		scopeKeys := make([]string, 0, len(config.Scopes))
		for k := range config.Scopes {
			scopeKeys = append(scopeKeys, k)
		}
		metadata["scopes_supported"] = scopeKeys
	}

	if config.Realm != "" {
		metadata["realm"] = config.Realm
	}

	return func(c *gin.Context) {
		c.JSON(http.StatusOK, metadata)
	}
}

// ── Agent Identity Middleware ────────────────────────────────────────────

// AgentIdentity returns middleware that verifies agent identity tokens
// and enforces authorization policies. On success it stores the
// AgentIdentityClaims in the context as "agentIdentity".
func AgentIdentity(config core.AgentIdentityConfig) gin.HandlerFunc {
	headerName := config.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	tokenPrefix := config.TokenPrefix
	if tokenPrefix == "" {
		tokenPrefix = "Bearer "
	}

	return func(c *gin.Context) {
		headerValue := c.GetHeader(headerName)
		if headerValue == "" {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "missing_identity",
				Message: "Agent identity token is required.",
				Status:  http.StatusUnauthorized,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		token := headerValue
		if strings.HasPrefix(headerValue, tokenPrefix) {
			token = headerValue[len(tokenPrefix):]
		}

		var claims core.AgentIdentityClaims

		if config.VerifyToken != nil {
			verifiedClaims, err := config.VerifyToken(token)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "invalid_token",
					Message: fmt.Sprintf("Token verification failed: %s", err.Error()),
					Status:  http.StatusUnauthorized,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}
			claims = *verifiedClaims
		} else {
			payload := core.DecodeJwtClaims(token)
			if payload == nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "malformed_token",
					Message: "Could not decode agent identity token.",
					Status:  http.StatusUnauthorized,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}
			claims = core.ExtractClaims(payload)
		}

		if validationErr := core.ValidateClaims(claims, config); validationErr != nil {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    validationErr.Code,
				Message: validationErr.Message,
				Status:  http.StatusUnauthorized,
			})
			c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
			return
		}

		if len(config.Policies) > 0 {
			authzCtx := core.AuthzContext{
				Method: c.Request.Method,
				Path:   c.Request.URL.Path,
				Headers: map[string]string{
					"user-agent":    c.GetHeader("User-Agent"),
					"authorization": c.GetHeader("Authorization"),
				},
			}

			result := core.EvaluateAuthz(claims, authzCtx, config.Policies, config.DefaultPolicy)
			if !result.Allowed {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "authorization_denied",
					Message: result.DeniedReason,
					Status:  http.StatusForbidden,
				})
				c.AbortWithStatusJSON(envelope.Status, gin.H{"error": envelope})
				return
			}
		}

		c.Set("agentIdentity", claims)
		c.Next()
	}
}

// ── One-Liner Composition ───────────────────────────────────────────────

// AgentLayer registers all middleware and discovery routes onto a Gin
// router in a single call. Middleware is applied in the following order:
// analytics (earliest), API key auth, rate limiting, agent meta (HTML
// transforms). Discovery route handlers (llms.txt, llms-full.txt,
// well-known/ai, A2A, agents.txt, auth discovery) are registered as
// GET routes. Error handling middleware runs last.
func AgentLayer(config core.AgentLayerConfig, router gin.IRouter) {
	// ── Middleware (applied in order) ──

	// 1. Analytics — earliest, wraps everything to capture timing.
	if config.Analytics != nil {
		router.Use(AgentAnalytics(*config.Analytics))
	}

	// 2. API key authentication.
	if config.ApiKeys != nil {
		router.Use(ApiKeyAuth(*config.ApiKeys))
	}

	// 3. Rate limiting.
	if config.RateLimit != nil {
		router.Use(RateLimits(*config.RateLimit))
	}

	// 4. X402 payment middleware.
	if config.X402 != nil {
		router.Use(X402Middleware(*config.X402))
	}

	// 5. Agent identity verification.
	if config.AgentIdentity != nil {
		router.Use(AgentIdentity(*config.AgentIdentity))
	}

	// 6. Agents.txt enforcement.
	if config.AgentsTxt != nil && config.AgentsTxt.Enforce {
		router.Use(AgentsTxtEnforce(config.AgentsTxt.AgentsTxtConfig))
	}

	// 7. Agent meta (HTML transforms).
	if config.AgentMeta != nil {
		router.Use(AgentMeta(*config.AgentMeta))
	}

	// ── Route Handlers ──

	// Unified discovery takes precedence — it generates all discovery
	// routes from a single config.
	if config.UnifiedDiscovery != nil {
		RegisterUnifiedDiscovery(router, *config.UnifiedDiscovery)
	} else {
		// Register individual discovery routes.
		if config.LlmsTxt != nil {
			router.GET("/llms.txt", LlmsTxtHandler(*config.LlmsTxt))
			routes := config.Routes
			if routes == nil {
				routes = []core.RouteMetadata{}
			}
			router.GET("/llms-full.txt", LlmsFullTxtHandler(*config.LlmsTxt, routes))
		}

		if config.Discovery != nil {
			router.GET("/.well-known/ai", DiscoveryHandler(*config.Discovery))
			router.GET("/.well-known/ai/json-ld", JsonLdHandler(*config.Discovery))
		}

		if config.A2A != nil {
			router.GET("/.well-known/agent.json", A2AHandler(*config.A2A))
		}

		if config.AgentsTxt != nil {
			router.GET("/agents.txt", AgentsTxtHandler(config.AgentsTxt.AgentsTxtConfig))
		}
	}

	// Auth discovery endpoint.
	if config.AgentAuth != nil {
		router.GET("/.well-known/agent-auth", AgentAuth(*config.AgentAuth))
	}

	// OAuth2 metadata endpoint.
	if config.OAuth2 != nil {
		router.GET("/.well-known/oauth-authorization-server", OAuth2MetadataHandler(*config.OAuth2))
	}

	// MCP endpoint.
	if config.MCP != nil {
		router.POST("/mcp", McpHandler(*config.MCP))
	}

	// Error handling — runs last, catches errors from all handlers.
	if config.Errors == nil || *config.Errors {
		router.Use(AgentErrors())
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────

// GetAgentKey retrieves the ScopedApiKey stored by ApiKeyAuth middleware.
// Returns nil if not present.
func GetAgentKey(c *gin.Context) *core.ScopedApiKey {
	val, exists := c.Get("agentKey")
	if !exists {
		return nil
	}
	key, ok := val.(*core.ScopedApiKey)
	if !ok {
		return nil
	}
	return key
}

// GetAgentIdentity retrieves the AgentIdentityClaims stored by
// AgentIdentity middleware. Returns nil if not present.
func GetAgentIdentity(c *gin.Context) *core.AgentIdentityClaims {
	val, exists := c.Get("agentIdentity")
	if !exists {
		return nil
	}
	claims, ok := val.(core.AgentIdentityClaims)
	if !ok {
		return nil
	}
	return &claims
}

// GetX402Payment retrieves the PaymentPayload stored by X402Middleware.
// Returns nil if not present.
func GetX402Payment(c *gin.Context) *core.PaymentPayload {
	val, exists := c.Get("x402")
	if !exists {
		return nil
	}
	payload, ok := val.(*core.PaymentPayload)
	if !ok {
		return nil
	}
	return payload
}

