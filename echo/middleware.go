// Package agentlayerecho provides Echo middleware and handlers for agent-layer-go.
// It wraps the core package into Echo-compatible middleware and route handlers.
package agentlayerecho

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lightlayer-dev/agent-layer-go/core"
)

// ── Error Handling ─────────────────────────────────────────────────────

// AgentErrors returns middleware that catches panics and formats errors into
// the standard agent-friendly JSON envelope.
func AgentErrors() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					msg := fmt.Sprintf("%v", r)
					envelope := core.FormatError(core.AgentErrorOptions{
						Code:    "internal_error",
						Message: msg,
						Status:  500,
					})
					_ = c.JSON(envelope.Status, map[string]interface{}{"error": envelope})
				}
			}()

			err := next(c)
			if err != nil {
				// Check if it is an AgentError
				if agentErr, ok := err.(*core.AgentError); ok {
					return c.JSON(agentErr.Envelope.Status, agentErr.ToJSON())
				}

				// Check if it is an Echo HTTPError
				if he, ok := err.(*echo.HTTPError); ok {
					msg := fmt.Sprintf("%v", he.Message)
					envelope := core.FormatError(core.AgentErrorOptions{
						Code:    strings.ReplaceAll(strings.ToLower(http.StatusText(he.Code)), " ", "_"),
						Message: msg,
						Status:  he.Code,
					})
					return c.JSON(envelope.Status, map[string]interface{}{"error": envelope})
				}

				// Generic error
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "internal_error",
					Message: err.Error(),
					Status:  500,
				})
				return c.JSON(envelope.Status, map[string]interface{}{"error": envelope})
			}
			return nil
		}
	}
}

// ── Rate Limiting ──────────────────────────────────────────────────────

// RateLimits returns middleware that enforces rate limiting using the core rate limiter.
func RateLimits(config core.RateLimitConfig) echo.MiddlewareFunc {
	limiter := core.CreateRateLimiter(config)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			result, err := limiter(c.Request())
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "rate_limit_error",
					Message: "Rate limit check failed.",
					Status:  500,
				})
				return c.JSON(500, map[string]interface{}{"error": envelope})
			}

			// Set rate limit headers
			c.Response().Header().Set("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetMs, 10))

			if !result.Allowed {
				retryAfter := int(0)
				if result.RetryAfter != nil {
					retryAfter = int(*result.RetryAfter)
				}
				c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
				envelope := core.RateLimitError(retryAfter)
				return c.JSON(envelope.Status, map[string]interface{}{"error": envelope})
			}

			return next(c)
		}
	}
}

// ── Analytics ──────────────────────────────────────────────────────────

// AgentAnalytics returns middleware that tracks agent requests for analytics.
func AgentAnalytics(config core.AnalyticsConfig) echo.MiddlewareFunc {
	analytics := core.CreateAnalytics(config)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			userAgent := c.Request().Header.Get("User-Agent")
			agentName := analytics.Detect(userAgent)

			if agentName == "" && !analytics.Config.TrackAll {
				return next(c)
			}

			err := next(c)

			durationMs := time.Since(start).Milliseconds()
			event := core.AgentEvent{
				Agent:        agentName,
				UserAgent:    userAgent,
				Method:       c.Request().Method,
				Path:         c.Request().URL.Path,
				StatusCode:   c.Response().Status,
				DurationMs:   durationMs,
				Timestamp:    time.Now().UTC().Format(time.RFC3339),
				ContentType:  c.Response().Header().Get("Content-Type"),
				ResponseSize: c.Response().Size,
			}
			analytics.Record(event)

			return err
		}
	}
}

// ── API Key Authentication ─────────────────────────────────────────────

// ApiKeyAuth returns middleware that validates API keys from request headers.
func ApiKeyAuth(config core.ApiKeyConfig) echo.MiddlewareFunc {
	headerName := config.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rawKey := c.Request().Header.Get(headerName)
			if rawKey == "" {
				// Also try Authorization: Bearer
				authHeader := c.Request().Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					rawKey = authHeader[7:]
				}
			}

			if rawKey == "" {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "missing_api_key",
					Message: fmt.Sprintf("API key is required. Provide it via the %s header.", headerName),
					Status:  401,
				})
				return c.JSON(401, map[string]interface{}{"error": envelope})
			}

			result, err := core.ValidateApiKey(config.Store, rawKey)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "auth_error",
					Message: "Failed to validate API key.",
					Status:  500,
				})
				return c.JSON(500, map[string]interface{}{"error": envelope})
			}

			if !result.Valid {
				status := 401
				code := result.Error
				message := "Invalid API key."
				if result.Error == "api_key_expired" {
					message = "API key has expired."
					status = 403
				}
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    code,
					Message: message,
					Status:  status,
				})
				return c.JSON(status, map[string]interface{}{"error": envelope})
			}

			c.Set("apiKey", result.Key)
			return next(c)
		}
	}
}

// ── Scope Authorization ────────────────────────────────────────────────

// RequireScope returns middleware that checks if the authenticated API key
// has the required scope.
func RequireScope(scope string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			keyVal := c.Get("apiKey")
			if keyVal == nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "missing_api_key",
					Message: "API key authentication is required before checking scopes.",
					Status:  401,
				})
				return c.JSON(401, map[string]interface{}{"error": envelope})
			}

			key, ok := keyVal.(*core.ScopedApiKey)
			if !ok {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "auth_error",
					Message: "Invalid API key context.",
					Status:  500,
				})
				return c.JSON(500, map[string]interface{}{"error": envelope})
			}

			if !core.HasScope(key, scope) {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "insufficient_scope",
					Message: fmt.Sprintf("This action requires the '%s' scope.", scope),
					Status:  403,
				})
				return c.JSON(403, map[string]interface{}{"error": envelope})
			}

			return next(c)
		}
	}
}

// ── Agent Meta (HTML Transform) ────────────────────────────────────────

// AgentMeta returns middleware that transforms HTML responses for agent consumption.
// It injects data-agent-id attributes, ARIA landmarks, and meta tags.
func AgentMeta(config core.AgentMetaConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Use a response writer wrapper to capture HTML output
			rec := newResponseRecorder(c.Response())
			c.Response().Writer = rec

			err := next(c)
			if err != nil {
				return err
			}

			contentType := c.Response().Header().Get("Content-Type")
			body := rec.Body()

			if strings.Contains(contentType, "text/html") && len(body) > 0 {
				transformed := core.TransformHTML(string(body), config)
				c.Response().Writer = rec.originalWriter
				c.Response().Header().Set("Content-Length", strconv.Itoa(len(transformed)))
				_, writeErr := c.Response().Writer.Write([]byte(transformed))
				return writeErr
			}

			// Not HTML, write original body
			c.Response().Writer = rec.originalWriter
			_, writeErr := c.Response().Writer.Write(body)
			return writeErr
		}
	}
}

// responseRecorder captures response body for post-processing.
type responseRecorder struct {
	originalWriter http.ResponseWriter
	body           []byte
	statusCode     int
	headerWritten  bool
}

func newResponseRecorder(resp *echo.Response) *responseRecorder {
	return &responseRecorder{
		originalWriter: resp.Writer,
		statusCode:     200,
	}
}

func (r *responseRecorder) Header() http.Header {
	return r.originalWriter.Header()
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.headerWritten = true
}

func (r *responseRecorder) Body() []byte {
	return r.body
}

func (r *responseRecorder) Flush() {
	if f, ok := r.originalWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ── LLMs.txt Handlers ──────────────────────────────────────────────────

// LlmsTxtHandler returns a handler that serves llms.txt content.
func LlmsTxtHandler(config core.LlmsTxtConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		content := core.GenerateLlmsTxt(config)
		return c.String(http.StatusOK, content)
	}
}

// LlmsFullTxtHandler returns a handler that serves llms-full.txt content
// with route documentation.
func LlmsFullTxtHandler(config core.LlmsTxtConfig, routes []core.RouteMetadata) echo.HandlerFunc {
	return func(c echo.Context) error {
		content := core.GenerateLlmsFullTxt(config, routes)
		return c.String(http.StatusOK, content)
	}
}

// ── Discovery Handlers ─────────────────────────────────────────────────

// DiscoveryHandler returns a handler that serves the /.well-known/ai manifest.
func DiscoveryHandler(config core.DiscoveryConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		manifest := core.GenerateAIManifest(config)
		return c.JSON(http.StatusOK, manifest)
	}
}

// JsonLdHandler returns a handler that serves JSON-LD structured data.
func JsonLdHandler(config core.DiscoveryConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		jsonLd := core.GenerateJsonLd(config)
		return c.JSON(http.StatusOK, jsonLd)
	}
}

// ── A2A Agent Card ─────────────────────────────────────────────────────

// A2AHandler returns a handler that serves the A2A Agent Card.
func A2AHandler(config core.A2AConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		card := core.GenerateAgentCard(config)
		return c.JSON(http.StatusOK, card)
	}
}

// ── Agents.txt ─────────────────────────────────────────────────────────

// AgentsTxtHandler returns a handler that serves agents.txt content.
func AgentsTxtHandler(config core.AgentsTxtConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		content := core.GenerateAgentsTxt(config)
		c.Response().Header().Set("Content-Type", "text/plain; charset=utf-8")
		return c.String(http.StatusOK, content)
	}
}

// AgentsTxtEnforce returns middleware that enforces agents.txt rules.
// It checks the User-Agent against the agents.txt config and denies
// requests from disallowed agents.
func AgentsTxtEnforce(config core.AgentsTxtConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userAgent := c.Request().Header.Get("User-Agent")
			agentName := core.DetectAgent(userAgent)

			if agentName == "" {
				return next(c)
			}

			path := c.Request().URL.Path
			allowed := core.IsAgentAllowed(config, agentName, path)

			if allowed != nil && !*allowed {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "agent_not_allowed",
					Message: fmt.Sprintf("Agent '%s' is not allowed to access %s per agents.txt policy.", agentName, path),
					Status:  403,
				})
				return c.JSON(403, map[string]interface{}{"error": envelope})
			}

			return next(c)
		}
	}
}

// ── robots.txt ──────────────────────────────────────────────────────────

// RobotsTxtHandler returns a handler that serves robots.txt.
func RobotsTxtHandler(config core.RobotsTxtConfig) echo.HandlerFunc {
	content := core.GenerateRobotsTxt(&config)
	return func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "public, max-age=86400")
		return c.Blob(http.StatusOK, "text/plain; charset=utf-8", []byte(content))
	}
}

// ── Security Headers ────────────────────────────────────────────────────

// SecurityHeaders returns middleware that sets security headers on every response.
func SecurityHeaders(config core.SecurityHeadersConfig) echo.MiddlewareFunc {
	headers := core.GenerateSecurityHeaders(&config)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			for k, v := range headers {
				c.Response().Header().Set(k, v)
			}
			return next(c)
		}
	}
}

// ── Agent Onboarding ────────────────────────────────────────────────────

// AgentOnboardingHandler returns a handler for POST /agent/register.
func AgentOnboardingHandler(config core.OnboardingConfig) echo.HandlerFunc {
	handler := core.CreateOnboardingHandler(config)
	return func(c echo.Context) error {
		var body core.RegistrationRequest
		if err := c.Bind(&body); err != nil {
			envelope := core.FormatError(core.AgentErrorOptions{
				Code:    "invalid_json",
				Message: "Request body must be valid JSON.",
				Status:  http.StatusBadRequest,
			})
			return c.JSON(envelope.Status, map[string]interface{}{"error": envelope})
		}

		result := handler.HandleRegister(body, echoClientIP(c.Request()))
		return c.JSON(result.Status, result.Body)
	}
}

// AgentOnboardingAuth returns middleware that emits the onboarding auth-required response.
func AgentOnboardingAuth(config core.OnboardingConfig) echo.MiddlewareFunc {
	handler := core.CreateOnboardingHandler(config)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			headers := map[string]string{}
			for k, values := range c.Request().Header {
				if len(values) > 0 {
					headers[k] = values[0]
				}
			}
			if handler.ShouldReturn401(c.Request().URL.Path, headers) {
				return c.JSON(http.StatusUnauthorized, handler.GetAuthRequiredResponse())
			}
			return next(c)
		}
	}
}

// ── MCP (Model Context Protocol) ───────────────────────────────────────

// McpHandler returns a handler that processes JSON-RPC requests for the MCP protocol.
func McpHandler(config core.McpServerConfig) echo.HandlerFunc {
	serverInfo := core.GenerateServerInfo(config)

	tools := config.Tools
	if len(tools) == 0 && len(config.Routes) > 0 {
		tools = core.GenerateToolDefinitions(config.Routes)
	}

	return func(c echo.Context) error {
		var request core.JsonRpcRequest
		if err := c.Bind(&request); err != nil {
			rpcErr := core.JsonRpcResponse{
				Jsonrpc: "2.0",
				Error: &core.JsonRpcError{
					Code:    -32700,
					Message: "Parse error: invalid JSON",
				},
			}
			return c.JSON(http.StatusOK, rpcErr)
		}

		response := core.HandleJsonRpc(request, serverInfo, tools, nil)
		if response == nil {
			// Notification acknowledged — return 204
			return c.NoContent(http.StatusNoContent)
		}

		return c.JSON(http.StatusOK, response)
	}
}

// ── AG-UI Streaming ────────────────────────────────────────────────────

// AgUiStreamHandler returns a handler that sets up SSE streaming for the AG-UI protocol.
// The provided handler function receives an emitter to send AG-UI events.
func AgUiStreamHandler(handler func(*core.AgUiEmitter) error) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Set SSE headers
		for key, value := range core.AgUiHeaders {
			c.Response().Header().Set(key, value)
		}
		c.Response().WriteHeader(http.StatusOK)

		// Flush after headers
		if flusher, ok := c.Response().Writer.(http.Flusher); ok {
			flusher.Flush()
		}

		// Create emitter that writes to the response
		write := func(chunk string) {
			_, _ = c.Response().Write([]byte(chunk))
			if flusher, ok := c.Response().Writer.(http.Flusher); ok {
				flusher.Flush()
			}
		}

		emitter := core.CreateAgUiEmitter(write, core.AgUiEmitterOptions{})

		return handler(emitter)
	}
}

// ── OAuth2 Metadata ────────────────────────────────────────────────────

// OAuth2MetadataHandler returns a handler that serves OAuth2 Authorization Server Metadata.
func OAuth2MetadataHandler(config core.OAuth2Config) echo.HandlerFunc {
	return func(c echo.Context) error {
		metadata := core.BuildOAuth2Metadata(config)
		return c.JSON(http.StatusOK, metadata)
	}
}

// ── Unified Discovery ──────────────────────────────────────────────────

// UnifiedDiscoveryRoutes registers all enabled discovery routes from a single config.
func UnifiedDiscoveryRoutes(config core.UnifiedDiscoveryConfig, e *echo.Echo) {
	documents := core.GenerateAllDiscovery(config)

	for path, content := range documents {
		routePath := path
		routeContent := content

		switch v := routeContent.(type) {
		case string:
			e.GET(routePath, func(c echo.Context) error {
				c.Response().Header().Set("Content-Type", "text/plain; charset=utf-8")
				return c.String(http.StatusOK, v)
			})
		default:
			e.GET(routePath, func(c echo.Context) error {
				return c.JSON(http.StatusOK, v)
			})
		}
	}
}

// ── X402 Payment Middleware ────────────────────────────────────────────

// X402Middleware returns middleware that enforces x402 payment requirements.
func X402Middleware(config core.X402Config) echo.MiddlewareFunc {
	facilitator := config.Facilitator
	if facilitator == nil && config.FacilitatorURL != "" {
		facilitator = &core.HttpFacilitatorClient{URL: config.FacilitatorURL}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			method := c.Request().Method
			path := c.Request().URL.Path

			routeConfig := core.MatchRoute(method, path, config.Routes)
			if routeConfig == nil {
				return next(c)
			}

			// Check for payment signature header
			paymentHeader := c.Request().Header.Get("Payment-Signature")
			if paymentHeader == "" {
				paymentHeader = c.Request().Header.Get("X-Payment-Signature")
			}

			if paymentHeader == "" {
				// No payment — return 402
				pr, err := core.BuildPaymentRequired(
					c.Request().URL.String(),
					*routeConfig,
					"Payment required to access this resource.",
				)
				if err != nil {
					envelope := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_config_error",
						Message: "Failed to build payment requirements.",
						Status:  500,
					})
					return c.JSON(500, map[string]interface{}{"error": envelope})
				}

				encoded := core.EncodePaymentRequired(*pr)
				c.Response().Header().Set("X-Payment-Required", encoded)
				return c.JSON(http.StatusPaymentRequired, pr)
			}

			// Decode payment payload
			payload, err := core.DecodePaymentPayload(paymentHeader)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "invalid_payment",
					Message: err.Error(),
					Status:  400,
				})
				return c.JSON(400, map[string]interface{}{"error": envelope})
			}

			if facilitator == nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_not_configured",
					Message: "Payment facilitator is not configured.",
					Status:  500,
				})
				return c.JSON(500, map[string]interface{}{"error": envelope})
			}

			// Build requirements for verification
			requirements, err := core.BuildRequirements(*routeConfig)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_config_error",
					Message: "Failed to build payment requirements.",
					Status:  500,
				})
				return c.JSON(500, map[string]interface{}{"error": envelope})
			}

			// Verify payment
			verifyResult, err := facilitator.Verify(*payload, *requirements)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_verification_failed",
					Message: fmt.Sprintf("Payment verification failed: %s", err.Error()),
					Status:  502,
				})
				return c.JSON(502, map[string]interface{}{"error": envelope})
			}

			if !verifyResult.IsValid {
				reason := verifyResult.InvalidReason
				if reason == "" {
					reason = "Payment verification failed."
				}
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_invalid",
					Message: reason,
					Status:  402,
				})
				return c.JSON(402, map[string]interface{}{"error": envelope})
			}

			// Settle payment
			settleResult, err := facilitator.Settle(*payload, *requirements)
			if err != nil {
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_settlement_failed",
					Message: fmt.Sprintf("Payment settlement failed: %s", err.Error()),
					Status:  502,
				})
				return c.JSON(502, map[string]interface{}{"error": envelope})
			}

			if !settleResult.Success {
				reason := settleResult.ErrorReason
				if reason == "" {
					reason = "Payment settlement failed."
				}
				envelope := core.FormatError(core.AgentErrorOptions{
					Code:    "payment_settlement_failed",
					Message: reason,
					Status:  502,
				})
				return c.JSON(502, map[string]interface{}{"error": envelope})
			}

			// Store settlement info in context
			c.Set("x402_settlement", settleResult)

			// Set payment response header
			if settleResult.TxHash != "" {
				responseData, _ := json.Marshal(settleResult)
				c.Response().Header().Set("X-Payment-Response", string(responseData))
			}

			return next(c)
		}
	}
}

// ── Agent Auth ─────────────────────────────────────────────────────────

// AgentAuthHandler returns a handler that serves OAuth2 discovery metadata
// for agent authentication.
func AgentAuthHandler(config core.AgentAuthConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
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

		return c.JSON(http.StatusOK, metadata)
	}
}

// ── One-Liner Setup ────────────────────────────────────────────────────

// AgentLayer registers all configured agent-layer features on an Echo instance.
// This is the one-liner setup function that wires everything together.
func AgentLayer(config core.AgentLayerConfig, e *echo.Echo) {
	// Error handling middleware
	if config.Errors == nil || *config.Errors {
		e.Use(AgentErrors())
	}

	// Security headers middleware
	if config.SecurityHeaders != nil {
		e.Use(SecurityHeaders(*config.SecurityHeaders))
	}

	// Onboarding auth-required middleware
	if config.AgentOnboarding != nil {
		e.Use(AgentOnboardingAuth(*config.AgentOnboarding))
	}

	// Rate limiting middleware
	if config.RateLimit != nil {
		e.Use(RateLimits(*config.RateLimit))
	}

	// Analytics middleware
	if config.Analytics != nil {
		e.Use(AgentAnalytics(*config.Analytics))
	}

	// API key authentication middleware
	if config.ApiKeys != nil {
		e.Use(ApiKeyAuth(*config.ApiKeys))
	}

	// Agent meta (HTML transform) middleware
	if config.AgentMeta != nil {
		e.Use(AgentMeta(*config.AgentMeta))
	}

	// Agents.txt enforcement and handler
	if config.AgentsTxt != nil {
		e.GET("/agents.txt", AgentsTxtHandler(config.AgentsTxt.AgentsTxtConfig))
		if config.AgentsTxt.Enforce {
			e.Use(AgentsTxtEnforce(config.AgentsTxt.AgentsTxtConfig))
		}
	}

	if config.RobotsTxt != nil {
		e.GET("/robots.txt", RobotsTxtHandler(*config.RobotsTxt))
	}

	if config.AgentOnboarding != nil {
		e.POST("/agent/register", AgentOnboardingHandler(*config.AgentOnboarding))
	}

	// X402 payment middleware
	if config.X402 != nil {
		e.Use(X402Middleware(*config.X402))
	}

	// LLMs.txt handlers
	if config.LlmsTxt != nil {
		e.GET("/llms.txt", LlmsTxtHandler(*config.LlmsTxt))
		routes := config.Routes
		if routes == nil {
			routes = []core.RouteMetadata{}
		}
		e.GET("/llms-full.txt", LlmsFullTxtHandler(*config.LlmsTxt, routes))
	}

	// Discovery handlers
	if config.Discovery != nil {
		e.GET("/.well-known/ai", DiscoveryHandler(*config.Discovery))
		e.GET("/.well-known/ai/json-ld", JsonLdHandler(*config.Discovery))
	}

	// A2A Agent Card handler
	if config.A2A != nil {
		e.GET("/.well-known/agent.json", A2AHandler(*config.A2A))
	}

	// MCP handler
	if config.MCP != nil {
		e.POST("/mcp", McpHandler(*config.MCP))
	}

	// OAuth2 metadata handler
	if config.OAuth2 != nil {
		e.GET("/.well-known/oauth-authorization-server", OAuth2MetadataHandler(*config.OAuth2))
	}

	// Agent auth handler
	if config.AgentAuth != nil {
		e.GET("/.well-known/agent-auth", AgentAuthHandler(*config.AgentAuth))
	}

	// Unified discovery routes (registers multiple routes from a single config)
	if config.UnifiedDiscovery != nil {
		UnifiedDiscoveryRoutes(*config.UnifiedDiscovery, e)
	}
}

func echoClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}
