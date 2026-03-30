// Package agentlayerchi provides Chi middleware and handlers that wrap the
// framework-agnostic core package into idiomatic Chi middleware.
package agentlayerchi

import (
	"context"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lightlayer-dev/agent-layer-go/core"
)

// ── Context keys ────────────────────────────────────────────────────────

type contextKey string

const (
	ctxAgentKey      contextKey = "agentKey"
	ctxAgentIdentity contextKey = "agentIdentity"
	ctxX402Payment   contextKey = "x402Payment"
)

// GetAgentKey retrieves the authenticated ScopedApiKey from the request context.
func GetAgentKey(r *http.Request) *core.ScopedApiKey {
	v, _ := r.Context().Value(ctxAgentKey).(*core.ScopedApiKey)
	return v
}

// GetAgentIdentity retrieves the verified AgentIdentityClaims from the request context.
func GetAgentIdentity(r *http.Request) *core.AgentIdentityClaims {
	v, _ := r.Context().Value(ctxAgentIdentity).(*core.AgentIdentityClaims)
	return v
}

// GetX402Payment retrieves the settled x402 PaymentPayload from the request context.
func GetX402Payment(r *http.Request) *core.PaymentPayload {
	v, _ := r.Context().Value(ctxX402Payment).(*core.PaymentPayload)
	return v
}

// ── Response writer wrapper ─────────────────────────────────────────────

// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// ── JSON helper ─────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErrorEnvelope(w http.ResponseWriter, env core.AgentErrorEnvelope) {
	writeJSON(w, env.Status, map[string]interface{}{"error": env})
}

// ── AgentErrors ─────────────────────────────────────────────────────────

// AgentErrors returns middleware that catches panics with *core.AgentError
// and writes them as structured JSON error envelopes.
func AgentErrors() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if agentErr, ok := rec.(*core.AgentError); ok {
						writeErrorEnvelope(w, agentErr.Envelope)
						return
					}
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "internal_error",
						Message: fmt.Sprintf("%v", rec),
						Status:  500,
					})
					writeErrorEnvelope(w, env)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ── RateLimits ──────────────────────────────────────────────────────────

// RateLimits returns middleware that enforces rate limiting using the core rate limiter.
func RateLimits(config core.RateLimitConfig) func(http.Handler) http.Handler {
	limiter := core.CreateRateLimiter(config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, err := limiter(r)
			if err != nil {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "rate_limit_error",
					Message: "Rate limit check failed.",
					Status:  500,
				})
				writeErrorEnvelope(w, env)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetMs, 10))

			if !result.Allowed {
				retryAfter := 60
				if result.RetryAfter != nil {
					retryAfter = int(*result.RetryAfter)
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				env := core.RateLimitError(retryAfter)
				writeErrorEnvelope(w, env)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── AgentAnalytics ──────────────────────────────────────────────────────

// AgentAnalytics returns middleware that records analytics events for agent requests.
func AgentAnalytics(config core.AnalyticsConfig) func(http.Handler) http.Handler {
	analytics := core.CreateAnalytics(config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userAgent := r.Header.Get("User-Agent")
			agent := analytics.Detect(userAgent)

			if !analytics.Config.TrackAll && agent == "" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			rw := newResponseWriter(w)
			next.ServeHTTP(rw, r)

			event := core.AgentEvent{
				Agent:        agent,
				UserAgent:    userAgent,
				Method:       r.Method,
				Path:         r.URL.Path,
				StatusCode:   rw.statusCode,
				DurationMs:   time.Since(start).Milliseconds(),
				Timestamp:    start.UTC().Format(time.RFC3339Nano),
				ContentType:  rw.Header().Get("Content-Type"),
				ResponseSize: rw.bytesWritten,
			}
			analytics.Record(event)
		})
	}
}

// ── ApiKeyAuth ──────────────────────────────────────────────────────────

// ApiKeyAuth returns middleware that validates API keys from the request header.
func ApiKeyAuth(config core.ApiKeyConfig) func(http.Handler) http.Handler {
	headerName := config.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawKey := r.Header.Get(headerName)
			if rawKey == "" {
				// Also try Authorization: Bearer <key>
				rawKey = core.ExtractBearerToken(r.Header.Get("Authorization"))
			}

			if rawKey == "" {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "missing_api_key",
					Message: "API key is required.",
					Status:  401,
				})
				writeErrorEnvelope(w, env)
				return
			}

			result, err := core.ValidateApiKey(config.Store, rawKey)
			if err != nil {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "auth_error",
					Message: "Failed to validate API key.",
					Status:  500,
				})
				writeErrorEnvelope(w, env)
				return
			}

			if !result.Valid {
				status := 401
				code := result.Error
				message := "Invalid API key."
				if code == "api_key_expired" {
					message = "API key has expired."
				}
				env := core.FormatError(core.AgentErrorOptions{
					Code:    code,
					Message: message,
					Status:  status,
				})
				writeErrorEnvelope(w, env)
				return
			}

			ctx := context.WithValue(r.Context(), ctxAgentKey, result.Key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ── RequireScope ────────────────────────────────────────────────────────

// RequireScope returns middleware that ensures the authenticated API key has the given scope.
// Must be used after ApiKeyAuth.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := GetAgentKey(r)
			if key == nil {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "missing_api_key",
					Message: "Authentication required.",
					Status:  401,
				})
				writeErrorEnvelope(w, env)
				return
			}

			if !core.HasScope(key, scope) {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "insufficient_scope",
					Message: fmt.Sprintf("Required scope: %s", scope),
					Status:  403,
				})
				writeErrorEnvelope(w, env)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── AgentMeta ───────────────────────────────────────────────────────────

// AgentMeta returns middleware that transforms HTML responses for agent consumption
// by injecting data-agent-id attributes, ARIA landmarks, and meta tags.
func AgentMeta(config core.AgentMetaConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := newResponseWriter(w)
			rec := &bufferedResponseWriter{
				header:     w.Header().Clone(),
				statusCode: http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			contentType := rec.header.Get("Content-Type")
			if strings.Contains(contentType, "text/html") {
				transformed := core.TransformHTML(rec.body.String(), config)
				for k, vv := range rec.header {
					for _, v := range vv {
						rw.Header().Set(k, v)
					}
				}
				rw.Header().Set("Content-Length", strconv.Itoa(len(transformed)))
				rw.WriteHeader(rec.statusCode)
				rw.Write([]byte(transformed))
			} else {
				for k, vv := range rec.header {
					for _, v := range vv {
						rw.Header().Set(k, v)
					}
				}
				rw.WriteHeader(rec.statusCode)
				rw.Write(rec.body.Bytes())
			}
		})
	}
}

// bufferedResponseWriter buffers the entire response body for post-processing.
type bufferedResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *bufferedResponseWriter) WriteHeader(code int) {
	w.statusCode = code
}

// ── LlmsTxtHandler ─────────────────────────────────────────────────────

// LlmsTxtHandler returns an http.HandlerFunc that serves /llms.txt.
func LlmsTxtHandler(config core.LlmsTxtConfig) http.HandlerFunc {
	body := core.GenerateLlmsTxt(config)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}
}

// ── LlmsFullTxtHandler ─────────────────────────────────────────────────

// LlmsFullTxtHandler returns an http.HandlerFunc that serves /llms-full.txt.
func LlmsFullTxtHandler(config core.LlmsTxtConfig, routes []core.RouteMetadata) http.HandlerFunc {
	body := core.GenerateLlmsFullTxt(config, routes)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}
}

// ── DiscoveryHandler ────────────────────────────────────────────────────

// DiscoveryHandler returns an http.HandlerFunc that serves /.well-known/ai manifest.
func DiscoveryHandler(config core.DiscoveryConfig) http.HandlerFunc {
	manifest := core.GenerateAIManifest(config)
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, manifest)
	}
}

// ── JsonLdHandler ───────────────────────────────────────────────────────

// JsonLdHandler returns an http.HandlerFunc that serves JSON-LD structured data.
func JsonLdHandler(config core.DiscoveryConfig) http.HandlerFunc {
	jsonLd := core.GenerateJsonLd(config)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(jsonLd)
	}
}

// ── A2AHandler ──────────────────────────────────────────────────────────

// A2AHandler returns an http.HandlerFunc that serves the A2A Agent Card.
func A2AHandler(config core.A2AConfig) http.HandlerFunc {
	card := core.GenerateAgentCard(config)
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, card)
	}
}

// ── AgentsTxtHandler ────────────────────────────────────────────────────

// AgentsTxtHandler returns an http.HandlerFunc that serves /agents.txt.
func AgentsTxtHandler(config core.AgentsTxtConfig) http.HandlerFunc {
	body := core.GenerateAgentsTxt(config)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}
}

// ── AgentsTxtEnforce ────────────────────────────────────────────────────

// AgentsTxtEnforce returns middleware that enforces agents.txt rules based on the
// User-Agent header. Requests from disallowed agents receive a 403 response.
func AgentsTxtEnforce(config core.AgentsTxtConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userAgent := r.Header.Get("User-Agent")
			agentName := core.DetectAgent(userAgent)

			if agentName == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed := core.IsAgentAllowed(config, agentName, r.URL.Path)
			if allowed != nil && !*allowed {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "agent_not_allowed",
					Message: fmt.Sprintf("Agent %s is not allowed to access %s", agentName, r.URL.Path),
					Status:  403,
				})
				writeErrorEnvelope(w, env)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── McpHandler ──────────────────────────────────────────────────────────

// McpHandler returns an http.HandlerFunc that implements the MCP JSON-RPC endpoint.
func McpHandler(config core.McpServerConfig) http.HandlerFunc {
	tools := config.Tools
	if len(tools) == 0 && len(config.Routes) > 0 {
		tools = core.GenerateToolDefinitions(config.Routes)
	}
	serverInfo := core.GenerateServerInfo(config)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			env := core.FormatError(core.AgentErrorOptions{
				Code:    "method_not_allowed",
				Message: "MCP endpoint only accepts POST requests.",
				Status:  405,
			})
			writeErrorEnvelope(w, env)
			return
		}

		var request core.JsonRpcRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSON(w, http.StatusOK, core.JsonRpcResponse{
				Jsonrpc: "2.0",
				Error: &core.JsonRpcError{
					Code:    -32700,
					Message: "Parse error",
				},
			})
			return
		}

		response := core.HandleJsonRpc(request, serverInfo, tools, nil)
		if response == nil {
			// Notification — no response needed
			w.WriteHeader(http.StatusNoContent)
			return
		}

		writeJSON(w, http.StatusOK, response)
	}
}

// ── AgUiStreamHandler ───────────────────────────────────────────────────

// AgUiStreamHandler returns an http.HandlerFunc that sets up AG-UI SSE streaming.
// The provided handler function receives an emitter and writes events to the stream.
func AgUiStreamHandler(handler func(*core.AgUiEmitter) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			env := core.FormatError(core.AgentErrorOptions{
				Code:    "streaming_not_supported",
				Message: "Streaming is not supported by this server.",
				Status:  500,
			})
			writeErrorEnvelope(w, env)
			return
		}

		for k, v := range core.AgUiHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		emitter := core.CreateAgUiEmitter(func(chunk string) {
			w.Write([]byte(chunk))
			flusher.Flush()
		}, core.AgUiEmitterOptions{})

		if err := handler(emitter); err != nil {
			emitter.RunError(err.Error(), "handler_error")
		}
	}
}

// ── OAuth2MetadataHandler ───────────────────────────────────────────────

// OAuth2MetadataHandler returns an http.HandlerFunc that serves OAuth2 Authorization
// Server Metadata (RFC 8414) at /.well-known/oauth-authorization-server.
func OAuth2MetadataHandler(config core.OAuth2Config) http.HandlerFunc {
	metadata := core.BuildOAuth2Metadata(config)
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, metadata)
	}
}

// ── X402Middleware ───────────────────────────────────────────────────────

// X402Middleware returns middleware that implements the x402 payment protocol.
// Routes matching the config receive a 402 response unless a valid payment
// signature is provided and verified.
func X402Middleware(config core.X402Config) func(http.Handler) http.Handler {
	facilitator := config.Facilitator
	if facilitator == nil && config.FacilitatorURL != "" {
		facilitator = &core.HttpFacilitatorClient{URL: config.FacilitatorURL}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			routeConfig := core.MatchRoute(r.Method, r.URL.Path, config.Routes)
			if routeConfig == nil {
				next.ServeHTTP(w, r)
				return
			}

			paymentHeader := r.Header.Get("Payment-Signature")
			if paymentHeader == "" {
				paymentHeader = r.Header.Get("X-Payment-Signature")
			}

			if paymentHeader == "" {
				pr, err := core.BuildPaymentRequired(r.URL.Path, *routeConfig, "Payment required")
				if err != nil {
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_config_error",
						Message: "Failed to build payment requirements.",
						Status:  500,
					})
					writeErrorEnvelope(w, env)
					return
				}
				encoded := core.EncodePaymentRequired(*pr)
				w.Header().Set("Payment-Required", encoded)
				writeJSON(w, http.StatusPaymentRequired, pr)
				return
			}

			payload, err := core.DecodePaymentPayload(paymentHeader)
			if err != nil {
				env := core.FormatError(core.AgentErrorOptions{
					Code:    "invalid_payment",
					Message: err.Error(),
					Status:  400,
				})
				writeErrorEnvelope(w, env)
				return
			}

			if facilitator != nil {
				requirements, err := core.BuildRequirements(*routeConfig)
				if err != nil {
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_config_error",
						Message: "Failed to build payment requirements.",
						Status:  500,
					})
					writeErrorEnvelope(w, env)
					return
				}

				verifyResp, err := facilitator.Verify(*payload, *requirements)
				if err != nil {
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_verification_failed",
						Message: "Payment verification failed.",
						Status:  502,
					})
					writeErrorEnvelope(w, env)
					return
				}

				if !verifyResp.IsValid {
					reason := verifyResp.InvalidReason
					if reason == "" {
						reason = "Payment is not valid."
					}
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_invalid",
						Message: reason,
						Status:  402,
					})
					writeErrorEnvelope(w, env)
					return
				}

				settleResp, err := facilitator.Settle(*payload, *requirements)
				if err != nil {
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_settlement_failed",
						Message: "Payment settlement failed.",
						Status:  502,
					})
					writeErrorEnvelope(w, env)
					return
				}

				if !settleResp.Success {
					reason := settleResp.ErrorReason
					if reason == "" {
						reason = "Payment settlement was not successful."
					}
					env := core.FormatError(core.AgentErrorOptions{
						Code:    "payment_settlement_failed",
						Message: reason,
						Status:  502,
					})
					writeErrorEnvelope(w, env)
					return
				}

				if settleResp.TxHash != "" {
					w.Header().Set("Payment-Response", settleResp.TxHash)
				}
			}

			ctx := context.WithValue(r.Context(), ctxX402Payment, payload)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ── AgentAuthHandler ────────────────────────────────────────────────────

// AgentAuthHandler returns an http.HandlerFunc that serves the agent-auth OAuth
// discovery document, including a WWW-Authenticate header.
func AgentAuthHandler(config core.AgentAuthConfig) http.HandlerFunc {
	discovery := map[string]interface{}{
		"issuer":                 config.Issuer,
		"authorization_endpoint": config.AuthorizationURL,
		"token_endpoint":         config.TokenURL,
	}
	if config.Scopes != nil {
		scopeKeys := make([]string, 0, len(config.Scopes))
		for k := range config.Scopes {
			scopeKeys = append(scopeKeys, k)
		}
		discovery["scopes_supported"] = scopeKeys
	}

	return func(w http.ResponseWriter, r *http.Request) {
		realm := config.Realm
		if realm == "" {
			realm = "agent"
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(
			`Bearer realm="%s", authorization_uri="%s", token_uri="%s"`,
			realm, config.AuthorizationURL, config.TokenURL,
		))
		writeJSON(w, http.StatusOK, discovery)
	}
}

// ── AgentLayer (one-liner setup) ────────────────────────────────────────

// AgentLayer returns a chi.Router with all configured middleware and handlers
// mounted. This is the one-liner setup for the full agent layer stack.
func AgentLayer(config core.AgentLayerConfig) chi.Router {
	r := chi.NewRouter()

	// ── Global middleware ────────────────────────────────────────────

	if config.Errors == nil || *config.Errors {
		r.Use(AgentErrors())
	}

	if config.RateLimit != nil {
		r.Use(RateLimits(*config.RateLimit))
	}

	if config.ApiKeys != nil {
		r.Use(ApiKeyAuth(*config.ApiKeys))
	}

	if config.Analytics != nil {
		r.Use(AgentAnalytics(*config.Analytics))
	}

	if config.AgentMeta != nil {
		r.Use(AgentMeta(*config.AgentMeta))
	}

	if config.AgentsTxt != nil && config.AgentsTxt.Enforce {
		r.Use(AgentsTxtEnforce(config.AgentsTxt.AgentsTxtConfig))
	}

	if config.X402 != nil {
		r.Use(X402Middleware(*config.X402))
	}

	// ── Discovery / static handlers ─────────────────────────────────

	if config.LlmsTxt != nil {
		r.Get("/llms.txt", LlmsTxtHandler(*config.LlmsTxt))
		routes := config.Routes
		if routes == nil {
			routes = []core.RouteMetadata{}
		}
		r.Get("/llms-full.txt", LlmsFullTxtHandler(*config.LlmsTxt, routes))
	}

	if config.Discovery != nil {
		r.Get("/.well-known/ai", DiscoveryHandler(*config.Discovery))
		r.Get("/.well-known/ai/json-ld", JsonLdHandler(*config.Discovery))
	}

	if config.A2A != nil {
		r.Get("/.well-known/agent.json", A2AHandler(*config.A2A))
	}

	if config.AgentsTxt != nil {
		r.Get("/agents.txt", AgentsTxtHandler(config.AgentsTxt.AgentsTxtConfig))
	}

	if config.MCP != nil {
		r.Post("/mcp", McpHandler(*config.MCP))
	}

	if config.OAuth2 != nil {
		r.Get("/.well-known/oauth-authorization-server", OAuth2MetadataHandler(*config.OAuth2))
	}

	if config.AgentAuth != nil {
		r.Get("/.well-known/agent-auth", AgentAuthHandler(*config.AgentAuth))
	}

	// ── Unified Discovery ───────────────────────────────────────────

	if config.UnifiedDiscovery != nil {
		ud := config.UnifiedDiscovery

		if core.IsFormatEnabled(ud.Formats, "wellKnownAi") {
			manifest := core.GenerateUnifiedAIManifest(*ud)
			r.Get("/.well-known/ai", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, manifest)
			})
		}

		if core.IsFormatEnabled(ud.Formats, "agentCard") {
			card := core.GenerateUnifiedAgentCard(*ud)
			r.Get("/.well-known/agent.json", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, card)
			})
		}

		if core.IsFormatEnabled(ud.Formats, "llmsTxt") {
			llmsTxt := core.GenerateUnifiedLlmsTxt(*ud)
			r.Get("/llms.txt", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(llmsTxt))
			})

			llmsFullTxt := core.GenerateUnifiedLlmsFullTxt(*ud)
			r.Get("/llms-full.txt", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(llmsFullTxt))
			})
		}

		if core.IsFormatEnabled(ud.Formats, "agentsTxt") {
			agentsTxt := core.GenerateUnifiedAgentsTxt(*ud)
			r.Get("/agents.txt", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(agentsTxt))
			})
		}
	}

	return r
}
