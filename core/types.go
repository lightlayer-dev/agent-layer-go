// Package core provides the core logic for agent-layer-go.
// All types, generators, and protocol implementations are framework-agnostic.
package core

// ── Error Envelope ──────────────────────────────────────────────────────

// AgentErrorEnvelope is the standard error response format for agent APIs.
type AgentErrorEnvelope struct {
	Type        string `json:"type"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Status      int    `json:"status"`
	IsRetriable bool   `json:"is_retriable"`
	RetryAfter  *int   `json:"retry_after,omitempty"`
	Param       string `json:"param,omitempty"`
	DocsURL     string `json:"docs_url,omitempty"`
}

// AgentErrorOptions are the options for creating an error envelope.
type AgentErrorOptions struct {
	Type        string
	Code        string
	Message     string
	Status      int
	IsRetriable *bool
	RetryAfter  *int
	Param       string
	DocsURL     string
}

// ── Rate Limiting ───────────────────────────────────────────────────────

// RateLimitStore is a pluggable interface for rate limit storage.
type RateLimitStore interface {
	Increment(key string, windowMs int64) (int64, error)
	Get(key string) (int64, error)
	Reset(key string) error
}

// RateLimitConfig configures the rate limiter.
type RateLimitConfig struct {
	Max      int64
	WindowMs int64
	KeyFn    func(r interface{}) string
	Store    RateLimitStore
}

// RateLimitResult is the result of a rate limit check.
type RateLimitResult struct {
	Allowed    bool
	Limit      int64
	Remaining  int64
	ResetMs    int64
	RetryAfter *int64
}

// ── LLMs.txt ────────────────────────────────────────────────────────────

// LlmsTxtSection is a manual section in llms.txt.
type LlmsTxtSection struct {
	Title   string
	Content string
}

// LlmsTxtConfig configures llms.txt generation.
type LlmsTxtConfig struct {
	Title       string
	Description string
	Sections    []LlmsTxtSection
}

// RouteMetadata describes an HTTP endpoint for discovery.
type RouteMetadata struct {
	Method      string
	Path        string
	Summary     string
	Description string
	Parameters  []RouteParameter
}

// RouteParameter describes a single parameter of an HTTP endpoint.
type RouteParameter struct {
	Name        string
	In          string // "path", "query", "header", "body"
	Required    bool
	Description string
}

// ── Discovery / .well-known/ai ──────────────────────────────────────────

// AIManifest is the /.well-known/ai manifest document.
type AIManifest struct {
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	OpenAPIURL   string             `json:"openapi_url,omitempty"`
	LlmsTxtURL   string             `json:"llms_txt_url,omitempty"`
	Auth         *AIManifestAuth    `json:"auth,omitempty"`
	Contact      *AIManifestContact `json:"contact,omitempty"`
	Capabilities []string           `json:"capabilities,omitempty"`
}

// AIManifestAuth describes the authentication for the API.
type AIManifestAuth struct {
	Type             string            `json:"type"`
	AuthorizationURL string            `json:"authorization_url,omitempty"`
	TokenURL         string            `json:"token_url,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"`
}

// AIManifestContact holds contact information.
type AIManifestContact struct {
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// DiscoveryConfig configures the discovery endpoint.
type DiscoveryConfig struct {
	Manifest    AIManifest
	OpenAPISpec map[string]interface{}
}

// ── Agent Meta (HTML transform) ─────────────────────────────────────────

// AgentMetaConfig configures HTML response transformation.
type AgentMetaConfig struct {
	AgentIDAttribute string
	AriaLandmarks    *bool
	MetaTags         map[string]string
}

// ── API Keys ─────────────────────────────────────────────────────────────

// ApiKeyConfig configures API key authentication middleware.
type ApiKeyConfig struct {
	Store      ApiKeyStore
	HeaderName string
}

// ── Agent Auth ───────────────────────────────────────────────────────────

// AgentAuthConfig configures OAuth discovery for agents.
type AgentAuthConfig struct {
	Issuer           string
	AuthorizationURL string
	TokenURL         string
	Scopes           map[string]string
	Realm            string
}

// ── Top-level composition ────────────────────────────────────────────────

// AgentLayerConfig is the top-level configuration for the one-liner setup.
type AgentLayerConfig struct {
	Errors           *bool
	RateLimit        *RateLimitConfig
	LlmsTxt          *LlmsTxtConfig
	Discovery        *DiscoveryConfig
	AgentMeta        *AgentMetaConfig
	AgentAuth        *AgentAuthConfig
	Analytics        *AnalyticsConfig
	ApiKeys          *ApiKeyConfig
	A2A              *A2AConfig
	AgentIdentity    *AgentIdentityConfig
	AgentsTxt        *AgentsTxtMiddlewareConfig
	RobotsTxt        *RobotsTxtConfig
	SecurityHeaders  *SecurityHeadersConfig
	AgentOnboarding  *OnboardingConfig
	UnifiedDiscovery *UnifiedDiscoveryConfig
	OAuth2           *OAuth2Config
	MCP              *McpServerConfig
	X402             *X402Config
	Routes           []RouteMetadata
}

// AgentsTxtMiddlewareConfig extends AgentsTxtConfig with enforce option.
type AgentsTxtMiddlewareConfig struct {
	AgentsTxtConfig
	Enforce bool
}
