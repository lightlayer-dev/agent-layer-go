# agent-layer-go

[![Go Reference](https://pkg.go.dev/badge/github.com/lightlayer-dev/agent-layer-go.svg)](https://pkg.go.dev/github.com/lightlayer-dev/agent-layer-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/lightlayer-dev/agent-layer-go)](https://goreportcard.com/report/github.com/lightlayer-dev/agent-layer-go)
[![CI](https://github.com/lightlayer-dev/agent-layer-go/actions/workflows/ci.yml/badge.svg)](https://github.com/lightlayer-dev/agent-layer-go/actions/workflows/ci.yml)

Go middleware to make web APIs AI-agent-friendly — **Gin**, **Echo**, **Chi**.

> Part of the [LightLayer](https://github.com/lightlayer-dev) ecosystem. Full feature parity with [agent-layer-ts](https://github.com/lightlayer-dev/agent-layer-ts) and [agent-layer-py](https://github.com/lightlayer-dev/agent-layer-py).

## Features

All 15 features from the TypeScript reference implementation, ported idiomatically to Go:

| Feature | Description | Endpoint |
|---------|-------------|----------|
| **MCP Server** | JSON-RPC 2.0 tool definitions, streamable HTTP | `POST /mcp` |
| **A2A Agent Card** | Google A2A protocol discovery | `GET /.well-known/agent.json` |
| **agents.txt** | Robots.txt-style permissions for AI agents | `GET /agents.txt` |
| **llms.txt** | LLM-oriented documentation | `GET /llms.txt`, `/llms-full.txt` |
| **Discovery** | AI manifest + JSON-LD | `GET /.well-known/ai` |
| **Rate Limiting** | In-memory sliding window, pluggable store | Middleware |
| **Analytics** | Agent detection, event buffering, remote flush | Middleware |
| **API Keys** | Scoped key generation, validation, `al_` prefix | Middleware |
| **x402 Payments** | HTTP-native micropayments via facilitator | Middleware |
| **Agent Identity** | SPIFFE/JWT claims, authz policies (IETF draft) | Middleware |
| **Unified Discovery** | Single config → all discovery formats | Multiple |
| **AG-UI Streaming** | Server-Sent Events for agent UIs | Handler |
| **OAuth2** | PKCE, token exchange, RFC 8414 metadata | Handler |
| **Error Handling** | Structured error envelopes | Middleware |
| **Agent Meta** | HTML transforms (meta tags, ARIA, data attrs) | Middleware |

## Installation

```bash
go get github.com/lightlayer-dev/agent-layer-go
```

## Quick Start

### One-liner Setup

The fastest way — a single function call registers all middleware and routes:

#### Gin

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/lightlayer-dev/agent-layer-go/core"
    agentgin "github.com/lightlayer-dev/agent-layer-go/gin"
)

func main() {
    r := gin.Default()

    agentgin.AgentLayer(core.AgentLayerConfig{
        LlmsTxt: &core.LlmsTxtConfig{
            Title:       "My API",
            Description: "A powerful API for agents",
        },
        Discovery: &core.DiscoveryConfig{
            Manifest: core.AIManifest{
                Name:        "My API",
                Description: "AI-friendly API",
            },
        },
        A2A: &core.A2AConfig{
            Card: core.A2AAgentCard{
                Name: "My Agent",
                URL:  "https://api.example.com",
                Skills: []core.A2ASkill{
                    {ID: "search", Name: "Search", Description: "Search the web"},
                },
            },
        },
        RateLimit: &core.RateLimitConfig{Max: 100},
    }, r)

    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, agent!"})
    })

    r.Run(":8080")
}
```

#### Echo

```go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/lightlayer-dev/agent-layer-go/core"
    agentecho "github.com/lightlayer-dev/agent-layer-go/echo"
)

func main() {
    e := echo.New()

    agentecho.AgentLayer(core.AgentLayerConfig{
        LlmsTxt: &core.LlmsTxtConfig{
            Title:       "My API",
            Description: "A powerful API for agents",
        },
        RateLimit: &core.RateLimitConfig{Max: 100},
    }, e)

    e.GET("/api/hello", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"message": "Hello, agent!"})
    })

    e.Start(":8080")
}
```

#### Chi

```go
package main

import (
    "encoding/json"
    "net/http"

    "github.com/lightlayer-dev/agent-layer-go/core"
    agentchi "github.com/lightlayer-dev/agent-layer-go/chi"
)

func main() {
    r := agentchi.AgentLayer(core.AgentLayerConfig{
        LlmsTxt: &core.LlmsTxtConfig{
            Title:       "My API",
            Description: "A powerful API for agents",
        },
        RateLimit: &core.RateLimitConfig{Max: 100},
    })

    r.Get("/api/hello", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Hello, agent!"})
    })

    http.ListenAndServe(":8080", r)
}
```

### Individual Features

Use features individually for fine-grained control:

#### Rate Limiting (Gin)

```go
r := gin.Default()
r.Use(agentgin.RateLimits(core.RateLimitConfig{
    Max:      100,
    WindowMs: 60000,
    KeyFn:    func(req interface{}) string { return "global" },
}))
```

#### API Key Authentication (Echo)

```go
store := core.NewMemoryApiKeyStore()
result := core.CreateApiKey(store, core.CreateApiKeyOptions{
    CompanyID: "acme",
    UserID:    "user-1",
    Scopes:    []string{"read", "write"},
})

e.Use(agentecho.ApiKeyAuth(core.ApiKeyConfig{
    Store: store,
}))
// Protect routes with scope checking
e.Use(agentecho.RequireScope("read"))
```

#### MCP Server (Chi)

```go
r := chi.NewRouter()
r.Post("/mcp", agentchi.McpHandler(core.McpServerConfig{
    Name:    "My API Tools",
    Version: "1.0.0",
    Routes: []core.RouteMetadata{
        {Method: "GET", Path: "/api/users", Summary: "List users"},
        {Method: "POST", Path: "/api/users", Summary: "Create user"},
    },
}))
```

#### AG-UI Streaming (Gin)

```go
r.POST("/agent/stream", agentgin.AgUiStreamHandler(func(emitter *core.AgUiEmitter) error {
    emitter.RunStarted("")
    emitter.TextStart("assistant", "")
    emitter.TextDelta("Hello from the agent!")
    emitter.TextEnd("")
    emitter.RunFinished(nil)
    return nil
}))
```

#### Unified Discovery (Echo)

```go
agentecho.UnifiedDiscoveryRoutes(core.UnifiedDiscoveryConfig{
    Name:        "My Service",
    Description: "An AI-friendly service",
    URL:         "https://api.example.com",
    Skills: []core.UnifiedSkill{
        {ID: "search", Name: "Search", Description: "Full-text search"},
    },
}, e)
// Serves: /.well-known/ai, /.well-known/agent.json, /agents.txt, /llms.txt, /llms-full.txt
```

#### x402 Payments (Chi)

```go
r.Use(agentchi.X402Middleware(core.X402Config{
    Routes: map[string]core.X402RouteConfig{
        "GET /api/premium": {
            PayTo:   "0x1234...",
            Price:   "$0.01",
            Network: "eip155:8453",
        },
    },
    FacilitatorURL: "https://facilitator.example.com",
}))
```

#### Agent Identity / SPIFFE (Gin)

```go
r.Use(agentgin.AgentIdentity(core.AgentIdentityConfig{
    TrustedIssuers: []string{"https://auth.example.com"},
    Audience:       []string{"https://api.example.com"},
    Policies: []core.AgentAuthzPolicy{
        {
            Name:           "read-only",
            Methods:        []string{"GET"},
            Paths:          []string{"/api/*"},
            RequiredScopes: []string{"read"},
        },
    },
}))
```

#### Analytics (Echo)

```go
e.Use(agentecho.AgentAnalytics(core.AnalyticsConfig{
    Endpoint: "https://dash.lightlayer.dev/api/agent-events/",
    ApiKey:   "your-api-key",
    OnEvent: func(event core.AgentEvent) {
        log.Printf("Agent %s hit %s %s", event.Agent, event.Method, event.Path)
    },
}))
```

## Architecture

```
github.com/lightlayer-dev/agent-layer-go/
├── core/                    # Framework-agnostic core logic
│   ├── types.go             # Shared types and configs
│   ├── mcp.go               # MCP JSON-RPC server
│   ├── a2a.go               # A2A Agent Card
│   ├── agents_txt.go        # agents.txt generation + parsing
│   ├── llms_txt.go          # llms.txt / llms-full.txt
│   ├── discovery.go         # /.well-known/ai + JSON-LD
│   ├── rate_limit.go        # Sliding window rate limiter
│   ├── analytics.go         # Agent detection + event buffer
│   ├── api_keys.go          # Scoped API key management
│   ├── x402.go              # x402 payment protocol
│   ├── agent_identity.go    # SPIFFE/JWT identity + authz
│   ├── unified_discovery.go # Multi-format discovery
│   ├── ag_ui.go             # AG-UI SSE streaming
│   ├── oauth2.go            # OAuth2 PKCE + metadata
│   ├── errors.go            # Structured error envelopes
│   ├── agent_meta.go        # HTML transforms
│   └── *_test.go            # Comprehensive tests
├── gin/                     # Gin adapter
│   ├── middleware.go
│   └── middleware_test.go
├── echo/                    # Echo adapter
│   ├── middleware.go
│   └── middleware_test.go
├── chi/                     # Chi adapter
│   ├── middleware.go
│   └── middleware_test.go
├── go.mod
└── README.md
```

## Context Helpers

Each adapter stores data in the request context for downstream handlers:

| Key | Type | Set by |
|-----|------|--------|
| `agentKey` | `*core.ScopedApiKey` | `ApiKeyAuth` middleware |
| `agentIdentity` | `*core.AgentIdentityClaims` | `AgentIdentity` middleware |
| `x402` / `x402Payment` | `*core.PaymentPayload` | `X402Middleware` |

Chi provides typed helpers: `GetAgentKey(r)`, `GetAgentIdentity(r)`, `GetX402Payment(r)`.

## Pluggable Stores

Rate limiting and API key management use pluggable store interfaces:

```go
// Implement for Redis, DynamoDB, etc.
type RateLimitStore interface {
    Increment(key string, windowMs int64) (int64, error)
    Get(key string) (int64, error)
    Reset(key string) error
}

type ApiKeyStore interface {
    Resolve(rawKey string) (*ScopedApiKey, error)
}
```

Built-in `MemoryRateLimitStore` and `MemoryApiKeyStore` are provided for development.

## Running Tests

```bash
go test ./...
```

## License

MIT
