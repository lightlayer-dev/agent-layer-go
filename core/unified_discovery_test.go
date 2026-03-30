package core

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool {
	return &b
}

func TestIsFormatEnabled_NilFormats(t *testing.T) {
	// All formats should be enabled when formats is nil
	for _, format := range []string{"wellKnownAi", "agentCard", "agentsTxt", "llmsTxt"} {
		if !IsFormatEnabled(nil, format) {
			t.Errorf("expected %s to be enabled when formats is nil", format)
		}
	}
}

func TestIsFormatEnabled_UnknownFormat(t *testing.T) {
	if !IsFormatEnabled(nil, "unknown") {
		t.Error("expected unknown format to default to true")
	}
	formats := &DiscoveryFormats{}
	if !IsFormatEnabled(formats, "something") {
		t.Error("expected unknown format to default to true with non-nil formats")
	}
}

func TestIsFormatEnabled_ExplicitlyDisabled(t *testing.T) {
	formats := &DiscoveryFormats{
		WellKnownAi: boolPtr(false),
		AgentCard:    boolPtr(false),
		AgentsTxt:    boolPtr(false),
		LlmsTxt:     boolPtr(false),
	}

	if IsFormatEnabled(formats, "wellKnownAi") {
		t.Error("expected wellKnownAi to be disabled")
	}
	if IsFormatEnabled(formats, "agentCard") {
		t.Error("expected agentCard to be disabled")
	}
	if IsFormatEnabled(formats, "agentsTxt") {
		t.Error("expected agentsTxt to be disabled")
	}
	if IsFormatEnabled(formats, "llmsTxt") {
		t.Error("expected llmsTxt to be disabled")
	}
}

func TestIsFormatEnabled_ExplicitlyEnabled(t *testing.T) {
	formats := &DiscoveryFormats{
		WellKnownAi: boolPtr(true),
		AgentCard:    boolPtr(true),
	}

	if !IsFormatEnabled(formats, "wellKnownAi") {
		t.Error("expected wellKnownAi to be enabled")
	}
	if !IsFormatEnabled(formats, "agentCard") {
		t.Error("expected agentCard to be enabled")
	}
}

func TestIsFormatEnabled_NilFieldDefaultsTrue(t *testing.T) {
	formats := &DiscoveryFormats{
		WellKnownAi: boolPtr(false),
		// AgentCard is nil
	}

	if IsFormatEnabled(formats, "wellKnownAi") {
		t.Error("expected wellKnownAi to be disabled")
	}
	if !IsFormatEnabled(formats, "agentCard") {
		t.Error("expected agentCard to default to true when nil")
	}
}

func TestGenerateUnifiedAIManifest_Basic(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:        "Test Agent",
		Description: "A test agent",
		URL:         "https://agent.example.com",
	}

	manifest := GenerateUnifiedAIManifest(config)
	if manifest.Name != "Test Agent" {
		t.Errorf("expected name 'Test Agent', got %s", manifest.Name)
	}
	if manifest.Description != "A test agent" {
		t.Errorf("expected description, got %s", manifest.Description)
	}
	// llmsTxt should be enabled by default
	if manifest.LlmsTxtURL != "https://agent.example.com/llms.txt" {
		t.Errorf("expected llms.txt URL, got %s", manifest.LlmsTxtURL)
	}
}

func TestGenerateUnifiedAIManifest_LlmsTxtDisabled(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Test Agent",
		URL:  "https://agent.example.com",
		Formats: &DiscoveryFormats{
			LlmsTxt: boolPtr(false),
		},
	}

	manifest := GenerateUnifiedAIManifest(config)
	if manifest.LlmsTxtURL != "" {
		t.Errorf("expected empty llms.txt URL when disabled, got %s", manifest.LlmsTxtURL)
	}
}

func TestGenerateUnifiedAIManifest_WithAuth(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Auth Agent",
		URL:  "https://agent.example.com",
		Auth: &UnifiedAuthConfig{
			Type:             "bearer",
			AuthorizationURL: "https://auth.example.com/authorize",
			TokenURL:         "https://auth.example.com/token",
		},
	}

	manifest := GenerateUnifiedAIManifest(config)
	if manifest.Auth == nil {
		t.Fatal("expected auth to be set")
	}
	// "bearer" should be converted to "api_key"
	if manifest.Auth.Type != "api_key" {
		t.Errorf("expected auth type api_key (converted from bearer), got %s", manifest.Auth.Type)
	}
}

func TestGenerateUnifiedAgentCard_Basic(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:        "Test Agent",
		Description: "A test agent",
		URL:         "https://agent.example.com",
		Version:     "1.0.0",
	}

	card := GenerateUnifiedAgentCard(config)
	if card.Name != "Test Agent" {
		t.Errorf("expected name, got %s", card.Name)
	}
	if card.URL != "https://agent.example.com" {
		t.Errorf("expected URL, got %s", card.URL)
	}
	if card.ProtocolVersion != "1.0.0" {
		t.Errorf("expected protocol version 1.0.0, got %s", card.ProtocolVersion)
	}
}

func TestGenerateUnifiedAgentCard_WithSkills(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Skilled Agent",
		URL:  "https://agent.example.com",
		Skills: []UnifiedSkill{
			{
				ID:          "search",
				Name:        "Web Search",
				Description: "Search the web",
				Tags:        []string{"search", "web"},
				Examples:    []string{"Search for Go tutorials"},
				InputModes:  []string{"text/plain"},
				OutputModes: []string{"text/plain"},
			},
			{
				ID:   "summarize",
				Name: "Summarize",
			},
		},
	}

	card := GenerateUnifiedAgentCard(config)
	if len(card.Skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(card.Skills))
	}
	if card.Skills[0].ID != "search" {
		t.Errorf("expected skill ID 'search', got %s", card.Skills[0].ID)
	}
	if card.Skills[0].Name != "Web Search" {
		t.Errorf("expected skill name 'Web Search', got %s", card.Skills[0].Name)
	}
	if len(card.Skills[0].Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(card.Skills[0].Tags))
	}
}

func TestGenerateUnifiedAgentCard_WithAuth(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Auth Agent",
		URL:  "https://agent.example.com",
		Auth: &UnifiedAuthConfig{
			Type: "api_key",
			In:   "header",
			Name: "X-API-Key",
		},
	}

	card := GenerateUnifiedAgentCard(config)
	if card.Authentication == nil {
		t.Fatal("expected authentication")
	}
	// "api_key" should be converted to "apiKey"
	if card.Authentication.Type != "apiKey" {
		t.Errorf("expected type apiKey (converted from api_key), got %s", card.Authentication.Type)
	}
	if card.Authentication.In != "header" {
		t.Errorf("expected in=header, got %s", card.Authentication.In)
	}
}

func TestGenerateUnifiedAgentCard_DocURLFallback(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:       "Agent",
		URL:        "https://agent.example.com",
		OpenApiURL: "https://agent.example.com/openapi.json",
	}

	card := GenerateUnifiedAgentCard(config)
	if card.DocumentationURL != "https://agent.example.com/openapi.json" {
		t.Errorf("expected documentation URL to fall back to OpenAPI URL, got %s", card.DocumentationURL)
	}
}

func TestGenerateUnifiedLlmsTxt_Basic(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:        "Test Agent",
		Description: "A helpful agent",
	}

	txt := GenerateUnifiedLlmsTxt(config)
	if !strings.Contains(txt, "# Test Agent") {
		t.Error("expected title in llms.txt")
	}
	if !strings.Contains(txt, "A helpful agent") {
		t.Error("expected description in llms.txt")
	}
}

func TestGenerateUnifiedLlmsTxt_WithSkills(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Skilled Agent",
		Skills: []UnifiedSkill{
			{
				ID:          "search",
				Name:        "Web Search",
				Description: "Search the web for information",
				Examples:    []string{"Find Go tutorials", "Search for API docs"},
			},
		},
	}

	txt := GenerateUnifiedLlmsTxt(config)
	if !strings.Contains(txt, "## Web Search") {
		t.Error("expected skill name as section header")
	}
	if !strings.Contains(txt, "Search the web for information") {
		t.Error("expected skill description")
	}
	if !strings.Contains(txt, "- Find Go tutorials") {
		t.Error("expected example")
	}
	if !strings.Contains(txt, "- Search for API docs") {
		t.Error("expected second example")
	}
}

func TestGenerateUnifiedLlmsTxt_WithExtraSections(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Agent",
		LlmsTxtSections: []LlmsTxtSection{
			{Title: "Authentication", Content: "Use Bearer tokens"},
		},
	}

	txt := GenerateUnifiedLlmsTxt(config)
	if !strings.Contains(txt, "## Authentication") {
		t.Error("expected extra section")
	}
	if !strings.Contains(txt, "Use Bearer tokens") {
		t.Error("expected extra section content")
	}
}

func TestGenerateUnifiedLlmsFullTxt_WithRoutes(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:        "API Agent",
		Description: "An API agent",
		Routes: []RouteMetadata{
			{
				Method:  "GET",
				Path:    "/api/users",
				Summary: "List users",
				Parameters: []RouteParameter{
					{Name: "limit", In: "query", Required: false, Description: "Max results"},
				},
			},
			{
				Method:      "POST",
				Path:        "/api/users",
				Summary:     "Create user",
				Description: "Creates a new user account",
			},
		},
	}

	txt := GenerateUnifiedLlmsFullTxt(config)
	if !strings.Contains(txt, "## API Endpoints") {
		t.Error("expected API Endpoints section")
	}
	if !strings.Contains(txt, "### GET /api/users") {
		t.Error("expected GET route")
	}
	if !strings.Contains(txt, "### POST /api/users") {
		t.Error("expected POST route")
	}
	if !strings.Contains(txt, "List users") {
		t.Error("expected route summary")
	}
	if !strings.Contains(txt, "`limit`") {
		t.Error("expected parameter name")
	}
	if !strings.Contains(txt, "Max results") {
		t.Error("expected parameter description")
	}
}

func TestGenerateUnifiedLlmsFullTxt_NoRoutes(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Agent",
	}

	txt := GenerateUnifiedLlmsFullTxt(config)
	if !strings.Contains(txt, "# Agent") {
		t.Error("expected title")
	}
	// Should not have API Endpoints section with no routes
	if strings.Contains(txt, "## API Endpoints") {
		t.Error("should not have API Endpoints section with no routes")
	}
}

func TestGenerateUnifiedAgentsTxt_Default(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "My Agent",
	}

	txt := GenerateUnifiedAgentsTxt(config)
	if !strings.Contains(txt, "My Agent") {
		t.Error("expected agent name")
	}
	if !strings.Contains(txt, "User-agent: *") {
		t.Error("expected wildcard user-agent")
	}
	if !strings.Contains(txt, "Allow: /") {
		t.Error("expected allow all")
	}
}

func TestGenerateUnifiedAgentsTxt_WithBlocks(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "My Agent",
		AgentsTxt: &UnifiedAgentsTxtConfig{
			Comment: "Custom rules",
			Blocks: []UnifiedAgentsTxtBlock{
				{
					UserAgent: "*",
					Rules: []UnifiedAgentsTxtRule{
						{Path: "/", Permission: "allow"},
						{Path: "/private", Permission: "disallow"},
					},
				},
				{
					UserAgent: "GPTBot",
					Rules: []UnifiedAgentsTxtRule{
						{Path: "/api", Permission: "allow"},
					},
				},
			},
			SitemapURL: "https://example.com/sitemap.xml",
		},
	}

	txt := GenerateUnifiedAgentsTxt(config)
	if !strings.Contains(txt, "# Custom rules") {
		t.Error("expected comment")
	}
	if !strings.Contains(txt, "User-agent: *") {
		t.Error("expected wildcard user-agent")
	}
	if !strings.Contains(txt, "Allow: /") {
		t.Error("expected allow rule")
	}
	if !strings.Contains(txt, "Disallow: /private") {
		t.Error("expected disallow rule")
	}
	if !strings.Contains(txt, "User-agent: GPTBot") {
		t.Error("expected GPTBot user-agent")
	}
	if !strings.Contains(txt, "Sitemap: https://example.com/sitemap.xml") {
		t.Error("expected sitemap")
	}
}

func TestGenerateUnifiedAgentsTxt_EmptyBlocks(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:      "Agent",
		AgentsTxt: &UnifiedAgentsTxtConfig{},
	}

	txt := GenerateUnifiedAgentsTxt(config)
	// Should produce output (possibly empty/minimal) without panic
	if txt == "" {
		// AgentsTxt is non-nil, so it won't use the default
		// Empty is acceptable when no blocks
	}
	_ = txt
}

func TestGenerateAllDiscovery_AllFormats(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name:        "Full Agent",
		Description: "A full agent",
		URL:         "https://agent.example.com",
	}

	result := GenerateAllDiscovery(config)

	if _, ok := result["/.well-known/ai"]; !ok {
		t.Error("expected /.well-known/ai")
	}
	if _, ok := result["/.well-known/agent.json"]; !ok {
		t.Error("expected /.well-known/agent.json")
	}
	if _, ok := result["/llms.txt"]; !ok {
		t.Error("expected /llms.txt")
	}
	if _, ok := result["/llms-full.txt"]; !ok {
		t.Error("expected /llms-full.txt")
	}
	if _, ok := result["/agents.txt"]; !ok {
		t.Error("expected /agents.txt")
	}
}

func TestGenerateAllDiscovery_SomeDisabled(t *testing.T) {
	config := UnifiedDiscoveryConfig{
		Name: "Partial Agent",
		URL:  "https://agent.example.com",
		Formats: &DiscoveryFormats{
			WellKnownAi: boolPtr(false),
			LlmsTxt:     boolPtr(false),
		},
	}

	result := GenerateAllDiscovery(config)

	if _, ok := result["/.well-known/ai"]; ok {
		t.Error("expected /.well-known/ai to be absent when disabled")
	}
	if _, ok := result["/llms.txt"]; ok {
		t.Error("expected /llms.txt to be absent when disabled")
	}
	if _, ok := result["/llms-full.txt"]; ok {
		t.Error("expected /llms-full.txt to be absent when disabled")
	}

	// These should still be present
	if _, ok := result["/.well-known/agent.json"]; !ok {
		t.Error("expected /.well-known/agent.json to be present")
	}
	if _, ok := result["/agents.txt"]; !ok {
		t.Error("expected /agents.txt to be present")
	}
}
