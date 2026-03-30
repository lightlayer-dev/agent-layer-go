package core

import (
	"strings"
	"testing"
)

func TestGenerateAgentsTxt_WithRules(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{
				Agent: "*",
				Allow: []string{"/api/*"},
				Deny:  []string{"/api/admin/*"},
			},
			{
				Agent:       "GPT-Bot",
				Allow:       []string{"/public/*"},
				Description: "OpenAI bot rules",
			},
		},
	}

	output := GenerateAgentsTxt(config)

	if !strings.Contains(output, "User-agent: *") {
		t.Error("expected wildcard User-agent line")
	}
	if !strings.Contains(output, "Allow: /api/*") {
		t.Error("expected Allow: /api/*")
	}
	if !strings.Contains(output, "Deny: /api/admin/*") {
		t.Error("expected Deny: /api/admin/*")
	}
	if !strings.Contains(output, "User-agent: GPT-Bot") {
		t.Error("expected User-agent: GPT-Bot")
	}
	if !strings.Contains(output, "Allow: /public/*") {
		t.Error("expected Allow: /public/*")
	}
}

func TestGenerateAgentsTxt_RateLimit(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{
				Agent:     "*",
				RateLimit: &AgentsTxtRateLimit{Max: 100, WindowSeconds: 60},
			},
		},
	}

	output := GenerateAgentsTxt(config)
	if !strings.Contains(output, "Rate-limit: 100/60s") {
		t.Errorf("expected 'Rate-limit: 100/60s' in output, got:\n%s", output)
	}
}

func TestGenerateAgentsTxt_RateLimitDefaultWindow(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{
				Agent:     "*",
				RateLimit: &AgentsTxtRateLimit{Max: 50, WindowSeconds: 0},
			},
		},
	}

	output := GenerateAgentsTxt(config)
	if !strings.Contains(output, "Rate-limit: 50/60s") {
		t.Errorf("expected default window 60s in rate limit, got:\n%s", output)
	}
}

func TestGenerateAgentsTxt_Auth(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{
				Agent: "*",
				Auth: &AgentsTxtAuth{
					Type:     "oauth2",
					Endpoint: "https://auth.example.com/token",
					DocsURL:  "https://docs.example.com/auth",
				},
			},
		},
	}

	output := GenerateAgentsTxt(config)
	if !strings.Contains(output, "Auth: oauth2 https://auth.example.com/token") {
		t.Errorf("expected Auth line, got:\n%s", output)
	}
	if !strings.Contains(output, "Auth-docs: https://docs.example.com/auth") {
		t.Errorf("expected Auth-docs line, got:\n%s", output)
	}
}

func TestGenerateAgentsTxt_HeaderMetadata(t *testing.T) {
	config := AgentsTxtConfig{
		SiteName:     "Example API",
		Contact:      "admin@example.com",
		DiscoveryURL: "https://example.com/.well-known/ai",
		Rules: []AgentsTxtRule{
			{Agent: "*", Allow: []string{"/*"}},
		},
	}

	output := GenerateAgentsTxt(config)
	if !strings.Contains(output, "# Site: Example API") {
		t.Error("expected site name header")
	}
	if !strings.Contains(output, "# Contact: admin@example.com") {
		t.Error("expected contact header")
	}
	if !strings.Contains(output, "# Discovery: https://example.com/.well-known/ai") {
		t.Error("expected discovery URL header")
	}
}

func TestParseAgentsTxt_Roundtrip(t *testing.T) {
	original := AgentsTxtConfig{
		SiteName:     "My Site",
		Contact:      "test@example.com",
		DiscoveryURL: "https://example.com/.well-known/ai",
		Rules: []AgentsTxtRule{
			{
				Agent: "*",
				Allow: []string{"/api/*"},
				Deny:  []string{"/api/admin/*"},
			},
			{
				Agent: "SpecialBot",
				Allow: []string{"/special/*"},
			},
		},
	}

	text := GenerateAgentsTxt(original)
	parsed := ParseAgentsTxt(text)

	if parsed.SiteName != original.SiteName {
		t.Errorf("expected SiteName %q, got %q", original.SiteName, parsed.SiteName)
	}
	if parsed.Contact != original.Contact {
		t.Errorf("expected Contact %q, got %q", original.Contact, parsed.Contact)
	}
	if parsed.DiscoveryURL != original.DiscoveryURL {
		t.Errorf("expected DiscoveryURL %q, got %q", original.DiscoveryURL, parsed.DiscoveryURL)
	}
	if len(parsed.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(parsed.Rules))
	}
	if parsed.Rules[0].Agent != "*" {
		t.Errorf("expected first rule agent '*', got %q", parsed.Rules[0].Agent)
	}
	if len(parsed.Rules[0].Allow) != 1 || parsed.Rules[0].Allow[0] != "/api/*" {
		t.Errorf("expected first rule Allow [/api/*], got %v", parsed.Rules[0].Allow)
	}
	if len(parsed.Rules[0].Deny) != 1 || parsed.Rules[0].Deny[0] != "/api/admin/*" {
		t.Errorf("expected first rule Deny [/api/admin/*], got %v", parsed.Rules[0].Deny)
	}
	if parsed.Rules[1].Agent != "SpecialBot" {
		t.Errorf("expected second rule agent 'SpecialBot', got %q", parsed.Rules[1].Agent)
	}
}

func TestParseAgentsTxt_RateLimit(t *testing.T) {
	text := `# agents.txt — AI Agent Access Policy

User-agent: *
Rate-limit: 200/30s
`
	parsed := ParseAgentsTxt(text)
	if len(parsed.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(parsed.Rules))
	}
	rl := parsed.Rules[0].RateLimit
	if rl == nil {
		t.Fatal("expected rate limit to be parsed")
	}
	if rl.Max != 200 {
		t.Errorf("expected Max 200, got %d", rl.Max)
	}
	if rl.WindowSeconds != 30 {
		t.Errorf("expected WindowSeconds 30, got %d", rl.WindowSeconds)
	}
}

func TestParseAgentsTxt_Auth(t *testing.T) {
	text := `# agents.txt — AI Agent Access Policy

User-agent: *
Auth: bearer https://auth.example.com/token
Auth-docs: https://docs.example.com
`
	parsed := ParseAgentsTxt(text)
	if len(parsed.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(parsed.Rules))
	}
	auth := parsed.Rules[0].Auth
	if auth == nil {
		t.Fatal("expected auth to be parsed")
	}
	if auth.Type != "bearer" {
		t.Errorf("expected auth type 'bearer', got %q", auth.Type)
	}
	if auth.Endpoint != "https://auth.example.com/token" {
		t.Errorf("expected auth endpoint, got %q", auth.Endpoint)
	}
	if auth.DocsURL != "https://docs.example.com" {
		t.Errorf("expected auth docs URL, got %q", auth.DocsURL)
	}
}

func TestParseAgentsTxt_PreferredInterface(t *testing.T) {
	text := `# agents.txt — AI Agent Access Policy

User-agent: *
Preferred-interface: mcp
`
	parsed := ParseAgentsTxt(text)
	if parsed.Rules[0].PreferredInterface != "mcp" {
		t.Errorf("expected preferred interface 'mcp', got %q", parsed.Rules[0].PreferredInterface)
	}
}

func TestParseAgentsTxt_HeaderComments(t *testing.T) {
	text := `# agents.txt — AI Agent Access Policy
# Site: Test Site
# Contact: hello@test.com
# Discovery: https://test.com/ai

User-agent: *
Allow: /
`
	parsed := ParseAgentsTxt(text)
	if parsed.SiteName != "Test Site" {
		t.Errorf("expected SiteName 'Test Site', got %q", parsed.SiteName)
	}
	if parsed.Contact != "hello@test.com" {
		t.Errorf("expected Contact 'hello@test.com', got %q", parsed.Contact)
	}
	if parsed.DiscoveryURL != "https://test.com/ai" {
		t.Errorf("expected DiscoveryURL, got %q", parsed.DiscoveryURL)
	}
}

func TestIsAgentAllowed_ExactMatch(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "MyBot", Allow: []string{"/api/*"}},
		},
	}
	result := IsAgentAllowed(config, "MyBot", "/api/v1/data")
	if result == nil || !*result {
		t.Error("expected exact match to allow /api/v1/data")
	}
}

func TestIsAgentAllowed_Wildcard(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "*", Allow: []string{"/*"}},
		},
	}
	result := IsAgentAllowed(config, "AnyBot", "/anything")
	if result == nil || !*result {
		t.Error("expected wildcard agent to allow any path")
	}
}

func TestIsAgentAllowed_PatternMatch(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "GPT*", Allow: []string{"/public/*"}},
		},
	}
	result := IsAgentAllowed(config, "GPT-4", "/public/data")
	if result == nil || !*result {
		t.Error("expected pattern match GPT* to allow GPT-4")
	}
}

func TestIsAgentAllowed_DenyTakesPrecedence(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{
				Agent: "*",
				Allow: []string{"/*"},
				Deny:  []string{"/admin/*"},
			},
		},
	}
	result := IsAgentAllowed(config, "SomeBot", "/admin/settings")
	if result == nil || *result {
		t.Error("expected deny to take precedence over allow for /admin/*")
	}

	result = IsAgentAllowed(config, "SomeBot", "/public/data")
	if result == nil || !*result {
		t.Error("expected allow for /public/data since deny doesn't match")
	}
}

func TestIsAgentAllowed_AllowRulesNoMatch(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "*", Allow: []string{"/api/*"}},
		},
	}
	result := IsAgentAllowed(config, "SomeBot", "/other/path")
	if result == nil || *result {
		t.Error("expected deny when allow rules exist but none match")
	}
}

func TestIsAgentAllowed_NoMatchingRule(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "SpecificBot", Allow: []string{"/*"}},
		},
	}
	result := IsAgentAllowed(config, "UnknownBot", "/something")
	if result != nil {
		t.Errorf("expected nil when no matching rule, got %v", *result)
	}
}

func TestIsAgentAllowed_ExactMatchPriority(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "*", Allow: []string{"/*"}},
			{Agent: "GPT*", Deny: []string{"/*"}},
			{Agent: "GPT-4", Allow: []string{"/special/*"}},
		},
	}
	// Exact match takes priority over pattern and wildcard
	result := IsAgentAllowed(config, "GPT-4", "/special/data")
	if result == nil || !*result {
		t.Error("expected exact match to take priority")
	}
}

func TestIsAgentAllowed_NoAllowDenyImplicitAllow(t *testing.T) {
	config := AgentsTxtConfig{
		Rules: []AgentsTxtRule{
			{Agent: "*"},
		},
	}
	result := IsAgentAllowed(config, "AnyBot", "/anything")
	if result == nil || !*result {
		t.Error("expected implicit allow when no allow/deny rules")
	}
}
