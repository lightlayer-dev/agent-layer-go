package core

import (
	"strings"
	"testing"
)

func TestGenerateRobotsTxt_Defaults(t *testing.T) {
	output := GenerateRobotsTxt(nil)

	if !strings.Contains(output, "User-agent: *\nAllow: /") {
		t.Fatalf("expected default wildcard allow block, got:\n%s", output)
	}
	if !strings.Contains(output, "User-agent: GPTBot") {
		t.Fatalf("expected AI agent block, got:\n%s", output)
	}
	if !strings.HasSuffix(output, "\n") {
		t.Fatal("expected trailing newline")
	}
}

func TestGenerateRobotsTxt_CustomRules(t *testing.T) {
	delay := 5
	output := GenerateRobotsTxt(&RobotsTxtConfig{
		Rules: []RobotsTxtRule{
			{
				UserAgent:  "ExampleBot",
				Allow:      []string{"/public"},
				Disallow:   []string{"/private"},
				CrawlDelay: &delay,
			},
		},
		Sitemaps: []string{"https://example.com/sitemap.xml"},
	})

	if !strings.Contains(output, "User-agent: ExampleBot") {
		t.Fatal("expected custom user-agent")
	}
	if !strings.Contains(output, "Allow: /public") || !strings.Contains(output, "Disallow: /private") {
		t.Fatal("expected allow/disallow directives")
	}
	if !strings.Contains(output, "Crawl-delay: 5") {
		t.Fatal("expected crawl-delay")
	}
	if strings.Contains(output, "User-agent: GPTBot") {
		t.Fatal("did not expect AI agent defaults when custom rules are present")
	}
	if !strings.Contains(output, "Sitemap: https://example.com/sitemap.xml") {
		t.Fatal("expected sitemap")
	}
}

func TestGenerateRobotsTxt_DisallowAIAgents(t *testing.T) {
	output := GenerateRobotsTxt(&RobotsTxtConfig{
		AIAgentPolicy: "disallow",
	})

	if !strings.Contains(output, "User-agent: ClaudeBot\nDisallow: /") {
		t.Fatalf("expected disallow AI-agent block, got:\n%s", output)
	}
}

func TestGenerateRobotsTxt_DisableAIAgents(t *testing.T) {
	include := false
	output := GenerateRobotsTxt(&RobotsTxtConfig{
		IncludeAIAgents: &include,
	})

	if strings.Contains(output, "User-agent: GPTBot") {
		t.Fatalf("did not expect AI agent blocks, got:\n%s", output)
	}
}
