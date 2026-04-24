package core

import (
	"strconv"
	"strings"
)

// AIAgents are the well-known AI crawlers explicitly listed in generated robots.txt files.
var AIAgents = []string{
	"GPTBot",
	"ChatGPT-User",
	"Google-Extended",
	"Anthropic",
	"ClaudeBot",
	"CCBot",
	"Amazonbot",
	"Bytespider",
	"Applebot-Extended",
	"PerplexityBot",
	"Cohere-ai",
}

// RobotsTxtRule is a single robots.txt user-agent block.
type RobotsTxtRule struct {
	UserAgent  string
	Allow      []string
	Disallow   []string
	CrawlDelay *int
}

// RobotsTxtConfig configures robots.txt generation.
type RobotsTxtConfig struct {
	Rules           []RobotsTxtRule
	Sitemaps        []string
	IncludeAIAgents *bool
	AIAgentPolicy   string
	AIAllow         []string
	AIDisallow      []string
}

// GenerateRobotsTxt generates a robots.txt document with explicit AI-agent rules.
func GenerateRobotsTxt(config *RobotsTxtConfig) string {
	cfg := RobotsTxtConfig{}
	if config != nil {
		cfg = *config
	}

	includeAIAgents := true
	if cfg.IncludeAIAgents != nil {
		includeAIAgents = *cfg.IncludeAIAgents
	}

	aiPolicy := cfg.AIAgentPolicy
	if aiPolicy == "" {
		aiPolicy = "allow"
	}

	aiAllow := cfg.AIAllow
	if len(aiAllow) == 0 {
		aiAllow = []string{"/"}
	}

	var lines []string

	if len(cfg.Rules) > 0 {
		for _, rule := range cfg.Rules {
			lines = append(lines, "User-agent: "+rule.UserAgent)
			for _, path := range rule.Allow {
				lines = append(lines, "Allow: "+path)
			}
			for _, path := range rule.Disallow {
				lines = append(lines, "Disallow: "+path)
			}
			if rule.CrawlDelay != nil {
				lines = append(lines, "Crawl-delay: "+strconv.Itoa(*rule.CrawlDelay))
			}
			lines = append(lines, "")
		}
	} else {
		lines = append(lines, "User-agent: *", "Allow: /", "")
	}

	if includeAIAgents && len(cfg.Rules) == 0 {
		for _, agent := range AIAgents {
			lines = append(lines, "User-agent: "+agent)
			if strings.EqualFold(aiPolicy, "disallow") {
				lines = append(lines, "Disallow: /")
			} else {
				for _, path := range aiAllow {
					lines = append(lines, "Allow: "+path)
				}
				for _, path := range cfg.AIDisallow {
					lines = append(lines, "Disallow: "+path)
				}
			}
			lines = append(lines, "")
		}
	}

	for _, sitemap := range cfg.Sitemaps {
		lines = append(lines, "Sitemap: "+sitemap)
	}

	return strings.Join(lines, "\n") + "\n"
}
