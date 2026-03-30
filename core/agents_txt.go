package core

import (
	"fmt"
	"strconv"
	"strings"
)

// AgentsTxtRateLimit is a rate limit declaration.
type AgentsTxtRateLimit struct {
	Max           int
	WindowSeconds int
}

// AgentsTxtAuth is an auth requirement.
type AgentsTxtAuth struct {
	Type     string
	Endpoint string
	DocsURL  string
}

// AgentsTxtRule is a single rule block in agents.txt.
type AgentsTxtRule struct {
	Agent              string
	Allow              []string
	Deny               []string
	RateLimit          *AgentsTxtRateLimit
	PreferredInterface string
	Auth               *AgentsTxtAuth
	Description        string
}

// AgentsTxtConfig is the top-level agents.txt configuration.
type AgentsTxtConfig struct {
	Rules        []AgentsTxtRule
	SiteName     string
	Contact      string
	DiscoveryURL string
}

// GenerateAgentsTxt generates the agents.txt file content.
func GenerateAgentsTxt(config AgentsTxtConfig) string {
	var lines []string

	lines = append(lines, "# agents.txt — AI Agent Access Policy")

	if config.SiteName != "" {
		lines = append(lines, fmt.Sprintf("# Site: %s", config.SiteName))
	}
	if config.Contact != "" {
		lines = append(lines, fmt.Sprintf("# Contact: %s", config.Contact))
	}
	if config.DiscoveryURL != "" {
		lines = append(lines, fmt.Sprintf("# Discovery: %s", config.DiscoveryURL))
	}

	for _, rule := range config.Rules {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("User-agent: %s", rule.Agent))

		if rule.Description != "" {
			lines = append(lines, fmt.Sprintf("# %s", rule.Description))
		}

		for _, path := range rule.Allow {
			lines = append(lines, fmt.Sprintf("Allow: %s", path))
		}
		for _, path := range rule.Deny {
			lines = append(lines, fmt.Sprintf("Deny: %s", path))
		}

		if rule.RateLimit != nil {
			window := rule.RateLimit.WindowSeconds
			if window == 0 {
				window = 60
			}
			lines = append(lines, fmt.Sprintf("Rate-limit: %d/%ds", rule.RateLimit.Max, window))
		}

		if rule.PreferredInterface != "" {
			lines = append(lines, fmt.Sprintf("Preferred-interface: %s", rule.PreferredInterface))
		}

		if rule.Auth != nil {
			authParts := []string{rule.Auth.Type}
			if rule.Auth.Endpoint != "" {
				authParts = append(authParts, rule.Auth.Endpoint)
			}
			lines = append(lines, fmt.Sprintf("Auth: %s", strings.Join(authParts, " ")))
			if rule.Auth.DocsURL != "" {
				lines = append(lines, fmt.Sprintf("Auth-docs: %s", rule.Auth.DocsURL))
			}
		}
	}

	return strings.Join(lines, "\n") + "\n"
}

// ParseAgentsTxt parses an agents.txt string back into structured rules.
func ParseAgentsTxt(content string) AgentsTxtConfig {
	lines := strings.Split(content, "\n")
	config := AgentsTxtConfig{}
	var currentRule *AgentsTxtRule

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)

		if strings.HasPrefix(line, "# Site:") {
			config.SiteName = strings.TrimSpace(line[len("# Site:"):])
			continue
		}
		if strings.HasPrefix(line, "# Contact:") {
			config.Contact = strings.TrimSpace(line[len("# Contact:"):])
			continue
		}
		if strings.HasPrefix(line, "# Discovery:") {
			config.DiscoveryURL = strings.TrimSpace(line[len("# Discovery:"):])
			continue
		}

		if line == "" || (strings.HasPrefix(line, "#") && currentRule == nil) {
			continue
		}
		if strings.HasPrefix(line, "#") && currentRule != nil {
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		directive := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])

		if directive == "user-agent" {
			rule := AgentsTxtRule{Agent: value}
			config.Rules = append(config.Rules, rule)
			currentRule = &config.Rules[len(config.Rules)-1]
			continue
		}

		if currentRule == nil {
			continue
		}

		switch directive {
		case "allow":
			currentRule.Allow = append(currentRule.Allow, value)
		case "deny":
			currentRule.Deny = append(currentRule.Deny, value)
		case "rate-limit":
			// Parse "100/60s"
			parts := strings.Split(value, "/")
			if len(parts) == 2 {
				max, err1 := strconv.Atoi(parts[0])
				windowStr := strings.TrimSuffix(parts[1], "s")
				window, err2 := strconv.Atoi(windowStr)
				if err1 == nil && err2 == nil {
					currentRule.RateLimit = &AgentsTxtRateLimit{Max: max, WindowSeconds: window}
				}
			}
		case "preferred-interface":
			if value == "rest" || value == "mcp" || value == "graphql" || value == "a2a" {
				currentRule.PreferredInterface = value
			}
		case "auth":
			parts := strings.Fields(value)
			auth := &AgentsTxtAuth{Type: parts[0]}
			if len(parts) > 1 {
				auth.Endpoint = parts[1]
			}
			currentRule.Auth = auth
		case "auth-docs":
			if currentRule.Auth != nil {
				currentRule.Auth.DocsURL = value
			}
		}
	}

	return config
}

// IsAgentAllowed checks whether a given agent + path combination is allowed.
func IsAgentAllowed(config AgentsTxtConfig, agentName, path string) *bool {
	matchingRule := findMatchingRule(config.Rules, agentName)
	if matchingRule == nil {
		return nil
	}

	// Check deny first
	if matchingRule.Deny != nil {
		for _, pattern := range matchingRule.Deny {
			if pathMatches(path, pattern) {
				result := false
				return &result
			}
		}
	}

	// Check allow
	if matchingRule.Allow != nil {
		for _, pattern := range matchingRule.Allow {
			if pathMatches(path, pattern) {
				result := true
				return &result
			}
		}
		// Allow rules exist but none matched
		result := false
		return &result
	}

	// No allow/deny rules — implicitly allowed
	result := true
	return &result
}

func findMatchingRule(rules []AgentsTxtRule, agentName string) *AgentsTxtRule {
	var wildcardRule, patternRule, exactRule *AgentsTxtRule

	for i := range rules {
		rule := &rules[i]
		if rule.Agent == "*" {
			wildcardRule = rule
		} else if strings.HasSuffix(rule.Agent, "*") {
			prefix := rule.Agent[:len(rule.Agent)-1]
			if strings.HasPrefix(agentName, prefix) {
				patternRule = rule
			}
		} else if rule.Agent == agentName {
			exactRule = rule
		}
	}

	if exactRule != nil {
		return exactRule
	}
	if patternRule != nil {
		return patternRule
	}
	return wildcardRule
}

func pathMatches(path, pattern string) bool {
	if pattern == "*" || pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}
