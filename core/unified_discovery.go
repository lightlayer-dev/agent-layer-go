package core

import (
	"fmt"
	"strings"
)

// UnifiedAgentsTxtRule is a rule in agents.txt (allow/disallow per user-agent).
type UnifiedAgentsTxtRule struct {
	Path       string `json:"path"`
	Permission string `json:"permission"` // "allow" or "disallow"
}

// UnifiedAgentsTxtBlock targets one or more user-agents.
type UnifiedAgentsTxtBlock struct {
	UserAgent string                 `json:"userAgent"`
	Rules     []UnifiedAgentsTxtRule `json:"rules"`
}

// UnifiedAgentsTxtConfig for agents.txt generation.
type UnifiedAgentsTxtConfig struct {
	Blocks     []UnifiedAgentsTxtBlock `json:"blocks"`
	SitemapURL string                  `json:"sitemapUrl,omitempty"`
	Comment    string                  `json:"comment,omitempty"`
}

// DiscoveryFormats controls which discovery formats are generated.
type DiscoveryFormats struct {
	WellKnownAi *bool `json:"wellKnownAi,omitempty"`
	AgentCard    *bool `json:"agentCard,omitempty"`
	AgentsTxt    *bool `json:"agentsTxt,omitempty"`
	LlmsTxt      *bool `json:"llmsTxt,omitempty"`
}

// UnifiedAuthConfig is shared auth configuration.
type UnifiedAuthConfig struct {
	Type             string            `json:"type"`
	In               string            `json:"in,omitempty"`
	Name             string            `json:"name,omitempty"`
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"`
}

// UnifiedSkill is a skill/capability.
type UnifiedSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// UnifiedDiscoveryConfig is the single source of truth for all discovery formats.
type UnifiedDiscoveryConfig struct {
	Name              string                  `json:"name"`
	Description       string                  `json:"description,omitempty"`
	URL               string                  `json:"url"`
	Version           string                  `json:"version,omitempty"`
	Provider          *A2AProvider            `json:"provider,omitempty"`
	Contact           *AIManifestContact      `json:"contact,omitempty"`
	OpenApiURL        string                  `json:"openApiUrl,omitempty"`
	DocumentationURL  string                  `json:"documentationUrl,omitempty"`
	Capabilities      []string                `json:"capabilities,omitempty"`
	AgentCapabilities *A2ACapabilities        `json:"agentCapabilities,omitempty"`
	Auth              *UnifiedAuthConfig      `json:"auth,omitempty"`
	Skills            []UnifiedSkill          `json:"skills,omitempty"`
	Routes            []RouteMetadata         `json:"routes,omitempty"`
	AgentsTxt         *UnifiedAgentsTxtConfig `json:"agentsTxt,omitempty"`
	Formats           *DiscoveryFormats       `json:"formats,omitempty"`
	LlmsTxtSections   []LlmsTxtSection       `json:"llmsTxtSections,omitempty"`
}

// IsFormatEnabled checks if a given format is enabled (defaults to true).
func IsFormatEnabled(formats *DiscoveryFormats, format string) bool {
	if formats == nil {
		return true
	}
	switch format {
	case "wellKnownAi":
		return formats.WellKnownAi == nil || *formats.WellKnownAi
	case "agentCard":
		return formats.AgentCard == nil || *formats.AgentCard
	case "agentsTxt":
		return formats.AgentsTxt == nil || *formats.AgentsTxt
	case "llmsTxt":
		return formats.LlmsTxt == nil || *formats.LlmsTxt
	default:
		return true
	}
}

// GenerateUnifiedAIManifest generates /.well-known/ai manifest from unified config.
func GenerateUnifiedAIManifest(config UnifiedDiscoveryConfig) AIManifest {
	var auth *AIManifestAuth
	if config.Auth != nil {
		authType := config.Auth.Type
		if authType == "bearer" {
			authType = "api_key"
		}
		auth = &AIManifestAuth{
			Type:             authType,
			AuthorizationURL: config.Auth.AuthorizationURL,
			TokenURL:         config.Auth.TokenURL,
			Scopes:           config.Auth.Scopes,
		}
	}

	var llmsTxtURL string
	if IsFormatEnabled(config.Formats, "llmsTxt") {
		llmsTxtURL = config.URL + "/llms.txt"
	}

	discoveryConfig := DiscoveryConfig{
		Manifest: AIManifest{
			Name:         config.Name,
			Description:  config.Description,
			OpenAPIURL:   config.OpenApiURL,
			LlmsTxtURL:  llmsTxtURL,
			Auth:         auth,
			Contact:      config.Contact,
			Capabilities: config.Capabilities,
		},
	}

	return GenerateAIManifest(discoveryConfig)
}

// GenerateUnifiedAgentCard generates A2A Agent Card from unified config.
func GenerateUnifiedAgentCard(config UnifiedDiscoveryConfig) A2AAgentCard {
	var authScheme *A2AAuthScheme
	if config.Auth != nil {
		authType := config.Auth.Type
		if authType == "api_key" {
			authType = "apiKey"
		}
		authScheme = &A2AAuthScheme{
			Type:             authType,
			In:               config.Auth.In,
			Name:             config.Auth.Name,
			AuthorizationURL: config.Auth.AuthorizationURL,
			TokenURL:         config.Auth.TokenURL,
			Scopes:           config.Auth.Scopes,
		}
	}

	skills := make([]A2ASkill, 0, len(config.Skills))
	for _, s := range config.Skills {
		skills = append(skills, A2ASkill{
			ID:          s.ID,
			Name:        s.Name,
			Description: s.Description,
			Tags:        s.Tags,
			Examples:    s.Examples,
			InputModes:  s.InputModes,
			OutputModes: s.OutputModes,
		})
	}

	docURL := config.DocumentationURL
	if docURL == "" {
		docURL = config.OpenApiURL
	}

	return GenerateAgentCard(A2AConfig{
		Card: A2AAgentCard{
			ProtocolVersion:  "1.0.0",
			Name:             config.Name,
			Description:      config.Description,
			URL:              config.URL,
			Provider:         config.Provider,
			Version:          config.Version,
			DocumentationURL: docURL,
			Capabilities:     config.AgentCapabilities,
			Authentication:   authScheme,
			Skills:           skills,
		},
	})
}

// GenerateUnifiedLlmsTxt generates /llms.txt from unified config.
func GenerateUnifiedLlmsTxt(config UnifiedDiscoveryConfig) string {
	var sections []LlmsTxtSection

	for _, s := range config.Skills {
		content := s.Description
		if len(s.Examples) > 0 {
			examples := make([]string, 0, len(s.Examples))
			for _, e := range s.Examples {
				examples = append(examples, "- "+e)
			}
			if content != "" {
				content += "\n"
			}
			content += "\nExamples:\n" + strings.Join(examples, "\n")
		}
		sections = append(sections, LlmsTxtSection{Title: s.Name, Content: content})
	}

	sections = append(sections, config.LlmsTxtSections...)

	return GenerateLlmsTxt(LlmsTxtConfig{
		Title:       config.Name,
		Description: config.Description,
		Sections:    sections,
	})
}

// GenerateUnifiedLlmsFullTxt generates /llms-full.txt from unified config with routes.
func GenerateUnifiedLlmsFullTxt(config UnifiedDiscoveryConfig) string {
	var sections []LlmsTxtSection

	for _, s := range config.Skills {
		content := s.Description
		if len(s.Examples) > 0 {
			examples := make([]string, 0, len(s.Examples))
			for _, e := range s.Examples {
				examples = append(examples, "- "+e)
			}
			if content != "" {
				content += "\n"
			}
			content += "\nExamples:\n" + strings.Join(examples, "\n")
		}
		sections = append(sections, LlmsTxtSection{Title: s.Name, Content: content})
	}

	sections = append(sections, config.LlmsTxtSections...)

	routes := config.Routes
	if routes == nil {
		routes = []RouteMetadata{}
	}

	return GenerateLlmsFullTxt(LlmsTxtConfig{
		Title:       config.Name,
		Description: config.Description,
		Sections:    sections,
	}, routes)
}

// GenerateUnifiedAgentsTxt generates /agents.txt from unified config.
func GenerateUnifiedAgentsTxt(config UnifiedDiscoveryConfig) string {
	if config.AgentsTxt == nil {
		return fmt.Sprintf("# agents.txt — AI agent access rules for %s\n# See https://github.com/nichochar/open-agent-schema\n\nUser-agent: *\nAllow: /\n", config.Name)
	}

	var lines []string

	if config.AgentsTxt.Comment != "" {
		for _, line := range strings.Split(config.AgentsTxt.Comment, "\n") {
			lines = append(lines, "# "+line)
		}
		lines = append(lines, "")
	}

	for _, block := range config.AgentsTxt.Blocks {
		lines = append(lines, fmt.Sprintf("User-agent: %s", block.UserAgent))
		for _, rule := range block.Rules {
			directive := "Allow"
			if rule.Permission == "disallow" {
				directive = "Disallow"
			}
			lines = append(lines, fmt.Sprintf("%s: %s", directive, rule.Path))
		}
		lines = append(lines, "")
	}

	if config.AgentsTxt.SitemapURL != "" {
		lines = append(lines, fmt.Sprintf("Sitemap: %s", config.AgentsTxt.SitemapURL))
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// GenerateAllDiscovery generates all enabled discovery documents.
func GenerateAllDiscovery(config UnifiedDiscoveryConfig) map[string]interface{} {
	result := map[string]interface{}{}

	if IsFormatEnabled(config.Formats, "wellKnownAi") {
		result["/.well-known/ai"] = GenerateUnifiedAIManifest(config)
	}

	if IsFormatEnabled(config.Formats, "agentCard") {
		result["/.well-known/agent.json"] = GenerateUnifiedAgentCard(config)
	}

	if IsFormatEnabled(config.Formats, "llmsTxt") {
		result["/llms.txt"] = GenerateUnifiedLlmsTxt(config)
		result["/llms-full.txt"] = GenerateUnifiedLlmsFullTxt(config)
	}

	if IsFormatEnabled(config.Formats, "agentsTxt") {
		result["/agents.txt"] = GenerateUnifiedAgentsTxt(config)
	}

	return result
}
