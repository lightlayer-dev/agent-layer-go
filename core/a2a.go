package core

// A2ASkill is a skill/capability the agent can perform.
type A2ASkill struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Examples        []string `json:"examples,omitempty"`
	InputModes      []string `json:"inputModes,omitempty"`
	OutputModes     []string `json:"outputModes,omitempty"`
}

// A2AAuthScheme describes authentication.
type A2AAuthScheme struct {
	Type             string            `json:"type"`
	In               string            `json:"in,omitempty"`
	Name             string            `json:"name,omitempty"`
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"`
}

// A2AProvider is organization info.
type A2AProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url,omitempty"`
}

// A2ACapabilities describes agent capabilities.
type A2ACapabilities struct {
	Streaming              *bool `json:"streaming,omitempty"`
	PushNotifications      *bool `json:"pushNotifications,omitempty"`
	StateTransitionHistory *bool `json:"stateTransitionHistory,omitempty"`
}

// A2AAgentCard is the full Agent Card document.
type A2AAgentCard struct {
	ProtocolVersion    string          `json:"protocolVersion"`
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	URL                string          `json:"url"`
	Provider           *A2AProvider    `json:"provider,omitempty"`
	Version            string          `json:"version,omitempty"`
	DocumentationURL   string          `json:"documentationUrl,omitempty"`
	Capabilities       *A2ACapabilities `json:"capabilities,omitempty"`
	Authentication     *A2AAuthScheme  `json:"authentication,omitempty"`
	DefaultInputModes  []string        `json:"defaultInputModes,omitempty"`
	DefaultOutputModes []string        `json:"defaultOutputModes,omitempty"`
	Skills             []A2ASkill      `json:"skills"`
}

// A2AConfig configures the A2A agent card.
type A2AConfig struct {
	Card A2AAgentCard
}

// GenerateAgentCard generates a valid A2A Agent Card JSON object.
func GenerateAgentCard(config A2AConfig) A2AAgentCard {
	card := config.Card

	if card.ProtocolVersion == "" {
		card.ProtocolVersion = "1.0.0"
	}
	if card.DefaultInputModes == nil {
		card.DefaultInputModes = []string{"text/plain"}
	}
	if card.DefaultOutputModes == nil {
		card.DefaultOutputModes = []string{"text/plain"}
	}
	if card.Skills == nil {
		card.Skills = []A2ASkill{}
	}

	return card
}

// ValidateAgentCard validates an Agent Card has the minimum required fields.
func ValidateAgentCard(card A2AAgentCard) []string {
	var errors []string

	if card.Name == "" {
		errors = append(errors, "name is required")
	}
	if card.URL == "" {
		errors = append(errors, "url is required")
	}
	if card.Skills == nil {
		errors = append(errors, "skills is required")
	}
	if card.ProtocolVersion == "" {
		errors = append(errors, "protocolVersion is required")
	}

	if card.URL != "" && len(card.URL) >= 4 && card.URL[:4] != "http" {
		errors = append(errors, "url must be an HTTP(S) URL")
	}

	if card.Skills != nil {
		for _, skill := range card.Skills {
			if skill.ID == "" {
				errors = append(errors, "each skill must have an id")
			}
			if skill.Name == "" {
				errors = append(errors, "each skill must have a name")
			}
		}
	}

	return errors
}
