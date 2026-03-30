package core

import (
	"testing"
)

func TestGenerateAgentCard_Defaults(t *testing.T) {
	card := GenerateAgentCard(A2AConfig{
		Card: A2AAgentCard{
			Name: "test-agent",
			URL:  "https://example.com/agent",
		},
	})

	if card.ProtocolVersion != "1.0.0" {
		t.Errorf("expected default protocolVersion '1.0.0', got %q", card.ProtocolVersion)
	}
	if len(card.DefaultInputModes) != 1 || card.DefaultInputModes[0] != "text/plain" {
		t.Errorf("expected default input modes [text/plain], got %v", card.DefaultInputModes)
	}
	if len(card.DefaultOutputModes) != 1 || card.DefaultOutputModes[0] != "text/plain" {
		t.Errorf("expected default output modes [text/plain], got %v", card.DefaultOutputModes)
	}
	if card.Skills == nil || len(card.Skills) != 0 {
		t.Errorf("expected empty skills slice, got %v", card.Skills)
	}
}

func TestGenerateAgentCard_CustomConfig(t *testing.T) {
	streaming := true
	card := GenerateAgentCard(A2AConfig{
		Card: A2AAgentCard{
			ProtocolVersion:    "2.0.0",
			Name:               "custom-agent",
			URL:                "https://custom.example.com",
			Description:        "A custom agent",
			Version:            "1.2.3",
			DefaultInputModes:  []string{"application/json"},
			DefaultOutputModes: []string{"application/json", "text/plain"},
			Capabilities:       &A2ACapabilities{Streaming: &streaming},
			Provider: &A2AProvider{
				Organization: "TestOrg",
				URL:          "https://testorg.com",
			},
		},
	})

	if card.ProtocolVersion != "2.0.0" {
		t.Errorf("expected protocolVersion '2.0.0', got %q", card.ProtocolVersion)
	}
	if card.Name != "custom-agent" {
		t.Errorf("expected name 'custom-agent', got %q", card.Name)
	}
	if card.Description != "A custom agent" {
		t.Errorf("expected description 'A custom agent', got %q", card.Description)
	}
	if len(card.DefaultInputModes) != 1 || card.DefaultInputModes[0] != "application/json" {
		t.Errorf("expected custom input modes, got %v", card.DefaultInputModes)
	}
	if len(card.DefaultOutputModes) != 2 {
		t.Errorf("expected 2 output modes, got %d", len(card.DefaultOutputModes))
	}
	if card.Capabilities == nil || card.Capabilities.Streaming == nil || !*card.Capabilities.Streaming {
		t.Error("expected streaming capability to be true")
	}
	if card.Provider == nil || card.Provider.Organization != "TestOrg" {
		t.Error("expected provider organization to be 'TestOrg'")
	}
}

func TestGenerateAgentCard_Skills(t *testing.T) {
	card := GenerateAgentCard(A2AConfig{
		Card: A2AAgentCard{
			Name: "skilled-agent",
			URL:  "https://example.com",
			Skills: []A2ASkill{
				{
					ID:          "translate",
					Name:        "Translate",
					Description: "Translates text between languages",
					Tags:        []string{"nlp", "translation"},
					Examples:    []string{"Translate hello to French"},
					InputModes:  []string{"text/plain"},
					OutputModes: []string{"text/plain"},
				},
				{
					ID:   "summarize",
					Name: "Summarize",
				},
			},
		},
	})

	if len(card.Skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(card.Skills))
	}
	if card.Skills[0].ID != "translate" {
		t.Errorf("expected first skill ID 'translate', got %q", card.Skills[0].ID)
	}
	if card.Skills[0].Description != "Translates text between languages" {
		t.Errorf("expected first skill description, got %q", card.Skills[0].Description)
	}
	if len(card.Skills[0].Tags) != 2 {
		t.Errorf("expected 2 tags on first skill, got %d", len(card.Skills[0].Tags))
	}
	if card.Skills[1].ID != "summarize" {
		t.Errorf("expected second skill ID 'summarize', got %q", card.Skills[1].ID)
	}
}

func TestValidateAgentCard_Valid(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		Name:            "my-agent",
		URL:             "https://example.com/agent",
		Skills:          []A2ASkill{{ID: "s1", Name: "Skill One"}},
	}
	errs := ValidateAgentCard(card)
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid card, got %v", errs)
	}
}

func TestValidateAgentCard_MissingName(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		URL:             "https://example.com",
		Skills:          []A2ASkill{{ID: "s1", Name: "S1"}},
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "name is required")
}

func TestValidateAgentCard_MissingURL(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		Name:            "agent",
		Skills:          []A2ASkill{{ID: "s1", Name: "S1"}},
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "url is required")
}

func TestValidateAgentCard_MissingSkills(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		Name:            "agent",
		URL:             "https://example.com",
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "skills is required")
}

func TestValidateAgentCard_MissingProtocolVersion(t *testing.T) {
	card := A2AAgentCard{
		Name:   "agent",
		URL:    "https://example.com",
		Skills: []A2ASkill{{ID: "s1", Name: "S1"}},
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "protocolVersion is required")
}

func TestValidateAgentCard_InvalidURL(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		Name:            "agent",
		URL:             "ftp://example.com",
		Skills:          []A2ASkill{{ID: "s1", Name: "S1"}},
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "url must be an HTTP(S) URL")
}

func TestValidateAgentCard_SkillWithoutID(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		Name:            "agent",
		URL:             "https://example.com",
		Skills:          []A2ASkill{{Name: "S1"}},
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "each skill must have an id")
}

func TestValidateAgentCard_SkillWithoutName(t *testing.T) {
	card := A2AAgentCard{
		ProtocolVersion: "1.0.0",
		Name:            "agent",
		URL:             "https://example.com",
		Skills:          []A2ASkill{{ID: "s1"}},
	}
	errs := ValidateAgentCard(card)
	assertContainsError(t, errs, "each skill must have a name")
}

func assertContainsError(t *testing.T, errs []string, expected string) {
	t.Helper()
	for _, e := range errs {
		if e == expected {
			return
		}
	}
	t.Errorf("expected error %q in %v", expected, errs)
}
