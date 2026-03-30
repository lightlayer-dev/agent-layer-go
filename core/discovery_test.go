package core

import (
	"testing"
)

func TestGenerateAIManifest_Basic(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name: "Test API",
		},
	}
	manifest := GenerateAIManifest(config)
	if manifest.Name != "Test API" {
		t.Errorf("expected name 'Test API', got %q", manifest.Name)
	}
}

func TestGenerateAIManifest_AllFields(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name:        "Full API",
			Description: "A complete API",
			OpenAPIURL:  "https://example.com/openapi.json",
			LlmsTxtURL:  "https://example.com/llms.txt",
			Auth: &AIManifestAuth{
				Type:             "oauth2",
				AuthorizationURL: "https://auth.example.com/authorize",
				TokenURL:         "https://auth.example.com/token",
				Scopes:           map[string]string{"read": "Read access"},
			},
			Contact: &AIManifestContact{
				Email: "admin@example.com",
				URL:   "https://example.com",
			},
			Capabilities: []string{"search", "create", "delete"},
		},
	}
	manifest := GenerateAIManifest(config)

	if manifest.Name != "Full API" {
		t.Errorf("expected name 'Full API', got %q", manifest.Name)
	}
	if manifest.Description != "A complete API" {
		t.Errorf("expected description, got %q", manifest.Description)
	}
	if manifest.OpenAPIURL != "https://example.com/openapi.json" {
		t.Errorf("expected OpenAPIURL, got %q", manifest.OpenAPIURL)
	}
	if manifest.LlmsTxtURL != "https://example.com/llms.txt" {
		t.Errorf("expected LlmsTxtURL, got %q", manifest.LlmsTxtURL)
	}
	if manifest.Auth == nil {
		t.Fatal("expected Auth to be set")
	}
	if manifest.Auth.Type != "oauth2" {
		t.Errorf("expected auth type 'oauth2', got %q", manifest.Auth.Type)
	}
	if manifest.Auth.TokenURL != "https://auth.example.com/token" {
		t.Errorf("expected token URL, got %q", manifest.Auth.TokenURL)
	}
	if manifest.Contact == nil {
		t.Fatal("expected Contact to be set")
	}
	if manifest.Contact.Email != "admin@example.com" {
		t.Errorf("expected contact email, got %q", manifest.Contact.Email)
	}
	if len(manifest.Capabilities) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(manifest.Capabilities))
	}
}

func TestGenerateJsonLd_Basic(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name: "JSON-LD API",
		},
	}
	jsonLd := GenerateJsonLd(config)

	if jsonLd["@context"] != "https://schema.org" {
		t.Errorf("expected @context 'https://schema.org', got %v", jsonLd["@context"])
	}
	if jsonLd["@type"] != "WebAPI" {
		t.Errorf("expected @type 'WebAPI', got %v", jsonLd["@type"])
	}
	if jsonLd["name"] != "JSON-LD API" {
		t.Errorf("expected name 'JSON-LD API', got %v", jsonLd["name"])
	}
}

func TestGenerateJsonLd_WithDescription(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name:        "Described API",
			Description: "An API with a description",
		},
	}
	jsonLd := GenerateJsonLd(config)

	if jsonLd["description"] != "An API with a description" {
		t.Errorf("expected description, got %v", jsonLd["description"])
	}
}

func TestGenerateJsonLd_NoDescription(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name: "No Desc",
		},
	}
	jsonLd := GenerateJsonLd(config)
	if _, ok := jsonLd["description"]; ok {
		t.Error("expected no description key when description is empty")
	}
}

func TestGenerateJsonLd_WithContact(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name: "Contact API",
			Contact: &AIManifestContact{
				Email: "hello@example.com",
				URL:   "https://example.com",
			},
		},
	}
	jsonLd := GenerateJsonLd(config)

	if jsonLd["url"] != "https://example.com" {
		t.Errorf("expected url from contact, got %v", jsonLd["url"])
	}
	cp, ok := jsonLd["contactPoint"].(map[string]interface{})
	if !ok {
		t.Fatal("expected contactPoint to be a map")
	}
	if cp["@type"] != "ContactPoint" {
		t.Errorf("expected contactPoint @type 'ContactPoint', got %v", cp["@type"])
	}
	if cp["email"] != "hello@example.com" {
		t.Errorf("expected contactPoint email, got %v", cp["email"])
	}
}

func TestGenerateJsonLd_WithCapabilities(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name:         "Cap API",
			Capabilities: []string{"search", "translate"},
		},
	}
	jsonLd := GenerateJsonLd(config)

	actions, ok := jsonLd["potentialAction"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected potentialAction to be a slice of maps")
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
	if actions[0]["@type"] != "Action" {
		t.Errorf("expected action @type 'Action', got %v", actions[0]["@type"])
	}
	if actions[0]["name"] != "search" {
		t.Errorf("expected first action name 'search', got %v", actions[0]["name"])
	}
	if actions[1]["name"] != "translate" {
		t.Errorf("expected second action name 'translate', got %v", actions[1]["name"])
	}
}

func TestGenerateJsonLd_WithDocumentation(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{
			Name:       "Documented API",
			OpenAPIURL: "https://example.com/openapi.json",
		},
	}
	jsonLd := GenerateJsonLd(config)
	if jsonLd["documentation"] != "https://example.com/openapi.json" {
		t.Errorf("expected documentation URL, got %v", jsonLd["documentation"])
	}
}

func TestGenerateJsonLd_NoCapabilities(t *testing.T) {
	config := DiscoveryConfig{
		Manifest: AIManifest{Name: "Simple"},
	}
	jsonLd := GenerateJsonLd(config)
	if _, ok := jsonLd["potentialAction"]; ok {
		t.Error("expected no potentialAction key when capabilities is empty")
	}
}
