package core

import (
	"strings"
	"testing"
)

func TestGenerateLlmsTxt_Title(t *testing.T) {
	output := GenerateLlmsTxt(LlmsTxtConfig{
		Title: "My API",
	})
	if !strings.HasPrefix(output, "# My API\n") {
		t.Errorf("expected output to start with '# My API', got:\n%s", output)
	}
}

func TestGenerateLlmsTxt_Description(t *testing.T) {
	output := GenerateLlmsTxt(LlmsTxtConfig{
		Title:       "My API",
		Description: "A helpful API for agents",
	})
	if !strings.Contains(output, "> A helpful API for agents") {
		t.Errorf("expected description blockquote, got:\n%s", output)
	}
}

func TestGenerateLlmsTxt_Sections(t *testing.T) {
	output := GenerateLlmsTxt(LlmsTxtConfig{
		Title:       "My API",
		Description: "Test API",
		Sections: []LlmsTxtSection{
			{Title: "Authentication", Content: "Use Bearer tokens."},
			{Title: "Rate Limits", Content: "100 requests per minute."},
		},
	})

	if !strings.Contains(output, "## Authentication") {
		t.Error("expected Authentication section header")
	}
	if !strings.Contains(output, "Use Bearer tokens.") {
		t.Error("expected Authentication content")
	}
	if !strings.Contains(output, "## Rate Limits") {
		t.Error("expected Rate Limits section header")
	}
	if !strings.Contains(output, "100 requests per minute.") {
		t.Error("expected Rate Limits content")
	}
}

func TestGenerateLlmsTxt_NoDescription(t *testing.T) {
	output := GenerateLlmsTxt(LlmsTxtConfig{
		Title: "Minimal",
	})
	if strings.Contains(output, ">") {
		t.Error("expected no blockquote when description is empty")
	}
}

func TestGenerateLlmsFullTxt_WithRoutes(t *testing.T) {
	config := LlmsTxtConfig{
		Title:       "Full API",
		Description: "Complete API docs",
	}
	routes := []RouteMetadata{
		{
			Method:      "get",
			Path:        "/api/users",
			Summary:     "List all users",
			Description: "Returns a paginated list of users.",
			Parameters: []RouteParameter{
				{Name: "page", In: "query", Required: false, Description: "Page number"},
				{Name: "limit", In: "query", Required: true, Description: "Items per page"},
			},
		},
		{
			Method:  "post",
			Path:    "/api/users",
			Summary: "Create a user",
		},
	}

	output := GenerateLlmsFullTxt(config, routes)

	if !strings.Contains(output, "## API Endpoints") {
		t.Error("expected API Endpoints section")
	}
	if !strings.Contains(output, "### GET /api/users") {
		t.Error("expected GET /api/users heading")
	}
	if !strings.Contains(output, "List all users") {
		t.Error("expected route summary")
	}
	if !strings.Contains(output, "Returns a paginated list of users.") {
		t.Error("expected route description")
	}
	if !strings.Contains(output, "**Parameters:**") {
		t.Error("expected Parameters heading")
	}
	if !strings.Contains(output, "- `page` (query)") {
		t.Error("expected page parameter")
	}
	if !strings.Contains(output, "(required)") {
		t.Error("expected required marker on limit parameter")
	}
	if !strings.Contains(output, "Page number") {
		t.Error("expected page parameter description")
	}
	if !strings.Contains(output, "### POST /api/users") {
		t.Error("expected POST /api/users heading")
	}
}

func TestGenerateLlmsFullTxt_NoRoutes(t *testing.T) {
	config := LlmsTxtConfig{
		Title: "Empty API",
	}
	output := GenerateLlmsFullTxt(config, nil)
	if strings.Contains(output, "## API Endpoints") {
		t.Error("expected no API Endpoints section when routes is nil")
	}
}

func TestGenerateLlmsFullTxt_RouteWithNoParameters(t *testing.T) {
	config := LlmsTxtConfig{Title: "API"}
	routes := []RouteMetadata{
		{Method: "delete", Path: "/api/users/{id}", Summary: "Delete a user"},
	}
	output := GenerateLlmsFullTxt(config, routes)
	if !strings.Contains(output, "### DELETE /api/users/{id}") {
		t.Error("expected DELETE heading")
	}
	if strings.Contains(output, "**Parameters:**") {
		t.Error("expected no Parameters section when route has no parameters")
	}
}

func TestGenerateLlmsFullTxt_ParameterRequiredFlag(t *testing.T) {
	config := LlmsTxtConfig{Title: "API"}
	routes := []RouteMetadata{
		{
			Method: "get",
			Path:   "/items",
			Parameters: []RouteParameter{
				{Name: "id", In: "path", Required: true},
				{Name: "filter", In: "query", Required: false},
			},
		},
	}
	output := GenerateLlmsFullTxt(config, routes)

	// The required parameter should have (required)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "`id`") && !strings.Contains(line, "(required)") {
			t.Error("expected 'id' parameter to be marked as required")
		}
		if strings.Contains(line, "`filter`") && strings.Contains(line, "(required)") {
			t.Error("expected 'filter' parameter to NOT be marked as required")
		}
	}
}
