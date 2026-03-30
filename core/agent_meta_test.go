package core

import (
	"strings"
	"testing"
)

func TestTransformHTML_MetaTagInjection(t *testing.T) {
	html := `<html><head><title>Test</title></head><body><p>Hello</p></body></html>`
	config := AgentMetaConfig{
		MetaTags: map[string]string{
			"agent-name":    "TestBot",
			"agent-version": "1.0",
		},
	}

	result := TransformHTML(html, config)

	if !strings.Contains(result, `<meta name="agent-name" content="TestBot">`) {
		t.Error("expected agent-name meta tag")
	}
	if !strings.Contains(result, `<meta name="agent-version" content="1.0">`) {
		t.Error("expected agent-version meta tag")
	}
	// Meta tags should be before </head>
	headEnd := strings.Index(result, "</head>")
	metaPos := strings.Index(result, `<meta name="agent-name"`)
	if metaPos > headEnd {
		t.Error("meta tags should be injected before </head>")
	}
}

func TestTransformHTML_NoMetaTags(t *testing.T) {
	html := `<html><head><title>Test</title></head><body><p>Hello</p></body></html>`
	config := AgentMetaConfig{}

	result := TransformHTML(html, config)
	if strings.Contains(result, "<meta ") {
		t.Error("expected no meta tags when none configured")
	}
}

func TestTransformHTML_NoHeadTag(t *testing.T) {
	html := `<html><body><p>Hello</p></body></html>`
	config := AgentMetaConfig{
		MetaTags: map[string]string{"agent-name": "TestBot"},
	}

	result := TransformHTML(html, config)
	// Should not inject meta tags when there's no </head>
	if strings.Contains(result, `<meta name="agent-name"`) {
		t.Error("should not inject meta tags without </head>")
	}
}

func TestTransformHTML_BodyAttribute(t *testing.T) {
	html := `<html><head></head><body><p>Hello</p></body></html>`
	config := AgentMetaConfig{}

	result := TransformHTML(html, config)
	if !strings.Contains(result, `<body data-agent-id="root"`) {
		t.Error("expected data-agent-id attribute on body")
	}
}

func TestTransformHTML_CustomAttributeName(t *testing.T) {
	html := `<html><head></head><body><p>Hello</p></body></html>`
	config := AgentMetaConfig{
		AgentIDAttribute: "data-custom-id",
	}

	result := TransformHTML(html, config)
	if !strings.Contains(result, `<body data-custom-id="root"`) {
		t.Errorf("expected custom attribute name, got: %s", result)
	}
	if strings.Contains(result, "data-agent-id") {
		t.Error("should use custom attribute, not default")
	}
}

func TestTransformHTML_AriaLandmarks(t *testing.T) {
	html := `<html><head></head><body><main><p>Content</p></main></body></html>`
	config := AgentMetaConfig{}

	result := TransformHTML(html, config)
	if !strings.Contains(result, `<main role="main"`) {
		t.Errorf("expected role=main on <main>, got: %s", result)
	}
}

func TestTransformHTML_AriaLandmarksAlreadyHasRole(t *testing.T) {
	html := `<html><head></head><body><main role="custom"><p>Content</p></main></body></html>`
	config := AgentMetaConfig{}

	result := TransformHTML(html, config)
	// Should not duplicate role attribute
	if strings.Contains(result, `role="main"`) {
		t.Error("should not overwrite existing role attribute")
	}
	if !strings.Contains(result, `role="custom"`) {
		t.Error("should preserve existing role attribute")
	}
}

func TestTransformHTML_AriaLandmarksDisabled(t *testing.T) {
	html := `<html><head></head><body><main><p>Content</p></main></body></html>`
	ariaDisabled := false
	config := AgentMetaConfig{
		AriaLandmarks: &ariaDisabled,
	}

	result := TransformHTML(html, config)
	if strings.Contains(result, `role="main"`) {
		t.Error("should not add role when ARIA landmarks disabled")
	}
}

func TestTransformHTML_AriaLandmarksExplicitlyEnabled(t *testing.T) {
	html := `<html><head></head><body><main><p>Content</p></main></body></html>`
	ariaEnabled := true
	config := AgentMetaConfig{
		AriaLandmarks: &ariaEnabled,
	}

	result := TransformHTML(html, config)
	if !strings.Contains(result, `role="main"`) {
		t.Error("expected role=main when ARIA landmarks explicitly enabled")
	}
}

func TestTransformHTML_SkipNonHTML(t *testing.T) {
	// Content without HTML structure should pass through mostly unchanged
	plainText := "This is plain text without any HTML tags"
	config := AgentMetaConfig{
		MetaTags: map[string]string{"agent-name": "TestBot"},
	}

	result := TransformHTML(plainText, config)
	// No </head> to inject into, no <body to add attribute, no <main to add role
	if strings.Contains(result, "<meta") {
		t.Error("should not inject meta tags into non-HTML")
	}
	if strings.Contains(result, "data-agent-id") {
		t.Error("should not add attributes to non-HTML")
	}
	if strings.Contains(result, `role="main"`) {
		t.Error("should not add ARIA landmarks to non-HTML")
	}
	if result != plainText {
		t.Error("plain text should pass through unchanged")
	}
}

func TestTransformHTML_FullDocument(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>My Page</title>
</head>
<body>
    <main>
        <p>Content here</p>
    </main>
</body>
</html>`

	config := AgentMetaConfig{
		MetaTags: map[string]string{
			"agent-name": "FullTest",
		},
	}

	result := TransformHTML(html, config)

	if !strings.Contains(result, `<meta name="agent-name" content="FullTest">`) {
		t.Error("expected meta tag in full document")
	}
	if !strings.Contains(result, `data-agent-id="root"`) {
		t.Error("expected data-agent-id on body")
	}
	if !strings.Contains(result, `role="main"`) {
		t.Error("expected role=main on main element")
	}
}

func TestTransformHTML_NoBodyTag(t *testing.T) {
	html := `<html><head></head><div>No body tag</div></html>`
	config := AgentMetaConfig{}

	result := TransformHTML(html, config)
	if strings.Contains(result, "data-agent-id") {
		t.Error("should not add attribute without body tag")
	}
}

func TestTransformHTML_MultipleMainTags(t *testing.T) {
	html := `<html><head></head><body><main><p>First</p></main><main><p>Second</p></main></body></html>`
	config := AgentMetaConfig{}

	result := TransformHTML(html, config)
	// Both main tags should get role="main"
	count := strings.Count(result, `role="main"`)
	if count != 2 {
		t.Errorf("expected role=main on both main tags, got %d occurrences", count)
	}
}
