package core

import (
	"fmt"
	"regexp"
	"strings"
)

var mainTagRe = regexp.MustCompile(`<main([^>]*)>`)
var roleAttrRe = regexp.MustCompile(`role=`)

// TransformHTML transforms HTML responses for agent consumption.
// Injects data-agent-id attributes, ARIA landmarks, and meta tags.
func TransformHTML(html string, config AgentMetaConfig) string {
	attrName := config.AgentIDAttribute
	if attrName == "" {
		attrName = "data-agent-id"
	}

	injectAria := config.AriaLandmarks == nil || *config.AriaLandmarks

	// Inject meta tags into <head>
	if len(config.MetaTags) > 0 && strings.Contains(html, "</head>") {
		var metaTags []string
		for name, content := range config.MetaTags {
			metaTags = append(metaTags, fmt.Sprintf(`<meta name="%s" content="%s">`, name, content))
		}
		metaTagsHTML := strings.Join(metaTags, "\n    ")
		html = strings.Replace(html, "</head>", "    "+metaTagsHTML+"\n</head>", 1)
	}

	// Add agent-id attribute to <body>
	if strings.Contains(html, "<body") {
		html = strings.Replace(html, "<body", fmt.Sprintf(`<body %s="root"`, attrName), 1)
	}

	// Add ARIA landmarks
	if injectAria && strings.Contains(html, "<main") {
		html = mainTagRe.ReplaceAllStringFunc(html, func(match string) string {
			if roleAttrRe.MatchString(match) {
				return match
			}
			return strings.Replace(match, "<main", `<main role="main"`, 1)
		})
	}

	return html
}
