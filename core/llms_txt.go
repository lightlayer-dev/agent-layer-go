package core

import (
	"fmt"
	"strings"
)

// GenerateLlmsTxt generates llms.txt content from manual config sections.
func GenerateLlmsTxt(config LlmsTxtConfig) string {
	var lines []string

	lines = append(lines, fmt.Sprintf("# %s", config.Title))

	if config.Description != "" {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("> %s", config.Description))
	}

	for _, section := range config.Sections {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("## %s", section.Title))
		lines = append(lines, "")
		lines = append(lines, section.Content)
	}

	return strings.Join(lines, "\n") + "\n"
}

// GenerateLlmsFullTxt generates llms-full.txt with route documentation.
func GenerateLlmsFullTxt(config LlmsTxtConfig, routes []RouteMetadata) string {
	var lines []string

	lines = append(lines, fmt.Sprintf("# %s", config.Title))

	if config.Description != "" {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("> %s", config.Description))
	}

	for _, section := range config.Sections {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("## %s", section.Title))
		lines = append(lines, "")
		lines = append(lines, section.Content)
	}

	if len(routes) > 0 {
		lines = append(lines, "")
		lines = append(lines, "## API Endpoints")

		for _, route := range routes {
			lines = append(lines, "")
			lines = append(lines, fmt.Sprintf("### %s %s", strings.ToUpper(route.Method), route.Path))

			if route.Summary != "" {
				lines = append(lines, "")
				lines = append(lines, route.Summary)
			}

			if route.Description != "" {
				lines = append(lines, "")
				lines = append(lines, route.Description)
			}

			if len(route.Parameters) > 0 {
				lines = append(lines, "")
				lines = append(lines, "**Parameters:**")
				for _, param := range route.Parameters {
					required := ""
					if param.Required {
						required = " (required)"
					}
					desc := ""
					if param.Description != "" {
						desc = fmt.Sprintf(" — %s", param.Description)
					}
					lines = append(lines, fmt.Sprintf("- `%s` (%s)%s%s", param.Name, param.In, required, desc))
				}
			}
		}
	}

	return strings.Join(lines, "\n") + "\n"
}
