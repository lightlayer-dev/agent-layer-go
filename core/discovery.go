package core

// GenerateAIManifest generates the /.well-known/ai manifest JSON.
func GenerateAIManifest(config DiscoveryConfig) AIManifest {
	return config.Manifest
}

// GenerateJsonLd generates JSON-LD structured data for the API.
func GenerateJsonLd(config DiscoveryConfig) map[string]interface{} {
	jsonLd := map[string]interface{}{
		"@context": "https://schema.org",
		"@type":    "WebAPI",
		"name":     config.Manifest.Name,
	}

	if config.Manifest.Description != "" {
		jsonLd["description"] = config.Manifest.Description
	}

	if config.Manifest.OpenAPIURL != "" {
		jsonLd["documentation"] = config.Manifest.OpenAPIURL
	}

	if config.Manifest.Contact != nil && config.Manifest.Contact.URL != "" {
		jsonLd["url"] = config.Manifest.Contact.URL
	}

	if config.Manifest.Contact != nil && config.Manifest.Contact.Email != "" {
		jsonLd["contactPoint"] = map[string]interface{}{
			"@type": "ContactPoint",
			"email": config.Manifest.Contact.Email,
		}
	}

	if len(config.Manifest.Capabilities) > 0 {
		actions := make([]map[string]interface{}, 0, len(config.Manifest.Capabilities))
		for _, cap := range config.Manifest.Capabilities {
			actions = append(actions, map[string]interface{}{
				"@type": "Action",
				"name":  cap,
			})
		}
		jsonLd["potentialAction"] = actions
	}

	return jsonLd
}
