package core

import "fmt"

// SecurityHeadersConfig configures default response security headers.
type SecurityHeadersConfig struct {
	HSTSMaxAge                   int
	HSTSIncludeSubdomains        bool
	DisableHSTS                  bool
	FrameOptions                 string
	DisableFrameOptions          bool
	ContentTypeOptions           string
	DisableContentTypeOptions    bool
	ReferrerPolicy               string
	DisableReferrerPolicy        bool
	ContentSecurityPolicy        string
	DisableContentSecurityPolicy bool
	PermissionsPolicy            string
}

// GenerateSecurityHeaders returns the configured response headers.
func GenerateSecurityHeaders(config *SecurityHeadersConfig) map[string]string {
	cfg := SecurityHeadersConfig{}
	if config != nil {
		cfg = *config
	}

	headers := map[string]string{}

	hstsMaxAge := cfg.HSTSMaxAge
	if hstsMaxAge == 0 {
		hstsMaxAge = 31536000
	}

	includeSubdomains := cfg.HSTSIncludeSubdomains
	if config == nil || (!cfg.HSTSIncludeSubdomains && !cfg.DisableHSTS && cfg.HSTSMaxAge == 0) {
		includeSubdomains = true
	}

	if !cfg.DisableHSTS && hstsMaxAge > 0 {
		value := fmt.Sprintf("max-age=%d", hstsMaxAge)
		if includeSubdomains {
			value += "; includeSubDomains"
		}
		headers["Strict-Transport-Security"] = value
	}

	if !cfg.DisableContentTypeOptions {
		value := cfg.ContentTypeOptions
		if value == "" {
			value = "nosniff"
		}
		headers["X-Content-Type-Options"] = value
	}

	if !cfg.DisableFrameOptions {
		value := cfg.FrameOptions
		if value == "" {
			value = "DENY"
		}
		headers["X-Frame-Options"] = value
	}

	if !cfg.DisableReferrerPolicy {
		value := cfg.ReferrerPolicy
		if value == "" {
			value = "strict-origin-when-cross-origin"
		}
		headers["Referrer-Policy"] = value
	}

	if !cfg.DisableContentSecurityPolicy {
		value := cfg.ContentSecurityPolicy
		if value == "" {
			value = "default-src 'self'"
		}
		headers["Content-Security-Policy"] = value
	}

	if cfg.PermissionsPolicy != "" {
		headers["Permissions-Policy"] = cfg.PermissionsPolicy
	}

	return headers
}
