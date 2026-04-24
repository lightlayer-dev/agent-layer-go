package core

import "testing"

func TestGenerateSecurityHeaders_Defaults(t *testing.T) {
	headers := GenerateSecurityHeaders(nil)

	if headers["Strict-Transport-Security"] != "max-age=31536000; includeSubDomains" {
		t.Fatalf("unexpected HSTS header: %q", headers["Strict-Transport-Security"])
	}
	if headers["X-Content-Type-Options"] != "nosniff" {
		t.Fatalf("unexpected X-Content-Type-Options: %q", headers["X-Content-Type-Options"])
	}
	if headers["X-Frame-Options"] != "DENY" {
		t.Fatalf("unexpected X-Frame-Options: %q", headers["X-Frame-Options"])
	}
	if headers["Referrer-Policy"] != "strict-origin-when-cross-origin" {
		t.Fatalf("unexpected Referrer-Policy: %q", headers["Referrer-Policy"])
	}
	if headers["Content-Security-Policy"] != "default-src 'self'" {
		t.Fatalf("unexpected CSP: %q", headers["Content-Security-Policy"])
	}
}

func TestGenerateSecurityHeaders_CustomAndDisabled(t *testing.T) {
	headers := GenerateSecurityHeaders(&SecurityHeadersConfig{
		HSTSMaxAge:                   86400,
		HSTSIncludeSubdomains:        false,
		FrameOptions:                 "SAMEORIGIN",
		DisableContentTypeOptions:    true,
		ReferrerPolicy:               "no-referrer",
		ContentSecurityPolicy:        "default-src 'none'",
		DisableContentSecurityPolicy: false,
		PermissionsPolicy:            "geolocation=()",
	})

	if headers["Strict-Transport-Security"] != "max-age=86400" {
		t.Fatalf("unexpected HSTS header: %q", headers["Strict-Transport-Security"])
	}
	if _, ok := headers["X-Content-Type-Options"]; ok {
		t.Fatal("expected X-Content-Type-Options to be disabled")
	}
	if headers["X-Frame-Options"] != "SAMEORIGIN" {
		t.Fatalf("unexpected frame options: %q", headers["X-Frame-Options"])
	}
	if headers["Referrer-Policy"] != "no-referrer" {
		t.Fatalf("unexpected referrer policy: %q", headers["Referrer-Policy"])
	}
	if headers["Content-Security-Policy"] != "default-src 'none'" {
		t.Fatalf("unexpected CSP: %q", headers["Content-Security-Policy"])
	}
	if headers["Permissions-Policy"] != "geolocation=()" {
		t.Fatalf("unexpected permissions policy: %q", headers["Permissions-Policy"])
	}
}

func TestGenerateSecurityHeaders_DisableHSTS(t *testing.T) {
	headers := GenerateSecurityHeaders(&SecurityHeadersConfig{
		DisableHSTS: true,
	})

	if _, ok := headers["Strict-Transport-Security"]; ok {
		t.Fatal("expected HSTS to be disabled")
	}
}
