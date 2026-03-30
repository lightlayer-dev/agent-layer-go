package core

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// buildFakeJWT creates a fake JWT token from a payload map.
// It base64url-encodes a dummy header and the JSON payload, with a dummy signature.
func buildFakeJWT(payload map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + encodedPayload + "." + signature
}

// --- ParseSpiffeId ---

func TestParseSpiffeId_Valid(t *testing.T) {
	id := ParseSpiffeId("spiffe://example.com/agent/mybot")
	if id == nil {
		t.Fatal("expected non-nil SpiffeId")
	}
	if id.TrustDomain != "example.com" {
		t.Errorf("expected trust domain 'example.com', got %q", id.TrustDomain)
	}
	if id.Path != "/agent/mybot" {
		t.Errorf("expected path '/agent/mybot', got %q", id.Path)
	}
	if id.Raw != "spiffe://example.com/agent/mybot" {
		t.Errorf("expected raw URI, got %q", id.Raw)
	}
}

func TestParseSpiffeId_InvalidString(t *testing.T) {
	id := ParseSpiffeId("not-a-spiffe-uri")
	if id != nil {
		t.Errorf("expected nil for invalid string, got %+v", id)
	}
}

func TestParseSpiffeId_NoPath(t *testing.T) {
	id := ParseSpiffeId("spiffe://example.com")
	if id == nil {
		t.Fatal("expected non-nil SpiffeId")
	}
	if id.TrustDomain != "example.com" {
		t.Errorf("expected trust domain 'example.com', got %q", id.TrustDomain)
	}
	if id.Path != "/" {
		t.Errorf("expected default path '/', got %q", id.Path)
	}
}

// --- DecodeJwtClaims ---

func TestDecodeJwtClaims_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "https://auth.example.com",
		"sub": "agent-123",
		"aud": "my-api",
	}
	token := buildFakeJWT(payload)
	claims := DecodeJwtClaims(token)
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}
	if claims["iss"] != "https://auth.example.com" {
		t.Errorf("expected iss, got %v", claims["iss"])
	}
	if claims["sub"] != "agent-123" {
		t.Errorf("expected sub, got %v", claims["sub"])
	}
	if claims["aud"] != "my-api" {
		t.Errorf("expected aud, got %v", claims["aud"])
	}
}

func TestDecodeJwtClaims_InvalidToken(t *testing.T) {
	claims := DecodeJwtClaims("not.a.valid-token!!!")
	if claims != nil {
		t.Errorf("expected nil for invalid token, got %v", claims)
	}
}

func TestDecodeJwtClaims_TooFewParts(t *testing.T) {
	claims := DecodeJwtClaims("only.two")
	if claims != nil {
		t.Errorf("expected nil for token with only 2 parts, got %v", claims)
	}
}

// --- ExtractClaims ---

func TestExtractClaims_Standard(t *testing.T) {
	payload := map[string]interface{}{
		"iss":      "https://auth.example.com",
		"sub":      "agent-bot",
		"aud":      "my-api",
		"exp":      float64(1700000000),
		"iat":      float64(1699999000),
		"agent_id": "custom-agent-id",
	}
	claims := ExtractClaims(payload)

	if claims.AgentID != "custom-agent-id" {
		t.Errorf("expected AgentID 'custom-agent-id', got %q", claims.AgentID)
	}
	if claims.Issuer != "https://auth.example.com" {
		t.Errorf("expected Issuer, got %q", claims.Issuer)
	}
	if claims.Subject != "agent-bot" {
		t.Errorf("expected Subject 'agent-bot', got %q", claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "my-api" {
		t.Errorf("expected Audience [my-api], got %v", claims.Audience)
	}
	if claims.ExpiresAt != 1700000000 {
		t.Errorf("expected ExpiresAt 1700000000, got %d", claims.ExpiresAt)
	}
	if claims.IssuedAt != 1699999000 {
		t.Errorf("expected IssuedAt 1699999000, got %d", claims.IssuedAt)
	}
}

func TestExtractClaims_AgentIDFallsBackToSub(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "issuer",
		"sub": "agent-from-sub",
	}
	claims := ExtractClaims(payload)
	if claims.AgentID != "agent-from-sub" {
		t.Errorf("expected AgentID to fall back to sub, got %q", claims.AgentID)
	}
}

func TestExtractClaims_ScopeSpaceDelimited(t *testing.T) {
	payload := map[string]interface{}{
		"iss":   "issuer",
		"sub":   "agent",
		"scope": "read write admin",
	}
	claims := ExtractClaims(payload)
	if len(claims.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d: %v", len(claims.Scopes), claims.Scopes)
	}
	expected := []string{"read", "write", "admin"}
	for i, s := range expected {
		if claims.Scopes[i] != s {
			t.Errorf("expected scope %q at index %d, got %q", s, i, claims.Scopes[i])
		}
	}
}

func TestExtractClaims_ScopesArray(t *testing.T) {
	payload := map[string]interface{}{
		"iss":    "issuer",
		"sub":    "agent",
		"scopes": []interface{}{"read", "write"},
	}
	claims := ExtractClaims(payload)
	if len(claims.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d: %v", len(claims.Scopes), claims.Scopes)
	}
	if claims.Scopes[0] != "read" || claims.Scopes[1] != "write" {
		t.Errorf("expected scopes [read, write], got %v", claims.Scopes)
	}
}

func TestExtractClaims_ScpArray(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "issuer",
		"sub": "agent",
		"scp": []interface{}{"api.read"},
	}
	claims := ExtractClaims(payload)
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "api.read" {
		t.Errorf("expected scopes from scp, got %v", claims.Scopes)
	}
}

func TestExtractClaims_Delegation(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "issuer",
		"sub": "delegated-agent",
		"act": map[string]interface{}{
			"sub": "parent-agent",
		},
	}
	claims := ExtractClaims(payload)
	if !claims.Delegated {
		t.Error("expected Delegated to be true")
	}
	if claims.DelegatedBy != "parent-agent" {
		t.Errorf("expected DelegatedBy 'parent-agent', got %q", claims.DelegatedBy)
	}
}

func TestExtractClaims_NoDelegation(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "issuer",
		"sub": "agent",
	}
	claims := ExtractClaims(payload)
	if claims.Delegated {
		t.Error("expected Delegated to be false")
	}
	if claims.DelegatedBy != "" {
		t.Errorf("expected empty DelegatedBy, got %q", claims.DelegatedBy)
	}
}

func TestExtractClaims_CustomClaims(t *testing.T) {
	payload := map[string]interface{}{
		"iss":          "issuer",
		"sub":          "agent",
		"custom_field": "custom_value",
		"org_id":       "org-123",
	}
	claims := ExtractClaims(payload)
	if claims.CustomClaims["custom_field"] != "custom_value" {
		t.Errorf("expected custom_field in custom claims, got %v", claims.CustomClaims)
	}
	if claims.CustomClaims["org_id"] != "org-123" {
		t.Errorf("expected org_id in custom claims, got %v", claims.CustomClaims)
	}
	// Known claims should NOT be in custom claims
	if _, ok := claims.CustomClaims["iss"]; ok {
		t.Error("iss should not be in custom claims")
	}
	if _, ok := claims.CustomClaims["sub"]; ok {
		t.Error("sub should not be in custom claims")
	}
}

func TestExtractClaims_SpiffeAgentID(t *testing.T) {
	payload := map[string]interface{}{
		"iss":      "issuer",
		"sub":      "spiffe://example.com/agent/bot",
		"agent_id": "spiffe://example.com/agent/bot",
	}
	claims := ExtractClaims(payload)
	if claims.SpiffeID == nil {
		t.Fatal("expected SpiffeID to be parsed")
	}
	if claims.SpiffeID.TrustDomain != "example.com" {
		t.Errorf("expected trust domain 'example.com', got %q", claims.SpiffeID.TrustDomain)
	}
}

func TestExtractClaims_AudienceArray(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "issuer",
		"sub": "agent",
		"aud": []interface{}{"api-1", "api-2"},
	}
	claims := ExtractClaims(payload)
	if len(claims.Audience) != 2 {
		t.Fatalf("expected 2 audiences, got %d", len(claims.Audience))
	}
	if claims.Audience[0] != "api-1" || claims.Audience[1] != "api-2" {
		t.Errorf("expected audiences [api-1, api-2], got %v", claims.Audience)
	}
}

// --- ValidateClaims ---

func validTestClaims() AgentIdentityClaims {
	now := time.Now().Unix()
	return AgentIdentityClaims{
		AgentID:   "agent-1",
		Issuer:    "https://auth.example.com",
		Subject:   "agent-1",
		Audience:  []string{"my-api"},
		ExpiresAt: now + 600,
		IssuedAt:  now,
		Scopes:    []string{"read"},
	}
}

func validTestConfig() AgentIdentityConfig {
	return AgentIdentityConfig{
		TrustedIssuers: []string{"https://auth.example.com"},
		Audience:       []string{"my-api"},
	}
}

func TestValidateClaims_Valid(t *testing.T) {
	err := ValidateClaims(validTestClaims(), validTestConfig())
	if err != nil {
		t.Errorf("expected no error for valid claims, got %v", err)
	}
}

func TestValidateClaims_UntrustedIssuer(t *testing.T) {
	claims := validTestClaims()
	claims.Issuer = "https://evil.example.com"
	err := ValidateClaims(claims, validTestConfig())
	if err == nil {
		t.Fatal("expected error for untrusted issuer")
	}
	if err.Code != "untrusted_issuer" {
		t.Errorf("expected code 'untrusted_issuer', got %q", err.Code)
	}
}

func TestValidateClaims_InvalidAudience(t *testing.T) {
	claims := validTestClaims()
	claims.Audience = []string{"wrong-api"}
	err := ValidateClaims(claims, validTestConfig())
	if err == nil {
		t.Fatal("expected error for invalid audience")
	}
	if err.Code != "invalid_audience" {
		t.Errorf("expected code 'invalid_audience', got %q", err.Code)
	}
}

func TestValidateClaims_ExpiredToken(t *testing.T) {
	claims := validTestClaims()
	claims.ExpiresAt = time.Now().Unix() - 3600 // expired 1 hour ago
	err := ValidateClaims(claims, validTestConfig())
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err.Code != "expired_token" {
		t.Errorf("expected code 'expired_token', got %q", err.Code)
	}
}

func TestValidateClaims_TooLongLived(t *testing.T) {
	claims := validTestClaims()
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = claims.IssuedAt + 7200 // 2 hours, exceeds default 3600
	err := ValidateClaims(claims, validTestConfig())
	if err == nil {
		t.Fatal("expected error for too long lived token")
	}
	if err.Code != "token_too_long_lived" {
		t.Errorf("expected code 'token_too_long_lived', got %q", err.Code)
	}
	if !strings.Contains(err.Message, "7200") {
		t.Errorf("expected message to include lifetime, got %q", err.Message)
	}
}

func TestValidateClaims_TooLongLived_CustomMax(t *testing.T) {
	claims := validTestClaims()
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = claims.IssuedAt + 500

	config := validTestConfig()
	config.MaxLifetimeSeconds = 300

	err := ValidateClaims(claims, config)
	if err == nil {
		t.Fatal("expected error for token exceeding custom max lifetime")
	}
	if err.Code != "token_too_long_lived" {
		t.Errorf("expected code 'token_too_long_lived', got %q", err.Code)
	}
}

func TestValidateClaims_UntrustedDomain(t *testing.T) {
	claims := validTestClaims()
	claims.SpiffeID = &SpiffeId{
		TrustDomain: "evil.com",
		Path:        "/agent",
		Raw:         "spiffe://evil.com/agent",
	}
	config := validTestConfig()
	config.TrustedDomains = []string{"trusted.com"}

	err := ValidateClaims(claims, config)
	if err == nil {
		t.Fatal("expected error for untrusted SPIFFE domain")
	}
	if err.Code != "untrusted_domain" {
		t.Errorf("expected code 'untrusted_domain', got %q", err.Code)
	}
}

func TestValidateClaims_TrustedDomain(t *testing.T) {
	claims := validTestClaims()
	claims.SpiffeID = &SpiffeId{
		TrustDomain: "trusted.com",
		Path:        "/agent",
		Raw:         "spiffe://trusted.com/agent",
	}
	config := validTestConfig()
	config.TrustedDomains = []string{"trusted.com"}

	err := ValidateClaims(claims, config)
	if err != nil {
		t.Errorf("expected no error for trusted domain, got %v", err)
	}
}

func TestValidateClaims_EmptyAudienceSkipsCheck(t *testing.T) {
	claims := validTestClaims()
	claims.Audience = nil
	err := ValidateClaims(claims, validTestConfig())
	if err != nil {
		t.Errorf("expected no audience error when audience is empty, got %v", err)
	}
}

// --- EvaluateAuthz ---

func TestEvaluateAuthz_MatchingPolicy(t *testing.T) {
	claims := AgentIdentityClaims{
		AgentID: "agent-bot",
		Scopes:  []string{"read", "write"},
	}
	policies := []AgentAuthzPolicy{
		{
			Name:           "allow-read-write",
			AgentPattern:   "agent-*",
			RequiredScopes: []string{"read"},
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %q", result.DeniedReason)
	}
	if result.MatchedPolicy != "allow-read-write" {
		t.Errorf("expected matched policy 'allow-read-write', got %q", result.MatchedPolicy)
	}
}

func TestEvaluateAuthz_NoMatchingPolicyDefaultDeny(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "unknown-agent"}
	policies := []AgentAuthzPolicy{
		{Name: "specific", AgentPattern: "known-*"},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if result.Allowed {
		t.Error("expected denied when no matching policy and default is deny")
	}
	if result.DeniedReason != "No matching authorization policy." {
		t.Errorf("unexpected denied reason: %q", result.DeniedReason)
	}
}

func TestEvaluateAuthz_NoMatchingPolicyDefaultAllow(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "unknown-agent"}
	policies := []AgentAuthzPolicy{
		{Name: "specific", AgentPattern: "known-*"},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "allow")
	if !result.Allowed {
		t.Error("expected allowed when no matching policy and default is allow")
	}
}

func TestEvaluateAuthz_DefaultPolicyIsEmpty(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "unknown-agent"}
	result := EvaluateAuthz(claims, AuthzContext{}, nil, "")
	if result.Allowed {
		t.Error("expected denied when default policy is empty (defaults to deny)")
	}
}

func TestEvaluateAuthz_RequiredScopesMissing(t *testing.T) {
	claims := AgentIdentityClaims{
		AgentID: "agent-bot",
		Scopes:  []string{"read"},
	}
	policies := []AgentAuthzPolicy{
		{
			Name:           "need-write",
			AgentPattern:   "agent-*",
			RequiredScopes: []string{"read", "write", "admin"},
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if result.Allowed {
		t.Error("expected denied for missing scopes")
	}
	if !strings.Contains(result.DeniedReason, "write") {
		t.Errorf("expected denied reason to mention 'write', got %q", result.DeniedReason)
	}
	if !strings.Contains(result.DeniedReason, "admin") {
		t.Errorf("expected denied reason to mention 'admin', got %q", result.DeniedReason)
	}
}

func TestEvaluateAuthz_DelegatedAccessDenied(t *testing.T) {
	allowDelegated := false
	claims := AgentIdentityClaims{
		AgentID:   "agent-bot",
		Delegated: true,
	}
	policies := []AgentAuthzPolicy{
		{
			Name:           "no-delegation",
			AgentPattern:   "agent-*",
			AllowDelegated: &allowDelegated,
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if result.Allowed {
		t.Error("expected denied for delegated access")
	}
	if result.DeniedReason != "Delegated access not allowed by policy." {
		t.Errorf("unexpected denied reason: %q", result.DeniedReason)
	}
}

func TestEvaluateAuthz_DelegatedAccessAllowed(t *testing.T) {
	allowDelegated := true
	claims := AgentIdentityClaims{
		AgentID:   "agent-bot",
		Delegated: true,
	}
	policies := []AgentAuthzPolicy{
		{
			Name:           "allow-delegation",
			AgentPattern:   "agent-*",
			AllowDelegated: &allowDelegated,
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if !result.Allowed {
		t.Errorf("expected allowed for delegated access when policy allows it, got: %q", result.DeniedReason)
	}
}

func TestEvaluateAuthz_CustomEvaluator(t *testing.T) {
	claims := AgentIdentityClaims{
		AgentID: "agent-bot",
		CustomClaims: map[string]interface{}{
			"org_id": "org-allowed",
		},
	}
	policies := []AgentAuthzPolicy{
		{
			Name:         "custom-check",
			AgentPattern: "*",
			Evaluate: func(c AgentIdentityClaims, ctx AuthzContext) bool {
				return c.CustomClaims["org_id"] == "org-allowed"
			},
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if !result.Allowed {
		t.Errorf("expected allowed by custom evaluator, got: %q", result.DeniedReason)
	}
}

func TestEvaluateAuthz_CustomEvaluatorDenies(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "agent-bot"}
	policies := []AgentAuthzPolicy{
		{
			Name:         "always-deny",
			AgentPattern: "*",
			Evaluate: func(c AgentIdentityClaims, ctx AuthzContext) bool {
				return false
			},
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "allow")
	if result.Allowed {
		t.Error("expected denied by custom evaluator")
	}
	if result.DeniedReason != "Custom policy evaluation denied access." {
		t.Errorf("unexpected denied reason: %q", result.DeniedReason)
	}
}

func TestEvaluateAuthz_MethodMatching(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "agent-bot"}
	policies := []AgentAuthzPolicy{
		{
			Name:         "get-only",
			AgentPattern: "*",
			Methods:      []string{"GET"},
		},
	}

	// GET should match
	result := EvaluateAuthz(claims, AuthzContext{Method: "GET"}, policies, "deny")
	if !result.Allowed {
		t.Error("expected GET to be allowed")
	}

	// POST should not match, falls to default deny
	result = EvaluateAuthz(claims, AuthzContext{Method: "POST"}, policies, "deny")
	if result.Allowed {
		t.Error("expected POST to be denied")
	}
}

func TestEvaluateAuthz_MethodMatchingCaseInsensitive(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "agent-bot"}
	policies := []AgentAuthzPolicy{
		{
			Name:         "get-only",
			AgentPattern: "*",
			Methods:      []string{"GET"},
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{Method: "get"}, policies, "deny")
	if !result.Allowed {
		t.Error("expected case-insensitive method match")
	}
}

func TestEvaluateAuthz_PathMatching(t *testing.T) {
	claims := AgentIdentityClaims{AgentID: "agent-bot"}
	policies := []AgentAuthzPolicy{
		{
			Name:         "api-only",
			AgentPattern: "*",
			Paths:        []string{"/api/*"},
		},
	}

	result := EvaluateAuthz(claims, AuthzContext{Path: "/api/v1/users"}, policies, "deny")
	if !result.Allowed {
		t.Error("expected /api/v1/users to match /api/*")
	}

	result = EvaluateAuthz(claims, AuthzContext{Path: "/admin/settings"}, policies, "deny")
	if result.Allowed {
		t.Error("expected /admin/settings to not match /api/*")
	}
}

func TestEvaluateAuthz_TrustDomainMatching(t *testing.T) {
	claims := AgentIdentityClaims{
		AgentID: "spiffe://trusted.com/agent",
		SpiffeID: &SpiffeId{
			TrustDomain: "trusted.com",
			Path:        "/agent",
			Raw:         "spiffe://trusted.com/agent",
		},
	}
	policies := []AgentAuthzPolicy{
		{
			Name:         "trusted-only",
			AgentPattern: "*",
			TrustDomains: []string{"trusted.com"},
		},
	}
	result := EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if !result.Allowed {
		t.Error("expected allowed for trusted domain")
	}

	// Untrusted domain should not match
	claims.SpiffeID.TrustDomain = "untrusted.com"
	result = EvaluateAuthz(claims, AuthzContext{}, policies, "deny")
	if result.Allowed {
		t.Error("expected denied for untrusted domain")
	}
}

// --- BuildAuditEvent ---

func TestBuildAuditEvent(t *testing.T) {
	claims := AgentIdentityClaims{
		AgentID:     "agent-1",
		Issuer:      "https://auth.example.com",
		Delegated:   true,
		DelegatedBy: "parent-agent",
		Scopes:      []string{"read", "write"},
		SpiffeID: &SpiffeId{
			TrustDomain: "example.com",
			Path:        "/agent/1",
			Raw:         "spiffe://example.com/agent/1",
		},
	}
	ctx := AuthzContext{Method: "POST", Path: "/api/data"}
	authzResult := AuthzResult{Allowed: true, MatchedPolicy: "test-policy"}

	event := BuildAuditEvent(claims, ctx, authzResult)

	if event.Type != "agent_identity" {
		t.Errorf("expected type 'agent_identity', got %q", event.Type)
	}
	if event.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	// Verify timestamp is parseable
	_, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		t.Errorf("expected RFC3339Nano timestamp, got %q: %v", event.Timestamp, err)
	}
	if event.AgentID != "agent-1" {
		t.Errorf("expected AgentID 'agent-1', got %q", event.AgentID)
	}
	if event.SpiffeID != "spiffe://example.com/agent/1" {
		t.Errorf("expected SpiffeID raw, got %q", event.SpiffeID)
	}
	if event.Issuer != "https://auth.example.com" {
		t.Errorf("expected Issuer, got %q", event.Issuer)
	}
	if !event.Delegated {
		t.Error("expected Delegated to be true")
	}
	if event.DelegatedBy != "parent-agent" {
		t.Errorf("expected DelegatedBy 'parent-agent', got %q", event.DelegatedBy)
	}
	if len(event.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(event.Scopes))
	}
	if event.Method != "POST" {
		t.Errorf("expected Method 'POST', got %q", event.Method)
	}
	if event.Path != "/api/data" {
		t.Errorf("expected Path '/api/data', got %q", event.Path)
	}
	if !event.AuthzResult.Allowed {
		t.Error("expected AuthzResult.Allowed to be true")
	}
	if event.AuthzResult.MatchedPolicy != "test-policy" {
		t.Errorf("expected matched policy 'test-policy', got %q", event.AuthzResult.MatchedPolicy)
	}
}

func TestBuildAuditEvent_NoSpiffe(t *testing.T) {
	claims := AgentIdentityClaims{
		AgentID: "agent-no-spiffe",
		Issuer:  "issuer",
		Scopes:  []string{},
	}
	ctx := AuthzContext{Method: "GET", Path: "/"}
	authzResult := AuthzResult{Allowed: false, DeniedReason: "no policy"}

	event := BuildAuditEvent(claims, ctx, authzResult)
	if event.SpiffeID != "" {
		t.Errorf("expected empty SpiffeID, got %q", event.SpiffeID)
	}
	if event.AuthzResult.Allowed {
		t.Error("expected AuthzResult.Allowed to be false")
	}
}
