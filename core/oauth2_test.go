package core

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func makeToken(payload map[string]interface{}) string {
	data, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return "header." + encoded + ".signature"
}

func TestGenerateCodeVerifier_DefaultLength(t *testing.T) {
	verifier := GenerateCodeVerifier(0)
	if len(verifier) != 64 {
		t.Errorf("expected length 64, got %d", len(verifier))
	}
}

func TestGenerateCodeVerifier_CustomLength(t *testing.T) {
	verifier := GenerateCodeVerifier(128)
	if len(verifier) != 128 {
		t.Errorf("expected length 128, got %d", len(verifier))
	}
}

func TestGenerateCodeVerifier_OnlyUnreservedChars(t *testing.T) {
	verifier := GenerateCodeVerifier(256)
	for _, ch := range verifier {
		if !strings.ContainsRune(unreservedChars, ch) {
			t.Errorf("verifier contains invalid character: %c", ch)
		}
	}
}

func TestGenerateCodeVerifier_Uniqueness(t *testing.T) {
	v1 := GenerateCodeVerifier(64)
	v2 := GenerateCodeVerifier(64)
	if v1 == v2 {
		t.Error("two generated verifiers should not be identical")
	}
}

func TestComputeCodeChallenge_Deterministic(t *testing.T) {
	verifier := "test-verifier-12345"
	c1 := ComputeCodeChallenge(verifier)
	c2 := ComputeCodeChallenge(verifier)
	if c1 != c2 {
		t.Errorf("expected same challenge for same verifier, got %s and %s", c1, c2)
	}
}

func TestComputeCodeChallenge_DifferentInputs(t *testing.T) {
	c1 := ComputeCodeChallenge("verifier-a")
	c2 := ComputeCodeChallenge("verifier-b")
	if c1 == c2 {
		t.Error("different verifiers should produce different challenges")
	}
}

func TestComputeCodeChallenge_Base64UrlEncoded(t *testing.T) {
	challenge := ComputeCodeChallenge("some-verifier")
	// base64url should not contain + / =
	if strings.ContainsAny(challenge, "+/=") {
		t.Errorf("challenge should be base64url encoded (no +, /, =), got: %s", challenge)
	}
}

func TestGeneratePKCE(t *testing.T) {
	pair := GeneratePKCE(0)
	if pair.CodeVerifier == "" {
		t.Error("expected non-empty code verifier")
	}
	if pair.CodeChallenge == "" {
		t.Error("expected non-empty code challenge")
	}
	if len(pair.CodeVerifier) != 64 {
		t.Errorf("expected verifier length 64, got %d", len(pair.CodeVerifier))
	}

	// Verify the challenge matches the verifier
	expected := ComputeCodeChallenge(pair.CodeVerifier)
	if pair.CodeChallenge != expected {
		t.Errorf("code challenge does not match verifier")
	}
}

func TestGeneratePKCE_CustomLength(t *testing.T) {
	pair := GeneratePKCE(32)
	if len(pair.CodeVerifier) != 32 {
		t.Errorf("expected verifier length 32, got %d", len(pair.CodeVerifier))
	}
}

func TestBuildAuthorizationUrl_IncludesAllParams(t *testing.T) {
	config := OAuth2Config{
		ClientID:              "my-client",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		RedirectURI:           "https://app.example.com/callback",
	}

	url := BuildAuthorizationUrl(config, "state-abc", "challenge-xyz", []string{"read", "write"})

	if !strings.Contains(url, "response_type=code") {
		t.Error("expected response_type=code")
	}
	if !strings.Contains(url, "client_id=my-client") {
		t.Error("expected client_id")
	}
	if !strings.Contains(url, "state=state-abc") {
		t.Error("expected state")
	}
	if !strings.Contains(url, "code_challenge=challenge-xyz") {
		t.Error("expected code_challenge")
	}
	if !strings.Contains(url, "code_challenge_method=S256") {
		t.Error("expected code_challenge_method=S256")
	}
	if !strings.Contains(url, "redirect_uri=") {
		t.Error("expected redirect_uri")
	}
}

func TestBuildAuthorizationUrl_ScopesFromParam(t *testing.T) {
	config := OAuth2Config{
		ClientID:              "my-client",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		RedirectURI:           "https://app.example.com/callback",
	}

	url := BuildAuthorizationUrl(config, "state", "challenge", []string{"openid", "profile"})
	// Scopes are joined by space which is URL-encoded as +
	if !strings.Contains(url, "scope=openid") {
		t.Error("expected scope parameter with openid")
	}
}

func TestBuildAuthorizationUrl_ScopesFromConfig(t *testing.T) {
	config := OAuth2Config{
		ClientID:              "my-client",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		RedirectURI:           "https://app.example.com/callback",
		Scopes:                map[string]string{"read": "Read access"},
	}

	url := BuildAuthorizationUrl(config, "state", "challenge", nil)
	if !strings.Contains(url, "scope=read") {
		t.Error("expected scope from config")
	}
}

func TestBuildAuthorizationUrl_NoScopes(t *testing.T) {
	config := OAuth2Config{
		ClientID:              "my-client",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		RedirectURI:           "https://app.example.com/callback",
	}

	url := BuildAuthorizationUrl(config, "state", "challenge", nil)
	if strings.Contains(url, "scope=") {
		t.Error("expected no scope param when no scopes provided")
	}
}

func TestExtractBearerToken_Valid(t *testing.T) {
	token := ExtractBearerToken("Bearer my-secret-token")
	if token != "my-secret-token" {
		t.Errorf("expected my-secret-token, got %s", token)
	}
}

func TestExtractBearerToken_CaseInsensitive(t *testing.T) {
	token := ExtractBearerToken("bearer my-token")
	if token != "my-token" {
		t.Errorf("expected my-token, got %s", token)
	}

	token2 := ExtractBearerToken("BEARER my-token")
	if token2 != "my-token" {
		t.Errorf("expected my-token, got %s", token2)
	}
}

func TestExtractBearerToken_Empty(t *testing.T) {
	token := ExtractBearerToken("")
	if token != "" {
		t.Errorf("expected empty string, got %s", token)
	}
}

func TestExtractBearerToken_InvalidPrefix(t *testing.T) {
	token := ExtractBearerToken("Basic abc123")
	if token != "" {
		t.Errorf("expected empty for non-Bearer scheme, got %s", token)
	}
}

func TestExtractBearerToken_NoSpace(t *testing.T) {
	token := ExtractBearerToken("Bearertoken")
	if token != "" {
		t.Errorf("expected empty for missing space, got %s", token)
	}
}

func TestValidateAccessToken_Valid(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	token := makeToken(map[string]interface{}{
		"sub":   "user-123",
		"exp":   futureExp,
		"iss":   "https://auth.example.com",
		"aud":   "my-api",
		"scope": "read write",
	})

	config := OAuth2Config{
		Issuer:   "https://auth.example.com",
		Audience: "my-api",
	}

	result := ValidateAccessToken(token, config, []string{"read"}, 0)
	if !result.Valid {
		t.Errorf("expected valid token, got error: %s", result.Error)
	}
	if result.Token == nil {
		t.Fatal("expected decoded token")
	}
	if result.Token.Sub != "user-123" {
		t.Errorf("expected sub user-123, got %s", result.Token.Sub)
	}
	if len(result.Token.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(result.Token.Scopes))
	}
}

func TestValidateAccessToken_Expired(t *testing.T) {
	pastExp := time.Now().Unix() - 3600
	token := makeToken(map[string]interface{}{
		"sub": "user-123",
		"exp": pastExp,
	})

	result := ValidateAccessToken(token, OAuth2Config{}, nil, 0)
	if result.Valid {
		t.Error("expected invalid for expired token")
	}
	if result.Error != "token_expired" {
		t.Errorf("expected token_expired error, got %s", result.Error)
	}
}

func TestValidateAccessToken_InvalidIssuer(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	token := makeToken(map[string]interface{}{
		"sub": "user-123",
		"exp": futureExp,
		"iss": "https://wrong.example.com",
	})

	config := OAuth2Config{
		Issuer: "https://auth.example.com",
	}

	result := ValidateAccessToken(token, config, nil, 0)
	if result.Valid {
		t.Error("expected invalid for wrong issuer")
	}
	if result.Error != "invalid_issuer" {
		t.Errorf("expected invalid_issuer, got %s", result.Error)
	}
}

func TestValidateAccessToken_InvalidAudience(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	token := makeToken(map[string]interface{}{
		"sub": "user-123",
		"exp": futureExp,
		"aud": "wrong-api",
	})

	config := OAuth2Config{
		Audience: "my-api",
	}

	result := ValidateAccessToken(token, config, nil, 0)
	if result.Valid {
		t.Error("expected invalid for wrong audience")
	}
	if result.Error != "invalid_audience" {
		t.Errorf("expected invalid_audience, got %s", result.Error)
	}
}

func TestValidateAccessToken_AudienceArray(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	token := makeToken(map[string]interface{}{
		"sub": "user-123",
		"exp": futureExp,
		"aud": []string{"api-1", "my-api", "api-2"},
	})

	config := OAuth2Config{
		Audience: "my-api",
	}

	result := ValidateAccessToken(token, config, nil, 0)
	if !result.Valid {
		t.Errorf("expected valid for audience array containing target, got: %s", result.Error)
	}
}

func TestValidateAccessToken_MissingScopes(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	token := makeToken(map[string]interface{}{
		"sub":   "user-123",
		"exp":   futureExp,
		"scope": "read",
	})

	result := ValidateAccessToken(token, OAuth2Config{}, []string{"read", "admin"}, 0)
	if result.Valid {
		t.Error("expected invalid for missing scopes")
	}
	if !strings.Contains(result.Error, "missing_scopes") {
		t.Errorf("expected missing_scopes error, got %s", result.Error)
	}
	if !strings.Contains(result.Error, "admin") {
		t.Errorf("expected 'admin' in missing scopes, got %s", result.Error)
	}
}

func TestValidateAccessToken_ScopesFromArray(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	token := makeToken(map[string]interface{}{
		"sub":    "user-123",
		"exp":    futureExp,
		"scopes": []string{"read", "write"},
	})

	result := ValidateAccessToken(token, OAuth2Config{}, []string{"read"}, 0)
	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.Error)
	}
}

func TestValidateAccessToken_MalformedToken(t *testing.T) {
	result := ValidateAccessToken("not-a-jwt", OAuth2Config{}, nil, 0)
	if result.Valid {
		t.Error("expected invalid for malformed token")
	}
	if result.Error != "malformed_token" {
		t.Errorf("expected malformed_token, got %s", result.Error)
	}
}

func TestValidateAccessToken_ClockSkew(t *testing.T) {
	// Token expired 10 seconds ago
	recentExp := time.Now().Unix() - 10
	token := makeToken(map[string]interface{}{
		"sub": "user-123",
		"exp": recentExp,
	})

	// With 30s clock skew (default), this should still be valid
	result := ValidateAccessToken(token, OAuth2Config{}, nil, 30)
	if !result.Valid {
		t.Errorf("expected valid with clock skew, got error: %s", result.Error)
	}
}

func TestValidateAccessToken_NoExpiry(t *testing.T) {
	token := makeToken(map[string]interface{}{
		"sub": "user-123",
	})

	result := ValidateAccessToken(token, OAuth2Config{}, nil, 0)
	if !result.Valid {
		t.Errorf("expected valid when no exp, got error: %s", result.Error)
	}
}

func TestValidateAccessToken_DecodedTokenFields(t *testing.T) {
	futureExp := time.Now().Unix() + 3600
	iat := time.Now().Unix()
	token := makeToken(map[string]interface{}{
		"sub":       "user-123",
		"exp":       futureExp,
		"iat":       iat,
		"iss":       "https://auth.example.com",
		"aud":       "my-api",
		"client_id": "client-abc",
		"scope":     "read write",
	})

	result := ValidateAccessToken(token, OAuth2Config{}, nil, 0)
	if !result.Valid {
		t.Fatalf("expected valid, got: %s", result.Error)
	}
	tk := result.Token
	if tk.Sub != "user-123" {
		t.Errorf("sub: got %s", tk.Sub)
	}
	if tk.Iss != "https://auth.example.com" {
		t.Errorf("iss: got %s", tk.Iss)
	}
	if tk.ClientID != "client-abc" {
		t.Errorf("client_id: got %s", tk.ClientID)
	}
	if tk.Iat == nil {
		t.Error("expected iat to be set")
	}
	if tk.Claims == nil {
		t.Error("expected claims map")
	}
}

func TestBuildOAuth2Metadata(t *testing.T) {
	config := OAuth2Config{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		Issuer:                "https://auth.example.com",
		Scopes:                map[string]string{"read": "Read", "write": "Write"},
	}

	metadata := BuildOAuth2Metadata(config)

	if metadata["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Error("expected authorization_endpoint")
	}
	if metadata["token_endpoint"] != "https://auth.example.com/token" {
		t.Error("expected token_endpoint")
	}
	if metadata["issuer"] != "https://auth.example.com" {
		t.Error("expected issuer")
	}

	responseTypes := metadata["response_types_supported"].([]string)
	if len(responseTypes) != 1 || responseTypes[0] != "code" {
		t.Error("expected response_types_supported [code]")
	}

	grantTypes := metadata["grant_types_supported"].([]string)
	if len(grantTypes) != 2 {
		t.Error("expected 2 grant types")
	}

	methods := metadata["code_challenge_methods_supported"].([]string)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Error("expected S256 code challenge method")
	}

	authMethods := metadata["token_endpoint_auth_methods_supported"].([]string)
	if authMethods[0] != "none" {
		t.Errorf("expected 'none' auth method without client secret, got %s", authMethods[0])
	}

	scopes := metadata["scopes_supported"].([]string)
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}
}

func TestBuildOAuth2Metadata_WithClientSecret(t *testing.T) {
	config := OAuth2Config{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		ClientSecret:          "secret-123",
	}

	metadata := BuildOAuth2Metadata(config)
	authMethods := metadata["token_endpoint_auth_methods_supported"].([]string)
	if authMethods[0] != "client_secret_post" {
		t.Errorf("expected client_secret_post with secret, got %s", authMethods[0])
	}
}

func TestBuildOAuth2Metadata_NoIssuer(t *testing.T) {
	config := OAuth2Config{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}

	metadata := BuildOAuth2Metadata(config)
	if _, ok := metadata["issuer"]; ok {
		t.Error("expected no issuer field when not configured")
	}
}
