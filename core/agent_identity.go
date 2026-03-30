package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SpiffeId is a SPIFFE ID in URI form.
type SpiffeId struct {
	TrustDomain string `json:"trustDomain"`
	Path        string `json:"path"`
	Raw         string `json:"raw"`
}

// AgentIdentityClaims are claims extracted from an agent identity token.
type AgentIdentityClaims struct {
	AgentID      string                 `json:"agentId"`
	SpiffeID     *SpiffeId              `json:"spiffeId,omitempty"`
	Issuer       string                 `json:"issuer"`
	Subject      string                 `json:"subject"`
	Audience     []string               `json:"audience"`
	ExpiresAt    int64                  `json:"expiresAt"`
	IssuedAt     int64                  `json:"issuedAt"`
	Scopes       []string               `json:"scopes"`
	Delegated    bool                   `json:"delegated"`
	DelegatedBy  string                 `json:"delegatedBy,omitempty"`
	CustomClaims map[string]interface{} `json:"customClaims"`
}

// AgentAuthzPolicy is a policy rule for agent authorization.
type AgentAuthzPolicy struct {
	Name           string
	AgentPattern   string
	TrustDomains   []string
	RequiredScopes []string
	Methods        []string
	Paths          []string
	AllowDelegated *bool
	Evaluate       func(claims AgentIdentityClaims, context AuthzContext) bool
}

// AuthzContext is the context for authorization evaluation.
type AuthzContext struct {
	Method  string
	Path    string
	Headers map[string]string
}

// AuthzResult is the result of authorization evaluation.
type AuthzResult struct {
	Allowed       bool   `json:"allowed"`
	MatchedPolicy string `json:"matchedPolicy,omitempty"`
	DeniedReason  string `json:"deniedReason,omitempty"`
}

// AgentIdentityConfig configures the agent identity module.
type AgentIdentityConfig struct {
	TrustedIssuers     []string
	Audience           []string
	JwksEndpoints      map[string]string
	TrustedDomains     []string
	Policies           []AgentAuthzPolicy
	DefaultPolicy      string // "allow" or "deny"
	VerifyToken        func(token string) (*AgentIdentityClaims, error)
	HeaderName         string
	TokenPrefix        string
	ClockSkewSeconds   int64
	MaxLifetimeSeconds int64
}

// TokenValidationError represents a token validation error.
type TokenValidationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *TokenValidationError) Error() string {
	return e.Message
}

// AgentIdentityAuditEvent is an audit event for agent identity.
type AgentIdentityAuditEvent struct {
	Type        string      `json:"type"`
	Timestamp   string      `json:"timestamp"`
	AgentID     string      `json:"agentId"`
	SpiffeID    string      `json:"spiffeId,omitempty"`
	Issuer      string      `json:"issuer"`
	Delegated   bool        `json:"delegated"`
	DelegatedBy string      `json:"delegatedBy,omitempty"`
	Scopes      []string    `json:"scopes"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	AuthzResult AuthzResult `json:"authzResult"`
}

var spiffeRe = regexp.MustCompile(`^spiffe://([^/]+)(/.*)?$`)

// ParseSpiffeId parses a SPIFFE ID URI.
func ParseSpiffeId(uri string) *SpiffeId {
	m := spiffeRe.FindStringSubmatch(uri)
	if m == nil {
		return nil
	}
	path := m[2]
	if path == "" {
		path = "/"
	}
	return &SpiffeId{
		TrustDomain: m[1],
		Path:        path,
		Raw:         uri,
	}
}

// IsSpiffeTrusted validates a SPIFFE ID against trusted domains.
func IsSpiffeTrusted(spiffeId *SpiffeId, trustedDomains []string) bool {
	for _, d := range trustedDomains {
		if d == spiffeId.TrustDomain {
			return true
		}
	}
	return false
}

func base64urlDecode(s string) ([]byte, error) {
	// Add padding
	padding := (4 - len(s)%4) % 4
	s += strings.Repeat("=", padding)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}

// DecodeJwtClaims decodes JWT claims WITHOUT verification.
func DecodeJwtClaims(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	decoded, err := base64urlDecode(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil
	}
	return claims
}

var knownClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"nbf": true, "jti": true, "scope": true, "scopes": true, "scp": true,
	"act": true, "agent_id": true,
}

// ExtractClaims extracts AgentIdentityClaims from raw JWT payload.
func ExtractClaims(payload map[string]interface{}) AgentIdentityClaims {
	iss := toString(payload["iss"])
	sub := toString(payload["sub"])

	agentID := toString(payload["agent_id"])
	if agentID == "" {
		agentID = sub
	}

	spiffeId := ParseSpiffeId(agentID)

	// Audience normalization
	var audience []string
	switch v := payload["aud"].(type) {
	case []interface{}:
		for _, a := range v {
			audience = append(audience, toString(a))
		}
	case string:
		audience = []string{v}
	}

	// Scopes
	var scopes []string
	if scopeStr, ok := payload["scope"].(string); ok {
		for _, s := range strings.Split(scopeStr, " ") {
			if s != "" {
				scopes = append(scopes, s)
			}
		}
	} else if scopeArr, ok := payload["scopes"].([]interface{}); ok {
		for _, s := range scopeArr {
			scopes = append(scopes, toString(s))
		}
	} else if scpArr, ok := payload["scp"].([]interface{}); ok {
		for _, s := range scpArr {
			scopes = append(scopes, toString(s))
		}
	}

	// Delegation
	delegated := payload["act"] != nil
	var delegatedBy string
	if delegated {
		if act, ok := payload["act"].(map[string]interface{}); ok {
			delegatedBy = toString(act["sub"])
		}
	}

	// Custom claims
	customClaims := map[string]interface{}{}
	for k, v := range payload {
		if !knownClaims[k] {
			customClaims[k] = v
		}
	}

	return AgentIdentityClaims{
		AgentID:      agentID,
		SpiffeID:     spiffeId,
		Issuer:       iss,
		Subject:      sub,
		Audience:     audience,
		ExpiresAt:    toInt64(payload["exp"]),
		IssuedAt:     toInt64(payload["iat"]),
		Scopes:       scopes,
		Delegated:    delegated,
		DelegatedBy:  delegatedBy,
		CustomClaims: customClaims,
	}
}

// ValidateClaims validates extracted claims against the identity config.
func ValidateClaims(claims AgentIdentityClaims, config AgentIdentityConfig) *TokenValidationError {
	now := time.Now().Unix()
	skew := config.ClockSkewSeconds
	if skew == 0 {
		skew = 30
	}

	// Check issuer
	trusted := false
	for _, iss := range config.TrustedIssuers {
		if iss == claims.Issuer {
			trusted = true
			break
		}
	}
	if !trusted {
		return &TokenValidationError{
			Code:    "untrusted_issuer",
			Message: fmt.Sprintf(`Issuer "%s" is not trusted.`, claims.Issuer),
		}
	}

	// Check audience
	if len(claims.Audience) > 0 {
		audMatch := false
		for _, a := range claims.Audience {
			for _, expected := range config.Audience {
				if a == expected {
					audMatch = true
					break
				}
			}
			if audMatch {
				break
			}
		}
		if !audMatch {
			return &TokenValidationError{
				Code:    "invalid_audience",
				Message: "Token audience does not match any expected audience.",
			}
		}
	}

	// Check expiration
	if claims.ExpiresAt != 0 && claims.ExpiresAt+skew < now {
		return &TokenValidationError{
			Code:    "expired_token",
			Message: "Token has expired.",
		}
	}

	// Check max lifetime
	maxLifetime := config.MaxLifetimeSeconds
	if maxLifetime == 0 {
		maxLifetime = 3600
	}
	if claims.IssuedAt != 0 && claims.ExpiresAt != 0 {
		lifetime := claims.ExpiresAt - claims.IssuedAt
		if lifetime > maxLifetime {
			return &TokenValidationError{
				Code:    "token_too_long_lived",
				Message: fmt.Sprintf("Token lifetime %ds exceeds maximum %ds.", lifetime, maxLifetime),
			}
		}
	}

	// Check SPIFFE trust domain
	if claims.SpiffeID != nil && len(config.TrustedDomains) > 0 {
		if !IsSpiffeTrusted(claims.SpiffeID, config.TrustedDomains) {
			return &TokenValidationError{
				Code:    "untrusted_domain",
				Message: fmt.Sprintf(`SPIFFE trust domain "%s" is not trusted.`, claims.SpiffeID.TrustDomain),
			}
		}
	}

	return nil
}

func globMatch(pattern, value string) bool {
	// Escape regex special chars except *
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	re, err := regexp.Compile("^" + escaped + "$")
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// EvaluateAuthz evaluates authorization policies against verified claims.
func EvaluateAuthz(
	claims AgentIdentityClaims,
	context AuthzContext,
	policies []AgentAuthzPolicy,
	defaultPolicy string,
) AuthzResult {
	if defaultPolicy == "" {
		defaultPolicy = "deny"
	}

	for _, policy := range policies {
		// Match agent pattern
		if policy.AgentPattern != "" && !globMatch(policy.AgentPattern, claims.AgentID) {
			continue
		}

		// Match trust domain
		if len(policy.TrustDomains) > 0 && claims.SpiffeID != nil {
			found := false
			for _, d := range policy.TrustDomains {
				if d == claims.SpiffeID.TrustDomain {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Match method
		if len(policy.Methods) > 0 {
			found := false
			for _, m := range policy.Methods {
				if strings.EqualFold(m, context.Method) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Match path
		if len(policy.Paths) > 0 {
			pathMatch := false
			for _, p := range policy.Paths {
				if globMatch(p, context.Path) {
					pathMatch = true
					break
				}
			}
			if !pathMatch {
				continue
			}
		}

		// Check delegation
		if policy.AllowDelegated != nil && !*policy.AllowDelegated && claims.Delegated {
			return AuthzResult{
				Allowed:       false,
				MatchedPolicy: policy.Name,
				DeniedReason:  "Delegated access not allowed by policy.",
			}
		}

		// Check required scopes
		if len(policy.RequiredScopes) > 0 {
			var missing []string
			for _, req := range policy.RequiredScopes {
				found := false
				for _, s := range claims.Scopes {
					if s == req {
						found = true
						break
					}
				}
				if !found {
					missing = append(missing, req)
				}
			}
			if len(missing) > 0 {
				return AuthzResult{
					Allowed:       false,
					MatchedPolicy: policy.Name,
					DeniedReason:  fmt.Sprintf("Missing required scopes: %s", strings.Join(missing, ", ")),
				}
			}
		}

		// Custom evaluator
		if policy.Evaluate != nil && !policy.Evaluate(claims, context) {
			return AuthzResult{
				Allowed:       false,
				MatchedPolicy: policy.Name,
				DeniedReason:  "Custom policy evaluation denied access.",
			}
		}

		// All checks passed
		return AuthzResult{Allowed: true, MatchedPolicy: policy.Name}
	}

	// No policy matched
	allowed := defaultPolicy == "allow"
	result := AuthzResult{Allowed: allowed}
	if !allowed {
		result.DeniedReason = "No matching authorization policy."
	}
	return result
}

// BuildAuditEvent builds an audit event from identity verification results.
func BuildAuditEvent(claims AgentIdentityClaims, context AuthzContext, authzResult AuthzResult) AgentIdentityAuditEvent {
	event := AgentIdentityAuditEvent{
		Type:        "agent_identity",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		AgentID:     claims.AgentID,
		Issuer:      claims.Issuer,
		Delegated:   claims.Delegated,
		DelegatedBy: claims.DelegatedBy,
		Scopes:      claims.Scopes,
		Method:      context.Method,
		Path:        context.Path,
		AuthzResult: authzResult,
	}
	if claims.SpiffeID != nil {
		event.SpiffeID = claims.SpiffeID.Raw
	}
	return event
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}
