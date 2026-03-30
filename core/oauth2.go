package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/rand"
)

// OAuth2Config configures the OAuth2 module.
type OAuth2Config struct {
	ClientID              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	RedirectURI           string
	Scopes                map[string]string
	TokenTTL              int
	Issuer                string
	Audience              string
}

// TokenResponse is the response from a token exchange.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// PKCEPair is a code verifier + code challenge pair.
type PKCEPair struct {
	CodeVerifier  string
	CodeChallenge string
}

// OAuth2Error is an OAuth2 error response.
type OAuth2Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// DecodedAccessToken is a decoded JWT access token.
type DecodedAccessToken struct {
	Sub      string                 `json:"sub"`
	Iss      string                 `json:"iss,omitempty"`
	Aud      interface{}            `json:"aud,omitempty"`
	Exp      int64                  `json:"exp"`
	Iat      *int64                 `json:"iat,omitempty"`
	Scopes   []string               `json:"scopes"`
	ClientID string                 `json:"client_id,omitempty"`
	Claims   map[string]interface{} `json:"claims"`
}

// TokenValidationResult is the result of validating an access token.
type OAuth2TokenValidationResult struct {
	Valid bool
	Token *DecodedAccessToken
	Error string
}

// OAuth2HttpClient is a pluggable HTTP client for token exchange.
type OAuth2HttpClient interface {
	Post(url string, body url.Values, headers map[string]string) (int, []byte, error)
}

// OAuth2TokenError is an error from token operations.
type OAuth2TokenError struct {
	Message    string
	ErrorCode  string
	StatusCode int
}

func (e *OAuth2TokenError) Error() string {
	return e.Message
}

// Characters allowed in code_verifier (RFC 7636).
const unreservedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// GenerateCodeVerifier generates a cryptographically random code verifier.
func GenerateCodeVerifier(length int) string {
	if length == 0 {
		length = 64
	}
	b := make([]byte, length)
	_, _ = rand.Read(b)
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = unreservedChars[int(b[i])%len(unreservedChars)]
	}
	return string(result)
}

// ComputeCodeChallenge computes the S256 code challenge from a verifier.
func ComputeCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GeneratePKCE generates a PKCE code verifier + code challenge pair.
func GeneratePKCE(verifierLength int) PKCEPair {
	if verifierLength == 0 {
		verifierLength = 64
	}
	verifier := GenerateCodeVerifier(verifierLength)
	challenge := ComputeCodeChallenge(verifier)
	return PKCEPair{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}
}

// BuildAuthorizationUrl builds the authorization URL for the code flow with PKCE.
func BuildAuthorizationUrl(config OAuth2Config, state, codeChallenge string, scopes []string) string {
	u, _ := url.Parse(config.AuthorizationEndpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", config.ClientID)
	q.Set("redirect_uri", config.RedirectURI)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	scopeList := scopes
	if len(scopeList) == 0 && config.Scopes != nil {
		for k := range config.Scopes {
			scopeList = append(scopeList, k)
		}
	}
	if len(scopeList) > 0 {
		q.Set("scope", strings.Join(scopeList, " "))
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// DefaultOAuth2HttpClient is the default HTTP client implementation.
type DefaultOAuth2HttpClient struct{}

func (c *DefaultOAuth2HttpClient) Post(targetURL string, body url.Values, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, data, nil
}

// ExchangeCode exchanges an authorization code for tokens.
func ExchangeCode(config OAuth2Config, code, codeVerifier string, httpClient OAuth2HttpClient) (*TokenResponse, error) {
	if httpClient == nil {
		httpClient = &DefaultOAuth2HttpClient{}
	}

	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {config.RedirectURI},
		"client_id":     {config.ClientID},
		"code_verifier": {codeVerifier},
	}
	if config.ClientSecret != "" {
		body.Set("client_secret", config.ClientSecret)
	}

	status, data, err := httpClient.Post(config.TokenEndpoint, body, nil)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		var oauthErr OAuth2Error
		_ = json.Unmarshal(data, &oauthErr)
		msg := oauthErr.ErrorDescription
		if msg == "" {
			msg = oauthErr.Error
		}
		if msg == "" {
			msg = "Token exchange failed"
		}
		errCode := oauthErr.Error
		if errCode == "" {
			errCode = "server_error"
		}
		return nil, &OAuth2TokenError{Message: msg, ErrorCode: errCode, StatusCode: status}
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(data, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// RefreshAccessToken refreshes an access token.
func RefreshAccessToken(config OAuth2Config, refreshToken string, httpClient OAuth2HttpClient) (*TokenResponse, error) {
	if httpClient == nil {
		httpClient = &DefaultOAuth2HttpClient{}
	}

	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {config.ClientID},
	}
	if config.ClientSecret != "" {
		body.Set("client_secret", config.ClientSecret)
	}

	status, data, err := httpClient.Post(config.TokenEndpoint, body, nil)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		var oauthErr OAuth2Error
		_ = json.Unmarshal(data, &oauthErr)
		msg := oauthErr.ErrorDescription
		if msg == "" {
			msg = oauthErr.Error
		}
		if msg == "" {
			msg = "Token refresh failed"
		}
		errCode := oauthErr.Error
		if errCode == "" {
			errCode = "server_error"
		}
		return nil, &OAuth2TokenError{Message: msg, ErrorCode: errCode, StatusCode: status}
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(data, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// ExtractBearerToken extracts a Bearer token from an Authorization header value.
func ExtractBearerToken(authorizationHeader string) string {
	if authorizationHeader == "" {
		return ""
	}
	parts := strings.SplitN(authorizationHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

func decodeJwtPayload(token string) map[string]interface{} {
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

func extractScopes(payload map[string]interface{}) []string {
	if scopeStr, ok := payload["scope"].(string); ok {
		var scopes []string
		for _, s := range strings.Split(scopeStr, " ") {
			if s != "" {
				scopes = append(scopes, s)
			}
		}
		return scopes
	}
	if arr, ok := payload["scopes"].([]interface{}); ok {
		scopes := make([]string, 0, len(arr))
		for _, s := range arr {
			scopes = append(scopes, fmt.Sprintf("%v", s))
		}
		return scopes
	}
	if arr, ok := payload["scp"].([]interface{}); ok {
		scopes := make([]string, 0, len(arr))
		for _, s := range arr {
			scopes = append(scopes, fmt.Sprintf("%v", s))
		}
		return scopes
	}
	return nil
}

// ValidateAccessToken validates and decodes an access token (JWT).
func ValidateAccessToken(token string, config OAuth2Config, requiredScopes []string, clockSkewSeconds int64) *OAuth2TokenValidationResult {
	if clockSkewSeconds == 0 {
		clockSkewSeconds = 30
	}

	decoded := decodeJwtPayload(token)
	if decoded == nil {
		return &OAuth2TokenValidationResult{Valid: false, Error: "malformed_token"}
	}

	now := time.Now().Unix()

	exp := toInt64(decoded["exp"])
	if exp != 0 && exp+clockSkewSeconds < now {
		return &OAuth2TokenValidationResult{Valid: false, Error: "token_expired"}
	}

	if config.Issuer != "" {
		iss, _ := decoded["iss"].(string)
		if iss != config.Issuer {
			return &OAuth2TokenValidationResult{Valid: false, Error: "invalid_issuer"}
		}
	}

	if config.Audience != "" {
		aud := decoded["aud"]
		var audList []string
		switch v := aud.(type) {
		case []interface{}:
			for _, a := range v {
				audList = append(audList, fmt.Sprintf("%v", a))
			}
		case string:
			audList = []string{v}
		}
		found := false
		for _, a := range audList {
			if a == config.Audience {
				found = true
				break
			}
		}
		if !found {
			return &OAuth2TokenValidationResult{Valid: false, Error: "invalid_audience"}
		}
	}

	scopes := extractScopes(decoded)

	if len(requiredScopes) > 0 {
		var missing []string
		for _, req := range requiredScopes {
			found := false
			for _, s := range scopes {
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
			return &OAuth2TokenValidationResult{
				Valid: false,
				Error: fmt.Sprintf("missing_scopes: %s", strings.Join(missing, ", ")),
			}
		}
	}

	decodedToken := &DecodedAccessToken{
		Sub:    toString(decoded["sub"]),
		Exp:    exp,
		Scopes: scopes,
		Claims: decoded,
	}

	if decoded["iss"] != nil {
		decodedToken.Iss = toString(decoded["iss"])
	}
	if decoded["aud"] != nil {
		decodedToken.Aud = decoded["aud"]
	}
	if decoded["iat"] != nil {
		iat := toInt64(decoded["iat"])
		decodedToken.Iat = &iat
	}
	if decoded["client_id"] != nil {
		decodedToken.ClientID = toString(decoded["client_id"])
	}

	return &OAuth2TokenValidationResult{Valid: true, Token: decodedToken}
}

// BuildOAuth2Metadata builds an OAuth2 Authorization Server Metadata document (RFC 8414).
func BuildOAuth2Metadata(config OAuth2Config) map[string]interface{} {
	metadata := map[string]interface{}{
		"authorization_endpoint":               config.AuthorizationEndpoint,
		"token_endpoint":                       config.TokenEndpoint,
		"response_types_supported":             []string{"code"},
		"grant_types_supported":                []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":     []string{"S256"},
	}

	if config.ClientSecret != "" {
		metadata["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
	} else {
		metadata["token_endpoint_auth_methods_supported"] = []string{"none"}
	}

	if config.Issuer != "" {
		metadata["issuer"] = config.Issuer
	}
	if config.Scopes != nil {
		scopeKeys := make([]string, 0, len(config.Scopes))
		for k := range config.Scopes {
			scopeKeys = append(scopeKeys, k)
		}
		metadata["scopes_supported"] = scopeKeys
	}

	return metadata
}
