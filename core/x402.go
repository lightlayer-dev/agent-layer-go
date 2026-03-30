package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	X402Version              = 1
	HeaderPaymentRequired    = "payment-required"
	HeaderPaymentSignature   = "payment-signature"
	HeaderPaymentResponse    = "payment-response"
)

// PaymentRequirements describes what the server requires for payment.
type PaymentRequirements struct {
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	Asset             string                 `json:"asset"`
	Amount            string                 `json:"amount"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
	Extra             map[string]interface{} `json:"extra"`
}

// PaymentRequired is the 402 response body.
type PaymentRequired struct {
	X402Version int                 `json:"x402Version"`
	Error       string              `json:"error,omitempty"`
	Resource    ResourceInfo        `json:"resource"`
	Accepts     []PaymentRequirements `json:"accepts"`
}

// ResourceInfo describes the resource being paid for.
type ResourceInfo struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// PaymentPayload is what the client sends back after paying.
type PaymentPayload struct {
	X402Version int                    `json:"x402Version"`
	Resource    *ResourceInfo          `json:"resource,omitempty"`
	Accepted    PaymentRequirements    `json:"accepted"`
	Payload     map[string]interface{} `json:"payload"`
}

// VerifyResponse is a facilitator verify response.
type VerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason,omitempty"`
}

// SettleResponse is a facilitator settle response.
type SettleResponse struct {
	Success     bool   `json:"success"`
	TxHash      string `json:"txHash,omitempty"`
	Network     string `json:"network,omitempty"`
	ErrorReason string `json:"errorReason,omitempty"`
}

// X402RouteConfig is per-route payment configuration.
type X402RouteConfig struct {
	PayTo             string
	Scheme            string
	Price             interface{} // string like "$0.01" or ResolvedPrice
	Network           string
	MaxTimeoutSeconds int
	Description       string
	Extra             map[string]interface{}
}

// X402Config is top-level x402 config.
type X402Config struct {
	Routes         map[string]X402RouteConfig
	FacilitatorURL string
	Facilitator    FacilitatorClient
}

// ResolvedPrice is a resolved price with amount and asset.
type ResolvedPrice struct {
	Amount string
	Asset  string
	Extra  map[string]interface{}
}

// FacilitatorClient communicates with an x402 facilitator.
type FacilitatorClient interface {
	Verify(payload PaymentPayload, requirements PaymentRequirements) (*VerifyResponse, error)
	Settle(payload PaymentPayload, requirements PaymentRequirements) (*SettleResponse, error)
}

// HttpFacilitatorClient is the default HTTP-based facilitator client.
type HttpFacilitatorClient struct {
	URL string
}

func (c *HttpFacilitatorClient) Verify(payload PaymentPayload, requirements PaymentRequirements) (*VerifyResponse, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"payload":      payload,
		"requirements": requirements,
	})

	req, err := http.NewRequest("POST", c.URL+"/verify", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("facilitator verify failed: %d %s", resp.StatusCode, resp.Status)
	}

	data, _ := io.ReadAll(resp.Body)
	var result VerifyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *HttpFacilitatorClient) Settle(payload PaymentPayload, requirements PaymentRequirements) (*SettleResponse, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"payload":      payload,
		"requirements": requirements,
	})

	req, err := http.NewRequest("POST", c.URL+"/settle", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("facilitator settle failed: %d %s", resp.StatusCode, resp.Status)
	}

	data, _ := io.ReadAll(resp.Body)
	var result SettleResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ResolvePrice resolves a Price into concrete amount + asset.
func ResolvePrice(price interface{}) (*ResolvedPrice, error) {
	switch p := price.(type) {
	case string:
		if len(p) < 2 || p[0] != '$' {
			return nil, fmt.Errorf("invalid price string: %s. Use \"$X.XX\" format", p)
		}
		return &ResolvedPrice{Amount: p[1:], Asset: "USDC"}, nil
	case ResolvedPrice:
		return &p, nil
	case *ResolvedPrice:
		return p, nil
	case map[string]interface{}:
		amount, _ := p["amount"].(string)
		asset, _ := p["asset"].(string)
		extra, _ := p["extra"].(map[string]interface{})
		return &ResolvedPrice{Amount: amount, Asset: asset, Extra: extra}, nil
	default:
		return nil, fmt.Errorf("unsupported price type: %T", price)
	}
}

// BuildRequirements builds PaymentRequirements from a route config.
func BuildRequirements(config X402RouteConfig) (*PaymentRequirements, error) {
	resolved, err := ResolvePrice(config.Price)
	if err != nil {
		return nil, err
	}

	scheme := config.Scheme
	if scheme == "" {
		scheme = "exact"
	}

	maxTimeout := config.MaxTimeoutSeconds
	if maxTimeout == 0 {
		maxTimeout = 60
	}

	extra := map[string]interface{}{}
	for k, v := range config.Extra {
		extra[k] = v
	}
	for k, v := range resolved.Extra {
		extra[k] = v
	}

	return &PaymentRequirements{
		Scheme:            scheme,
		Network:           config.Network,
		Asset:             resolved.Asset,
		Amount:            resolved.Amount,
		PayTo:             config.PayTo,
		MaxTimeoutSeconds: maxTimeout,
		Extra:             extra,
	}, nil
}

// BuildPaymentRequired builds the 402 response payload.
func BuildPaymentRequired(url string, config X402RouteConfig, errMsg string) (*PaymentRequired, error) {
	requirements, err := BuildRequirements(config)
	if err != nil {
		return nil, err
	}

	return &PaymentRequired{
		X402Version: X402Version,
		Error:       errMsg,
		Resource: ResourceInfo{
			URL:         url,
			Description: config.Description,
		},
		Accepts: []PaymentRequirements{*requirements},
	}, nil
}

// EncodePaymentRequired encodes a PaymentRequired to a base64 header value.
func EncodePaymentRequired(pr PaymentRequired) string {
	data, _ := json.Marshal(pr)
	return base64.StdEncoding.EncodeToString(data)
}

// DecodePaymentPayload decodes a base64 PAYMENT-SIGNATURE header.
func DecodePaymentPayload(header string) (*PaymentPayload, error) {
	data, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("invalid PAYMENT-SIGNATURE header: not valid base64 JSON")
	}
	var payload PaymentPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("invalid PAYMENT-SIGNATURE header: not valid base64 JSON")
	}
	return &payload, nil
}

// MatchRoute matches an incoming request to a route config key.
func MatchRoute(method, path string, routes map[string]X402RouteConfig) *X402RouteConfig {
	key := strings.ToUpper(method) + " " + path
	if config, ok := routes[key]; ok {
		return &config
	}
	return nil
}
