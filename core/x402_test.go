package core

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestResolvePrice_DollarString(t *testing.T) {
	resolved, err := ResolvePrice("$0.01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Amount != "0.01" {
		t.Errorf("expected amount 0.01, got %s", resolved.Amount)
	}
	if resolved.Asset != "USDC" {
		t.Errorf("expected asset USDC, got %s", resolved.Asset)
	}
}

func TestResolvePrice_DollarStringLarger(t *testing.T) {
	resolved, err := ResolvePrice("$10.50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Amount != "10.50" {
		t.Errorf("expected amount 10.50, got %s", resolved.Amount)
	}
}

func TestResolvePrice_ResolvedPriceStruct(t *testing.T) {
	input := ResolvedPrice{Amount: "5.00", Asset: "ETH"}
	resolved, err := ResolvePrice(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Amount != "5.00" {
		t.Errorf("expected amount 5.00, got %s", resolved.Amount)
	}
	if resolved.Asset != "ETH" {
		t.Errorf("expected asset ETH, got %s", resolved.Asset)
	}
}

func TestResolvePrice_ResolvedPricePointer(t *testing.T) {
	input := &ResolvedPrice{Amount: "1.00", Asset: "DAI"}
	resolved, err := ResolvePrice(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Amount != "1.00" || resolved.Asset != "DAI" {
		t.Errorf("expected 1.00 DAI, got %s %s", resolved.Amount, resolved.Asset)
	}
}

func TestResolvePrice_MapType(t *testing.T) {
	input := map[string]interface{}{
		"amount": "2.50",
		"asset":  "USDT",
	}
	resolved, err := ResolvePrice(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Amount != "2.50" || resolved.Asset != "USDT" {
		t.Errorf("expected 2.50 USDT, got %s %s", resolved.Amount, resolved.Asset)
	}
}

func TestResolvePrice_InvalidString(t *testing.T) {
	_, err := ResolvePrice("0.01")
	if err == nil {
		t.Error("expected error for price string without $")
	}
}

func TestResolvePrice_TooShort(t *testing.T) {
	_, err := ResolvePrice("$")
	if err == nil {
		t.Error("expected error for single $ character")
	}
}

func TestResolvePrice_UnsupportedType(t *testing.T) {
	_, err := ResolvePrice(42)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestBuildRequirements_Defaults(t *testing.T) {
	config := X402RouteConfig{
		PayTo:   "0xabc123",
		Price:   "$0.01",
		Network: "base",
	}

	req, err := BuildRequirements(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Scheme != "exact" {
		t.Errorf("expected default scheme 'exact', got %s", req.Scheme)
	}
	if req.MaxTimeoutSeconds != 60 {
		t.Errorf("expected default timeout 60, got %d", req.MaxTimeoutSeconds)
	}
	if req.Amount != "0.01" {
		t.Errorf("expected amount 0.01, got %s", req.Amount)
	}
	if req.Asset != "USDC" {
		t.Errorf("expected asset USDC, got %s", req.Asset)
	}
	if req.PayTo != "0xabc123" {
		t.Errorf("expected payTo 0xabc123, got %s", req.PayTo)
	}
	if req.Network != "base" {
		t.Errorf("expected network base, got %s", req.Network)
	}
}

func TestBuildRequirements_CustomSchemeTimeout(t *testing.T) {
	config := X402RouteConfig{
		PayTo:             "0xabc123",
		Price:             "$1.00",
		Network:           "ethereum",
		Scheme:            "streaming",
		MaxTimeoutSeconds: 120,
	}

	req, err := BuildRequirements(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Scheme != "streaming" {
		t.Errorf("expected scheme streaming, got %s", req.Scheme)
	}
	if req.MaxTimeoutSeconds != 120 {
		t.Errorf("expected timeout 120, got %d", req.MaxTimeoutSeconds)
	}
}

func TestBuildRequirements_MergesExtra(t *testing.T) {
	config := X402RouteConfig{
		PayTo:   "0xabc",
		Price:   &ResolvedPrice{Amount: "1.00", Asset: "USDC", Extra: map[string]interface{}{"fromPrice": true}},
		Network: "base",
		Extra:   map[string]interface{}{"fromConfig": true},
	}

	req, err := BuildRequirements(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Extra["fromConfig"] != true {
		t.Error("expected fromConfig in extra")
	}
	if req.Extra["fromPrice"] != true {
		t.Error("expected fromPrice in extra")
	}
}

func TestBuildRequirements_InvalidPrice(t *testing.T) {
	config := X402RouteConfig{
		PayTo:   "0xabc",
		Price:   "invalid",
		Network: "base",
	}

	_, err := BuildRequirements(config)
	if err == nil {
		t.Error("expected error for invalid price")
	}
}

func TestBuildPaymentRequired(t *testing.T) {
	config := X402RouteConfig{
		PayTo:       "0xabc123",
		Price:       "$0.01",
		Network:     "base",
		Description: "Access to premium endpoint",
	}

	pr, err := BuildPaymentRequired("https://api.example.com/premium", config, "Payment required")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.X402Version != X402Version {
		t.Errorf("expected version %d, got %d", X402Version, pr.X402Version)
	}
	if pr.Error != "Payment required" {
		t.Errorf("expected error message, got %s", pr.Error)
	}
	if pr.Resource.URL != "https://api.example.com/premium" {
		t.Errorf("expected resource URL")
	}
	if pr.Resource.Description != "Access to premium endpoint" {
		t.Errorf("expected resource description")
	}
	if len(pr.Accepts) != 1 {
		t.Fatalf("expected 1 accept entry, got %d", len(pr.Accepts))
	}
	if pr.Accepts[0].Amount != "0.01" {
		t.Errorf("expected amount 0.01")
	}
}

func TestBuildPaymentRequired_InvalidPrice(t *testing.T) {
	config := X402RouteConfig{
		PayTo: "0xabc",
		Price: "bad",
	}
	_, err := BuildPaymentRequired("https://example.com", config, "")
	if err == nil {
		t.Error("expected error for invalid price")
	}
}

func TestEncodeDecodePaymentRequired_Roundtrip(t *testing.T) {
	config := X402RouteConfig{
		PayTo:       "0xabc123",
		Price:       "$0.50",
		Network:     "base",
		Description: "Test resource",
	}

	pr, err := BuildPaymentRequired("https://api.example.com/resource", config, "pay up")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encoded := EncodePaymentRequired(*pr)
	if encoded == "" {
		t.Fatal("expected non-empty encoded string")
	}

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("encoded value is not valid base64: %v", err)
	}

	// Verify the JSON content
	var roundtrip PaymentRequired
	if err := json.Unmarshal(decoded, &roundtrip); err != nil {
		t.Fatalf("decoded value is not valid JSON: %v", err)
	}
	if roundtrip.X402Version != pr.X402Version {
		t.Errorf("version mismatch after roundtrip")
	}
	if roundtrip.Resource.URL != pr.Resource.URL {
		t.Errorf("resource URL mismatch after roundtrip")
	}
	if roundtrip.Error != "pay up" {
		t.Errorf("error message mismatch after roundtrip")
	}
	if len(roundtrip.Accepts) != 1 {
		t.Fatalf("accepts length mismatch")
	}
	if roundtrip.Accepts[0].Amount != "0.50" {
		t.Errorf("amount mismatch after roundtrip")
	}
}

func TestDecodePaymentPayload(t *testing.T) {
	payload := PaymentPayload{
		X402Version: 1,
		Accepted: PaymentRequirements{
			Scheme:  "exact",
			Network: "base",
			Asset:   "USDC",
			Amount:  "0.01",
			PayTo:   "0xabc",
		},
		Payload: map[string]interface{}{"txHash": "0x123"},
	}

	data, _ := json.Marshal(payload)
	encoded := base64.StdEncoding.EncodeToString(data)

	decoded, err := DecodePaymentPayload(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.X402Version != 1 {
		t.Errorf("expected version 1, got %d", decoded.X402Version)
	}
	if decoded.Accepted.Amount != "0.01" {
		t.Errorf("expected amount 0.01, got %s", decoded.Accepted.Amount)
	}
}

func TestDecodePaymentPayload_InvalidBase64(t *testing.T) {
	_, err := DecodePaymentPayload("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecodePaymentPayload_InvalidJSON(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := DecodePaymentPayload(encoded)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMatchRoute_Found(t *testing.T) {
	routes := map[string]X402RouteConfig{
		"GET /premium": {
			PayTo:   "0xabc",
			Price:   "$0.01",
			Network: "base",
		},
		"POST /api/data": {
			PayTo:   "0xdef",
			Price:   "$0.05",
			Network: "ethereum",
		},
	}

	config := MatchRoute("GET", "/premium", routes)
	if config == nil {
		t.Fatal("expected matching route config")
	}
	if config.PayTo != "0xabc" {
		t.Errorf("expected payTo 0xabc, got %s", config.PayTo)
	}
}

func TestMatchRoute_MethodCaseInsensitive(t *testing.T) {
	routes := map[string]X402RouteConfig{
		"GET /test": {PayTo: "0xabc", Price: "$0.01"},
	}

	config := MatchRoute("get", "/test", routes)
	if config == nil {
		t.Fatal("expected matching route config for lowercase method")
	}
}

func TestMatchRoute_NoMatch(t *testing.T) {
	routes := map[string]X402RouteConfig{
		"GET /premium": {PayTo: "0xabc", Price: "$0.01"},
	}

	config := MatchRoute("POST", "/premium", routes)
	if config != nil {
		t.Error("expected nil for non-matching route")
	}

	config2 := MatchRoute("GET", "/other", routes)
	if config2 != nil {
		t.Error("expected nil for non-matching path")
	}
}

func TestMatchRoute_EmptyRoutes(t *testing.T) {
	config := MatchRoute("GET", "/test", map[string]X402RouteConfig{})
	if config != nil {
		t.Error("expected nil for empty routes")
	}
}
