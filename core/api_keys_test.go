package core

import (
	"strings"
	"testing"
	"time"
)

func TestMemoryApiKeyStore_SetAndResolve(t *testing.T) {
	store := NewMemoryApiKeyStore()
	key := &ScopedApiKey{
		KeyID:     "kid1",
		CompanyID: "comp1",
		UserID:    "user1",
		Scopes:    []string{"read"},
	}

	store.Set("raw_key_1", key)

	resolved, err := store.Resolve("raw_key_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved == nil {
		t.Fatal("expected non-nil key")
	}
	if resolved.KeyID != "kid1" {
		t.Errorf("expected keyId kid1, got %s", resolved.KeyID)
	}
	if resolved.CompanyID != "comp1" {
		t.Errorf("expected companyId comp1, got %s", resolved.CompanyID)
	}
}

func TestMemoryApiKeyStore_ResolveUnknown(t *testing.T) {
	store := NewMemoryApiKeyStore()
	resolved, err := store.Resolve("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != nil {
		t.Error("expected nil for unknown key")
	}
}

func TestMemoryApiKeyStore_Delete(t *testing.T) {
	store := NewMemoryApiKeyStore()
	store.Set("key1", &ScopedApiKey{KeyID: "kid1"})
	store.Delete("key1")

	resolved, _ := store.Resolve("key1")
	if resolved != nil {
		t.Error("expected nil after delete")
	}
}

func TestMemoryApiKeyStore_Size(t *testing.T) {
	store := NewMemoryApiKeyStore()
	if store.Size() != 0 {
		t.Errorf("expected size 0, got %d", store.Size())
	}

	store.Set("k1", &ScopedApiKey{KeyID: "1"})
	store.Set("k2", &ScopedApiKey{KeyID: "2"})
	if store.Size() != 2 {
		t.Errorf("expected size 2, got %d", store.Size())
	}

	store.Delete("k1")
	if store.Size() != 1 {
		t.Errorf("expected size 1 after delete, got %d", store.Size())
	}
}

func TestCreateApiKey_Prefix(t *testing.T) {
	store := NewMemoryApiKeyStore()
	result := CreateApiKey(store, CreateApiKeyOptions{
		CompanyID: "comp1",
		UserID:    "user1",
		Scopes:    []string{"read"},
	})

	if !strings.HasPrefix(result.RawKey, "al_") {
		t.Errorf("expected key to start with 'al_', got %s", result.RawKey)
	}
}

func TestCreateApiKey_Length(t *testing.T) {
	store := NewMemoryApiKeyStore()
	result := CreateApiKey(store, CreateApiKeyOptions{
		CompanyID: "comp1",
		Scopes:    []string{"read"},
	})

	// "al_" (3 chars) + 32 hex chars = 35 chars
	if len(result.RawKey) < 35 {
		t.Errorf("expected key length >= 35, got %d (%s)", len(result.RawKey), result.RawKey)
	}
}

func TestCreateApiKey_StoresInStore(t *testing.T) {
	store := NewMemoryApiKeyStore()
	result := CreateApiKey(store, CreateApiKeyOptions{
		CompanyID: "comp1",
		UserID:    "user1",
		Scopes:    []string{"write"},
	})

	if store.Size() != 1 {
		t.Errorf("expected store size 1, got %d", store.Size())
	}

	resolved, _ := store.Resolve(result.RawKey)
	if resolved == nil {
		t.Fatal("expected to resolve created key")
	}
	if resolved.CompanyID != "comp1" {
		t.Errorf("expected companyId comp1, got %s", resolved.CompanyID)
	}
	if resolved.UserID != "user1" {
		t.Errorf("expected userId user1, got %s", resolved.UserID)
	}
}

func TestCreateApiKey_UniqueKeys(t *testing.T) {
	store := NewMemoryApiKeyStore()
	r1 := CreateApiKey(store, CreateApiKeyOptions{Scopes: []string{"read"}})
	r2 := CreateApiKey(store, CreateApiKeyOptions{Scopes: []string{"read"}})
	if r1.RawKey == r2.RawKey {
		t.Error("expected unique keys")
	}
}

func TestValidateApiKey_ValidKey(t *testing.T) {
	store := NewMemoryApiKeyStore()
	result := CreateApiKey(store, CreateApiKeyOptions{
		CompanyID: "comp1",
		Scopes:    []string{"read"},
	})

	validation, err := ValidateApiKey(store, result.RawKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.Valid {
		t.Error("expected valid key")
	}
	if validation.Key == nil {
		t.Error("expected key to be set")
	}
	if validation.Error != "" {
		t.Errorf("expected no error, got %s", validation.Error)
	}
}

func TestValidateApiKey_InvalidKey(t *testing.T) {
	store := NewMemoryApiKeyStore()

	validation, err := ValidateApiKey(store, "al_nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.Valid {
		t.Error("expected invalid key")
	}
	if validation.Error != "invalid_api_key" {
		t.Errorf("expected error 'invalid_api_key', got '%s'", validation.Error)
	}
}

func TestValidateApiKey_ExpiredKey(t *testing.T) {
	store := NewMemoryApiKeyStore()
	expired := time.Now().Add(-1 * time.Hour)
	result := CreateApiKey(store, CreateApiKeyOptions{
		CompanyID: "comp1",
		Scopes:    []string{"read"},
		ExpiresAt: &expired,
	})

	validation, err := ValidateApiKey(store, result.RawKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.Valid {
		t.Error("expected expired key to be invalid")
	}
	if validation.Error != "api_key_expired" {
		t.Errorf("expected error 'api_key_expired', got '%s'", validation.Error)
	}
}

func TestValidateApiKey_NotExpiredKey(t *testing.T) {
	store := NewMemoryApiKeyStore()
	future := time.Now().Add(1 * time.Hour)
	result := CreateApiKey(store, CreateApiKeyOptions{
		CompanyID: "comp1",
		Scopes:    []string{"read"},
		ExpiresAt: &future,
	})

	validation, err := ValidateApiKey(store, result.RawKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.Valid {
		t.Error("expected key with future expiry to be valid")
	}
}

func TestHasScope_SingleScope(t *testing.T) {
	key := &ScopedApiKey{Scopes: []string{"read", "write"}}

	if !HasScope(key, "read") {
		t.Error("expected HasScope to return true for 'read'")
	}
	if HasScope(key, "admin") {
		t.Error("expected HasScope to return false for 'admin'")
	}
}

func TestHasScope_MultipleScopes(t *testing.T) {
	key := &ScopedApiKey{Scopes: []string{"read", "write", "delete"}}

	if !HasScope(key, "read", "write") {
		t.Error("expected HasScope to return true for 'read' and 'write'")
	}
	if HasScope(key, "read", "admin") {
		t.Error("expected HasScope to return false when one scope is missing")
	}
}

func TestHasScope_Wildcard(t *testing.T) {
	key := &ScopedApiKey{Scopes: []string{"*"}}

	if !HasScope(key, "read") {
		t.Error("wildcard should grant any scope")
	}
	if !HasScope(key, "read", "write", "admin") {
		t.Error("wildcard should grant all scopes")
	}
}

func TestHasScope_EmptyRequired(t *testing.T) {
	key := &ScopedApiKey{Scopes: []string{"read"}}
	if !HasScope(key) {
		t.Error("no required scopes should return true")
	}
}
