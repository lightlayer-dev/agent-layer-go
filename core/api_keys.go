package core

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// ScopedApiKey represents an API key with scopes and metadata.
type ScopedApiKey struct {
	KeyID     string                 `json:"keyId"`
	CompanyID string                 `json:"companyId"`
	UserID    string                 `json:"userId"`
	Scopes    []string               `json:"scopes"`
	ExpiresAt *time.Time             `json:"expiresAt,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ApiKeyStore resolves a raw API key to a ScopedApiKey.
type ApiKeyStore interface {
	Resolve(rawKey string) (*ScopedApiKey, error)
}

// ApiKeyValidationResult is the result of validating an API key.
type ApiKeyValidationResult struct {
	Valid bool
	Key   *ScopedApiKey
	Error string
}

// CreateApiKeyOptions are the options for creating a new API key.
type CreateApiKeyOptions struct {
	CompanyID string
	UserID    string
	Scopes    []string
	ExpiresAt *time.Time
	Metadata  map[string]interface{}
}

// CreateApiKeyResult is the result of creating a new API key.
type CreateApiKeyResult struct {
	RawKey string
	Key    ScopedApiKey
}

// MemoryApiKeyStore is an in-memory API key store.
type MemoryApiKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*ScopedApiKey
}

// NewMemoryApiKeyStore creates a new in-memory API key store.
func NewMemoryApiKeyStore() *MemoryApiKeyStore {
	return &MemoryApiKeyStore{
		keys: make(map[string]*ScopedApiKey),
	}
}

func (s *MemoryApiKeyStore) Resolve(rawKey string) (*ScopedApiKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[rawKey]
	if !ok {
		return nil, nil
	}
	return key, nil
}

// Set stores a key mapping.
func (s *MemoryApiKeyStore) Set(rawKey string, key *ScopedApiKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[rawKey] = key
}

// Delete removes a key mapping.
func (s *MemoryApiKeyStore) Delete(rawKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, rawKey)
}

// Size returns the number of stored keys.
func (s *MemoryApiKeyStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

func randomHex(byteLength int) string {
	b := make([]byte, byteLength)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateApiKey generates a new scoped API key and stores it.
// Key format: "al_" prefix + 32 random hex characters.
func CreateApiKey(store *MemoryApiKeyStore, opts CreateApiKeyOptions) CreateApiKeyResult {
	rawKey := "al_" + randomHex(16)
	keyID := randomHex(8)

	key := ScopedApiKey{
		KeyID:     keyID,
		CompanyID: opts.CompanyID,
		UserID:    opts.UserID,
		Scopes:    opts.Scopes,
		ExpiresAt: opts.ExpiresAt,
		Metadata:  opts.Metadata,
	}

	store.Set(rawKey, &key)

	return CreateApiKeyResult{RawKey: rawKey, Key: key}
}

// ValidateApiKey validates a raw API key string against a store.
func ValidateApiKey(store ApiKeyStore, rawKey string) (*ApiKeyValidationResult, error) {
	key, err := store.Resolve(rawKey)
	if err != nil {
		return nil, err
	}

	if key == nil {
		return &ApiKeyValidationResult{Valid: false, Error: "invalid_api_key"}, nil
	}

	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return &ApiKeyValidationResult{Valid: false, Error: "api_key_expired"}, nil
	}

	return &ApiKeyValidationResult{Valid: true, Key: key}, nil
}

// HasScope checks if a scoped API key has the required scope(s).
// Supports wildcard "*" which grants all scopes.
func HasScope(key *ScopedApiKey, required ...string) bool {
	for _, s := range key.Scopes {
		if s == "*" {
			return true
		}
	}

	for _, req := range required {
		found := false
		for _, s := range key.Scopes {
			if s == req {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
