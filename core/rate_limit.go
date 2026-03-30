package core

import (
	"sync"
	"time"
)

const DefaultWindowMs int64 = 60000

// windowEntry stores a count and expiration for a rate limit window.
type windowEntry struct {
	Count     int64
	ExpiresAt int64
}

// MemoryRateLimitStore is an in-memory sliding window counter store.
type MemoryRateLimitStore struct {
	mu      sync.Mutex
	windows map[string]*windowEntry
}

// NewMemoryRateLimitStore creates a new in-memory rate limit store.
func NewMemoryRateLimitStore() *MemoryRateLimitStore {
	return &MemoryRateLimitStore{
		windows: make(map[string]*windowEntry),
	}
}

func (s *MemoryRateLimitStore) Increment(key string, windowMs int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	entry, exists := s.windows[key]

	if !exists || now >= entry.ExpiresAt {
		s.windows[key] = &windowEntry{Count: 1, ExpiresAt: now + windowMs}
		return 1, nil
	}

	entry.Count++
	return entry.Count, nil
}

func (s *MemoryRateLimitStore) Get(key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	entry, exists := s.windows[key]

	if !exists || now >= entry.ExpiresAt {
		return 0, nil
	}

	return entry.Count, nil
}

func (s *MemoryRateLimitStore) Reset(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.windows, key)
	return nil
}

// Cleanup removes expired entries.
func (s *MemoryRateLimitStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	for key, entry := range s.windows {
		if now >= entry.ExpiresAt {
			delete(s.windows, key)
		}
	}
}

// RateLimiter checks whether a request is allowed.
type RateLimiter func(req interface{}) (*RateLimitResult, error)

// CreateRateLimiter creates a rate limiter with the given configuration.
func CreateRateLimiter(config RateLimitConfig) RateLimiter {
	windowMs := config.WindowMs
	if windowMs == 0 {
		windowMs = DefaultWindowMs
	}

	store := config.Store
	if store == nil {
		store = NewMemoryRateLimitStore()
	}

	keyFn := config.KeyFn
	if keyFn == nil {
		keyFn = func(req interface{}) string { return "__global__" }
	}

	return func(req interface{}) (*RateLimitResult, error) {
		key := keyFn(req)
		count, err := store.Increment(key, windowMs)
		if err != nil {
			return nil, err
		}

		allowed := count <= config.Max
		remaining := config.Max - count
		if remaining < 0 {
			remaining = 0
		}

		result := &RateLimitResult{
			Allowed:   allowed,
			Limit:     config.Max,
			Remaining: remaining,
			ResetMs:   windowMs,
		}

		if !allowed {
			retryAfter := (windowMs + 999) / 1000
			result.RetryAfter = &retryAfter
		}

		return result, nil
	}
}
