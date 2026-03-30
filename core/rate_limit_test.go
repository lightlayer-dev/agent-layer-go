package core

import (
	"testing"
	"time"
)

func TestMemoryRateLimitStore_IncrementCreatesNewWindow(t *testing.T) {
	store := NewMemoryRateLimitStore()
	count, err := store.Increment("key1", 60000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}
}

func TestMemoryRateLimitStore_IncrementExisting(t *testing.T) {
	store := NewMemoryRateLimitStore()
	store.Increment("key1", 60000)
	store.Increment("key1", 60000)
	count, err := store.Increment("key1", 60000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestMemoryRateLimitStore_GetReturnsZeroForExpired(t *testing.T) {
	store := NewMemoryRateLimitStore()
	// Use a very short window so it expires quickly
	store.Increment("key1", 1) // 1ms window
	time.Sleep(5 * time.Millisecond)

	count, err := store.Get("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 for expired window, got %d", count)
	}
}

func TestMemoryRateLimitStore_GetReturnsCountForActive(t *testing.T) {
	store := NewMemoryRateLimitStore()
	store.Increment("key1", 60000)
	store.Increment("key1", 60000)

	count, err := store.Get("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestMemoryRateLimitStore_GetReturnsZeroForUnknown(t *testing.T) {
	store := NewMemoryRateLimitStore()
	count, err := store.Get("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 for unknown key, got %d", count)
	}
}

func TestMemoryRateLimitStore_Reset(t *testing.T) {
	store := NewMemoryRateLimitStore()
	store.Increment("key1", 60000)
	store.Increment("key1", 60000)

	err := store.Reset("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count, _ := store.Get("key1")
	if count != 0 {
		t.Errorf("expected 0 after reset, got %d", count)
	}
}

func TestMemoryRateLimitStore_Cleanup(t *testing.T) {
	store := NewMemoryRateLimitStore()
	store.Increment("expired", 1) // 1ms window
	store.Increment("active", 60000)
	time.Sleep(5 * time.Millisecond)

	store.Cleanup()

	// expired key should be gone
	count, _ := store.Get("expired")
	if count != 0 {
		t.Errorf("expected expired key to be cleaned up, got %d", count)
	}

	// active key should remain
	count, _ = store.Get("active")
	if count != 1 {
		t.Errorf("expected active key to remain with count 1, got %d", count)
	}
}

func TestCreateRateLimiter_AllowsWithinLimit(t *testing.T) {
	limiter := CreateRateLimiter(RateLimitConfig{
		Max:      3,
		WindowMs: 60000,
	})

	for i := 0; i < 3; i++ {
		result, err := limiter(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
}

func TestCreateRateLimiter_BlocksExceeding(t *testing.T) {
	limiter := CreateRateLimiter(RateLimitConfig{
		Max:      2,
		WindowMs: 60000,
	})

	limiter(nil)
	limiter(nil)
	result, err := limiter(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("third request should be blocked")
	}
	if result.Remaining != 0 {
		t.Errorf("expected remaining 0, got %d", result.Remaining)
	}
	if result.RetryAfter == nil {
		t.Error("expected retry_after to be set when blocked")
	}
}

func TestCreateRateLimiter_CustomKeyFunction(t *testing.T) {
	limiter := CreateRateLimiter(RateLimitConfig{
		Max:      1,
		WindowMs: 60000,
		KeyFn:    func(req interface{}) string { return req.(string) },
	})

	r1, _ := limiter("user-a")
	if !r1.Allowed {
		t.Error("user-a first request should be allowed")
	}

	r2, _ := limiter("user-b")
	if !r2.Allowed {
		t.Error("user-b first request should be allowed (different key)")
	}

	r3, _ := limiter("user-a")
	if r3.Allowed {
		t.Error("user-a second request should be blocked")
	}
}

func TestCreateRateLimiter_WindowExpiration(t *testing.T) {
	limiter := CreateRateLimiter(RateLimitConfig{
		Max:      1,
		WindowMs: 1, // 1ms window
	})

	limiter(nil)
	time.Sleep(5 * time.Millisecond)

	result, _ := limiter(nil)
	if !result.Allowed {
		t.Error("request should be allowed after window expiration")
	}
}

func TestCreateRateLimiter_CustomStore(t *testing.T) {
	store := NewMemoryRateLimitStore()
	limiter := CreateRateLimiter(RateLimitConfig{
		Max:      5,
		WindowMs: 60000,
		Store:    store,
	})

	limiter(nil)
	limiter(nil)

	// Verify the custom store was used
	count, _ := store.Get("__global__")
	if count != 2 {
		t.Errorf("expected custom store to have count 2, got %d", count)
	}
}

func TestCreateRateLimiter_ResultFields(t *testing.T) {
	limiter := CreateRateLimiter(RateLimitConfig{
		Max:      5,
		WindowMs: 30000,
	})

	result, _ := limiter(nil)
	if result.Limit != 5 {
		t.Errorf("expected limit 5, got %d", result.Limit)
	}
	if result.Remaining != 4 {
		t.Errorf("expected remaining 4, got %d", result.Remaining)
	}
	if result.ResetMs != 30000 {
		t.Errorf("expected resetMs 30000, got %d", result.ResetMs)
	}
	if result.RetryAfter != nil {
		t.Error("expected no retry_after when allowed")
	}
}
