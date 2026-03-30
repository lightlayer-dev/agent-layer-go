package core

import (
	"sync"
	"testing"
)

func TestDetectAgent_ChatGPT(t *testing.T) {
	result := DetectAgent("Mozilla/5.0 (compatible; ChatGPT-User/1.0)")
	if result != "ChatGPT" {
		t.Errorf("expected ChatGPT, got '%s'", result)
	}
}

func TestDetectAgent_GPTBot(t *testing.T) {
	result := DetectAgent("Mozilla/5.0 (compatible; GPTBot/1.0)")
	if result != "GPTBot" {
		t.Errorf("expected GPTBot, got '%s'", result)
	}
}

func TestDetectAgent_ClaudeBot(t *testing.T) {
	result := DetectAgent("ClaudeBot/1.0")
	if result != "ClaudeBot" {
		t.Errorf("expected ClaudeBot, got '%s'", result)
	}
}

func TestDetectAgent_PerplexityBot(t *testing.T) {
	result := DetectAgent("Mozilla/5.0 PerplexityBot/1.0")
	if result != "PerplexityBot" {
		t.Errorf("expected PerplexityBot, got '%s'", result)
	}
}

func TestDetectAgent_CaseInsensitive(t *testing.T) {
	result := DetectAgent("mozilla/5.0 claudebot/1.0")
	if result != "ClaudeBot" {
		t.Errorf("expected ClaudeBot (case insensitive), got '%s'", result)
	}
}

func TestDetectAgent_UnknownReturnsEmpty(t *testing.T) {
	result := DetectAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	if result != "" {
		t.Errorf("expected empty string for unknown agent, got '%s'", result)
	}
}

func TestDetectAgent_EmptyStringReturnsEmpty(t *testing.T) {
	result := DetectAgent("")
	if result != "" {
		t.Errorf("expected empty string for empty user-agent, got '%s'", result)
	}
}

func TestEventBuffer_PushCallsOnEvent(t *testing.T) {
	var mu sync.Mutex
	var received []AgentEvent

	buf := NewEventBuffer(AnalyticsConfig{
		OnEvent: func(event AgentEvent) {
			mu.Lock()
			received = append(received, event)
			mu.Unlock()
		},
	})
	defer buf.Shutdown()

	event := AgentEvent{
		Agent:  "TestBot",
		Method: "GET",
		Path:   "/test",
	}
	buf.Push(event)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 event, got %d", count)
	}
}

func TestEventBuffer_PushDoesNotBufferWithoutEndpoint(t *testing.T) {
	buf := NewEventBuffer(AnalyticsConfig{
		OnEvent: func(event AgentEvent) {},
	})
	defer buf.Shutdown()

	buf.Push(AgentEvent{Agent: "TestBot", Method: "GET", Path: "/test"})

	if buf.Pending() != 0 {
		t.Errorf("expected 0 pending without endpoint, got %d", buf.Pending())
	}
}

func TestEventBuffer_BuffersWhenEndpointSet(t *testing.T) {
	buf := NewEventBuffer(AnalyticsConfig{
		Endpoint:        "http://localhost:9999/events",
		FlushIntervalMs: 999999, // large interval to prevent auto-flush
		BufferSize:      100,
	})
	defer buf.Shutdown()

	buf.Push(AgentEvent{Agent: "TestBot", Method: "GET", Path: "/test"})

	if buf.Pending() != 1 {
		t.Errorf("expected 1 pending with endpoint, got %d", buf.Pending())
	}
}

func TestEventBuffer_MultipleEvents(t *testing.T) {
	var mu sync.Mutex
	callCount := 0

	buf := NewEventBuffer(AnalyticsConfig{
		OnEvent: func(event AgentEvent) {
			mu.Lock()
			callCount++
			mu.Unlock()
		},
	})
	defer buf.Shutdown()

	for i := 0; i < 5; i++ {
		buf.Push(AgentEvent{Agent: "Bot", Method: "GET", Path: "/test"})
	}

	mu.Lock()
	c := callCount
	mu.Unlock()

	if c != 5 {
		t.Errorf("expected onEvent called 5 times, got %d", c)
	}
}

func TestCreateAnalytics_DefaultDetection(t *testing.T) {
	analytics := CreateAnalytics(AnalyticsConfig{})
	defer analytics.Shutdown()

	result := analytics.Detect("ClaudeBot/1.0")
	if result != "ClaudeBot" {
		t.Errorf("expected ClaudeBot from default detect, got '%s'", result)
	}
}

func TestCreateAnalytics_CustomDetectionFunction(t *testing.T) {
	analytics := CreateAnalytics(AnalyticsConfig{
		DetectAgent: func(userAgent string) string {
			if userAgent == "MyCustomBot/1.0" {
				return "MyCustomBot"
			}
			return ""
		},
	})
	defer analytics.Shutdown()

	result := analytics.Detect("MyCustomBot/1.0")
	if result != "MyCustomBot" {
		t.Errorf("expected MyCustomBot, got '%s'", result)
	}

	result = analytics.Detect("ClaudeBot/1.0")
	if result != "" {
		t.Errorf("custom detector should not know ClaudeBot, got '%s'", result)
	}
}

func TestCreateAnalytics_Record(t *testing.T) {
	var mu sync.Mutex
	var events []AgentEvent

	analytics := CreateAnalytics(AnalyticsConfig{
		OnEvent: func(event AgentEvent) {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		},
	})
	defer analytics.Shutdown()

	analytics.Record(AgentEvent{Agent: "TestBot", Method: "POST", Path: "/api"})

	mu.Lock()
	count := len(events)
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 recorded event, got %d", count)
	}
}

func TestIsAgentRequest(t *testing.T) {
	if !IsAgentRequest("ClaudeBot/1.0") {
		t.Error("expected ClaudeBot to be recognized as agent")
	}
	if IsAgentRequest("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") {
		t.Error("expected regular browser not to be recognized as agent")
	}
}
