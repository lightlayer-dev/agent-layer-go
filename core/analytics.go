package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Known agent User-Agent patterns.
var agentPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	{regexp.MustCompile(`(?i)ChatGPT-User`), "ChatGPT"},
	{regexp.MustCompile(`(?i)GPTBot`), "GPTBot"},
	{regexp.MustCompile(`(?i)Google-Extended`), "Google-Extended"},
	{regexp.MustCompile(`(?i)Googlebot`), "Googlebot"},
	{regexp.MustCompile(`(?i)Bingbot`), "Bingbot"},
	{regexp.MustCompile(`(?i)ClaudeBot`), "ClaudeBot"},
	{regexp.MustCompile(`(?i)Claude-Web`), "Claude-Web"},
	{regexp.MustCompile(`(?i)Anthropic`), "Anthropic"},
	{regexp.MustCompile(`(?i)PerplexityBot`), "PerplexityBot"},
	{regexp.MustCompile(`(?i)Cohere-AI`), "Cohere"},
	{regexp.MustCompile(`(?i)YouBot`), "YouBot"},
	{regexp.MustCompile(`(?i)CCBot`), "CCBot"},
	{regexp.MustCompile(`(?i)Bytespider`), "Bytespider"},
	{regexp.MustCompile(`(?i)Applebot`), "Applebot"},
	{regexp.MustCompile(`(?i)Meta-ExternalAgent`), "Meta-ExternalAgent"},
	{regexp.MustCompile(`(?i)AI2Bot`), "AI2Bot"},
	{regexp.MustCompile(`(?i)Diffbot`), "Diffbot"},
	{regexp.MustCompile(`(?i)Amazonbot`), "Amazonbot"},
}

// DetectAgent detects an AI agent from a User-Agent string.
// Returns the agent name or empty string if not detected.
func DetectAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}
	for _, ap := range agentPatterns {
		if ap.Pattern.MatchString(userAgent) {
			return ap.Name
		}
	}
	return ""
}

// AgentEvent represents a single agent request event.
type AgentEvent struct {
	Agent        string `json:"agent"`
	UserAgent    string `json:"userAgent"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	StatusCode   int    `json:"statusCode"`
	DurationMs   int64  `json:"durationMs"`
	Timestamp    string `json:"timestamp"`
	ContentType  string `json:"contentType,omitempty"`
	ResponseSize int64  `json:"responseSize,omitempty"`
}

// AnalyticsConfig configures analytics collection.
type AnalyticsConfig struct {
	Endpoint       string
	ApiKey         string
	OnEvent        func(event AgentEvent)
	BufferSize     int
	FlushIntervalMs int
	TrackAll       bool
	DetectAgent    func(userAgent string) string
}

// EventBuffer buffers agent events and flushes them.
type EventBuffer struct {
	mu             sync.Mutex
	buffer         []AgentEvent
	bufferSize     int
	flushIntervalMs int
	endpoint       string
	apiKey         string
	onEvent        func(event AgentEvent)
	stopCh         chan struct{}
	stopped        bool
}

// NewEventBuffer creates a new event buffer.
func NewEventBuffer(config AnalyticsConfig) *EventBuffer {
	bufferSize := config.BufferSize
	if bufferSize == 0 {
		bufferSize = 50
	}
	flushIntervalMs := config.FlushIntervalMs
	if flushIntervalMs == 0 {
		flushIntervalMs = 30000
	}

	eb := &EventBuffer{
		buffer:          make([]AgentEvent, 0, bufferSize),
		bufferSize:      bufferSize,
		flushIntervalMs: flushIntervalMs,
		endpoint:        config.Endpoint,
		apiKey:          config.ApiKey,
		onEvent:         config.OnEvent,
		stopCh:          make(chan struct{}),
	}

	if eb.endpoint != "" {
		go eb.flushLoop()
	}

	return eb
}

func (eb *EventBuffer) flushLoop() {
	ticker := time.NewTicker(time.Duration(eb.flushIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			eb.Flush()
		case <-eb.stopCh:
			return
		}
	}
}

// Push adds an event to the buffer.
func (eb *EventBuffer) Push(event AgentEvent) {
	if eb.onEvent != nil {
		eb.onEvent(event)
	}

	if eb.endpoint != "" {
		eb.mu.Lock()
		eb.buffer = append(eb.buffer, event)
		shouldFlush := len(eb.buffer) >= eb.bufferSize
		eb.mu.Unlock()

		if shouldFlush {
			go eb.Flush()
		}
	}
}

// Flush sends buffered events to the remote endpoint.
func (eb *EventBuffer) Flush() {
	eb.mu.Lock()
	if len(eb.buffer) == 0 || eb.endpoint == "" {
		eb.mu.Unlock()
		return
	}
	batch := make([]AgentEvent, len(eb.buffer))
	copy(batch, eb.buffer)
	eb.buffer = eb.buffer[:0]
	eb.mu.Unlock()

	body, err := json.Marshal(map[string]interface{}{"events": batch})
	if err != nil {
		eb.mu.Lock()
		if len(eb.buffer) < eb.bufferSize*3 {
			eb.buffer = append(batch, eb.buffer...)
		}
		eb.mu.Unlock()
		return
	}

	req, err := http.NewRequest("POST", eb.endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if eb.apiKey != "" {
		req.Header.Set("X-API-Key", eb.apiKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		eb.mu.Lock()
		if len(eb.buffer) < eb.bufferSize*3 {
			eb.buffer = append(batch, eb.buffer...)
		}
		eb.mu.Unlock()
		return
	}
	resp.Body.Close()
}

// Shutdown stops the flush timer and flushes remaining events.
func (eb *EventBuffer) Shutdown() {
	eb.mu.Lock()
	if eb.stopped {
		eb.mu.Unlock()
		return
	}
	eb.stopped = true
	eb.mu.Unlock()

	close(eb.stopCh)
	eb.Flush()
}

// Pending returns the number of buffered events.
func (eb *EventBuffer) Pending() int {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	return len(eb.buffer)
}

// AnalyticsInstance wraps an event buffer with detection.
type AnalyticsInstance struct {
	Buffer *EventBuffer
	Detect func(userAgent string) string
	Config AnalyticsConfig
}

// Record records an agent event.
func (a *AnalyticsInstance) Record(event AgentEvent) {
	a.Buffer.Push(event)
}

// Flush flushes pending events.
func (a *AnalyticsInstance) Flush() {
	a.Buffer.Flush()
}

// Shutdown stops the analytics instance.
func (a *AnalyticsInstance) Shutdown() {
	a.Buffer.Shutdown()
}

// CreateAnalytics creates an analytics instance.
func CreateAnalytics(config AnalyticsConfig) *AnalyticsInstance {
	buffer := NewEventBuffer(config)

	detect := func(userAgent string) string {
		return DetectAgent(userAgent)
	}
	if config.DetectAgent != nil {
		detect = config.DetectAgent
	}

	return &AnalyticsInstance{
		Buffer: buffer,
		Detect: detect,
		Config: config,
	}
}

// IsAgentRequest checks if a User-Agent string belongs to a known agent.
func IsAgentRequest(userAgent string) bool {
	return strings.TrimSpace(DetectAgent(userAgent)) != ""
}
