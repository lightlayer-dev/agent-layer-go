package core

import (
	"encoding/json"
	"fmt"
	"time"

	"crypto/rand"
	mrand "math/rand"
)

// AG-UI Event Types
const (
	AgUiRunStarted         = "RUN_STARTED"
	AgUiRunFinished        = "RUN_FINISHED"
	AgUiRunError           = "RUN_ERROR"
	AgUiStepStarted        = "STEP_STARTED"
	AgUiStepFinished       = "STEP_FINISHED"
	AgUiTextMessageStart   = "TEXT_MESSAGE_START"
	AgUiTextMessageContent = "TEXT_MESSAGE_CONTENT"
	AgUiTextMessageEnd     = "TEXT_MESSAGE_END"
	AgUiToolCallStart      = "TOOL_CALL_START"
	AgUiToolCallArgs       = "TOOL_CALL_ARGS"
	AgUiToolCallEnd        = "TOOL_CALL_END"
	AgUiToolCallResult     = "TOOL_CALL_RESULT"
	AgUiStateSnapshot      = "STATE_SNAPSHOT"
	AgUiStateDelta         = "STATE_DELTA"
	AgUiCustom             = "CUSTOM"
)

// AgUiHeaders are standard SSE response headers for AG-UI streams.
var AgUiHeaders = map[string]string{
	"Content-Type":      "text/event-stream",
	"Cache-Control":     "no-cache, no-transform",
	"Connection":        "keep-alive",
	"X-Accel-Buffering": "no",
}

// AgUiEvent is a generic AG-UI event.
type AgUiEvent map[string]interface{}

// EncodeEvent encodes an AG-UI event as SSE format.
func EncodeEvent(event AgUiEvent) string {
	eventType, _ := event["type"].(string)
	data, _ := json.Marshal(event)
	return fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(data))
}

// EncodeEvents encodes multiple AG-UI events.
func EncodeEvents(events []AgUiEvent) string {
	result := ""
	for _, event := range events {
		result += EncodeEvent(event)
	}
	return result
}

// AgUiEmitterOptions configures the emitter.
type AgUiEmitterOptions struct {
	ThreadID string
	RunID    string
}

// AgUiEmitter is a high-level AG-UI event emitter.
type AgUiEmitter struct {
	write            func(chunk string)
	threadID         string
	runID            string
	currentMessageID string
	currentToolCallID string
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback
		for i := range b {
			b[i] = byte(mrand.Intn(256))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// CreateAgUiEmitter creates a new AG-UI event emitter.
func CreateAgUiEmitter(write func(chunk string), options AgUiEmitterOptions) *AgUiEmitter {
	threadID := options.ThreadID
	if threadID == "" {
		threadID = generateUUID()
	}
	runID := options.RunID
	if runID == "" {
		runID = generateUUID()
	}

	return &AgUiEmitter{
		write:    write,
		threadID: threadID,
		runID:    runID,
	}
}

// ThreadID returns the current thread ID.
func (e *AgUiEmitter) ThreadID() string { return e.threadID }

// RunID returns the current run ID.
func (e *AgUiEmitter) RunID() string { return e.runID }

// Emit emits a raw event.
func (e *AgUiEmitter) Emit(event AgUiEvent) {
	if _, ok := event["timestamp"]; !ok {
		event["timestamp"] = time.Now().UnixMilli()
	}
	e.write(EncodeEvent(event))
}

// RunStarted emits a RUN_STARTED event.
func (e *AgUiEmitter) RunStarted(parentRunID string) {
	event := AgUiEvent{
		"type":     AgUiRunStarted,
		"threadId": e.threadID,
		"runId":    e.runID,
	}
	if parentRunID != "" {
		event["parentRunId"] = parentRunID
	}
	e.Emit(event)
}

// RunFinished emits a RUN_FINISHED event.
func (e *AgUiEmitter) RunFinished(result interface{}) {
	event := AgUiEvent{
		"type":     AgUiRunFinished,
		"threadId": e.threadID,
		"runId":    e.runID,
	}
	if result != nil {
		event["result"] = result
	}
	e.Emit(event)
}

// RunError emits a RUN_ERROR event.
func (e *AgUiEmitter) RunError(message string, code string) {
	event := AgUiEvent{
		"type":    AgUiRunError,
		"message": message,
	}
	if code != "" {
		event["code"] = code
	}
	e.Emit(event)
}

// StepStarted emits a STEP_STARTED event.
func (e *AgUiEmitter) StepStarted(stepName string) {
	e.Emit(AgUiEvent{
		"type":     AgUiStepStarted,
		"stepName": stepName,
	})
}

// StepFinished emits a STEP_FINISHED event.
func (e *AgUiEmitter) StepFinished(stepName string) {
	e.Emit(AgUiEvent{
		"type":     AgUiStepFinished,
		"stepName": stepName,
	})
}

// TextStart emits a TEXT_MESSAGE_START event.
func (e *AgUiEmitter) TextStart(role string, messageID string) string {
	if role == "" {
		role = "assistant"
	}
	if messageID == "" {
		messageID = generateUUID()
	}
	e.currentMessageID = messageID
	e.Emit(AgUiEvent{
		"type":      AgUiTextMessageStart,
		"messageId": messageID,
		"role":      role,
	})
	return messageID
}

// TextDelta emits a TEXT_MESSAGE_CONTENT event.
func (e *AgUiEmitter) TextDelta(delta string, messageID string) {
	id := messageID
	if id == "" {
		id = e.currentMessageID
	}
	if id == "" {
		panic("textDelta called without an active message. Call TextStart() first.")
	}
	e.Emit(AgUiEvent{
		"type":      AgUiTextMessageContent,
		"messageId": id,
		"delta":     delta,
	})
}

// TextEnd emits a TEXT_MESSAGE_END event.
func (e *AgUiEmitter) TextEnd(messageID string) {
	id := messageID
	if id == "" {
		id = e.currentMessageID
	}
	if id == "" {
		panic("textEnd called without an active message. Call TextStart() first.")
	}
	e.Emit(AgUiEvent{
		"type":      AgUiTextMessageEnd,
		"messageId": id,
	})
	if id == e.currentMessageID {
		e.currentMessageID = ""
	}
}

// TextMessage emits a complete text message (start + content + end).
func (e *AgUiEmitter) TextMessage(text string, role string) string {
	if role == "" {
		role = "assistant"
	}
	id := generateUUID()
	e.Emit(AgUiEvent{
		"type":      AgUiTextMessageStart,
		"messageId": id,
		"role":      role,
	})
	e.Emit(AgUiEvent{
		"type":      AgUiTextMessageContent,
		"messageId": id,
		"delta":     text,
	})
	e.Emit(AgUiEvent{
		"type":      AgUiTextMessageEnd,
		"messageId": id,
	})
	return id
}

// ToolCallStart emits a TOOL_CALL_START event.
func (e *AgUiEmitter) ToolCallStart(toolCallName string, toolCallID string, parentMessageID string) string {
	if toolCallID == "" {
		toolCallID = generateUUID()
	}
	e.currentToolCallID = toolCallID
	event := AgUiEvent{
		"type":         AgUiToolCallStart,
		"toolCallId":   toolCallID,
		"toolCallName": toolCallName,
	}
	if parentMessageID != "" {
		event["parentMessageId"] = parentMessageID
	}
	e.Emit(event)
	return toolCallID
}

// ToolCallArgs emits a TOOL_CALL_ARGS event.
func (e *AgUiEmitter) ToolCallArgs(delta string, toolCallID string) {
	id := toolCallID
	if id == "" {
		id = e.currentToolCallID
	}
	if id == "" {
		panic("toolCallArgs called without an active tool call.")
	}
	e.Emit(AgUiEvent{
		"type":       AgUiToolCallArgs,
		"toolCallId": id,
		"delta":      delta,
	})
}

// ToolCallEnd emits a TOOL_CALL_END event.
func (e *AgUiEmitter) ToolCallEnd(toolCallID string) {
	id := toolCallID
	if id == "" {
		id = e.currentToolCallID
	}
	if id == "" {
		panic("toolCallEnd called without an active tool call.")
	}
	e.Emit(AgUiEvent{
		"type":       AgUiToolCallEnd,
		"toolCallId": id,
	})
}

// ToolCallResult emits a TOOL_CALL_RESULT event.
func (e *AgUiEmitter) ToolCallResult(result string, toolCallID string) {
	id := toolCallID
	if id == "" {
		id = e.currentToolCallID
	}
	if id == "" {
		panic("toolCallResult called without an active tool call.")
	}
	e.Emit(AgUiEvent{
		"type":       AgUiToolCallResult,
		"toolCallId": id,
		"result":     result,
	})
	if id == e.currentToolCallID {
		e.currentToolCallID = ""
	}
}

// StateSnapshot emits a STATE_SNAPSHOT event.
func (e *AgUiEmitter) StateSnapshot(snapshot map[string]interface{}) {
	e.Emit(AgUiEvent{
		"type":     AgUiStateSnapshot,
		"snapshot": snapshot,
	})
}

// StateDelta emits a STATE_DELTA event.
func (e *AgUiEmitter) StateDelta(delta []interface{}) {
	e.Emit(AgUiEvent{
		"type":  AgUiStateDelta,
		"delta": delta,
	})
}

// Custom emits a CUSTOM event.
func (e *AgUiEmitter) Custom(name string, value interface{}) {
	e.Emit(AgUiEvent{
		"type":  AgUiCustom,
		"name":  name,
		"value": value,
	})
}
