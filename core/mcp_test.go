package core

import (
	"errors"
	"testing"
)

func TestFormatToolName(t *testing.T) {
	tests := []struct {
		method   string
		path     string
		expected string
	}{
		{"GET", "/api/users", "get_api_users"},
		{"POST", "/api/users", "post_api_users"},
		{"GET", "/api/users/:id", "get_api_users_by_id"},
		{"PUT", "/api/users/:id", "put_api_users_by_id"},
		{"DELETE", "/api/users/{id}", "delete_api_users_by_id"},
		{"GET", "/api/users/:userId/posts/:postId", "get_api_users_by_userid_posts_by_postid"},
		{"GET", "/health", "get_health"},
		{"GET", "/", "get_"},
		{"PATCH", "/api/items/{itemId}/tags", "patch_api_items_by_itemid_tags"},
	}

	for _, tt := range tests {
		result := FormatToolName(tt.method, tt.path)
		if result != tt.expected {
			t.Errorf("FormatToolName(%q, %q) = %q, expected %q", tt.method, tt.path, result, tt.expected)
		}
	}
}

func TestBuildInputSchema_EmptyParams(t *testing.T) {
	schema := BuildInputSchema(nil)

	if schema["type"] != "object" {
		t.Errorf("expected type 'object', got %v", schema["type"])
	}
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("expected properties to be a map")
	}
	if len(props) != 0 {
		t.Errorf("expected empty properties, got %d", len(props))
	}
	if _, exists := schema["required"]; exists {
		t.Error("expected no 'required' field for empty params")
	}
}

func TestBuildInputSchema_WithDescriptions(t *testing.T) {
	params := []RouteParameter{
		{Name: "name", Description: "The user's name"},
		{Name: "age", Description: "The user's age"},
	}

	schema := BuildInputSchema(params)
	props := schema["properties"].(map[string]interface{})

	nameProp := props["name"].(map[string]interface{})
	if nameProp["description"] != "The user's name" {
		t.Errorf("expected description for name, got %v", nameProp["description"])
	}
	if nameProp["type"] != "string" {
		t.Errorf("expected type string, got %v", nameProp["type"])
	}

	ageProp := props["age"].(map[string]interface{})
	if ageProp["description"] != "The user's age" {
		t.Errorf("expected description for age, got %v", ageProp["description"])
	}
}

func TestBuildInputSchema_RequiredParams(t *testing.T) {
	params := []RouteParameter{
		{Name: "id", Required: true},
		{Name: "name", Required: true},
		{Name: "bio", Required: false},
	}

	schema := BuildInputSchema(params)
	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatal("expected required to be a string slice")
	}
	if len(required) != 2 {
		t.Errorf("expected 2 required fields, got %d", len(required))
	}

	reqMap := map[string]bool{}
	for _, r := range required {
		reqMap[r] = true
	}
	if !reqMap["id"] || !reqMap["name"] {
		t.Errorf("expected id and name in required, got %v", required)
	}
}

func TestBuildInputSchema_NoDescription(t *testing.T) {
	params := []RouteParameter{
		{Name: "id"},
	}

	schema := BuildInputSchema(params)
	props := schema["properties"].(map[string]interface{})
	idProp := props["id"].(map[string]interface{})

	if _, exists := idProp["description"]; exists {
		t.Error("expected no description field when empty")
	}
}

func TestGenerateToolDefinitions_FromRoutes(t *testing.T) {
	routes := []RouteMetadata{
		{
			Method:  "GET",
			Path:    "/api/users",
			Summary: "List all users",
		},
		{
			Method:      "POST",
			Path:        "/api/users",
			Description: "Create a new user",
		},
		{
			Method: "DELETE",
			Path:   "/api/users/:id",
		},
	}

	tools := GenerateToolDefinitions(routes)

	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	// First tool uses Summary
	if tools[0].Name != "get_api_users" {
		t.Errorf("expected name get_api_users, got %s", tools[0].Name)
	}
	if tools[0].Description != "List all users" {
		t.Errorf("expected description 'List all users', got '%s'", tools[0].Description)
	}

	// Second tool uses Description (no Summary)
	if tools[1].Description != "Create a new user" {
		t.Errorf("expected description 'Create a new user', got '%s'", tools[1].Description)
	}

	// Third tool falls back to "METHOD PATH"
	if tools[2].Description != "DELETE /api/users/:id" {
		t.Errorf("expected fallback description, got '%s'", tools[2].Description)
	}
}

func TestGenerateToolDefinitions_WithParameters(t *testing.T) {
	routes := []RouteMetadata{
		{
			Method:  "GET",
			Path:    "/api/users/:id",
			Summary: "Get user by ID",
			Parameters: []RouteParameter{
				{Name: "id", Required: true, Description: "User ID"},
			},
		},
	}

	tools := GenerateToolDefinitions(routes)
	schema := tools[0].InputSchema
	props := schema["properties"].(map[string]interface{})

	if _, exists := props["id"]; !exists {
		t.Error("expected id in properties")
	}
}

func TestGenerateServerInfo_DefaultVersion(t *testing.T) {
	info := GenerateServerInfo(McpServerConfig{
		Name: "test-server",
	})

	if info.Name != "test-server" {
		t.Errorf("expected name 'test-server', got '%s'", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("expected default version '1.0.0', got '%s'", info.Version)
	}
}

func TestGenerateServerInfo_CustomVersion(t *testing.T) {
	info := GenerateServerInfo(McpServerConfig{
		Name:    "test-server",
		Version: "2.5.0",
	})

	if info.Version != "2.5.0" {
		t.Errorf("expected version '2.5.0', got '%s'", info.Version)
	}
}

func TestGenerateServerInfo_Instructions(t *testing.T) {
	info := GenerateServerInfo(McpServerConfig{
		Name:         "test-server",
		Instructions: "Use this API for user management",
	})

	if info.Instructions != "Use this API for user management" {
		t.Errorf("expected instructions, got '%s'", info.Instructions)
	}
}

func TestParseToolName(t *testing.T) {
	tests := []struct {
		toolName       string
		expectedMethod string
		expectedPath   string
	}{
		{"get_api_users", "GET", "/api/users"},
		{"post_api_users", "POST", "/api/users"},
		{"get_api_users_by_id", "GET", "/api/users/:id"},
		{"delete_api_users_by_id", "DELETE", "/api/users/:id"},
		{"get_api_users_by_userid_posts_by_postid", "GET", "/api/users/:userid/posts/:postid"},
		{"get_health", "GET", "/health"},
	}

	for _, tt := range tests {
		method, path := ParseToolName(tt.toolName)
		if method != tt.expectedMethod {
			t.Errorf("ParseToolName(%q): expected method %q, got %q", tt.toolName, tt.expectedMethod, method)
		}
		if path != tt.expectedPath {
			t.Errorf("ParseToolName(%q): expected path %q, got %q", tt.toolName, tt.expectedPath, path)
		}
	}
}

func TestHandleJsonRpc_Initialize(t *testing.T) {
	serverInfo := McpServerInfo{Name: "test", Version: "1.0.0"}
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "initialize",
	}

	resp := HandleJsonRpc(req, serverInfo, nil, nil)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Jsonrpc != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", resp.Jsonrpc)
	}
	if resp.Error != nil {
		t.Errorf("expected no error, got %v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	if result["protocolVersion"] != "2025-03-26" {
		t.Errorf("expected protocol version 2025-03-26, got %v", result["protocolVersion"])
	}

	si := result["serverInfo"].(map[string]interface{})
	if si["name"] != "test" {
		t.Errorf("expected server name 'test', got %v", si["name"])
	}
}

func TestHandleJsonRpc_InitializeWithInstructions(t *testing.T) {
	serverInfo := McpServerInfo{Name: "test", Version: "1.0.0", Instructions: "Be helpful"}
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "initialize",
	}

	resp := HandleJsonRpc(req, serverInfo, nil, nil)
	result := resp.Result.(map[string]interface{})
	if result["instructions"] != "Be helpful" {
		t.Errorf("expected instructions 'Be helpful', got %v", result["instructions"])
	}
}

func TestHandleJsonRpc_Ping(t *testing.T) {
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "ping",
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, nil, nil)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Errorf("expected no error for ping, got %v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	if len(result) != 0 {
		t.Errorf("expected empty result for ping, got %v", result)
	}
}

func TestHandleJsonRpc_ToolsList(t *testing.T) {
	tools := []McpToolDefinition{
		{
			Name:        "get_users",
			Description: "List users",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			Name:        "post_users",
			Description: "Create user",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/list",
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, tools, nil)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	toolList := result["tools"].([]map[string]interface{})
	if len(toolList) != 2 {
		t.Errorf("expected 2 tools, got %d", len(toolList))
	}
	if toolList[0]["name"] != "get_users" {
		t.Errorf("expected first tool name 'get_users', got %v", toolList[0]["name"])
	}
}

func TestHandleJsonRpc_ToolsCallSuccess(t *testing.T) {
	tools := []McpToolDefinition{
		{Name: "get_users", Description: "List users", InputSchema: map[string]interface{}{}},
	}

	handler := func(toolName string, args map[string]interface{}) ([]map[string]interface{}, error) {
		return []map[string]interface{}{
			{"type": "text", "text": "user list"},
		}, nil
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "get_users",
			"arguments": map[string]interface{}{},
		},
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, tools, handler)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	content := result["content"].([]map[string]interface{})
	if len(content) != 1 {
		t.Errorf("expected 1 content item, got %d", len(content))
	}
	if content[0]["text"] != "user list" {
		t.Errorf("expected text 'user list', got %v", content[0]["text"])
	}
}

func TestHandleJsonRpc_ToolsCallMissingName(t *testing.T) {
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params:  map[string]interface{}{},
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, nil, nil)
	if resp.Error == nil {
		t.Fatal("expected error for missing tool name")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("expected error code -32602, got %d", resp.Error.Code)
	}
}

func TestHandleJsonRpc_ToolsCallUnknownTool(t *testing.T) {
	tools := []McpToolDefinition{
		{Name: "get_users", Description: "List users"},
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "delete_everything",
		},
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, tools, nil)
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("expected error code -32602, got %d", resp.Error.Code)
	}
}

func TestHandleJsonRpc_ToolsCallNoHandler(t *testing.T) {
	tools := []McpToolDefinition{
		{Name: "get_users", Description: "List users"},
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "get_users",
		},
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, tools, nil)
	if resp.Error == nil {
		t.Fatal("expected error when handler is nil")
	}
	if resp.Error.Code != -32603 {
		t.Errorf("expected error code -32603, got %d", resp.Error.Code)
	}
}

func TestHandleJsonRpc_ToolsCallHandlerError(t *testing.T) {
	tools := []McpToolDefinition{
		{Name: "get_users", Description: "List users"},
	}

	handler := func(toolName string, args map[string]interface{}) ([]map[string]interface{}, error) {
		return nil, errors.New("database connection failed")
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "get_users",
		},
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, tools, handler)
	if resp.Error == nil {
		t.Fatal("expected error from handler")
	}
	if resp.Error.Code != -32603 {
		t.Errorf("expected error code -32603, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "database connection failed" {
		t.Errorf("expected handler error message, got '%s'", resp.Error.Message)
	}
}

func TestHandleJsonRpc_ToolsCallWithArguments(t *testing.T) {
	tools := []McpToolDefinition{
		{Name: "get_user", Description: "Get user by ID"},
	}

	var receivedArgs map[string]interface{}
	handler := func(toolName string, args map[string]interface{}) ([]map[string]interface{}, error) {
		receivedArgs = args
		return []map[string]interface{}{{"type": "text", "text": "ok"}}, nil
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "get_user",
			"arguments": map[string]interface{}{"id": "123"},
		},
	}

	HandleJsonRpc(req, McpServerInfo{}, tools, handler)
	if receivedArgs["id"] != "123" {
		t.Errorf("expected args id=123, got %v", receivedArgs)
	}
}

func TestHandleJsonRpc_ToolsCallNilArguments(t *testing.T) {
	tools := []McpToolDefinition{
		{Name: "get_users", Description: "List users"},
	}

	var receivedArgs map[string]interface{}
	handler := func(toolName string, args map[string]interface{}) ([]map[string]interface{}, error) {
		receivedArgs = args
		return []map[string]interface{}{{"type": "text", "text": "ok"}}, nil
	}

	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "get_users",
		},
	}

	HandleJsonRpc(req, McpServerInfo{}, tools, handler)
	if receivedArgs == nil {
		t.Error("expected non-nil args even when not provided")
	}
}

func TestHandleJsonRpc_UnknownMethod(t *testing.T) {
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(1),
		Method:  "unknown/method",
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, nil, nil)
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestHandleJsonRpc_NotificationNilID(t *testing.T) {
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      nil,
		Method:  "notifications/initialized",
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, nil, nil)
	if resp != nil {
		t.Error("expected nil response for notification (nil ID)")
	}
}

func TestHandleJsonRpc_ResponseIDMatches(t *testing.T) {
	req := JsonRpcRequest{
		Jsonrpc: "2.0",
		ID:      float64(42),
		Method:  "ping",
	}

	resp := HandleJsonRpc(req, McpServerInfo{}, nil, nil)
	if resp.ID != float64(42) {
		t.Errorf("expected response ID 42, got %v", resp.ID)
	}
}
