package core

import (
	"fmt"
	"regexp"
	"strings"
)

// McpToolDefinition is a single MCP tool definition.
type McpToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// McpServerInfo is returned during MCP initialize.
type McpServerInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Instructions string `json:"instructions,omitempty"`
}

// McpServerConfig configures the MCP server.
type McpServerConfig struct {
	Tools        []McpToolDefinition
	Name         string
	Version      string
	Instructions string
	Routes       []RouteMetadata
}

// JsonRpcRequest is a JSON-RPC 2.0 request.
type JsonRpcRequest struct {
	Jsonrpc string                 `json:"jsonrpc"`
	ID      interface{}            `json:"id,omitempty"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params,omitempty"`
}

// JsonRpcResponse is a JSON-RPC 2.0 response.
type JsonRpcResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *JsonRpcError `json:"error,omitempty"`
}

// JsonRpcError is a JSON-RPC 2.0 error.
type JsonRpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var (
	paramColonRe = regexp.MustCompile(`:(\w+)`)
	paramBraceRe = regexp.MustCompile(`\{(\w+)\}`)
	nonAlnumRe   = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	multiUnderRe = regexp.MustCompile(`_+`)
)

// FormatToolName converts HTTP method + path into a snake_case tool name.
func FormatToolName(method, path string) string {
	cleanPath := strings.Trim(path, "/")
	cleanPath = paramColonRe.ReplaceAllString(cleanPath, "by_$1")
	cleanPath = paramBraceRe.ReplaceAllString(cleanPath, "by_$1")
	cleanPath = nonAlnumRe.ReplaceAllString(cleanPath, "_")
	cleanPath = multiUnderRe.ReplaceAllString(cleanPath, "_")
	cleanPath = strings.Trim(cleanPath, "_")

	return strings.ToLower(method) + "_" + strings.ToLower(cleanPath)
}

// BuildInputSchema builds a JSON Schema object from route parameters.
func BuildInputSchema(params []RouteParameter) map[string]interface{} {
	schema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}

	if len(params) == 0 {
		return schema
	}

	properties := map[string]interface{}{}
	var required []string

	for _, param := range params {
		prop := map[string]interface{}{
			"type": "string",
		}
		if param.Description != "" {
			prop["description"] = param.Description
		}
		properties[param.Name] = prop

		if param.Required {
			required = append(required, param.Name)
		}
	}

	schema["properties"] = properties
	if len(required) > 0 {
		schema["required"] = required
	}

	return schema
}

// GenerateToolDefinitions generates MCP tool definitions from route metadata.
func GenerateToolDefinitions(routes []RouteMetadata) []McpToolDefinition {
	tools := make([]McpToolDefinition, 0, len(routes))
	for _, route := range routes {
		desc := route.Summary
		if desc == "" {
			desc = route.Description
		}
		if desc == "" {
			desc = fmt.Sprintf("%s %s", strings.ToUpper(route.Method), route.Path)
		}

		tools = append(tools, McpToolDefinition{
			Name:        FormatToolName(route.Method, route.Path),
			Description: desc,
			InputSchema: BuildInputSchema(route.Parameters),
		})
	}
	return tools
}

// GenerateServerInfo generates MCP server info from config.
func GenerateServerInfo(config McpServerConfig) McpServerInfo {
	version := config.Version
	if version == "" {
		version = "1.0.0"
	}
	return McpServerInfo{
		Name:         config.Name,
		Version:      version,
		Instructions: config.Instructions,
	}
}

// ParseToolName parses a tool name back into HTTP method and path.
func ParseToolName(toolName string) (method string, path string) {
	parts := strings.Split(toolName, "_")
	method = strings.ToUpper(parts[0])
	pathParts := parts[1:]

	var segments []string
	for i := 0; i < len(pathParts); i++ {
		if pathParts[i] == "by" && i+1 < len(pathParts) {
			segments = append(segments, ":"+pathParts[i+1])
			i++
		} else {
			segments = append(segments, pathParts[i])
		}
	}

	path = "/" + strings.Join(segments, "/")
	return
}

// ToolCallHandler handles tool invocations.
type ToolCallHandler func(toolName string, args map[string]interface{}) ([]map[string]interface{}, error)

// HandleJsonRpc handles a JSON-RPC request per the MCP protocol.
func HandleJsonRpc(
	request JsonRpcRequest,
	serverInfo McpServerInfo,
	tools []McpToolDefinition,
	toolCallHandler ToolCallHandler,
) *JsonRpcResponse {
	// Notifications (no id) — acknowledge silently
	if request.ID == nil {
		return nil
	}

	switch request.Method {
	case "initialize":
		result := map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    serverInfo.Name,
				"version": serverInfo.Version,
			},
		}
		if serverInfo.Instructions != "" {
			result["instructions"] = serverInfo.Instructions
		}
		return &JsonRpcResponse{
			Jsonrpc: "2.0",
			ID:      request.ID,
			Result:  result,
		}

	case "ping":
		return &JsonRpcResponse{
			Jsonrpc: "2.0",
			ID:      request.ID,
			Result:  map[string]interface{}{},
		}

	case "tools/list":
		toolList := make([]map[string]interface{}, 0, len(tools))
		for _, t := range tools {
			toolList = append(toolList, map[string]interface{}{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.InputSchema,
			})
		}
		return &JsonRpcResponse{
			Jsonrpc: "2.0",
			ID:      request.ID,
			Result: map[string]interface{}{
				"tools": toolList,
			},
		}

	case "tools/call":
		name, _ := request.Params["name"].(string)
		if name == "" {
			return &JsonRpcResponse{
				Jsonrpc: "2.0",
				ID:      request.ID,
				Error: &JsonRpcError{
					Code:    -32602,
					Message: "Invalid params: tool name is required",
				},
			}
		}

		var found *McpToolDefinition
		for i := range tools {
			if tools[i].Name == name {
				found = &tools[i]
				break
			}
		}

		if found == nil {
			return &JsonRpcResponse{
				Jsonrpc: "2.0",
				ID:      request.ID,
				Error: &JsonRpcError{
					Code:    -32602,
					Message: fmt.Sprintf("Unknown tool: %s", name),
				},
			}
		}

		if toolCallHandler == nil {
			return &JsonRpcResponse{
				Jsonrpc: "2.0",
				ID:      request.ID,
				Error: &JsonRpcError{
					Code:    -32603,
					Message: "Tool call handler not configured",
				},
			}
		}

		args, _ := request.Params["arguments"].(map[string]interface{})
		if args == nil {
			args = map[string]interface{}{}
		}

		content, err := toolCallHandler(name, args)
		if err != nil {
			return &JsonRpcResponse{
				Jsonrpc: "2.0",
				ID:      request.ID,
				Error: &JsonRpcError{
					Code:    -32603,
					Message: err.Error(),
				},
			}
		}

		return &JsonRpcResponse{
			Jsonrpc: "2.0",
			ID:      request.ID,
			Result: map[string]interface{}{
				"content": content,
			},
		}

	default:
		return &JsonRpcResponse{
			Jsonrpc: "2.0",
			ID:      request.ID,
			Error: &JsonRpcError{
				Code:    -32601,
				Message: fmt.Sprintf("Method not found: %s", request.Method),
			},
		}
	}
}
