package mcptests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const injectedSearchTool = "bifrostInternal-web_search"

// fakeOpenAI answers /v1/chat/completions from a script and records every body it got.
type fakeOpenAI struct {
	mu      sync.Mutex
	bodies  []map[string]any
	replies []string
}

func (f *fakeOpenAI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	reply := f.replies[0]
	f.replies = f.replies[1:]
	f.mu.Unlock()
	if strings.HasPrefix(reply, "data:") {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	_, _ = w.Write([]byte(reply))
}

func (f *fakeOpenAI) toolNames(turn int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	tools, _ := f.bodies[turn]["tools"].([]any)
	for _, tool := range tools {
		entry, _ := tool.(map[string]any)
		if fn, ok := entry["function"].(map[string]any); ok {
			names = append(names, fn["name"].(string))
		} else if name, ok := entry["name"].(string); ok {
			names = append(names, name)
		} else {
			names = append(names, entry["type"].(string))
		}
	}
	return names
}

func chatCompletionJSON(content string, finish string, toolCall string) string {
	message := map[string]any{"role": "assistant", "content": content}
	if toolCall != "" {
		message["content"] = nil
		message["tool_calls"] = []any{map[string]any{
			"id": "call_1", "type": "function",
			"function": map[string]any{"name": toolCall, "arguments": `{"query":"weather in paris"}`},
		}}
	}
	out, _ := json.Marshal(map[string]any{
		"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o",
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}},
		"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
	})
	return string(out)
}

// injectedToolsAccount serves one OpenAI provider pointed at a fake server, with the
// in-process web_search tool configured as the provider's injected web search.
type injectedToolsAccount struct{ baseURL string }

func (a *injectedToolsAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI}, nil
}

func (a *injectedToolsAccount) GetKeysForProvider(ctx context.Context, provider schemas.ModelProvider) ([]schemas.Key, error) {
	return []schemas.Key{{ID: "k1", Value: *schemas.NewSecretVar("sk-test"), Models: schemas.WhiteList{"*"}, Weight: 1}}, nil
}

func (a *injectedToolsAccount) GetConfigForProvider(provider schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	network := schemas.DefaultNetworkConfig
	network.BaseURL = a.baseURL
	network.MaxRetries = 0
	return &schemas.ProviderConfig{
		NetworkConfig:            network,
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
		InjectedTools: &schemas.InjectedToolsConfig{
			WebSearch: &schemas.InjectedToolRef{MCPClientName: "bifrostInternal", ToolName: "web_search"},
		},
	}, nil
}

func setupInjectedToolsBifrost(t *testing.T, fake *fakeOpenAI, searches *[]string) *bifrost.Bifrost {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	b, err := bifrost.Init(context.Background(), schemas.BifrostConfig{
		Account: &injectedToolsAccount{baseURL: server.URL},
		Logger:  bifrost.NewDefaultLogger(schemas.LogLevelError),
		MCPConfig: &schemas.MCPConfig{
			// Regular MCP auto-injection stays off: the provider config alone must put
			// the tool on the wire.
			ToolManagerConfig: &schemas.MCPToolManagerConfig{DisableAutoToolInject: true},
		},
	})
	require.NoError(t, err)
	t.Cleanup(b.Shutdown)

	var mu sync.Mutex
	schema := schemas.ChatTool{
		Type: schemas.ChatToolTypeFunction,
		Function: &schemas.ChatToolFunction{
			Name: "web_search",
			Parameters: &schemas.ToolFunctionParameters{
				Type:       "object",
				Properties: schemas.NewOrderedMapFromPairs(schemas.KV("query", map[string]any{"type": "string"})),
				Required:   []string{"query"},
			},
		},
	}
	require.NoError(t, b.RegisterMCPTool("web_search", "Search the web", func(args any) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		query, _ := args.(map[string]any)["query"].(string)
		*searches = append(*searches, query)
		return "Paris: sunny, 24C", nil
	}, schema))
	return b
}

// TestInjectedWebSearch_ChatEndToEnd drives a chat request through Bifrost against a
// provider whose config injects an MCP web search tool. The client sends Anthropic's
// native web search tool and an include list that excludes the MCP tool; Bifrost must
// replace the native tool, run the search itself, and return only the final answer.
func TestInjectedWebSearch_ChatEndToEnd(t *testing.T) {
	fake := &fakeOpenAI{replies: []string{
		chatCompletionJSON("", "tool_calls", injectedSearchTool),
		chatCompletionJSON("It is sunny in Paris.", "stop", ""),
	}}
	var searches []string
	b := setupInjectedToolsBifrost(t, fake, &searches)

	ctx := createTestContext()
	ctx.SetValue(schemas.MCPContextKeyIncludeTools, []string{"other-tool"})
	resp, bifrostErr := b.ChatCompletionRequest(ctx, &schemas.BifrostChatRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt-4o",
		Input:    []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Weather in Paris?")}}},
		Params: &schemas.ChatParameters{
			Tools: []schemas.ChatTool{{Type: "web_search_20250305", Name: "web_search"}},
		},
	})

	require.Nil(t, bifrostErr, "%v", bifrostErr)
	assert.Equal(t, []string{"weather in paris"}, searches, "Bifrost ran the search itself")
	require.Len(t, fake.bodies, 2)
	assert.Equal(t, []string{injectedSearchTool}, fake.toolNames(0), "the native tool is replaced by the MCP tool")

	messages, _ := fake.bodies[1]["messages"].([]any)
	require.Len(t, messages, 3, "user, assistant tool call, tool result")
	toolResult := messages[2].(map[string]any)
	assert.Equal(t, "tool", toolResult["role"])
	assert.Contains(t, toolResult["content"], "sunny")

	msg := resp.Choices[0].Message
	assert.Equal(t, "It is sunny in Paris.", *msg.Content.ContentStr)
	assert.True(t, msg.ChatAssistantMessage == nil || len(msg.ToolCalls) == 0, "the client never sees the injected call")
	assert.Equal(t, 20, resp.Usage.PromptTokens, "usage covers both model turns")
}

// TestInjectedWebSearch_ClientToolCallsPassThrough pins that injection does not take
// over the client's own tools: they stay declared next to the injected one, and a call
// to them comes back to the client unexecuted.
func TestInjectedWebSearch_ClientToolCallsPassThrough(t *testing.T) {
	fake := &fakeOpenAI{replies: []string{
		chatCompletionJSON("", "tool_calls", "get_weather"),
	}}
	var searches []string
	b := setupInjectedToolsBifrost(t, fake, &searches)

	resp, bifrostErr := b.ChatCompletionRequest(createTestContext(), &schemas.BifrostChatRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt-4o",
		Input:    []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Weather?")}}},
		Params: &schemas.ChatParameters{Tools: []schemas.ChatTool{{
			Type: schemas.ChatToolTypeFunction, Function: &schemas.ChatToolFunction{Name: "get_weather"},
		}}},
	})

	require.Nil(t, bifrostErr, "%v", bifrostErr)
	assert.Empty(t, searches)
	assert.Equal(t, []string{"get_weather", injectedSearchTool}, fake.toolNames(0))
	require.Len(t, resp.Choices[0].Message.ToolCalls, 1, "a client tool call goes back to the client")
	assert.Equal(t, "get_weather", *resp.Choices[0].Message.ToolCalls[0].Function.Name)
}

// sseChat renders chat completion chunks as an OpenAI SSE body.
func sseChat(id string, chunks ...string) string {
	var b strings.Builder
	for _, chunk := range chunks {
		b.WriteString(`data: {"id":"` + id + `","object":"chat.completion.chunk","created":1,"model":"gpt-4o",` + chunk + "}\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

// TestInjectedWebSearch_ChatStreamEndToEnd streams a chat request across two upstream
// turns. The client must get one stream: the first turn's text live, no injected tool
// call deltas, the answer, and a single final chunk carrying both turns' usage.
func TestInjectedWebSearch_ChatStreamEndToEnd(t *testing.T) {
	fake := &fakeOpenAI{replies: []string{
		sseChat("turn-1",
			`"choices":[{"index":0,"delta":{"role":"assistant","content":"Let me search. "},"finish_reason":null}]`,
			`"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"`+injectedSearchTool+`","arguments":""}}]},"finish_reason":null}]`,
			`"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"query\":\"weather in paris\"}"}}]},"finish_reason":null}]`,
			`"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]`,
			`"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}`,
		),
		sseChat("turn-2",
			`"choices":[{"index":0,"delta":{"role":"assistant","content":"It is sunny."},"finish_reason":null}]`,
			`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]`,
			`"choices":[],"usage":{"prompt_tokens":20,"completion_tokens":3,"total_tokens":23}`,
		),
	}}
	var searches []string
	b := setupInjectedToolsBifrost(t, fake, &searches)

	stream, bifrostErr := b.ChatCompletionStreamRequest(createTestContext(), &schemas.BifrostChatRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt-4o",
		Input:    []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Weather in Paris?")}}},
		Params:   &schemas.ChatParameters{WebSearchOptions: &schemas.ChatWebSearchOptions{}},
	})
	require.Nil(t, bifrostErr, "%v", bifrostErr)

	var text strings.Builder
	var finishes []string
	var usages []*schemas.BifrostLLMUsage
	ids := map[string]bool{}
	for chunk := range stream {
		require.Nil(t, chunk.BifrostError, "%v", chunk.BifrostError)
		require.NotNil(t, chunk.BifrostChatResponse)
		ids[chunk.BifrostChatResponse.ID] = true
		if chunk.BifrostChatResponse.Usage != nil {
			usages = append(usages, chunk.BifrostChatResponse.Usage)
		}
		for _, choice := range chunk.BifrostChatResponse.Choices {
			if choice.Delta != nil {
				assert.Empty(t, choice.Delta.ToolCalls, "no tool call delta reaches the client")
				if choice.Delta.Content != nil {
					text.WriteString(*choice.Delta.Content)
				}
			}
			if choice.FinishReason != nil {
				finishes = append(finishes, *choice.FinishReason)
			}
		}
	}

	assert.Equal(t, []string{"weather in paris"}, searches)
	assert.Equal(t, "Let me search. It is sunny.", text.String())
	assert.Equal(t, []string{"stop"}, finishes, "one finish reason, from the last turn")
	require.Len(t, usages, 1, "one usage, on the final chunk")
	assert.Equal(t, 30, usages[0].PromptTokens)
	assert.Equal(t, map[string]bool{"turn-1": true}, ids, "the client sees one stream id")
	require.Len(t, fake.bodies, 2)
	assert.Equal(t, []string{injectedSearchTool}, fake.toolNames(0))
	assert.Nil(t, fake.bodies[0]["web_search_options"], "native web search is not enabled upstream")
}

// sseEvents renders Responses API events as an SSE body.
func sseEvents(events ...string) string {
	var b strings.Builder
	for _, event := range events {
		b.WriteString("data: " + event + "\n\n")
	}
	return b.String()
}

// TestInjectedWebSearch_ResponsesStreamEndToEnd streams a Responses request across two
// upstream turns. The client must see one response: one created and one completed
// event, gapless sequence numbers, no function call events, and summed usage.
func TestInjectedWebSearch_ResponsesStreamEndToEnd(t *testing.T) {
	call := `{"type":"function_call","id":"fc_1","call_id":"call_1","name":"` + injectedSearchTool + `","arguments":"{\"query\":\"weather in paris\"}","status":"completed"}`
	fake := &fakeOpenAI{replies: []string{
		sseEvents(
			`{"type":"response.created","sequence_number":0,"response":{"id":"resp_1","object":"response","created_at":1,"status":"in_progress","model":"gpt-4o","output":[]}}`,
			`{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"`+injectedSearchTool+`","arguments":"","status":"in_progress"}}`,
			`{"type":"response.function_call_arguments.delta","sequence_number":2,"output_index":0,"item_id":"fc_1","delta":"{\"query\":\"weather in paris\"}"}`,
			`{"type":"response.output_item.done","sequence_number":3,"output_index":0,"item":`+call+`}`,
			`{"type":"response.completed","sequence_number":4,"response":{"id":"resp_1","object":"response","created_at":1,"status":"completed","model":"gpt-4o","output":[`+call+`],"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12}}}`,
		),
		sseEvents(
			`{"type":"response.created","sequence_number":0,"response":{"id":"resp_2","object":"response","created_at":2,"status":"in_progress","model":"gpt-4o","output":[]}}`,
			`{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"type":"message","id":"msg_2","role":"assistant","status":"in_progress","content":[]}}`,
			`{"type":"response.output_text.delta","sequence_number":2,"output_index":0,"item_id":"msg_2","content_index":0,"delta":"It is sunny."}`,
			`{"type":"response.output_item.done","sequence_number":3,"output_index":0,"item":{"type":"message","id":"msg_2","role":"assistant","status":"completed","content":[{"type":"output_text","text":"It is sunny.","annotations":[]}]}}`,
			`{"type":"response.completed","sequence_number":4,"response":{"id":"resp_2","object":"response","created_at":2,"status":"completed","model":"gpt-4o","output":[{"type":"message","id":"msg_2","role":"assistant","status":"completed","content":[{"type":"output_text","text":"It is sunny.","annotations":[]}]}],"usage":{"input_tokens":20,"output_tokens":3,"total_tokens":23}}}`,
		),
	}}
	var searches []string
	b := setupInjectedToolsBifrost(t, fake, &searches)

	stream, bifrostErr := b.ResponsesStreamRequest(createTestContext(), &schemas.BifrostResponsesRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt-4o",
		Input: []schemas.ResponsesMessage{{
			Type:    schemas.Ptr(schemas.ResponsesMessageTypeMessage),
			Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleUser),
			Content: &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr("Weather in Paris?")},
		}},
		Params: &schemas.ResponsesParameters{Tools: []schemas.ResponsesTool{{Type: schemas.ResponsesToolTypeWebSearch}}},
	})
	require.Nil(t, bifrostErr, "%v", bifrostErr)

	var types []schemas.ResponsesStreamResponseType
	var text strings.Builder
	var completed *schemas.BifrostResponsesResponse
	lastSeq := -1
	for chunk := range stream {
		require.Nil(t, chunk.BifrostError, "%v", chunk.BifrostError)
		ev := chunk.BifrostResponsesStreamResponse
		require.NotNil(t, ev)
		assert.Equal(t, lastSeq+1, ev.SequenceNumber, "sequence numbers are gapless across turns")
		lastSeq = ev.SequenceNumber
		types = append(types, ev.Type)
		if ev.Type == schemas.ResponsesStreamResponseTypeOutputTextDelta && ev.Delta != nil {
			text.WriteString(*ev.Delta)
		}
		if ev.Type == schemas.ResponsesStreamResponseTypeCompleted {
			completed = ev.Response
		}
	}

	assert.Equal(t, []string{"weather in paris"}, searches)
	assert.Equal(t, "It is sunny.", text.String())
	count := func(typ schemas.ResponsesStreamResponseType) int {
		n := 0
		for _, got := range types {
			if got == typ {
				n++
			}
		}
		return n
	}
	assert.Equal(t, 1, count(schemas.ResponsesStreamResponseTypeCreated))
	assert.Equal(t, 1, count(schemas.ResponsesStreamResponseTypeCompleted))
	assert.Zero(t, count(schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta), "no injected call event reaches the client")
	require.NotNil(t, completed)
	assert.Equal(t, "resp_1", *completed.ID)
	assert.Equal(t, 30, completed.Usage.InputTokens)

	require.Len(t, fake.bodies, 2)
	assert.Equal(t, []string{injectedSearchTool}, fake.toolNames(0), "the native web_search tool is replaced")
	input, _ := fake.bodies[1]["input"].([]any)
	var replayed []string
	for _, item := range input {
		if typ, ok := item.(map[string]any)["type"].(string); ok {
			replayed = append(replayed, typ)
		}
	}
	assert.Contains(t, replayed, "function_call")
	assert.Contains(t, replayed, "function_call_output")
}
