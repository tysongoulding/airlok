package bifrost

import (
	"errors"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeInjectedToolSource struct {
	tools    map[string]schemas.ChatTool
	maxDepth int
}

func (f fakeInjectedToolSource) GetInjectedTool(clientName, toolName string) (schemas.ChatTool, error) {
	tool, ok := f.tools[clientName+"-"+toolName]
	if !ok {
		return schemas.ChatTool{}, errors.New("not found")
	}
	return tool, nil
}

func (f fakeInjectedToolSource) GetMaxAgentDepth() int { return f.maxDepth }

func tavilySearchTool() schemas.ChatTool {
	return schemas.ChatTool{
		Type: schemas.ChatToolTypeFunction,
		Function: &schemas.ChatToolFunction{
			Name:        "tavily-search",
			Description: schemas.Ptr("Search the web"),
			Parameters:  &schemas.ToolFunctionParameters{Type: "object"},
		},
	}
}

func webSearchConfig() *schemas.ProviderConfig {
	return &schemas.ProviderConfig{InjectedTools: &schemas.InjectedToolsConfig{
		WebSearch: &schemas.InjectedToolRef{MCPClientName: "tavily", ToolName: "search"},
	}}
}

func testInjectedSet(t *testing.T) *injectedToolSet {
	t.Helper()
	src := fakeInjectedToolSource{tools: map[string]schemas.ChatTool{"tavily-search": tavilySearchTool()}, maxDepth: 4}
	set := resolveInjectedTools(src, webSearchConfig(), schemas.ChatCompletionRequest, nil)
	require.NotNil(t, set)
	return set
}

func TestResolveInjectedTools(t *testing.T) {
	src := fakeInjectedToolSource{tools: map[string]schemas.ChatTool{"tavily-search": tavilySearchTool()}, maxDepth: 4}

	for _, rt := range []schemas.RequestType{schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest, schemas.ResponsesRequest, schemas.ResponsesStreamRequest} {
		set := resolveInjectedTools(src, webSearchConfig(), rt, nil)
		require.NotNil(t, set, "%s requests get the injected tool", rt)
		assert.True(t, set.isInjected("tavily-search"))
		assert.False(t, set.isInjected("tavily-crawl"))
		assert.Equal(t, 4, set.maxDepth)
	}

	assert.Nil(t, resolveInjectedTools(src, webSearchConfig(), schemas.EmbeddingRequest, nil), "only chat and responses carry tools")
	assert.Nil(t, resolveInjectedTools(src, &schemas.ProviderConfig{}, schemas.ChatCompletionRequest, nil))
	assert.Nil(t, resolveInjectedTools(src, nil, schemas.ChatCompletionRequest, nil))
	assert.Nil(t, resolveInjectedTools(nil, webSearchConfig(), schemas.ChatCompletionRequest, nil), "no MCP manager, nothing to inject")

	missing := webSearchConfig()
	missing.InjectedTools.WebSearch.ToolName = "crawl"
	assert.Nil(t, resolveInjectedTools(src, missing, schemas.ChatCompletionRequest, nil), "an unresolvable tool fails open")

	noDepth := fakeInjectedToolSource{tools: src.tools}
	assert.Equal(t, schemas.DefaultMaxAgentDepth, resolveInjectedTools(noDepth, webSearchConfig(), schemas.ChatCompletionRequest, nil).maxDepth)
}

func TestApplyInjectedToolsChat_ReplacesNativeWebSearch(t *testing.T) {
	set := testInjectedSet(t)
	weather := schemas.ChatTool{Type: schemas.ChatToolTypeFunction, Function: &schemas.ChatToolFunction{Name: "get_weather"}}
	original := &schemas.BifrostChatRequest{
		Provider: schemas.Anthropic,
		Model:    "claude",
		Params: &schemas.ChatParameters{
			Tools: []schemas.ChatTool{
				weather,
				{Type: "web_search_20250305", Name: "web_search", MaxUses: schemas.Ptr(3)},
				{Type: "openrouter:web_search"},
			},
			WebSearchOptions: &schemas.ChatWebSearchOptions{},
			ToolChoice: &schemas.ChatToolChoice{ChatToolChoiceStruct: &schemas.ChatToolChoiceStruct{
				Type:     schemas.ChatToolChoiceTypeFunction,
				Function: &schemas.ChatToolChoiceFunction{Name: "web_search"},
			}},
		},
	}

	got := applyInjectedToolsChat(original, set)

	require.NotSame(t, original, got)
	require.Len(t, got.Params.Tools, 2)
	assert.Equal(t, "get_weather", got.Params.Tools[0].Function.Name)
	assert.Equal(t, "tavily-search", got.Params.Tools[1].Function.Name)
	assert.Nil(t, got.Params.WebSearchOptions, "web_search_options would turn native search back on")
	assert.Equal(t, "tavily-search", got.Params.ToolChoice.ChatToolChoiceStruct.Function.Name,
		"a choice pinned to the native tool now pins the tool that replaced it")

	// Copy-on-write: a fallback to another provider reuses the original request.
	assert.Len(t, original.Params.Tools, 3)
	assert.NotNil(t, original.Params.WebSearchOptions)
	assert.Equal(t, "web_search", original.Params.ToolChoice.ChatToolChoiceStruct.Function.Name)
}

func TestApplyInjectedToolsChat_NoToolsAndDuplicates(t *testing.T) {
	set := testInjectedSet(t)

	bare := applyInjectedToolsChat(&schemas.BifrostChatRequest{Model: "m"}, set)
	require.NotNil(t, bare.Params)
	require.Len(t, bare.Params.Tools, 1, "every request gets the tool, even one that sent none")

	// The regular MCP auto-injection may already have added the same client tool.
	dup := applyInjectedToolsChat(&schemas.BifrostChatRequest{Params: &schemas.ChatParameters{Tools: []schemas.ChatTool{tavilySearchTool()}}}, set)
	assert.Len(t, dup.Params.Tools, 1, "the injected tool is never declared twice")

	assert.Nil(t, applyInjectedToolsChat(nil, set))
	plain := &schemas.BifrostChatRequest{Model: "m"}
	assert.Same(t, plain, applyInjectedToolsChat(plain, nil))
}

func TestApplyInjectedToolsResponses_ReplacesNativeWebSearch(t *testing.T) {
	set := testInjectedSet(t)
	original := &schemas.BifrostResponsesRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt",
		Params: &schemas.ResponsesParameters{
			Tools: []schemas.ResponsesTool{
				{Type: schemas.ResponsesToolTypeFunction, Name: schemas.Ptr("get_weather")},
				{Type: schemas.ResponsesToolTypeWebSearch},
				{Type: schemas.ResponsesToolTypeWebSearchPreview},
			},
			ToolChoice: &schemas.ResponsesToolChoice{ResponsesToolChoiceStruct: &schemas.ResponsesToolChoiceStruct{
				Type: schemas.ResponsesToolChoiceTypeWebSearchPreview,
			}},
		},
	}

	got := applyInjectedToolsResponses(original, set)

	require.Len(t, got.Params.Tools, 2)
	assert.Equal(t, "get_weather", *got.Params.Tools[0].Name)
	assert.Equal(t, schemas.ResponsesToolTypeFunction, got.Params.Tools[1].Type)
	assert.Equal(t, "tavily-search", *got.Params.Tools[1].Name)
	choice := got.Params.ToolChoice.ResponsesToolChoiceStruct
	assert.Equal(t, schemas.ResponsesToolChoiceTypeFunction, choice.Type)
	assert.Equal(t, "tavily-search", *choice.Name)

	assert.Len(t, original.Params.Tools, 3, "the shared request keeps the caller's tools for a fallback")
	assert.Equal(t, schemas.ResponsesToolChoiceTypeWebSearchPreview, original.Params.ToolChoice.ResponsesToolChoiceStruct.Type)
}

// A caller's own function that happens to be called web_search is not a native tool:
// it stays declared and a choice pinning it is left alone.
func TestApplyInjectedTools_ClientFunctionNamedWebSearchIsUntouched(t *testing.T) {
	set := testInjectedSet(t)
	own := schemas.ChatTool{Type: schemas.ChatToolTypeFunction, Function: &schemas.ChatToolFunction{Name: "web_search"}}
	chat := applyInjectedToolsChat(&schemas.BifrostChatRequest{Params: &schemas.ChatParameters{
		Tools: []schemas.ChatTool{own},
		ToolChoice: &schemas.ChatToolChoice{ChatToolChoiceStruct: &schemas.ChatToolChoiceStruct{
			Type: schemas.ChatToolChoiceTypeFunction, Function: &schemas.ChatToolChoiceFunction{Name: "web_search"},
		}},
	}}, set)
	require.Len(t, chat.Params.Tools, 2)
	assert.Equal(t, "web_search", chat.Params.ToolChoice.ChatToolChoiceStruct.Function.Name)

	responses := applyInjectedToolsResponses(&schemas.BifrostResponsesRequest{Params: &schemas.ResponsesParameters{
		Tools: []schemas.ResponsesTool{{Type: schemas.ResponsesToolTypeFunction, Name: schemas.Ptr("web_search")}},
		ToolChoice: &schemas.ResponsesToolChoice{ResponsesToolChoiceStruct: &schemas.ResponsesToolChoiceStruct{
			Type: schemas.ResponsesToolChoiceTypeFunction, Name: schemas.Ptr("web_search"),
		}},
	}}, set)
	require.Len(t, responses.Params.Tools, 2)
	assert.Equal(t, "web_search", *responses.Params.ToolChoice.ResponsesToolChoiceStruct.Name)
}

func chatToolCall(id, name string) schemas.ChatAssistantMessageToolCall {
	return schemas.ChatAssistantMessageToolCall{
		ID:       schemas.Ptr(id),
		Type:     schemas.Ptr("function"),
		Function: schemas.ChatAssistantMessageToolCallFunction{Name: schemas.Ptr(name), Arguments: `{"query":"q"}`},
	}
}

func chatTurnResponse(text string, finish string, promptTokens int, calls ...schemas.ChatAssistantMessageToolCall) *schemas.BifrostChatResponse {
	msg := &schemas.ChatMessage{Role: schemas.ChatMessageRoleAssistant}
	if text != "" {
		msg.Content = &schemas.ChatMessageContent{ContentStr: schemas.Ptr(text)}
	}
	if len(calls) > 0 {
		msg.ChatAssistantMessage = &schemas.ChatAssistantMessage{ToolCalls: calls}
	}
	return &schemas.BifrostChatResponse{
		ID: "resp",
		Choices: []schemas.BifrostResponseChoice{{
			FinishReason:                schemas.Ptr(finish),
			ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: msg},
		}},
		Usage: &schemas.BifrostLLMUsage{PromptTokens: promptTokens, CompletionTokens: 1, TotalTokens: promptTokens + 1},
	}
}

// scriptedChatTurns answers each dispatch with the next scripted response and records
// every request the loop sent.
type scriptedChatTurns struct {
	responses []*schemas.BifrostChatResponse
	sent      []*schemas.BifrostChatRequest
}

func (s *scriptedChatTurns) dispatch(req *schemas.BifrostChatRequest) (*schemas.BifrostChatResponse, *schemas.BifrostError) {
	s.sent = append(s.sent, req)
	resp := s.responses[0]
	s.responses = s.responses[1:]
	return resp, nil
}

func searchResult(call schemas.ChatAssistantMessageToolCall) *schemas.ChatMessage {
	return &schemas.ChatMessage{
		Role:            schemas.ChatMessageRoleTool,
		Content:         &schemas.ChatMessageContent{ContentStr: schemas.Ptr("results for " + *call.ID)},
		ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: call.ID},
	}
}

func TestRunInjectedChatLoop_ExecutesInjectedCallsAndReturnsFinalAnswer(t *testing.T) {
	set := testInjectedSet(t)
	turns := &scriptedChatTurns{responses: []*schemas.BifrostChatResponse{
		chatTurnResponse("Let me search.", "tool_calls", 10, chatToolCall("c1", "tavily-search")),
		chatTurnResponse("It is sunny.", "stop", 20),
	}}
	var executed []string
	exec := func(call schemas.ChatAssistantMessageToolCall) *schemas.ChatMessage {
		executed = append(executed, *call.ID)
		return searchResult(call)
	}
	original := &schemas.BifrostChatRequest{Model: "m", Input: []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("weather?")}}}}

	resp, err := runInjectedChatLoop(original, set, turns.dispatch, exec)

	require.Nil(t, err)
	assert.Equal(t, []string{"c1"}, executed)
	require.Len(t, turns.sent, 2)
	second := turns.sent[1]
	require.Len(t, second.Input, 3, "user, assistant turn with the injected call, tool result")
	assert.Equal(t, "c1", *second.Input[1].ToolCalls[0].ID)
	assert.Equal(t, "c1", *second.Input[2].ToolCallID)
	assert.Equal(t, "tavily-search", second.Params.Tools[0].Function.Name, "every turn still declares the injected tool")

	msg := resp.Choices[0].Message
	assert.Nil(t, msg.ChatAssistantMessage, "the client never sees the injected call")
	assert.Equal(t, "Let me search.\n\nIt is sunny.", *msg.Content.ContentStr)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	assert.Equal(t, 30, resp.Usage.PromptTokens, "usage covers every model turn")
	assert.Equal(t, 32, resp.Usage.TotalTokens)
	assert.Len(t, original.Input, 1, "the caller's request is never appended to")
}

func TestRunInjectedChatLoop_MixedTurnDropsClientCallAndReasks(t *testing.T) {
	set := testInjectedSet(t)
	turns := &scriptedChatTurns{responses: []*schemas.BifrostChatResponse{
		chatTurnResponse("", "tool_calls", 10, chatToolCall("c1", "get_weather"), chatToolCall("c2", "tavily-search")),
		chatTurnResponse("", "tool_calls", 10, chatToolCall("c3", "get_weather")),
	}}
	resp, err := runInjectedChatLoop(&schemas.BifrostChatRequest{Model: "m"}, set, turns.dispatch, searchResult)

	require.Nil(t, err)
	second := turns.sent[1]
	assistant := second.Input[0]
	require.Len(t, assistant.ToolCalls, 1, "the client call is dropped: it has no result to pair with")
	assert.Equal(t, "c2", *assistant.ToolCalls[0].ID)

	calls := resp.Choices[0].Message.ToolCalls
	require.Len(t, calls, 1, "the re-issued client call comes back untouched")
	assert.Equal(t, "c3", *calls[0].ID)
	assert.Equal(t, "tool_calls", *resp.Choices[0].FinishReason)
}

func TestRunInjectedChatLoop_StopsAtMaxDepth(t *testing.T) {
	set := testInjectedSet(t)
	set.maxDepth = 2
	turns := &scriptedChatTurns{responses: []*schemas.BifrostChatResponse{
		chatTurnResponse("", "tool_calls", 1, chatToolCall("c1", "tavily-search")),
		chatTurnResponse("Still searching.", "tool_calls", 1, chatToolCall("c2", "tavily-search")),
	}}
	resp, err := runInjectedChatLoop(&schemas.BifrostChatRequest{Model: "m"}, set, turns.dispatch, searchResult)

	require.Nil(t, err)
	assert.Len(t, turns.sent, 2)
	assert.Nil(t, resp.Choices[0].Message.ChatAssistantMessage, "an unexecuted injected call never reaches the client")
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
}

func TestRunInjectedChatLoop_PropagatesTurnError(t *testing.T) {
	set := testInjectedSet(t)
	calls := 0
	dispatch := func(*schemas.BifrostChatRequest) (*schemas.BifrostChatResponse, *schemas.BifrostError) {
		calls++
		if calls == 1 {
			return chatTurnResponse("", "tool_calls", 1, chatToolCall("c1", "tavily-search")), nil
		}
		return nil, &schemas.BifrostError{Error: &schemas.ErrorField{Message: "upstream down"}}
	}
	resp, err := runInjectedChatLoop(&schemas.BifrostChatRequest{Model: "m"}, set, dispatch, searchResult)
	assert.Nil(t, resp)
	require.NotNil(t, err)
	assert.Equal(t, "upstream down", err.Error.Message)
}

func responsesFunctionCall(callID, name string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID:   schemas.Ptr("fc_" + callID),
		Type: schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall),
		ResponsesToolMessage: &schemas.ResponsesToolMessage{
			CallID: schemas.Ptr(callID), Name: schemas.Ptr(name), Arguments: schemas.Ptr(`{"query":"q"}`),
		},
	}
}

func responsesText(text string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		Type:    schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant),
		Content: &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr(text)},
	}
}

func TestRunInjectedResponsesLoop_ExecutesInjectedCalls(t *testing.T) {
	set := testInjectedSet(t)
	var sent []*schemas.BifrostResponsesRequest
	scripted := []*schemas.BifrostResponsesResponse{
		{Output: []schemas.ResponsesMessage{responsesText("Searching."), responsesFunctionCall("c1", "tavily-search"), responsesFunctionCall("c2", "get_weather")},
			Usage: &schemas.ResponsesResponseUsage{InputTokens: 10, OutputTokens: 1, TotalTokens: 11}},
		{Output: []schemas.ResponsesMessage{responsesText("Sunny.")},
			Usage: &schemas.ResponsesResponseUsage{InputTokens: 20, OutputTokens: 2, TotalTokens: 22}},
	}
	dispatch := func(req *schemas.BifrostResponsesRequest) (*schemas.BifrostResponsesResponse, *schemas.BifrostError) {
		sent = append(sent, req)
		resp := scripted[0]
		scripted = scripted[1:]
		return resp, nil
	}

	resp, err := runInjectedResponsesLoop(&schemas.BifrostResponsesRequest{Model: "m"}, set, dispatch, searchResult)

	require.Nil(t, err)
	require.Len(t, sent, 2)
	next := sent[1].Input
	require.Len(t, next, 3, "prior text, the injected call and its output; the client call is dropped")
	assert.Equal(t, schemas.ResponsesMessageTypeFunctionCall, *next[1].Type)
	assert.Equal(t, "c1", *next[1].CallID)
	assert.Equal(t, schemas.ResponsesMessageTypeFunctionCallOutput, *next[2].Type)
	assert.Equal(t, "c1", *next[2].CallID)

	require.Len(t, resp.Output, 2, "the client sees both turns' text and no function calls")
	assert.Equal(t, "Searching.", *resp.Output[0].Content.ContentStr)
	assert.Equal(t, "Sunny.", *resp.Output[1].Content.ContentStr)
	assert.Equal(t, 30, resp.Usage.InputTokens)
	assert.Equal(t, 33, resp.Usage.TotalTokens)
}
