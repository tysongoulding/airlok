package governance

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrossPlaneDataBoundary_DirectChecks(t *testing.T) {
	acl := DefaultAirlokPolicy()

	// 1. google_workspace -> openai -> violation
	err := acl.CheckCrossPlaneDataBoundary("google_workspace", "openai")
	require.Error(t, err)
	assert.Equal(t, "cross-plane violation: data from google_workspace cannot be forwarded to openai models", err.Error())

	// 2. google_workspace -> anthropic -> allowed
	err = acl.CheckCrossPlaneDataBoundary("google_workspace", "anthropic")
	require.NoError(t, err)

	// 3. slack -> openai -> violation
	err = acl.CheckCrossPlaneDataBoundary("slack", "openai")
	require.Error(t, err)
	assert.Equal(t, "cross-plane violation: data from slack cannot be forwarded to openai models", err.Error())

	// 4. slack -> xai -> allowed
	err = acl.CheckCrossPlaneDataBoundary("slack", "xai")
	require.NoError(t, err)

	// Delegation through GovernancePlugin
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(acl)

	err = plugin.CheckCrossPlaneDataBoundary("google_workspace", "openai")
	require.Error(t, err)
	assert.Equal(t, "cross-plane violation: data from google_workspace cannot be forwarded to openai models", err.Error())

	err = plugin.CheckCrossPlaneDataBoundary("google_workspace", "anthropic")
	require.NoError(t, err)
}

func TestCrossPlane_ProvenanceAndPreLLMHookInterception(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	// 1. Simulate PostMCPHook recording provenance for google_workspace tool
	resp := &schemas.BifrostMCPResponse{
		ExtraFields: schemas.BifrostMCPResponseExtraFields{
			MCPRequestType: schemas.MCPRequestTypeExecuteTool,
			ClientName:     "google_workspace",
			ToolName:       "drive_read",
		},
	}
	_, _, err := plugin.PostMCPHook(ctx, resp, nil)
	require.NoError(t, err)

	active := GetActiveConnectors(ctx)
	assert.Contains(t, active, "google_workspace")

	// 2. Next turn: LLM call to OpenAI -> should short-circuit with cross_plane_violation (HTTP 403)
	openAIReq := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-4o",
		},
	}
	_, shortCircuit, err := plugin.PreLLMHook(ctx, openAIReq)
	require.NoError(t, err)
	require.NotNil(t, shortCircuit, "should short circuit on cross-plane violation")
	require.NotNil(t, shortCircuit.Error)
	assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
	assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
	assert.False(t, *shortCircuit.Error.AllowFallbacks)
	assert.Contains(t, shortCircuit.Error.Error.Message, "cross-plane violation: data from google_workspace cannot be forwarded to openai models")

	// 3. Next turn: LLM call to Anthropic Claude -> allowed (proceeds to audit)
	anthropicReq := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.Anthropic,
			Model:    "claude-3-7-sonnet",
		},
	}
	_, shortCircuitClaude, err := plugin.PreLLMHook(ctx, anthropicReq)
	require.NoError(t, err)
	assert.Nil(t, shortCircuitClaude, "Anthropic request should not be blocked by cross-plane boundary")
}

func TestCrossPlane_MessageHistoryInspection(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	// Context with no active connectors recorded yet
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	toolName := "slack-read_channel"
	reqWithToolHistory := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-4o",
			Input: []schemas.ChatMessage{
				{
					Role: schemas.ChatMessageRoleAssistant,
					ChatAssistantMessage: &schemas.ChatAssistantMessage{
						ToolCalls: []schemas.ChatAssistantMessageToolCall{
							{
								Function: schemas.ChatAssistantMessageToolCallFunction{
									Name: &toolName,
								},
							},
						},
					},
				},
			},
		},
	}

	_, shortCircuit, err := plugin.PreLLMHook(ctx, reqWithToolHistory)
	require.NoError(t, err)
	require.NotNil(t, shortCircuit, "should short circuit from message history inspection")
	assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
	assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
	assert.Contains(t, shortCircuit.Error.Error.Message, "cross-plane violation: data from slack cannot be forwarded to openai models")
}
