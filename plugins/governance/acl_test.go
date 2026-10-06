package governance

import (
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDualPlaneAclLLM(t *testing.T) {
	acl := DefaultAirlokPolicy()

	// Gemini -> Allowed
	action, reason := acl.CheckLLM(schemas.ModelProvider("google"), "gemini-2.5-pro")
	assert.Equal(t, PolicyActionAllow, action)
	assert.Empty(t, reason)

	// Grok -> Allowed
	action, reason = acl.CheckLLM(schemas.ModelProvider("xai"), "grok-3")
	assert.Equal(t, PolicyActionAllow, action)
	assert.Empty(t, reason)

	// Claude -> Audit
	action, tag := acl.CheckLLM(schemas.ModelProvider("anthropic"), "claude-3-7-sonnet")
	assert.Equal(t, PolicyActionAudit, action)
	assert.Equal(t, "monitored-claude", tag)

	// OpenAI ChatGPT -> Denied
	action, reason = acl.CheckLLM(schemas.ModelProvider("openai"), "gpt-4o")
	assert.Equal(t, PolicyActionDeny, action)
	assert.Contains(t, reason, "OpenAI ChatGPT models blocked")
}

func TestDualPlaneAclConnectors(t *testing.T) {
	acl := DefaultAirlokPolicy()

	// Google Workspace -> Allowed
	action, reason := acl.CheckConnector("google_workspace", "docs")
	assert.Equal(t, PolicyActionAllow, action)
	assert.Empty(t, reason)

	// Slack -> Allowed
	action, reason = acl.CheckConnector("slack", "chat:write")
	assert.Equal(t, PolicyActionAllow, action)
	assert.Empty(t, reason)

	// Office365 -> Denied
	action, reason = acl.CheckConnector("office365", "")
	assert.Equal(t, PolicyActionDeny, action)
	assert.Contains(t, reason, "Office365 integrations disabled")

	// Catalog 3000 -> Require Approval
	action, _ = acl.CheckConnector("catalog_3000", "")
	assert.Equal(t, PolicyActionRequireApproval, action)
}

func TestDualPlaneAclCrossPlane(t *testing.T) {
	acl := DefaultAirlokPolicy()

	activeConnectors := []string{"google_workspace"}

	// Google Workspace -> OpenAI blocked
	err := acl.CheckCrossPlane(activeConnectors, schemas.ModelProvider("openai"), "gpt-4o")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-plane security violation")

	// Google Workspace -> Gemini permitted
	err = acl.CheckCrossPlane(activeConnectors, schemas.ModelProvider("google"), "gemini-2.5-pro")
	require.NoError(t, err)
}

func TestDualPlaneAclPluginHooks(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	ctx := schemas.NewBifrostContext(nil, time.Time{})

	// Test 1: PreLLMHook with OpenAI gpt-4o -> blocked (403)
	openAIReq := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-4o",
		},
	}
	_, shortCircuit, err := plugin.PreLLMHook(ctx, openAIReq)
	require.NoError(t, err)
	require.NotNil(t, shortCircuit, "OpenAI request should short circuit")
	require.NotNil(t, shortCircuit.Error)
	assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
	assert.Contains(t, shortCircuit.Error.Error.Message, "OpenAI ChatGPT models blocked")

	// Test 2: PreMCPHook with Office 365 tool -> blocked (403)
	o365Req := mcpToolCall("office365")
	_, mcpShortCircuit, err := plugin.PreMCPHook(ctx, o365Req)
	require.NoError(t, err)
	require.NotNil(t, mcpShortCircuit, "Office 365 tool execution should short circuit")
	require.NotNil(t, mcpShortCircuit.Error)
	assert.Equal(t, 403, *mcpShortCircuit.Error.StatusCode)
	assert.Contains(t, mcpShortCircuit.Error.Error.Message, "Office365 integrations disabled")

	// Test 3: PreMCPHook with Slack tool -> allowed (no short circuit)
	slackReq := mcpToolCall("slack")
	// For slack, ACL allows it so it proceeds past ACL check
	_, slackShortCircuit, _ := plugin.PreMCPHook(ctx, slackReq)
	if slackShortCircuit != nil && slackShortCircuit.Error != nil && slackShortCircuit.Error.Type != nil {
		assert.NotEqual(t, "airlok_connector_blocked", *slackShortCircuit.Error.Type)
	}
}
