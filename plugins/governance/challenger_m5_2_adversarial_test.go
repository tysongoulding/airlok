package governance

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CHALLENGE 1: ADVERSARIAL BYPASS ATTACKS ON CROSS-PLANE DATA BOUNDARY
// ============================================================================

// TestAdversarial_CrossPlane_CaseVariations_TrailingSlashes_Wildcards tests boundary evasion
// attempts using case manipulation, trailing slashes, wildcards, and whitespace.
func TestAdversarial_CrossPlane_CaseVariations_TrailingSlashes_Wildcards(t *testing.T) {
	acl := DefaultAirlokPolicy()

	t.Run("Case variations across source and destination", func(t *testing.T) {
		caseVariants := []struct {
			source string
			dest   string
			expectError bool
		}{
			{"google_workspace", "openai", true},
			{"Google_Workspace", "openai", true},
			{"GOOGLE_WORKSPACE", "openai", true},
			{"google_WORKSPACE", "OPENAI", true},
			{"slack", "openai", true},
			{"SLACK", "openai", true},
			{"Slack", "OpenAI", true},
			{"slack", "OPENAI", true},
			{"google_workspace", "OpenAI", true},
			// Benign destinations with mixed case
			{"google_workspace", "Anthropic", false},
			{"Google_Workspace", "ANTHROPIC", false},
			{"slack", "Google", false},
			{"SLACK", "GOOGLE", false},
			{"slack", "XAI", false},
		}

		for _, tc := range caseVariants {
			t.Run(fmt.Sprintf("%s -> %s", tc.source, tc.dest), func(t *testing.T) {
				err := acl.CheckCrossPlaneDataBoundary(tc.source, tc.dest)
				if tc.expectError {
					require.Error(t, err, "expected cross-plane violation for %s -> %s", tc.source, tc.dest)
					assert.Contains(t, err.Error(), "cross-plane violation")
				} else {
					require.NoError(t, err, "benign destination should not be blocked: %s -> %s", tc.source, tc.dest)
				}
			})
		}
	})

	t.Run("Trailing slashes and path patterns", func(t *testing.T) {
		trailingVariants := []struct {
			source string
			dest   string
			expectError bool
		}{
			{"google_workspace", "openai/", true},
			{"google_workspace", "openai/*", true},
			{"slack", "openai/", true},
			{"slack", "openai/*", true},
			{"google_workspace", "anthropic/", false},
			{"slack", "google/", false},
		}

		for _, tc := range trailingVariants {
			t.Run(fmt.Sprintf("%s -> %s", tc.source, tc.dest), func(t *testing.T) {
				err := acl.CheckCrossPlaneDataBoundary(tc.source, tc.dest)
				if tc.expectError {
					require.Error(t, err, "expected error for trailing slash: %s -> %s", tc.source, tc.dest)
					assert.Contains(t, err.Error(), "cross-plane violation")
				} else {
					require.NoError(t, err, "benign destination should not be blocked: %s -> %s", tc.source, tc.dest)
				}
			})
		}
	})

	t.Run("Wildcard destinations and specific models", func(t *testing.T) {
		modelVariants := []struct {
			source string
			dest   string
			expectError bool
		}{
			{"google_workspace", "openai/gpt-4o", true},
			{"google_workspace", "openai/o3-mini", true},
			{"google_workspace", "openai/text-embedding-3-small", true},
			{"slack", "openai/gpt-4.5-preview", true},
			{"slack", "openai/chatgpt-4o-latest", true},
			// Negative controls: benign destinations
			{"google_workspace", "anthropic/claude-3-7-sonnet", false},
			{"google_workspace", "google/gemini-2.5-pro", false},
			{"slack", "xai/grok-3", false},
		}

		for _, tc := range modelVariants {
			t.Run(fmt.Sprintf("%s -> %s", tc.source, tc.dest), func(t *testing.T) {
				err := acl.CheckCrossPlaneDataBoundary(tc.source, tc.dest)
				if tc.expectError {
					require.Error(t, err, "expected violation for specific model: %s -> %s", tc.source, tc.dest)
					assert.Contains(t, err.Error(), "cross-plane violation")
				} else {
					require.NoError(t, err, "benign destination should not be blocked: %s -> %s", tc.source, tc.dest)
				}
			})
		}
	})

	t.Run("Policy-level wildcard constraints", func(t *testing.T) {
		// Custom policy with wildcard source and wildcard destination
		wildcardPolicyJSON := []byte(`{
			"version": "1.0",
			"cross_plane_constraints": [
				{
					"rule_id": "block_all_from_vault",
					"when_source_connector": ["vault_secrets"],
					"disallow_destination_llm": ["*"]
				},
				{
					"rule_id": "block_all_to_untrusted",
					"when_source_connector": ["*"],
					"disallow_destination_llm": ["untrusted_provider/*"]
				}
			]
		}`)
		wildcardACL, err := NewDualPlaneACL(wildcardPolicyJSON)
		require.NoError(t, err)

		// 1. Source vault_secrets -> blocked to any destination
		assert.Error(t, wildcardACL.CheckCrossPlaneDataBoundary("vault_secrets", "openai"))
		assert.Error(t, wildcardACL.CheckCrossPlaneDataBoundary("vault_secrets", "anthropic"))
		assert.Error(t, wildcardACL.CheckCrossPlaneDataBoundary("vault_secrets", "google"))

		// 2. Any source connector -> blocked to untrusted_provider
		assert.Error(t, wildcardACL.CheckCrossPlaneDataBoundary("any_connector", "untrusted_provider"))
		assert.Error(t, wildcardACL.CheckCrossPlaneDataBoundary("slack", "untrusted_provider/model-x"))

		// 3. Other combinations allowed
		assert.NoError(t, wildcardACL.CheckCrossPlaneDataBoundary("slack", "anthropic"))
	})
}

// TestAdversarial_CrossPlane_MultiTurnConversationalNesting tests message history inspection
// under complex multi-turn conversational nesting, sequential tool executions, and delimiter variations.
func TestAdversarial_CrossPlane_MultiTurnConversationalNesting(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	t.Run("Sequential multiple tool executions in history targeting OpenAI", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		tool1 := "google_workspace-drive_read"
		tool2 := "slack-post_message"
		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.OpenAI,
				Model:    "gpt-4o",
				Input: []schemas.ChatMessage{
					{
						Role:    schemas.ChatMessageRoleUser,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Analyze the quarterly reports")},
					},
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tool1}},
							},
						},
					},
					{
						Role: schemas.ChatMessageRoleTool,
						Name: &tool1,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Confidential Google Drive Document content")},
						ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: bifrost.Ptr("call_1")},
					},
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tool2}},
							},
						},
					},
					{
						Role: schemas.ChatMessageRoleTool,
						Name: &tool2,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Message posted to Slack #finance channel")},
						ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: bifrost.Ptr("call_2")},
					},
					{
						Role:    schemas.ChatMessageRoleUser,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Summarize findings and output summary")},
					},
				},
			},
		}

		_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "sequential tools history targeting OpenAI must short-circuit")
		require.NotNil(t, shortCircuit.Error)
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
		assert.False(t, *shortCircuit.Error.AllowFallbacks, "AllowFallbacks must be unconditionally false")
		assert.Contains(t, shortCircuit.Error.Error.Message, "cross-plane violation")
	})

	t.Run("Deeply nested multi-turn history (10 turns)", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		var history []schemas.ChatMessage
		history = append(history, schemas.ChatMessage{
			Role:    schemas.ChatMessageRoleUser,
			Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Start pipeline")},
		})

		// 8 intermediate assistant/tool turns
		for i := 0; i < 4; i++ {
			tName := fmt.Sprintf("google_workspace-step_%d", i)
			callID := fmt.Sprintf("call_%d", i)
			history = append(history, schemas.ChatMessage{
				Role: schemas.ChatMessageRoleAssistant,
				ChatAssistantMessage: &schemas.ChatAssistantMessage{
					ToolCalls: []schemas.ChatAssistantMessageToolCall{
						{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tName}},
					},
				},
			})
			history = append(history, schemas.ChatMessage{
				Role: schemas.ChatMessageRoleTool,
				Name: &tName,
				Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr(fmt.Sprintf("Output step %d", i))},
				ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: &callID},
			})
		}
		history = append(history, schemas.ChatMessage{
			Role:    schemas.ChatMessageRoleUser,
			Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Final synthesis")},
		})

		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.OpenAI,
				Model:    "gpt-4o",
				Input:    history,
			},
		}

		_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "deeply nested history must be caught")
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
		assert.False(t, *shortCircuit.Error.AllowFallbacks)
	})

	t.Run("Benign destination Anthropic proceeds without false positive", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		toolName := "google_workspace-drive_read"
		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.Anthropic,
				Model:    "claude-3-7-sonnet",
				Input: []schemas.ChatMessage{
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName}},
							},
						},
					},
					{
						Role: schemas.ChatMessageRoleTool,
						Name: &toolName,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Drive doc text")},
						ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: bifrost.Ptr("call_1")},
					},
				},
			},
		}

		_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		assert.Nil(t, shortCircuit, "Anthropic must not be blocked by cross-plane boundary")
	})

	t.Run("Benign destination Google Gemini proceeds without false positive", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		toolName := "slack-read_channel"
		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.ModelProvider("google"),
				Model:    "gemini-2.5-pro",
				Input: []schemas.ChatMessage{
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName}},
							},
						},
					},
				},
			},
		}

		_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		assert.Nil(t, shortCircuit, "Google provider must not be blocked by cross-plane boundary")
	})

	t.Run("Delimiter variations: hyphen, colon, prefix", func(t *testing.T) {
		delims := []string{
			"google_workspace-read",
			"google_workspace:read",
			"google_workspace_read",
			"slack-send",
			"slack:send",
		}

		for _, tool := range delims {
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			toolCopy := tool
			req := &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.OpenAI,
					Model:    "gpt-4o",
					Input: []schemas.ChatMessage{
						{
							Role: schemas.ChatMessageRoleAssistant,
							ChatAssistantMessage: &schemas.ChatAssistantMessage{
								ToolCalls: []schemas.ChatAssistantMessageToolCall{
									{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolCopy}},
								},
							},
						},
					},
				},
			}
			_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, shortCircuit, "delimiter variant '%s' must short-circuit against OpenAI", tool)
			assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
			assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
			assert.False(t, *shortCircuit.Error.AllowFallbacks)
		}
	})

	t.Run("Adversarial Evasion: Snake_case slack_post_message in tool history leaks to OpenAI", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		toolName := "slack_post_message"
		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.OpenAI,
				Model:    "gpt-4o",
				Input: []schemas.ChatMessage{
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName}},
							},
						},
					},
					{
						Role: schemas.ChatMessageRoleTool,
						Name: &toolName,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Exfiltrated Slack financial data")},
						ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: bifrost.Ptr("call_slack_1")},
					},
				},
			},
		}
		_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		// DISPATCH REQUIREMENT:
		// "Verify that whenever data from google_workspace or slack is present in context or message history,
		//  targeting openai triggers an unconditional HTTP 403 cross_plane_violation with AllowFallbacks: false."
		require.NotNil(t, shortCircuit, "BUG REPRODUCTION: tool name 'slack_post_message' in message history bypasses cross-plane leak prevention!")
		if shortCircuit != nil {
			assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
			assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
		}
	})

	t.Run("Adversarial Evasion: Permitted LLM receives Slack data via snake_case tool name", func(t *testing.T) {
		// Policy where openai is allowed by LLM rules, but cross-plane constraint disallows slack -> openai
		policyJSON := []byte(`{
			"version": "1.0",
			"llm": {
				"defaults": {"action": "deny"},
				"rules": [
					{"provider": "openai", "model_pattern": "*", "action": "allow"}
				]
			},
			"connectors": {
				"defaults": {"action": "allow"},
				"rules": [
					{"name": "slack", "action": "allow"}
				]
			},
			"cross_plane_constraints": [
				{
					"rule_id": "no_slack_to_openai",
					"when_source_connector": ["slack"],
					"disallow_destination_llm": ["openai/*"]
				}
			]
		}`)
		customACL, err := NewDualPlaneACL(policyJSON)
		require.NoError(t, err)

		customPlugin := &GovernancePlugin{}
		customPlugin.SetDualPlaneACL(customACL)

		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		toolName := "slack_read_channel"
		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.OpenAI,
				Model:    "gpt-4o",
				Input: []schemas.ChatMessage{
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName}},
							},
						},
					},
					{
						Role: schemas.ChatMessageRoleTool,
						Name: &toolName,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Confidential Slack messages from executive channel")},
						ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: bifrost.Ptr("call_slack_exec")},
					},
				},
			},
		}

		_, shortCircuit, err := customPlugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		// EMPIRICAL BUG CONFIRMATION:
		// shortCircuit should have been non-nil (HTTP 403 cross_plane_violation).
		// Because PreLLMHook only splits on '-' and ':', "slack_read_channel" extracts as "slack_read_channel",
		// which does NOT match "slack" in WhenSourceConnector!
		// As a result, shortCircuit is nil and sensitive data is sent directly to OpenAI!
		require.NotNil(t, shortCircuit, "EMPIRICAL BUG REPRODUCTION: sensitive Slack data leaked to OpenAI due to snake_case delimiter evasion!")
	})
}

// ============================================================================
// CHALLENGE 2: DUAL-PLANE ACL APPROVAL & AUDIT STRESS
// ============================================================================

// TestAdversarial_DualPlaneACL_RequireApproval_UnattendedGate tests the require_approval
// unattended execution gate under all combination branches.
func TestAdversarial_DualPlaneACL_RequireApproval_UnattendedGate(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	t.Run("Unattended execution with NO authorization -> rejected HTTP 403", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, true)

		toolName := "catalog_3000-query_items"
		req := &schemas.BifrostMCPRequest{
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "unattended execution must short-circuit")
		require.NotNil(t, shortCircuit.Error)
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "airlok_approval_required", *shortCircuit.Error.Type)
		assert.Contains(t, shortCircuit.Error.Error.Message, "requires authorization approval")
	})

	t.Run("Unattended execution EVEN WITH authorization -> fail-closed rejected HTTP 403", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		// Stamping unattended execution = true
		ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, true)

		// Transport or handler attempted to pre-approve:
		toolName := "catalog_3000-query_items"
		req := &schemas.BifrostMCPRequest{
			ClientName:  "catalog_3000",
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}
		SetMCPExecutionAuthorization(ctx, "catalog_3000", toolName)

		// Must FAIL-CLOSED: unattended autonomous execution cannot run require_approval tools
		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "unattended execution must fail closed even if approved")
		require.NotNil(t, shortCircuit.Error)
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "airlok_approval_required", *shortCircuit.Error.Type)
	})

	t.Run("Attended execution with NO authorization -> rejected HTTP 403", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, false)

		toolName := "catalog_3000-query_items"
		req := &schemas.BifrostMCPRequest{
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "attended execution without approval must be rejected")
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "airlok_approval_required", *shortCircuit.Error.Type)
	})

	t.Run("Attended execution with valid authorization -> approved and allowed", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, false)

		toolName := "catalog_3000-query_items"
		req := &schemas.BifrostMCPRequest{
			ClientName:  "catalog_3000",
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}
		SetMCPExecutionAuthorization(ctx, "catalog_3000", toolName)

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		if shortCircuit != nil && shortCircuit.Error != nil && shortCircuit.Error.Type != nil {
			assert.NotEqual(t, "airlok_approval_required", *shortCircuit.Error.Type, "attended execution with valid approval should not be blocked for approval")
		}
	})

	t.Run("Attended execution with mismatched tool authorization -> rejected HTTP 403", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, false)

		toolName := "catalog_3000-mutate_records"
		req := &schemas.BifrostMCPRequest{
			ClientName:  "catalog_3000",
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}
		// Authorization granted for read only, not mutation:
		SetMCPExecutionAuthorization(ctx, "catalog_3000", "catalog_3000-query_items")

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "mismatched tool approval must be rejected")
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "airlok_approval_required", *shortCircuit.Error.Type)
	})
}

// TestAdversarial_DualPlaneACL_SpoofedToolNamesResolution tests that connector resolution
// correctly identifies true connectors and blocks spoofing attempts.
func TestAdversarial_DualPlaneACL_SpoofedToolNamesResolution(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	t.Run("Empty ClientName with office365-prefixed tool is denied", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		toolName := "office365-safe_read"
		req := &schemas.BifrostMCPRequest{
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "office365 tool must be denied")
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "airlok_connector_blocked", *shortCircuit.Error.Type)
		assert.Contains(t, shortCircuit.Error.Error.Message, "Office365 integrations disabled")
	})

	t.Run("Spoofed tool name does not override explicit ClientName", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		// ClientName is office365, but toolName claims to be slack
		toolName := "slack-post_message"
		req := &schemas.BifrostMCPRequest{
			ClientName:  "office365",
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "office365 ClientName must be enforced regardless of tool name spoofing")
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
		assert.Equal(t, "airlok_connector_blocked", *shortCircuit.Error.Type)
	})

	t.Run("Spoofed ClientName with google_workspace tool uses ClientName", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		// ClientName is office365, but toolName claims to be google_workspace
		toolName := "google_workspace-drive_read"
		req := &schemas.BifrostMCPRequest{
			ClientName:  "office365",
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, shortCircuit, "blocked connector cannot execute google tools")
		assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
	})

	t.Run("Valid allowed connector ClientName google_workspace proceeds", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		toolName := "google_workspace-drive_read"
		req := &schemas.BifrostMCPRequest{
			ClientName:  "google_workspace",
			RequestType: schemas.MCPRequestTypeChatToolCall,
			ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
			},
		}

		_, shortCircuit, err := plugin.PreMCPHook(ctx, req)
		require.NoError(t, err)
		if shortCircuit != nil && shortCircuit.Error != nil {
			t.Logf("Short circuit error: type=%v, msg=%v", *shortCircuit.Error.Type, shortCircuit.Error.Error.Message)
		}
		if shortCircuit != nil && shortCircuit.Error != nil && shortCircuit.Error.Type != nil {
			assert.NotEqual(t, "airlok_connector_blocked", *shortCircuit.Error.Type)
		}
	})
}

// ============================================================================
// CHALLENGE 3: HIGH CONCURRENCY STRESS & RACE DETECTION (500+ GOROUTINES)
// ============================================================================

// TestAdversarial_DualPlaneACL_HighConcurrencyStress_500Goroutines launches 600 concurrent
// goroutines exercising allowed, denied, audited, and require_approval connectors and cross-plane
// validations to verify race-free execution under -race.
func TestAdversarial_DualPlaneACL_HighConcurrencyStress_500Goroutines(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	numGoroutines := 600
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var allowedCount int64
	var deniedCount int64
	var approvalCount int64
	var crossPlaneViolations int64

	for i := 0; i < numGoroutines; i++ {
		workerID := i
		go func() {
			defer wg.Done()

			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

			switch workerID % 6 {
			case 0:
				// Allowed connector: google_workspace
				tName := "google_workspace-read_doc"
				req := &schemas.BifrostMCPRequest{
					ClientName:  "google_workspace",
					RequestType: schemas.MCPRequestTypeChatToolCall,
					ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
						Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tName},
					},
				}
				_, sc, err := plugin.PreMCPHook(ctx, req)
				if err == nil && (sc == nil || (sc.Error != nil && sc.Error.Type != nil && *sc.Error.Type != "airlok_connector_blocked")) {
					atomic.AddInt64(&allowedCount, 1)
					// PostMCPHook stamps provenance
					resp := &schemas.BifrostMCPResponse{
						ExtraFields: schemas.BifrostMCPResponseExtraFields{
							MCPRequestType: schemas.MCPRequestTypeExecuteTool,
							ClientName:     "google_workspace",
							ToolName:       tName,
						},
					}
					plugin.PostMCPHook(ctx, resp, nil)
				}

			case 1:
				// Denied connector: office365
				tName := "office365-read_mail"
				req := &schemas.BifrostMCPRequest{
					ClientName:  "office365",
					RequestType: schemas.MCPRequestTypeChatToolCall,
					ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
						Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tName},
					},
				}
				_, sc, _ := plugin.PreMCPHook(ctx, req)
				if sc != nil && sc.Error != nil && *sc.Error.StatusCode == 403 {
					atomic.AddInt64(&deniedCount, 1)
				}

			case 2:
				// Require approval connector under unattended mode: catalog_3000
				ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, true)
				tName := "catalog_3000-query"
				req := &schemas.BifrostMCPRequest{
					ClientName:  "catalog_3000",
					RequestType: schemas.MCPRequestTypeChatToolCall,
					ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
						Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tName},
					},
				}
				_, sc, _ := plugin.PreMCPHook(ctx, req)
				if sc != nil && sc.Error != nil && *sc.Error.Type == "airlok_approval_required" {
					atomic.AddInt64(&approvalCount, 1)
				}

			case 3:
				// Allowed connector: slack
				tName := "slack-post_msg"
				req := &schemas.BifrostMCPRequest{
					ClientName:  "slack",
					RequestType: schemas.MCPRequestTypeChatToolCall,
					ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
						Function: schemas.ChatAssistantMessageToolCallFunction{Name: &tName},
					},
				}
				_, sc, err := plugin.PreMCPHook(ctx, req)
				if err == nil && (sc == nil || (sc.Error != nil && sc.Error.Type != nil && *sc.Error.Type != "airlok_connector_blocked")) {
					atomic.AddInt64(&allowedCount, 1)
					resp := &schemas.BifrostMCPResponse{
						ExtraFields: schemas.BifrostMCPResponseExtraFields{
							MCPRequestType: schemas.MCPRequestTypeExecuteTool,
							ClientName:     "slack",
							ToolName:       tName,
						},
					}
					plugin.PostMCPHook(ctx, resp, nil)
				}

			case 4:
				// Cross-plane leak check: active connector data passed to OpenAI
				AddActiveConnector(ctx, "google_workspace")
				llmReq := &schemas.BifrostRequest{
					RequestType: schemas.ChatCompletionRequest,
					ChatRequest: &schemas.BifrostChatRequest{
						Provider: schemas.OpenAI,
						Model:    "gpt-4o",
					},
				}
				_, sc, _ := plugin.PreLLMHook(ctx, llmReq)
				if sc != nil && sc.Error != nil && *sc.Error.Type == "cross_plane_violation" {
					atomic.AddInt64(&crossPlaneViolations, 1)
				}

			case 5:
				// Benign cross-plane check: active connector data passed to Anthropic
				AddActiveConnector(ctx, "slack")
				llmReq := &schemas.BifrostRequest{
					RequestType: schemas.ChatCompletionRequest,
					ChatRequest: &schemas.BifrostChatRequest{
						Provider: schemas.Anthropic,
						Model:    "claude-3-7-sonnet",
					},
				}
				_, sc, err := plugin.PreLLMHook(ctx, llmReq)
				if err == nil && sc == nil {
					atomic.AddInt64(&allowedCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(100), atomic.LoadInt64(&deniedCount), "all 100 office365 calls must be denied")
	assert.Equal(t, int64(100), atomic.LoadInt64(&approvalCount), "all 100 catalog_3000 unattended calls must require approval")
	assert.Equal(t, int64(100), atomic.LoadInt64(&crossPlaneViolations), "all 100 cross-plane leak attempts must be blocked")
	assert.Equal(t, int64(300), atomic.LoadInt64(&allowedCount), "all 300 legitimate calls must succeed")
}
