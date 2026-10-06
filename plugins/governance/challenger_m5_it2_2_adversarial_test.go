package governance

import (
	"context"
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
// CHALLENGER M5 IT2 2: ADVERSARIAL STRESS SUITE (FEATURES 34 & 35)
// ============================================================================

// 1. Cross-Plane Delimiter Evasion and Canonical Connector Extraction
func TestChallengerM5It2_CrossPlane_DelimiterEvasion_Comprehensive(t *testing.T) {
	acl := DefaultAirlokPolicy()
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(acl)

	testCases := []struct {
		name          string
		toolName      string
		destProvider  schemas.ModelProvider
		destModel     string
		expectBlocked bool
	}{
		// Slack variations targeting OpenAI (Must be BLOCKED)
		{"Slack snake_case read", "slack_read_channel", schemas.OpenAI, "gpt-4o", true},
		{"Slack snake_case post", "slack_post_message", schemas.OpenAI, "gpt-4o", true},
		{"Slack snake_case uppercase", "SLACK_READ_CHANNEL", schemas.OpenAI, "gpt-4o", true},
		{"Slack mixed case", "Slack_Post_Message", schemas.OpenAI, "chatgpt-4o-latest", true},
		{"Slack hyphen delimiter", "slack-read_channel", schemas.OpenAI, "o3-mini", true},
		{"Slack colon delimiter", "slack:read_channel", schemas.OpenAI, "gpt-4o", true},
		{"Slack slash delimiter", "slack/read_channel", schemas.OpenAI, "gpt-4o", true},
		{"Slack dot delimiter", "slack.read_channel", schemas.OpenAI, "gpt-4o", true},
		{"Slack double underscore", "slack__post__message", schemas.OpenAI, "gpt-4o", true},
		{"Slack bare name", "slack", schemas.OpenAI, "gpt-4o", true},

		// Google Workspace variations targeting OpenAI (Must be BLOCKED)
		{"Google Workspace snake_case", "google_workspace_drive_read", schemas.OpenAI, "gpt-4o", true},
		{"Google Workspace uppercase", "GOOGLE_WORKSPACE_GMAIL_SEND", schemas.OpenAI, "gpt-4o", true},
		{"Google Workspace hyphen", "google_workspace-sheets_get", schemas.OpenAI, "gpt-4o", true},
		{"Google Workspace colon", "google_workspace:docs_read", schemas.OpenAI, "gpt-4o", true},
		{"Google Workspace slash", "google_workspace/drive_read", schemas.OpenAI, "gpt-4o", true},
		{"Google Workspace dot", "google_workspace.sheets_get", schemas.OpenAI, "gpt-4o", true},

		// Benign destinations (Must be ALLOWED - negative controls)
		{"Slack to Anthropic", "slack_read_channel", schemas.Anthropic, "claude-3-7-sonnet", false},
		{"Slack to Google Gemini", "slack_post_message", schemas.ModelProvider("google"), "gemini-2.5-pro", false},
		{"Slack to xAI", "slack_read_channel", schemas.ModelProvider("xai"), "grok-3", false},
		{"Google Workspace to Anthropic", "google_workspace_drive_read", schemas.Anthropic, "claude-3-7-sonnet", false},
		{"Google Workspace to Google Gemini", "google_workspace_gmail_send", schemas.ModelProvider("google"), "gemini-2.5-pro", false},

		// Allowed non-sensitive connectors targeting OpenAI
		{"Trello to OpenAI", "trello_create_card", schemas.OpenAI, "gpt-4o", false},
		{"GitHub to OpenAI", "github_list_issues", schemas.OpenAI, "gpt-4o", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			toolNameCopy := tc.toolName

			req := &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: tc.destProvider,
					Model:    tc.destModel,
					Input: []schemas.ChatMessage{
						{
							Role: schemas.ChatMessageRoleAssistant,
							ChatAssistantMessage: &schemas.ChatAssistantMessage{
								ToolCalls: []schemas.ChatAssistantMessageToolCall{
									{
										ID: bifrost.Ptr("call_test_123"),
										Function: schemas.ChatAssistantMessageToolCallFunction{
											Name: &toolNameCopy,
										},
									},
								},
							},
						},
						{
							Role: schemas.ChatMessageRoleTool,
							Name: &toolNameCopy,
							Content: &schemas.ChatMessageContent{
								ContentStr: bifrost.Ptr("Confidential payload data"),
							},
							ChatToolMessage: &schemas.ChatToolMessage{
								ToolCallID: bifrost.Ptr("call_test_123"),
							},
						},
					},
				},
			}

			_, shortCircuit, err := plugin.PreLLMHook(ctx, req)
			require.NoError(t, err)

			if tc.expectBlocked {
				require.NotNil(t, shortCircuit, "tool %s targeting %s must be blocked by cross-plane boundary", tc.toolName, tc.destProvider)
				require.NotNil(t, shortCircuit.Error)
				assert.Equal(t, 403, *shortCircuit.Error.StatusCode)
				assert.Equal(t, "cross_plane_violation", *shortCircuit.Error.Type)
				assert.False(t, *shortCircuit.Error.AllowFallbacks)
				assert.Contains(t, shortCircuit.Error.Error.Message, "cross-plane violation")
			} else {
				if shortCircuit != nil && shortCircuit.Error != nil && shortCircuit.Error.Type != nil {
					assert.NotEqual(t, "cross_plane_violation", *shortCircuit.Error.Type, "tool %s targeting %s should not trigger cross_plane_violation", tc.toolName, tc.destProvider)
				}
			}
		})
	}
}

// 2. Custom Connectors and Policy Extraction
func TestChallengerM5It2_CrossPlane_CustomConnectorsInPolicy(t *testing.T) {
	policyJSON := []byte(`{
		"version": "1.0",
		"llm": {
			"defaults": {"action": "allow"},
			"rules": []
		},
		"connectors": {
			"defaults": {"action": "allow"},
			"rules": [
				{"name": "salesforce_enterprise", "action": "allow"},
				{"name": "internal_vault", "action": "allow"}
			]
		},
		"cross_plane_constraints": [
			{
				"rule_id": "protect_salesforce",
				"when_source_connector": ["salesforce_enterprise"],
				"disallow_destination_llm": ["openai/*"]
			},
			{
				"rule_id": "protect_vault",
				"when_source_connector": ["internal_vault"],
				"disallow_destination_llm": ["*"]
			}
		]
	}`)

	acl, err := NewDualPlaneACL(policyJSON)
	require.NoError(t, err)

	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(acl)

	t.Run("salesforce_enterprise snake_case tool blocked to OpenAI", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		toolName := "salesforce_enterprise_query_accounts"
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
				},
			},
		}

		_, sc, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, sc)
		assert.Equal(t, 403, *sc.Error.StatusCode)
		assert.Equal(t, "cross_plane_violation", *sc.Error.Type)
	})

	t.Run("internal_vault snake_case tool blocked to all LLMs", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		toolName := "internal_vault_read_secret"
		for _, prov := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.ModelProvider("google")} {
			req := &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: prov,
					Model:    "any-model",
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
			_, sc, err := plugin.PreLLMHook(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, sc, "internal_vault must be blocked to provider %s", prov)
			assert.Equal(t, 403, *sc.Error.StatusCode)
		}
	})
}

// 3. Multi-Turn Conversational Tool Call Association (ToolCallID Pairing)
func TestChallengerM5It2_MultiTurnToolCallIDAssociation(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	t.Run("Tool message with msg.Name == nil correctly correlated by ToolCallID", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		slackTool := "slack_read_channel"
		callID := "call_slack_secret_999"

		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.OpenAI,
				Model:    "gpt-4o",
				Input: []schemas.ChatMessage{
					{
						Role:    schemas.ChatMessageRoleUser,
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Read private channels")},
					},
					{
						Role: schemas.ChatMessageRoleAssistant,
						ChatAssistantMessage: &schemas.ChatAssistantMessage{
							ToolCalls: []schemas.ChatAssistantMessageToolCall{
								{
									ID: &callID,
									Function: schemas.ChatAssistantMessageToolCallFunction{
										Name: &slackTool,
									},
								},
							},
						},
					},
					{
						Role: schemas.ChatMessageRoleTool,
						// CRITICAL: msg.Name is explicitly nil! Correlation MUST happen via ToolCallID
						Name: nil,
						Content: &schemas.ChatMessageContent{
							ContentStr: bifrost.Ptr("Financial secrets from Slack"),
						},
						ChatToolMessage: &schemas.ChatToolMessage{
							ToolCallID: &callID,
						},
					},
				},
			},
		}

		_, sc, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, sc, "correlation via ToolCallID must block request to OpenAI")
		assert.Equal(t, 403, *sc.Error.StatusCode)
		assert.Equal(t, "cross_plane_violation", *sc.Error.Type)
	})

	t.Run("Multiple interleaved tool calls with out-of-order tool responses and nil names", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		slackTool := "slack_post_message"
		benignTool := "trello_get_board"

		callSlack := "call_id_slack"
		callTrello := "call_id_trello"

		// Assistant dispatches both tools at once
		// Tool messages return in reverse order: Trello first, Slack second, with msg.Name = nil
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
								{
									ID:       &callSlack,
									Function: schemas.ChatAssistantMessageToolCallFunction{Name: &slackTool},
								},
								{
									ID:       &callTrello,
									Function: schemas.ChatAssistantMessageToolCallFunction{Name: &benignTool},
								},
							},
						},
					},
					// Trello response arrives first (nil Name)
					{
						Role: schemas.ChatMessageRoleTool,
						Name: nil,
						ChatToolMessage: &schemas.ChatToolMessage{
							ToolCallID: &callTrello,
						},
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Trello Board Content")},
					},
					// Slack response arrives second (nil Name)
					{
						Role: schemas.ChatMessageRoleTool,
						Name: nil,
						ChatToolMessage: &schemas.ChatToolMessage{
							ToolCallID: &callSlack,
						},
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Slack Channel Content")},
					},
				},
			},
		}

		_, sc, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, sc, "slack tool in multi-tool batch must block OpenAI destination")
		assert.Equal(t, 403, *sc.Error.StatusCode)
		assert.Equal(t, "cross_plane_violation", *sc.Error.Type)
	})

	t.Run("Orphaned tool message with unmapped ToolCallID does not panic", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		orphanID := "unknown_call_id_xyz"
		req := &schemas.BifrostRequest{
			RequestType: schemas.ChatCompletionRequest,
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.Anthropic,
				Model:    "claude-3-7-sonnet",
				Input: []schemas.ChatMessage{
					{
						Role: schemas.ChatMessageRoleTool,
						Name: nil,
						ChatToolMessage: &schemas.ChatToolMessage{
							ToolCallID: &orphanID,
						},
						Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("Orphan content")},
					},
				},
			},
		}

		_, sc, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		assert.Nil(t, sc, "orphan tool message should not trigger short-circuit on benign provider")
	})

	t.Run("Pending assistant tool call without response blocks forward request", func(t *testing.T) {
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

		slackTool := "slack_read_channel"
		callID := "call_pending"

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
								{
									ID:       &callID,
									Function: schemas.ChatAssistantMessageToolCallFunction{Name: &slackTool},
								},
							},
						},
					},
				},
			},
		}

		_, sc, err := plugin.PreLLMHook(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, sc, "pending assistant tool call to Slack must block OpenAI destination")
		assert.Equal(t, 403, *sc.Error.StatusCode)
	})
}

// 4. Concurrent Active Connector Modifications & Lookups Under -race
func TestChallengerM5It2_ConcurrentActiveConnectorsStress_Race(t *testing.T) {
	acl := DefaultAirlokPolicy()
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	const numGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	connectors := []string{
		"slack", "google_workspace", "office365", "trello",
		"github", "notion", "zendesk", "salesforce",
	}

	stopSignal := make(chan struct{})

	// Background continuous reader loop
	var readOps int64
	var readWg sync.WaitGroup
	for r := 0; r < 20; r++ {
		readWg.Add(1)
		go func() {
			defer readWg.Done()
			for {
				select {
				case <-stopSignal:
					return
				default:
					conns := GetActiveConnectors(ctx)
					for _, c := range conns {
						_ = acl.CheckCrossPlaneDataBoundary(c, "openai")
						_ = acl.CheckCrossPlaneDataBoundary(c, "anthropic")
					}
					atomic.AddInt64(&readOps, 1)
				}
			}
		}()
	}

	// Concurrent writers adding active connectors
	for i := 0; i < numGoroutines; i++ {
		cIdx := i % len(connectors)
		conn := connectors[cIdx]
		go func(connName string) {
			defer wg.Done()
			AddActiveConnector(ctx, connName)
			// Read immediately after add
			current := GetActiveConnectors(ctx)
			require.NotEmpty(t, current)
		}(conn)
	}

	wg.Wait()
	close(stopSignal)
	readWg.Wait()

	finalConns := GetActiveConnectors(ctx)
	require.NotEmpty(t, finalConns, "active connectors must not be empty")
	t.Logf("Completed %d concurrent AddActiveConnector operations alongside %d reads with 0 race warnings. Final conns: %v", numGoroutines, atomic.LoadInt64(&readOps), finalConns)

	// Sequential addition verification on a separate context: all connectors retained without loss
	seqCtx := schemas.NewBifrostContext(context.Background(), time.Time{})
	for _, c := range connectors {
		AddActiveConnector(seqCtx, c)
	}
	seqConns := GetActiveConnectors(seqCtx)
	assert.Len(t, seqConns, len(connectors), "sequential additions must retain all unique connectors")
}

// 5. Unattended Approval Gate Under -race
func TestChallengerM5It2_UnattendedApprovalGate_HighConcurrencyStress(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	const numGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var unattendedBlockedCount int64
	var unattendedSpoofedBlockedCount int64
	var attendedApprovedAllowedCount int64
	var attendedUnapprovedBlockedCount int64

	for i := 0; i < numGoroutines; i++ {
		workerID := i
		go func(id int) {
			defer wg.Done()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

			toolName := "catalog_3000-query_items"
			req := &schemas.BifrostMCPRequest{
				ClientName:  "catalog_3000",
				RequestType: schemas.MCPRequestTypeChatToolCall,
				ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
					Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName},
				},
			}

			switch id % 4 {
			case 0:
				// Unattended, no approval
				ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, true)
				_, sc, err := plugin.PreMCPHook(ctx, req)
				require.NoError(t, err)
				if sc != nil && sc.Error != nil && *sc.Error.Type == "airlok_approval_required" {
					atomic.AddInt64(&unattendedBlockedCount, 1)
				}

			case 1:
				// Unattended, WITH approval (Fail-Closed verification!)
				ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, true)
				SetMCPExecutionAuthorization(ctx, "catalog_3000", toolName)
				_, sc, err := plugin.PreMCPHook(ctx, req)
				require.NoError(t, err)
				if sc != nil && sc.Error != nil && *sc.Error.Type == "airlok_approval_required" {
					atomic.AddInt64(&unattendedSpoofedBlockedCount, 1)
				}

			case 2:
				// Attended, with valid approval
				ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, false)
				SetMCPExecutionAuthorization(ctx, "catalog_3000", toolName)
				_, sc, err := plugin.PreMCPHook(ctx, req)
				require.NoError(t, err)
				if sc == nil || (sc.Error != nil && *sc.Error.Type != "airlok_approval_required") {
					atomic.AddInt64(&attendedApprovedAllowedCount, 1)
				}

			case 3:
				// Attended, without approval
				ctx.SetValue(schemas.BifrostContextKeyMCPUnattendedExecution, false)
				_, sc, err := plugin.PreMCPHook(ctx, req)
				require.NoError(t, err)
				if sc != nil && sc.Error != nil && *sc.Error.Type == "airlok_approval_required" {
					atomic.AddInt64(&attendedUnapprovedBlockedCount, 1)
				}
			}
		}(workerID)
	}

	wg.Wait()

	expectedEach := int64(numGoroutines / 4)
	assert.Equal(t, expectedEach, atomic.LoadInt64(&unattendedBlockedCount), "all unattended unapproved calls must be blocked")
	assert.Equal(t, expectedEach, atomic.LoadInt64(&unattendedSpoofedBlockedCount), "all unattended approved calls must fail closed and be blocked")
	assert.Equal(t, expectedEach, atomic.LoadInt64(&attendedApprovedAllowedCount), "all attended approved calls must be allowed")
	assert.Equal(t, expectedEach, atomic.LoadInt64(&attendedUnapprovedBlockedCount), "all attended unapproved calls must be blocked")
}

// 6. Dynamic ACL Mutation and Concurrent Read Stress
func TestChallengerM5It2_DynamicACLMutation_ConcurrencyStress(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetDualPlaneACL(DefaultAirlokPolicy())

	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		workerID := i
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-timeoutCtx.Done():
					return
				default:
					if id%10 == 0 {
						// Writer: update ACL
						newPolicy := DefaultAirlokPolicy()
						plugin.SetDualPlaneACL(newPolicy)
					} else {
						// Reader: evaluate ACL
						currentACL := plugin.GetDualPlaneACL()
						if currentACL != nil {
							_ = currentACL.CheckCrossPlaneDataBoundary("slack", "openai")
							_, _ = currentACL.CheckLLM(schemas.OpenAI, "gpt-4o")
							_, _ = currentACL.CheckConnector("slack", "")
						}
					}
				}
			}
		}(workerID)
	}

	wg.Wait()
}
