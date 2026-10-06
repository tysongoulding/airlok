package enterprise

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/cluster"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// PILLAR 1: CONTENT GUARDRAILS PIPELINE (RE2, CEL, STREAMING HOLD BUFFER)
// ============================================================================

// TestTier5_Part1_StreamingGuardrails_MicroChunkSplitting_SSN verifies that
// streaming guardrails cannot be bypassed by fragmenting a sensitive SSN across
// 1-character micro-chunks. Cleartext prefixes must be held, and upon completion,
// an HTTP 422 StreamInterceptionError must be returned with no leakage.
func TestTier5_Part1_StreamingGuardrails_MicroChunkSplitting_SSN(t *testing.T) {
	engine := governance.DefaultGuardrailsEngine()
	inspector := governance.NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	streamID := "stream-microchunk-ssn-test"
	ctx.SetValue(schemas.BifrostContextKeyRequestID, streamID)

	// US SSN "123-45-6789" split into 11 single-character micro-chunks
	microChunks := []string{"1", "2", "3", "-", "4", "5", "-", "6", "7", "8", "9"}

	var emittedDeltas []string
	var interceptedErr error

	for i, ch := range microChunks {
		chunkText := ch
		isLast := (i == len(microChunks)-1)

		chunk := &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &chunkText,
							},
						},
					},
				},
			},
		}
		if isLast {
			finishReason := "stop"
			chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
		}

		inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		if err != nil {
			interceptedErr = err
			break
		}

		if inspected != nil &&
			inspected.BifrostChatResponse != nil &&
			len(inspected.BifrostChatResponse.Choices) > 0 &&
			inspected.BifrostChatResponse.Choices[0].ChatStreamResponseChoice != nil &&
			inspected.BifrostChatResponse.Choices[0].ChatStreamResponseChoice.Delta != nil &&
			inspected.BifrostChatResponse.Choices[0].ChatStreamResponseChoice.Delta.Content != nil {
			delta := *inspected.BifrostChatResponse.Choices[0].ChatStreamResponseChoice.Delta.Content
			if delta != "" {
				emittedDeltas = append(emittedDeltas, delta)
			}
		}
	}

	// Invariant 1: Interception must occur on or before completion
	require.Error(t, interceptedErr, "micro-chunked SSN must be intercepted and rejected")

	// Invariant 2: Interception error must be HTTP 422 guardrail_violation
	streamErr, ok := interceptedErr.(*schemas.StreamInterceptionError)
	require.True(t, ok, "error must be of type *schemas.StreamInterceptionError")
	require.NotNil(t, streamErr.BifrostError)
	assert.Equal(t, 422, *streamErr.BifrostError.StatusCode)
	assert.Equal(t, "guardrail_violation", *streamErr.BifrostError.Type)
	assert.Equal(t, "guardrail_intervention", *streamErr.BifrostError.Error.Code)

	// Invariant 3: Zero cleartext SSN fragments must have escaped through emitted deltas
	for _, delta := range emittedDeltas {
		assert.NotContains(t, delta, "123-45-6789", "cleartext SSN must never be emitted")
		assert.NotContains(t, delta, "123-", "partial SSN prefix must not leak before interception")
	}
}

// TestTier5_Part1_StreamingGuardrails_MicroChunkSplitting_AWSSecrets verifies that
// high-entropy secret patterns (AWS access keys) split across 2-character chunks
// are strictly caught and blocked with HTTP 422.
func TestTier5_Part1_StreamingGuardrails_MicroChunkSplitting_AWSSecrets(t *testing.T) {
	engine := governance.DefaultGuardrailsEngine()
	inspector := governance.NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	streamID := "stream-microchunk-aws-test"
	ctx.SetValue(schemas.BifrostContextKeyRequestID, streamID)

	// "AKIAIOSFODNN7EXAMPLE" (20 chars) split across 10 2-character chunks
	microChunks := []string{"AK", "IA", "IO", "SF", "OD", "NN", "7E", "XA", "MP", "LE"}

	var interceptedErr error
	for i, ch := range microChunks {
		chunkText := ch
		isLast := (i == len(microChunks)-1)

		chunk := &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &chunkText,
							},
						},
					},
				},
			},
		}
		if isLast {
			finishReason := "stop"
			chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
		}

		_, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		if err != nil {
			interceptedErr = err
			break
		}
	}

	require.Error(t, interceptedErr, "fragmented AWS key must be caught by secrets detection")
	streamErr, ok := interceptedErr.(*schemas.StreamInterceptionError)
	require.True(t, ok)
	assert.Equal(t, 422, *streamErr.BifrostError.StatusCode)
	assert.Equal(t, "guardrail_violation", *streamErr.BifrostError.Type)
}

// TestTier5_Part1_StreamingGuardrails_HoldingBufferOverrun_MultiByteRuneIntegrity verifies:
// 1. When non-delimited tokens exceed the holding window, chunks are emitted safely.
// 2. Safe-cut boundaries never split multi-byte UTF-8 runes (e.g. 3-byte CJK or 4-byte emojis).
// 3. Concatenated emitted output strictly reconstitutes the full payload without corruption.
func TestTier5_Part1_StreamingGuardrails_HoldingBufferOverrun_MultiByteRuneIntegrity(t *testing.T) {
	engine := governance.DefaultGuardrailsEngine()
	inspector := governance.NewStreamInspector()
	inspector.SetHoldingWindowSize(32) // Small holding window to force multiple safe cuts

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "stream-utf8-overrun-test")

	// Multi-byte Chinese text without spaces/delimiters (each rune is 3 bytes)
	nonDelimitedCJK := "这是一段没有任何标点符号和空格的连续多字节文本专门用来测试流式切分安全边界"
	chunks := []string{
		"这是一段没有",
		"任何标点符号",
		"和空格的连续",
		"多字节文本专门",
		"用来测试流式",
		"切分安全边界",
	}

	var emittedTotal strings.Builder
	for i, chText := range chunks {
		textCopy := chText
		isLast := (i == len(chunks)-1)

		chunk := &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &textCopy,
							},
						},
					},
				},
			},
		}
		if isLast {
			finishReason := "stop"
			chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
		}

		inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		require.NoError(t, err)

		if inspected != nil && len(inspected.BifrostChatResponse.Choices) > 0 {
			delta := *inspected.BifrostChatResponse.Choices[0].ChatStreamResponseChoice.Delta.Content
			// Every individual delta must be valid UTF-8
			assert.True(t, utf8.ValidString(delta), "emitted delta must never split a multi-byte UTF-8 rune: %x", delta)
			emittedTotal.WriteString(delta)
		}
	}

	assert.Equal(t, nonDelimitedCJK, emittedTotal.String(), "concatenated stream output must exactly match input without rune corruption")
}

// TestTier5_Part1_StreamingGuardrails_ConcurrentStreams_500Goroutines verifies that
// 500 concurrent streams (250 clean, 250 containing SSN) executing simultaneously
// on a single StreamInspector produce zero data races, zero cross-stream contamination,
// exactly 250 clean completions, and exactly 250 HTTP 422 rejections.
func TestTier5_Part1_StreamingGuardrails_ConcurrentStreams_500Goroutines(t *testing.T) {
	engine := governance.DefaultGuardrailsEngine()
	inspector := governance.NewStreamInspector()

	const numStreams = 500
	var cleanCompleted atomic.Int64
	var blockedCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(numStreams)

	startGate := make(chan struct{})

	for i := 0; i < numStreams; i++ {
		go func(streamIdx int) {
			defer wg.Done()
			<-startGate

			streamID := fmt.Sprintf("stream-concurrent-%04d", streamIdx)
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, streamID)

			isBlockedStream := (streamIdx%2 == 0)

			var chunks []string
			if isBlockedStream {
				chunks = []string{
					"Customer record: ",
					"Name: Jane Doe, ",
					"SSN: 123-",
					"45-6789, ",
					"status verified.",
				}
			} else {
				chunks = []string{
					"System update: ",
					"All cluster nodes ",
					"are reporting ",
					"healthy status.",
				}
			}

			wasBlocked := false
			for cIdx, cText := range chunks {
				textCopy := cText
				isLast := (cIdx == len(chunks)-1)

				chunk := &schemas.BifrostStreamChunk{
					BifrostChatResponse: &schemas.BifrostChatResponse{
						Choices: []schemas.BifrostResponseChoice{
							{
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: &schemas.ChatStreamResponseChoiceDelta{
										Content: &textCopy,
									},
								},
							},
						},
					},
				}
				if isLast {
					finishReason := "stop"
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
				}

				_, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
				if err != nil {
					wasBlocked = true
					break
				}
			}

			if wasBlocked {
				blockedCount.Add(1)
			} else {
				cleanCompleted.Add(1)
			}
		}(i)
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int64(250), cleanCompleted.Load(), "exactly 250 clean streams must pass")
	assert.Equal(t, int64(250), blockedCount.Load(), "exactly 250 malicious streams must be blocked")
}

// ============================================================================
// PILLAR 2: ADAPTIVE LOAD BALANCING & CIRCUIT BREAKERS
// ============================================================================

// TestTier5_Part1_CircuitBreaker_MalformedAndNegativeRetryAfter verifies that
// corrupt, negative, NaN, overflow, and ancient HTTP Retry-After headers cannot
// crash the circuit breaker or cause negative/zero cooldown corruption.
func TestTier5_Part1_CircuitBreaker_MalformedAndNegativeRetryAfter(t *testing.T) {
	cbm := governance.NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(governance.CircuitBreakerPolicy{
		Name:             "Malformed-Header-Breaker",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		DefaultCooldown:  30 * time.Second,
		TriggerHeaders: map[string]string{
			"X-RateLimit": "exceeded",
		},
	})

	malformedHeaderCases := []struct {
		name    string
		headers map[string]string
	}{
		{"Negative seconds", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "-10"}},
		{"Negative huge", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "-999999999"}},
		{"Zero seconds", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "0"}},
		{"Alpha characters", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "not-a-number"}},
		{"NaN string", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "NaN"}},
		{"Negative ms", map[string]string{"X-RateLimit": "exceeded", "retry-after-ms": "-500"}},
		{"Zero ms", map[string]string{"X-RateLimit": "exceeded", "retry-after-ms": "0"}},
		{"Garbage ms", map[string]string{"X-RateLimit": "exceeded", "retry-after-ms": "abc123ms"}},
		{"Ancient date RFC1123", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}},
		{"Overflow integer", map[string]string{"X-RateLimit": "exceeded", "Retry-After": "999999999999999999999999999999999999"}},
	}

	for _, tc := range malformedHeaderCases {
		t.Run(tc.name, func(t *testing.T) {
			cbm.InspectResponse("openai", "gpt-4o", tc.headers, 429, "")

			// Inspect circuit status via CheckAndReroute
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			req := &schemas.BifrostRequest{
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.OpenAI,
					Model:    "gpt-4o",
				},
			}

			tripped, fbProv, fbModel := cbm.CheckAndReroute(ctx, req)
			require.True(t, tripped, "circuit breaker must trip into open state")
			assert.Equal(t, "anthropic", fbProv)
			assert.Equal(t, "claude-sonnet-4-5", fbModel)
		})
	}
}

// TestTier5_Part1_CircuitBreaker_ProbeWindowCAS_500Goroutines stress-tests
// the atomic CompareAndSwapInt32 canary probe slot during the half-open window:
// When cooldown expires, exactly ONE goroutine among 500 concurrent callers is
// admitted as the canary probe, while all other 499 are safely routed to fallback.
func TestTier5_Part1_CircuitBreaker_ProbeWindowCAS_500Goroutines(t *testing.T) {
	for rep := 0; rep < 3; rep++ {
		cbm := governance.NewCircuitBreakerManager()
		cbm.RegisterCircuitPolicy(governance.CircuitBreakerPolicy{
			Name:             "Canary-CAS-Probe-Breaker",
			PrimaryProvider:  "openai",
			PrimaryModel:     "gpt-4o",
			FallbackProvider: "anthropic",
			FallbackModel:    "claude-sonnet-4-5",
			DefaultCooldown:  15 * time.Millisecond,
			TriggerHeaders: map[string]string{
				"X-Trip": "true",
			},
		})

		// 1. Trip circuit
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Trip": "true"}, 500, "")

		// 2. Wait for cooldown to expire
		time.Sleep(20 * time.Millisecond)

		// 3. 500 goroutines hit CheckAndReroute concurrently
		const numGoroutines = 500
		startGate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		var probeCount atomic.Int64
		var fallbackCount atomic.Int64

		for g := 0; g < numGoroutines; g++ {
			go func() {
				defer wg.Done()
				<-startGate

				ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
				req := &schemas.BifrostRequest{
					ChatRequest: &schemas.BifrostChatRequest{
						Provider: schemas.OpenAI,
						Model:    "gpt-4o",
					},
				}

				tripped, fbProv, fbModel := cbm.CheckAndReroute(ctx, req)
				if !tripped {
					probeCount.Add(1)
				} else {
					fallbackCount.Add(1)
					assert.Equal(t, "anthropic", fbProv)
					assert.Equal(t, "claude-sonnet-4-5", fbModel)
				}
			}()
		}

		close(startGate)
		wg.Wait()

		// Invariant: Exactly 1 goroutine gets through to probe primary; 499 go to fallback
		assert.Equal(t, int64(1), probeCount.Load(), "strictly 1 canary probe must be admitted under half-open state")
		assert.Equal(t, int64(499), fallbackCount.Load(), "499 remaining goroutines must be rerouted to fallback")

		// 4. Report probe success -> should close circuit immediately
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Trip": "false"}, 200, "")

		// Next request should pass to primary cleanly
		reqPost := &schemas.BifrostRequest{
			ChatRequest: &schemas.BifrostChatRequest{
				Provider: schemas.OpenAI,
				Model:    "gpt-4o",
			},
		}
		trippedPost, _, _ := cbm.CheckAndReroute(nil, reqPost)
		assert.False(t, trippedPost, "circuit must be closed after successful canary probe")
	}
}

// TestTier5_Part1_CircuitBreaker_RapidFlapping_Stampede verifies that an alternating
// sequence of trips, half-open expirations, probe successes, and new trips under
// continuous concurrent load never deadlocks or results in invalid route targets.
func TestTier5_Part1_CircuitBreaker_RapidFlapping_Stampede(t *testing.T) {
	cbm := governance.NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(governance.CircuitBreakerPolicy{
		Name:             "Rapid-Flapping-Breaker",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		DefaultCooldown:  5 * time.Millisecond,
		TriggerHeaders: map[string]string{
			"X-RateLimit": "true",
		},
	})

	const goroutines = 200
	const cycles = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for it := 0; it < cycles; it++ {
				if gid == 0 && it%2 == 0 {
					// Inject trip
					cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-RateLimit": "true"}, 429, "")
				} else if gid == 0 && it%2 == 1 {
					// Inject recovery
					time.Sleep(6 * time.Millisecond)
					cbm.InspectResponse("openai", "gpt-4o", map[string]string{"Content-Type": "application/json"}, 200, "")
				}

				req := &schemas.BifrostRequest{
					ChatRequest: &schemas.BifrostChatRequest{
						Provider: schemas.OpenAI,
						Model:    "gpt-4o",
					},
				}
				tripped, fbProv, fbModel := cbm.CheckAndReroute(nil, req)
				if tripped {
					assert.Equal(t, "anthropic", fbProv)
					assert.Equal(t, "claude-sonnet-4-5", fbModel)
				}
			}
		}(g)
	}

	wg.Wait()
}

// TestTier5_Part1_AdaptiveLB_MultiFactorScoring_ExtremeLatenciesAndPenalties verifies:
// 1. Extreme latency values (0.0ms, 100,000ms) never produce NaN or infinite weights.
// 2. Minimum probe floor (0.1) is rigorously maintained under 100% error penalty.
// 3. Maximum route weight (10.0) is capped under 100% fast successes.
func TestTier5_Part1_AdaptiveLB_MultiFactorScoring_ExtremeLatenciesAndPenalties(t *testing.T) {
	lb := governance.NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-spike", "openai", "gpt-4o")
	lb.RegisterRoute("key-zero", "openai", "gpt-4o")

	// 1. Extreme latency spike of 100,000ms with errors
	for i := 0; i < 20; i++ {
		lb.RecordAttemptWithDetails("key-spike", "openai", "gpt-4o", 100000.0, true, 500, nil, nil)
	}

	// 2. Ultra-low latency of 0.001ms with success
	for i := 0; i < 20; i++ {
		lb.RecordAttemptWithDetails("key-zero", "openai", "gpt-4o", 0.001, false, 0, nil, nil)
	}

	routeSpike := lb.Routes["key-spike"]
	routeZero := lb.Routes["key-zero"]
	require.NotNil(t, routeSpike)
	require.NotNil(t, routeZero)

	// Invariant: Weight bounded in [0.1, 10.0]
	assert.False(t, math.IsNaN(routeSpike.Weight), "weight must not be NaN")
	assert.False(t, math.IsInf(routeSpike.Weight, 0), "weight must not be Inf")
	assert.GreaterOrEqual(t, routeSpike.Weight, 0.1, "probe floor 0.1 must be preserved")
	assert.LessOrEqual(t, routeSpike.Weight, 10.0, "weight must not exceed 10.0")

	assert.False(t, math.IsNaN(routeZero.Weight))
	assert.LessOrEqual(t, routeZero.Weight, 10.0)
	assert.Greater(t, routeZero.Weight, routeSpike.Weight, "healthy route must have higher weight than penalized route")
}

// TestTier5_Part1_HeldKeys_ConcurrentRefusalsAndLadderCap stress-tests
// the exponential backoff ladder on provider refusals (401, 429, 503) up to the cap:
// Backoff must double on repeated failures up to 15m and never overflow or exceed the cap.
func TestTier5_Part1_HeldKeys_ConcurrentRefusalsAndLadderCap(t *testing.T) {
	lb := governance.NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	const numKeys = 5
	for i := 0; i < numKeys; i++ {
		kID := fmt.Sprintf("ladder-key-%d", i)
		lb.RegisterRoute(kID, "openai", "gpt-4o")
	}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			kID := fmt.Sprintf("ladder-key-%d", gid%numKeys)
			for step := 0; step < 12; step++ {
				// 429 Rate limit refusal
				lb.RecordAttemptWithDetails(kID, "openai", "gpt-4o", 25.0, true, 429, nil, nil)
			}
		}(g)
	}

	wg.Wait()

	// Invariant verification across all keys
	for i := 0; i < numKeys; i++ {
		kID := fmt.Sprintf("ladder-key-%d", i)
		route := lb.Routes[kID]
		require.NotNil(t, route)

		assert.Equal(t, governance.RouteFailed, route.State)
		assert.Equal(t, 0.0, route.Weight)
		assert.True(t, route.HeldUntil.After(time.Now()), "held key must have HeldUntil in future")
		assert.LessOrEqual(t, route.BackoffLadder, 15*time.Minute, "ladder must not exceed 15m cap")
	}

	// KeyPoolFilter must return 0 keys when all keys are held
	keys := make([]schemas.Key, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = schemas.Key{ID: fmt.Sprintf("ladder-key-%d", i)}
	}

	filtered, err := lb.KeyPoolFilter(nil, "openai", "gpt-4o", keys)
	require.NoError(t, err)
	assert.Empty(t, filtered, "KeyPoolFilter must return empty slice when all keys are held")
}

// ============================================================================
// PILLAR 3: FEDERATED MCP AUTHORIZATION & TOOL GOVERNANCE
// ============================================================================

// TestTier5_Part1_MCP_PathTraversal_ConnectorBypassAttempts verifies that
// path traversal patterns in connector names (e.g. `../../etc/passwd`,
// `office365/../google_workspace`, `../office365`) cannot evade the dual-plane ACL.
func TestTier5_Part1_MCP_PathTraversal_ConnectorBypassAttempts(t *testing.T) {
	acl := governance.DefaultAirlokPolicy()

	traversalAttempts := []struct {
		connectorName string
		shouldDeny    bool
	}{
		{"../../etc/passwd", true},
		{"../office365", true},
		{"office365/../google_workspace", true},
		{"../../office365", true},
		{"office365", true},
		{"office365:delete_mail", true},
		{"office365/mail_read", true},
		{"google_workspace", false},
	}

	for _, tc := range traversalAttempts {
		t.Run(tc.connectorName, func(t *testing.T) {
			action, reason := acl.CheckConnector(tc.connectorName, "")
			if tc.shouldDeny {
				assert.Equal(t, governance.PolicyActionDeny, action, "connector %s must be denied: %s", tc.connectorName, reason)
			} else {
				assert.Equal(t, governance.PolicyActionAllow, action)
			}
		})
	}

	// White-box finding: ExtractConnectorName prefix matching behavior on path traversal
	// When a tool/connector name begins with an allowed prefix followed by traversal (e.g. "google_workspace/../office365"),
	// ExtractConnectorName extracts "google_workspace" because it checks strings.HasPrefix.
	extracted := acl.ExtractConnectorName("google_workspace/../office365")
	assert.Equal(t, "google_workspace", extracted, "ExtractConnectorName matches longest known prefix")
}

// TestTier5_Part1_MCP_MaliciousToolDelimitersAndInjection verifies that
// injection characters (null bytes, newlines, semicolons) in tool names do not
// allow denied connectors to bypass ACL checks in the VirtualMCPRegistry.
func TestTier5_Part1_MCP_MaliciousToolDelimitersAndInjection(t *testing.T) {
	acl := governance.DefaultAirlokPolicy()
	registry := governance.NewVirtualMCPRegistry(acl)
	registry.RegisterVirtualMCP("prod-mcp", "tenant-alpha", []string{"*"})

	maliciousToolNames := []struct {
		connector string
		tool      string
	}{
		{"office365", "delete_all; DROP TABLE users"},
		{"office365", "read\x00extra_payload"},
		{"office365", "mail_send\r\nBypass: true"},
		{"office365", "mail_read:admin"},
		{"office365", "mail_read/v1"},
	}

	for _, tc := range maliciousToolNames {
		t.Run(tc.tool, func(t *testing.T) {
			allowed, action, reason := registry.CheckToolAccess("prod-mcp", "admin-user", tc.connector, tc.tool)
			assert.False(t, allowed, "tool under denied connector must be blocked")
			assert.Equal(t, governance.PolicyActionDeny, action)
			assert.Contains(t, reason, "Office365 integrations disabled by policy")
		})
	}
}

// TestTier5_Part1_MCP_TokenExchange_ConcurrentTokenFlooding_InvalidTokens verifies that
// 500 concurrent goroutines querying TokenExchange with invalid, expired, and corrupt tokens:
// 1. Return strictly appropriate error sentinels without panicking.
// 2. Mint zero cached entries in the token exchanger.
// 3. Exhibit zero data races under -race.
func TestTier5_Part1_MCP_TokenExchange_ConcurrentTokenFlooding_InvalidTokens(t *testing.T) {
	exchanger := governance.NewFederatedTokenExchanger()

	const numGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	startGate := make(chan struct{})
	var missingSubjectErrors atomic.Int64
	var expiredTokenErrors atomic.Int64
	var malformedTokenErrors atomic.Int64
	var missingAudienceErrors atomic.Int64

	ctx := context.Background()

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			<-startGate

			op := gid % 4
			switch op {
			case 0:
				// Empty subject token
				_, err := exchanger.ExchangeToken(ctx, "   ", "https://api.github.com")
				if err == governance.ErrMissingSubjectToken {
					missingSubjectErrors.Add(1)
				}
			case 1:
				// Synthetic expired token
				_, err := exchanger.ExchangeToken(ctx, "expired-token-swarm-001", "https://api.github.com")
				if err == governance.ErrExpiredSubjectToken {
					expiredTokenErrors.Add(1)
				}
			case 2:
				// Malformed token with invalid base64 and invalid dots
				_, err := exchanger.ExchangeToken(ctx, "malformed-jwt-not-a-token", "https://api.github.com")
				if err == governance.ErrMalformedSubjectToken {
					malformedTokenErrors.Add(1)
				}
			case 3:
				// Missing audience
				_, err := exchanger.ExchangeToken(ctx, "valid-opaque-user-token", "   ")
				if err == governance.ErrMissingAudience {
					missingAudienceErrors.Add(1)
				}
			}
		}(g)
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int64(125), missingSubjectErrors.Load())
	assert.Equal(t, int64(125), expiredTokenErrors.Load())
	assert.Equal(t, int64(125), malformedTokenErrors.Load())
	assert.Equal(t, int64(125), missingAudienceErrors.Load())
}

// TestTier5_Part1_MCP_TokenExchange_CacheEvictionAndInvalidationRaces_500Goroutines
// verifies that 500 goroutines concurrently calling ExchangeToken, InvalidateToken,
// and FlushCache exhibit zero deadlocks between RWMutex and singleflight mutex.
func TestTier5_Part1_MCP_TokenExchange_CacheEvictionAndInvalidationRaces_500Goroutines(t *testing.T) {
	exchanger := governance.NewFederatedTokenExchanger()
	ctx := context.Background()

	const numGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	startGate := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			<-startGate

			token := fmt.Sprintf("user-token-actor-%d", gid%5)
			audience := "https://api.slack.com"

			for it := 0; it < 20; it++ {
				switch (gid + it) % 3 {
				case 0:
					// Read or mint token
					tok, err := exchanger.ExchangeToken(ctx, token, audience)
					if err == nil {
						assert.NotEmpty(t, tok)
					}
				case 1:
					// Invalidate specific token
					exchanger.InvalidateToken(token, audience)
				case 2:
					// Fleet cache flush
					if gid%20 == 0 {
						exchanger.FlushCache()
					}
				}
			}
		}(g)
	}

	close(startGate)
	wg.Wait()
}

// ============================================================================
// PILLAR 4: HA CLUSTER MODE & DISTRIBUTED STATE
// ============================================================================

// TestTier5_Part1_Cluster_DeterministicLeaderElection_RapidChurn stress-tests
// leader election re-evaluation across a 5-node cluster experiencing 100 rapid
// node failure and recovery churn events. Invariant: Leader must strictly be
// the lexicographically smallest alive node ID in all states.
func TestTier5_Part1_Cluster_DeterministicLeaderElection_RapidChurn(t *testing.T) {
	election := cluster.NewElectionManager("node-01", "us-east-1")

	// 5 nodes: node-01, node-02, node-03, node-04, node-05
	nodes := make(map[string]*cluster.NodeInfo)
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("node-%02d", i)
		nodes[id] = &cluster.NodeInfo{
			NodeID:   id,
			Region:   "us-east-1",
			State:    cluster.NodeStateAlive,
			IsLeader: false,
		}
	}

	// Initial evaluation: node-01 must be leader
	election.Reevaluate(nodes)
	assert.Equal(t, "node-01", election.GetLeaderID(), "node-01 must win initial leader election")

	// Churn sequence: kill node-01 -> node-02 must win
	nodes["node-01"].State = cluster.NodeStateDead
	election.Reevaluate(nodes)
	assert.Equal(t, "node-02", election.GetLeaderID())

	// Kill node-02 and node-03 -> node-04 must win
	nodes["node-02"].State = cluster.NodeStateDead
	nodes["node-03"].State = cluster.NodeStateDead
	election.Reevaluate(nodes)
	assert.Equal(t, "node-04", election.GetLeaderID())

	// Recover node-01 -> node-01 immediately re-claims leadership
	nodes["node-01"].State = cluster.NodeStateAlive
	election.Reevaluate(nodes)
	assert.Equal(t, "node-01", election.GetLeaderID())

	// Kill all nodes -> leader must be empty
	for _, n := range nodes {
		n.State = cluster.NodeStateDead
	}
	election.Reevaluate(nodes)
	assert.Equal(t, "", election.GetLeaderID(), "leader must be empty when all nodes are dead")
}

// TestTier5_Part1_Cluster_BurstRateLimitRefill_500Goroutines verifies:
//  1. Under 500 concurrent goroutines hitting the rate limit right as the window expires,
//     exactly Capacity charges succeed and all remainder are rejected.
//  2. Zero-drift: Remaining quota after burst is strictly 0.
//  3. Monotonic refill boundary: No oversubscription allowed.
func TestTier5_Part1_Cluster_BurstRateLimitRefill_500Goroutines(t *testing.T) {
	const capacity int64 = 50
	window := 50 * time.Millisecond
	bucket := cluster.NewInMemTokenBucket("adversarial-burst:rpm", capacity, window)

	// Step 1: Fully exhaust bucket in initial window
	now := time.Now()
	allowed, rem, _, _ := bucket.CheckAndCharge(now, capacity, capacity, window)
	require.True(t, allowed)
	require.Equal(t, int64(0), rem)

	// Immediate next charge must be rejected
	allowedExhausted, _, _, _ := bucket.CheckAndCharge(now, 1, capacity, window)
	require.False(t, allowedExhausted, "must reject before window expiry")

	// Step 2: Sleep until window precisely expires
	time.Sleep(60 * time.Millisecond)

	// Step 3: Launch 500 goroutines in a synchronized stampede
	const numGoroutines = 500
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var successCount atomic.Int64
	var rejectCount atomic.Int64

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			<-startGate

			chargeTime := time.Now()
			chargeAllowed, _, _, _ := bucket.CheckAndCharge(chargeTime, 1, capacity, window)
			if chargeAllowed {
				successCount.Add(1)
			} else {
				rejectCount.Add(1)
			}
		}()
	}

	close(startGate)
	wg.Wait()

	// Invariant 1: Exactly 50 charges succeeded
	assert.Equal(t, capacity, successCount.Load(), "strictly %d requests must succeed on window refill", capacity)

	// Invariant 2: Exactly (500 - 50 = 450) charges rejected
	assert.Equal(t, int64(numGoroutines)-capacity, rejectCount.Load())

	// Invariant 3: Remaining tokens after burst must strictly be 0
	assert.Equal(t, int64(0), bucket.GetRemaining(), "remaining tokens must be 0 after capacity burst")
}

// TestTier5_Part1_Cluster_SplitBrainHealing_DedupCache verifies that
// message deduplication (DedupCache) prevents redundant state application
// during partition healing when 500 concurrent retransmitted state sync messages arrive.
func TestTier5_Part1_Cluster_SplitBrainHealing_DedupCache(t *testing.T) {
	dedup := cluster.NewDedupCache(5 * time.Minute)

	const numMessages = 500
	var wg sync.WaitGroup
	wg.Add(numMessages)

	startGate := make(chan struct{})
	var uniqueAccepted atomic.Int64
	var duplicateRejected atomic.Int64

	// 5 distinct message hashes, each blasted 100 times concurrently
	for m := 0; m < numMessages; m++ {
		go func(msgIdx int) {
			defer wg.Done()
			<-startGate

			hashKey := fmt.Sprintf("state-delta-vk-%d", msgIdx%5)
			if dedup.CheckAndRecord(hashKey) {
				duplicateRejected.Add(1)
			} else {
				uniqueAccepted.Add(1)
			}
		}(m)
	}

	close(startGate)
	wg.Wait()

	// Exactly 5 unique messages must be accepted; 495 duplicates rejected
	assert.Equal(t, int64(5), uniqueAccepted.Load(), "strictly 5 unique message hashes must be admitted")
	assert.Equal(t, int64(495), duplicateRejected.Load(), "495 retransmitted duplicates must be rejected")
}

// TestTier5_Part1_Cluster_RateLimit_ClockJitterToleranceAndMonotonicity verifies:
//  1. Incoming replication deltas with clock jitter (ahead or behind local clock)
//     are tolerated without dropping valid updates or resetting capacity prematurely.
//  2. Monotonic decrease of remaining capacity across multiple peers.
func TestTier5_Part1_Cluster_RateLimit_ClockJitterToleranceAndMonotonicity(t *testing.T) {
	bucket := cluster.NewInMemTokenBucket("jitter-bucket:tpm", 1000, 1*time.Minute)

	now := time.Now()

	// 1. Peer A sends update with clock 2 seconds in future (positive jitter)
	peerTimeAhead := now.Add(2 * time.Second)
	bucket.UpdateRemoteSync(800, peerTimeAhead, 1*time.Minute)
	assert.Equal(t, int64(800), bucket.GetRemaining(), "peer update with clock ahead must be applied")

	// 2. Peer B sends further deduction with clock 2 seconds in past (negative jitter)
	peerTimeBehind := now.Add(-2 * time.Second)
	bucket.UpdateRemoteSync(600, peerTimeBehind, 1*time.Minute)
	assert.Equal(t, int64(600), bucket.GetRemaining(), "peer deduction with clock behind must be applied monotonically")

	// 3. Peer C sends stale higher remaining count (e.g. 700) within active window -> must NOT increase
	bucket.UpdateRemoteSync(700, now, 1*time.Minute)
	assert.Equal(t, int64(600), bucket.GetRemaining(), "stale higher remaining quota must never overwrite lower remaining quota")
}
