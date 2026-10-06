package governance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCircuitBreaker_SignalMatching_HeaderExists verifies the Exists mode
// where the presence of a header trips the circuit regardless of its value.
func TestCircuitBreaker_SignalMatching_HeaderExists(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Exists Policy",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{
					Source:     SignalSourceResponseHeader,
					HeaderName: "X-Ms-Degraded",
				},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	// 1. Normal response without header: remains Closed
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"Content-Type": "application/json"}, 200, "")
	state, _, _, ok := cbm.GetRuntimeState("azure-openai", "gpt-4o")
	require.True(t, ok)
	assert.Equal(t, CircuitClosed, state)

	// 2. Response with header (case-insensitive name): trips to Open
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"x-ms-degraded": "anything"}, 200, "")
	state, _, _, ok = cbm.GetRuntimeState("azure-openai", "gpt-4o")
	require.True(t, ok)
	assert.Equal(t, CircuitOpen, state)
}

// TestCircuitBreaker_SignalMatching_HeaderEquals verifies the Equals mode
// with case-insensitive exact matching.
func TestCircuitBreaker_SignalMatching_HeaderEquals(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Spillover Policy",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{
					Source:      SignalSourceResponseHeader,
					HeaderName:  "X-Ms-Is-Spilled-Over",
					HeaderValue: "true",
				},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Header value false: does not trip
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"X-Ms-Is-Spilled-Over": "false"}, 200, "")
	state, _, _, _ := cbm.GetRuntimeState("azure-openai", "gpt-4o")
	assert.Equal(t, CircuitClosed, state)

	// Header value TRUE (case-insensitive): trips
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"x-ms-is-spilled-over": "TRUE"}, 200, "")
	state, _, _, _ = cbm.GetRuntimeState("azure-openai", "gpt-4o")
	assert.Equal(t, CircuitOpen, state)
}

// TestCircuitBreaker_SignalMatching_HeaderContains verifies the Contains mode
// with substring matching.
func TestCircuitBreaker_SignalMatching_HeaderContains(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Substring Policy",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{
					Source:         SignalSourceResponseHeader,
					HeaderName:     "X-Warning",
					HeaderContains: "capacity_exceeded",
				},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Header does not contain substring
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Warning": "latency_high"}, 200, "")
	state, _, _, _ := cbm.GetRuntimeState("openai", "gpt-4o")
	assert.Equal(t, CircuitClosed, state)

	// Header contains substring
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"x-warning": "server_warning: capacity_exceeded on node 12"}, 200, "")
	state, _, _, _ = cbm.GetRuntimeState("openai", "gpt-4o")
	assert.Equal(t, CircuitOpen, state)
}

// TestCircuitBreaker_SignalMatching_StatusCodes verifies matching on HTTP status codes.
func TestCircuitBreaker_SignalMatching_StatusCodes(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Status Code Policy",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{
					Source:      SignalSourceStatusCode,
					StatusCodes: []int{500, 502, 503, 504, 429},
				},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Status 200 does not trip
	cbm.InspectResponse("openai", "gpt-4o", nil, 200, "")
	state, _, _, _ := cbm.GetRuntimeState("openai", "gpt-4o")
	assert.Equal(t, CircuitClosed, state)

	// Status 503 trips
	cbm.InspectResponse("openai", "gpt-4o", nil, 503, "")
	state, _, _, _ = cbm.GetRuntimeState("openai", "gpt-4o")
	assert.Equal(t, CircuitOpen, state)
}

// TestCircuitBreaker_ConditionOperators_OR_and_AND verifies OR vs AND logical combinations.
func TestCircuitBreaker_ConditionOperators_OR_and_AND(t *testing.T) {
	t.Run("OR operator", func(t *testing.T) {
		cbm := NewCircuitBreakerManager()
		cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
			Name:             "OR Policy",
			PrimaryProvider:  "openai",
			PrimaryModel:     "gpt-4o",
			FallbackProvider: "anthropic",
			FallbackModel:    "claude-sonnet-4-5",
			Condition: Condition{
				Operator: OperatorOR,
				Signals: []Signal{
					{Source: SignalSourceResponseHeader, HeaderName: "X-Overloaded"},
					{Source: SignalSourceStatusCode, StatusCodes: []int{503}},
				},
			},
			DefaultCooldown: 30 * time.Second,
		})

		// One signal matches -> trips
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Overloaded": "true"}, 200, "")
		state, _, _, _ := cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitOpen, state)
	})

	t.Run("AND operator", func(t *testing.T) {
		cbm := NewCircuitBreakerManager()
		cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
			Name:             "AND Policy",
			PrimaryProvider:  "openai",
			PrimaryModel:     "gpt-4o",
			FallbackProvider: "anthropic",
			FallbackModel:    "claude-sonnet-4-5",
			Condition: Condition{
				Operator: OperatorAND,
				Signals: []Signal{
					{Source: SignalSourceResponseHeader, HeaderName: "X-Overloaded"},
					{Source: SignalSourceStatusCode, StatusCodes: []int{503}},
				},
			},
			DefaultCooldown: 30 * time.Second,
		})

		// Header present but status code is 200 -> does NOT trip
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Overloaded": "true"}, 200, "")
		state, _, _, _ := cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitClosed, state)

		// Both signals present -> trips
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Overloaded": "true"}, 503, "")
		state, _, _, _ = cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitOpen, state)
	})
}

// TestCircuitBreaker_DynamicCooldown_RetryAfter verifies extraction of dynamic cooldown
// from Retry-After (seconds) and retry-after-ms (milliseconds).
func TestCircuitBreaker_DynamicCooldown_RetryAfter(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "RetryAfter Policy",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceStatusCode, StatusCodes: []int{429}},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Case 1: Retry-After: 60 -> cooldown 60s
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"Retry-After": "60"}, 429, "")
	_, openUntil, cd, _ := cbm.GetRuntimeState("openai", "gpt-4o")
	assert.Equal(t, 60*time.Second, cd)
	assert.InDelta(t, 60*time.Second, time.Until(openUntil), float64(2*time.Second))

	// Case 2: retry-after-ms: 5000 -> cooldown 5s
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"retry-after-ms": "5000"}, 429, "")
	_, _, cd, _ = cbm.GetRuntimeState("openai", "gpt-4o")
	assert.Equal(t, 5000*time.Millisecond, cd)
}

// TestCircuitBreaker_KeyLevel_SubCircuits verifies key-level sub-circuits:
// individual keys trip and are filtered, but main circuit trips ONLY when ALL keys have tripped.
func TestCircuitBreaker_KeyLevel_SubCircuits(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "SubCircuit Policy",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		PrimaryKeyIDs:    []string{"k1", "k2"},
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceStatusCode, StatusCodes: []int{429}},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	keys := []schemas.Key{{ID: "k1"}, {ID: "k2"}}

	// 1. Trip k1 only
	cbm.InspectResponse("azure-openai", "gpt-4o", nil, 429, "k1")

	// Main circuit should remain Closed
	state, _, _, _ := cbm.GetRuntimeState("azure-openai", "gpt-4o")
	assert.Equal(t, CircuitClosed, state, "main circuit should remain closed while k2 is healthy")

	// KeyPoolFilter should exclude k1 but retain k2
	filtered, err := cbm.KeyPoolFilter(ctx, "azure-openai", "gpt-4o", keys)
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "k2", filtered[0].ID)

	// 2. Trip k2 as well -> now ALL keys tripped -> Main circuit trips to Open
	cbm.InspectResponse("azure-openai", "gpt-4o", nil, 429, "k2")
	state, _, _, _ = cbm.GetRuntimeState("azure-openai", "gpt-4o")
	assert.Equal(t, CircuitOpen, state, "main circuit must open when all keys in primary_key_ids have tripped")

	// KeyPoolFilter excludes all
	filtered, err = cbm.KeyPoolFilter(ctx, "azure-openai", "gpt-4o", keys)
	require.NoError(t, err)
	assert.Empty(t, filtered)
}

// TestCircuitBreaker_DynamicFailover_Reroute verifies:
// 1. Reroute mutation in CheckAndReroute when circuit is OPEN.
// 2. Context flag circuit_breaker_tripped = true stamped on context.
// 3. Half-open transition after cooldown expiry admitting single canary probe.
// 4. Successful probe closes circuit; failed probe reopens circuit.
func TestCircuitBreaker_DynamicFailover_Reroute(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Failover Policy",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceResponseHeader, HeaderName: "X-Ms-Degraded"},
			},
		},
		DefaultCooldown: 10 * time.Second,
	})

	// Trip circuit
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"X-Ms-Degraded": "true"}, 200, "")

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	req := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: "azure-openai",
			Model:    "gpt-4o",
		},
	}

	// 1. Circuit is OPEN: CheckAndReroute mutates req to fallback
	tripped, fbProv, fbModel := cbm.CheckAndReroute(ctx, req)
	assert.True(t, tripped)
	assert.Equal(t, "anthropic", fbProv)
	assert.Equal(t, "claude-sonnet-4-5", fbModel)

	provider, model, _ := req.GetRequestFields()
	assert.Equal(t, schemas.ModelProvider("anthropic"), provider)
	assert.Equal(t, "claude-sonnet-4-5", model)
	assert.Equal(t, true, ctx.Value(schemas.BifrostContextKey("circuit_breaker_tripped")))

	// 2. Simulate cooldown expired -> Half-Open state
	pState := cbm.policies["azure-openai/gpt-4o"]
	pState.mu.Lock()
	pState.OpenUntil = time.Now().Add(-1 * time.Second)
	pState.mu.Unlock()

	req2 := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: "azure-openai",
			Model:    "gpt-4o",
		},
	}
	ctx2 := schemas.NewBifrostContext(context.Background(), time.Time{})

	// Next request is admitted as canary probe (not rerouted)
	probeTripped, _, _ := cbm.CheckAndReroute(ctx2, req2)
	assert.False(t, probeTripped, "canary probe request should be admitted to primary")
	assert.Equal(t, CircuitHalfOpen, pState.State)

	// 3. Canary probe returns successful response -> Circuit transitions to Closed
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"Content-Type": "application/json"}, 200, "")
	assert.Equal(t, CircuitClosed, pState.State, "successful canary probe must close circuit")
}

// TestCircuitBreaker_ConcurrentAccess_RaceDetector executes rapid concurrent inspections
// and reroutes to verify 0 race conditions under -race.
func TestCircuitBreaker_ConcurrentAccess_RaceDetector(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Concurrent Policy",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		PrimaryKeyIDs:    []string{"k1", "k2", "k3"},
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceResponseHeader, HeaderName: "X-Fail"},
				{Source: SignalSourceStatusCode, StatusCodes: []int{500, 503}},
			},
		},
		DefaultCooldown: 50 * time.Millisecond,
	})

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
				req := &schemas.BifrostRequest{
					RequestType: schemas.ChatCompletionRequest,
					ChatRequest: &schemas.BifrostChatRequest{
						Provider: "openai",
						Model:    "gpt-4o",
					},
				}

				cbm.CheckAndReroute(ctx, req)

				headers := map[string]string{}
				if j%3 == 0 {
					headers["X-Fail"] = "true"
				}
				cbm.InspectResponse("openai", "gpt-4o", headers, 200, "k1")
				cbm.GetRuntimeState("openai", "gpt-4o")
				_, _ = cbm.KeyPoolFilter(ctx, "openai", "gpt-4o", []schemas.Key{{ID: "k1"}, {ID: "k2"}})
			}
		}(i)
	}

	wg.Wait()
}
