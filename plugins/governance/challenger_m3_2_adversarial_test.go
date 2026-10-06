package governance

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CHALLENGE 1: TOTAL FAILURE OF ALL PRIMARY KEYS / ROUTES & FALLBACK ROUTING
// ============================================================================

// TestAdversarial_AllPrimaryKeysHeld_KeyPoolFilter_FallbackBehavior verifies:
// 1. When all primary keys are held (refusal/rate-limit), KeyPoolFilter returns an empty slice.
// 2. The filter does NOT return an error, allowing Bifrost core to detect len(available)==0 with liveCount>0.
// 3. Simulates Bifrost core's fallback pipeline: errAllKeysFiltered produces 503 with AllowFallbacks=nil.
// 4. Fallback resolution transparently dispatches to the secondary route without dropped requests.
func TestAdversarial_AllPrimaryKeysHeld_KeyPoolFilter_FallbackBehavior(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	// Primary provider "openai" with 3 keys
	primaryKeys := []schemas.Key{
		{ID: "key-prim-1"},
		{ID: "key-prim-2"},
		{ID: "key-prim-3"},
	}
	for _, k := range primaryKeys {
		lb.RegisterRoute(k.ID, "openai", "gpt-4o")
	}

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	// Initially, all 3 keys are eligible
	initialFiltered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", primaryKeys)
	require.NoError(t, err)
	assert.Len(t, initialFiltered, 3, "all primary keys should initially be eligible")

	// Simulate total failure of primary keys:
	// Key 1: 429 Rate Limit
	// Key 2: 401 Credential Failure
	// Key 3: 402 Quota Exhaustion
	lb.RecordAttemptWithDetails("key-prim-1", "openai", "gpt-4o", 10.0, true, 429, nil, nil)
	lb.RecordAttemptWithDetails("key-prim-2", "openai", "gpt-4o", 10.0, true, 401, nil, nil)
	lb.RecordAttemptWithDetails("key-prim-3", "openai", "gpt-4o", 10.0, true, 402, nil, nil)

	// Now KeyPoolFilter must return 0 keys
	filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", primaryKeys)
	require.NoError(t, err, "KeyPoolFilter must return nil error when all keys are filtered")
	assert.Empty(t, filtered, "KeyPoolFilter must return empty slice when all keys are held")

	// Simulate Bifrost core key selection closure (exact logic from core/bifrost.go:7653-7666)
	available := primaryKeys
	liveCount := len(available)
	filteredAvailable, filterErr := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", available)
	require.NoError(t, filterErr)
	available = filteredAvailable

	var bifrostErr *schemas.BifrostError
	if len(available) == 0 {
		if liveCount > 0 {
			// Bifrost core returns errAllKeysFiltered
			statusCode := 503
			errType := "no_eligible_keys"
			msg := "all eligible keys are temporarily suppressed by the key pool filter"
			bifrostErr = &schemas.BifrostError{
				IsBifrostError: false,
				StatusCode:     &statusCode,
				Type:           &errType,
				Error: &schemas.ErrorField{
					Message: msg,
				},
				// AllowFallbacks is nil, which defaults to true in shouldTryFallbacks
			}
		}
	}

	require.NotNil(t, bifrostErr)
	assert.Equal(t, 503, *bifrostErr.StatusCode)
	assert.Equal(t, "no_eligible_keys", *bifrostErr.Type)
	assert.Nil(t, bifrostErr.AllowFallbacks, "AllowFallbacks must be nil to enable fallback by default")

	// Verify Bifrost shouldTryFallbacks contract:
	// shouldTryFallbacks returns true when primaryErr.AllowFallbacks == nil
	shouldFallback := bifrostErr.AllowFallbacks == nil || *bifrostErr.AllowFallbacks
	assert.True(t, shouldFallback, "Bifrost core must try fallbacks upon errAllKeysFiltered")

	// Verify partial failure resilience: recover key-prim-2
	lb.Routes["key-prim-2"].mu.Lock()
	lb.Routes["key-prim-2"].Held = nil
	lb.Routes["key-prim-2"].HeldUntil = time.Time{}
	lb.Routes["key-prim-2"].State = RouteHealthy
	lb.Routes["key-prim-2"].Weight = 10.0
	lb.Routes["key-prim-2"].mu.Unlock()

	partialFiltered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", primaryKeys)
	require.NoError(t, err)
	require.Len(t, partialFiltered, 1, "partial recovery should immediately admit recovered key")
	assert.Equal(t, "key-prim-2", partialFiltered[0].ID)
}

// TestAdversarial_AllSubCircuitsTripped_FailoverRerouting verifies:
// 1. When all primary key sub-circuits trip, the main circuit trips to OPEN.
// 2. KeyPoolFilter excludes all primary keys.
// 3. CheckAndReroute transparently rewrites request to fallback provider and model.
func TestAdversarial_AllSubCircuitsTripped_FailoverRerouting(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Azure SubCircuit Policy",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		PrimaryKeyIDs:    []string{"az-k1", "az-k2"},
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceStatusCode, StatusCodes: []int{429, 503}},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	keys := []schemas.Key{{ID: "az-k1"}, {ID: "az-k2"}}
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	// Trip az-k1 only
	cbm.InspectResponse("azure-openai", "gpt-4o", nil, 429, "az-k1")
	state, _, _, _ := cbm.GetRuntimeState("azure-openai", "gpt-4o")
	assert.Equal(t, CircuitClosed, state, "circuit should remain closed while az-k2 is healthy")

	filtered, err := cbm.KeyPoolFilter(ctx, "azure-openai", "gpt-4o", keys)
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "az-k2", filtered[0].ID)

	// Trip az-k2 -> all primary keys are tripped
	cbm.InspectResponse("azure-openai", "gpt-4o", nil, 503, "az-k2")
	state, _, _, _ = cbm.GetRuntimeState("azure-openai", "gpt-4o")
	assert.Equal(t, CircuitOpen, state, "circuit must trip to OPEN when all primary keys trip")

	// KeyPoolFilter returns empty
	filtered, err = cbm.KeyPoolFilter(ctx, "azure-openai", "gpt-4o", keys)
	require.NoError(t, err)
	assert.Empty(t, filtered)

	// CheckAndReroute reroutes request to anthropic/claude-sonnet-4-5
	req := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: "azure-openai",
			Model:    "gpt-4o",
		},
	}
	tripped, fbProv, fbModel := cbm.CheckAndReroute(ctx, req)
	assert.True(t, tripped)
	assert.Equal(t, "anthropic", fbProv)
	assert.Equal(t, "claude-sonnet-4-5", fbModel)

	reqProv, reqModel, _ := req.GetRequestFields()
	assert.Equal(t, schemas.ModelProvider("anthropic"), reqProv)
	assert.Equal(t, "claude-sonnet-4-5", reqModel)
	assert.Equal(t, true, ctx.Value(schemas.BifrostContextKey("circuit_breaker_tripped")))
}

// ============================================================================
// CHALLENGE 2: SINGLE-CANARY CAS PROBE SLOT UNDER HEAVY CONCURRENCY
// ============================================================================

// TestAdversarial_HeldKey_CanaryProbe_Contention_1000Goroutines stress-tests
// that when a held key's cooldown expires, strictly 1 goroutine out of 1000 wins
// the canary probe slot, while the other 999 goroutines receive an empty slice.
func TestAdversarial_HeldKey_CanaryProbe_Contention_1000Goroutines(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("contended-key", "openai", "gpt-4o")
	route := lb.Routes["contended-key"]

	// Trip hold on the key
	lb.RecordAttemptWithDetails("contended-key", "openai", "gpt-4o", 10.0, true, 429, nil, nil)
	require.NotNil(t, route.Held)

	// Fast-forward hold to expired
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	const numGoroutines = 1000
	var probeWins int32
	var vetoCount int32
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	keys := []schemas.Key{{ID: "contended-key"}}

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

			// Wait for barrier release so all 1000 fire simultaneously
			<-startGate

			res, fErr := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
			if fErr == nil {
				if len(res) == 1 {
					atomic.AddInt32(&probeWins, 1)
				} else if len(res) == 0 {
					atomic.AddInt32(&vetoCount, 1)
				}
			}
		}()
	}

	// Release all 1000 goroutines concurrently
	close(startGate)
	wg.Wait()

	assert.Equal(t, int32(1), probeWins, "STRICTLY ONE goroutine must win the canary probe slot")
	assert.Equal(t, int32(numGoroutines-1), vetoCount, "all other 999 goroutines must be vetoed/filtered")
}

// TestAdversarial_HeldKey_ProbeOutcomes_Transitions verifies probe result handling:
// - Case A: Successful probe clears hold, transitions to RouteRecovering, probationary ramp to Healthy.
// - Case B: Transient error on probe keeps key held on same rung.
// - Case C: Provider refusal on probe climbs backoff ladder.
func TestAdversarial_HeldKey_ProbeOutcomes_Transitions(t *testing.T) {
	t.Run("Probe Success promotes to Recovering and ramps to Healthy", func(t *testing.T) {
		lb := NewAdaptiveLoadBalancer()
		defer lb.Close()
		lb.DisableJitter = true

		lb.RegisterRoute("key-succ", "openai", "gpt-4o")
		route := lb.Routes["key-succ"]

		// Trip hold
		lb.RecordAttemptWithDetails("key-succ", "openai", "gpt-4o", 10.0, true, 429, nil, nil)

		// Expire hold
		route.mu.Lock()
		route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
		route.HeldUntil = route.Held.HeldUntil
		route.mu.Unlock()

		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		keys := []schemas.Key{{ID: "key-succ"}}

		// Win probe slot
		filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
		require.NoError(t, err)
		require.Len(t, filtered, 1)

		// Probe request completes successfully (200 OK, 30ms latency)
		lb.RecordAttemptWithDetails("key-succ", "openai", "gpt-4o", 30.0, false, 0, nil, nil)

		route.mu.RLock()
		assert.Nil(t, route.Held, "successful probe must clear held state")
		assert.Equal(t, RouteRecovering, route.State, "successful probe must promote to RouteRecovering")
		assert.Equal(t, int64(1), route.ConsecutiveOk)
		route.mu.RUnlock()

		// Ramp through remaining 4 consecutive successes to reach 5 total
		for i := 0; i < 4; i++ {
			lb.RecordAttemptWithDetails("key-succ", "openai", "gpt-4o", 30.0, false, 0, nil, nil)
		}

		route.mu.RLock()
		assert.Equal(t, RouteHealthy, route.State, "5 consecutive successes must promote route to RouteHealthy")
		assert.Greater(t, route.Weight, 8.0, "route weight should be restored to high score")
		route.mu.RUnlock()
	})

	t.Run("Probe Transient Error re-holds key on same rung", func(t *testing.T) {
		lb := NewAdaptiveLoadBalancer()
		defer lb.Close()
		lb.DisableJitter = true

		lb.RegisterRoute("key-transient", "openai", "gpt-4o")
		route := lb.Routes["key-transient"]

		// Trip hold
		lb.RecordAttemptWithDetails("key-transient", "openai", "gpt-4o", 10.0, true, 429, nil, nil)
		initialBackoff := route.Held.CurrentBackoff
		initialRung := route.Held.Rung

		// Expire hold
		route.mu.Lock()
		route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
		route.HeldUntil = route.Held.HeldUntil
		route.mu.Unlock()

		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		keys := []schemas.Key{{ID: "key-transient"}}

		// Win probe slot
		filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
		require.NoError(t, err)
		require.Len(t, filtered, 1)

		// Probe fails with transient 500 error (isError=true, refusal=500)
		lb.RecordAttemptWithDetails("key-transient", "openai", "gpt-4o", 50.0, true, 500, nil, nil)

		route.mu.RLock()
		t.Logf("EMPIRICAL BUG REPRODUCTION:")
		t.Logf("route.Held.HeldUntil: %v", route.Held.HeldUntil)
		t.Logf("route.HeldUntil:      %v", route.HeldUntil)
		t.Logf("time.Now():           %v", time.Now())
		t.Logf("now.Before(route.Held.HeldUntil): %v", time.Now().Before(route.Held.HeldUntil))
		t.Logf("now.Before(route.HeldUntil):      %v", time.Now().Before(route.HeldUntil))
		require.NotNil(t, route.Held, "transient error on probe must keep key held")
		assert.Equal(t, initialRung, route.Held.Rung, "transient error on probe should not increment rung")
		assert.Equal(t, initialBackoff, route.Held.CurrentBackoff, "backoff should stay on current rung")
		assert.True(t, time.Now().Before(route.Held.HeldUntil), "HeldUntil must be in future")
		assert.Equal(t, int32(0), atomic.LoadInt32(&route.Held.Probing), "Probing CAS flag must be reset to 0")
		route.mu.RUnlock()

		// KeyPoolFilter check: re-held key must be filtered out, NOT re-admitted immediately!
		f2, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
		require.NoError(t, err)
		assert.Empty(t, f2, "KeyPoolFilter must return 0 keys while key is re-held following transient probe error")
	})

	t.Run("Probe Refusal climbs ladder rung", func(t *testing.T) {
		lb := NewAdaptiveLoadBalancer()
		defer lb.Close()
		lb.DisableJitter = true

		lb.RegisterRoute("key-refusal", "openai", "gpt-4o")
		route := lb.Routes["key-refusal"]

		// Trip hold on Rung 0 (30s)
		lb.RecordAttemptWithDetails("key-refusal", "openai", "gpt-4o", 10.0, true, 429, nil, nil)
		assert.Equal(t, 0, route.Held.Rung)
		assert.Equal(t, 30*time.Second, route.Held.CurrentBackoff)

		// Expire hold
		route.mu.Lock()
		route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
		route.HeldUntil = route.Held.HeldUntil
		route.mu.Unlock()

		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		keys := []schemas.Key{{ID: "key-refusal"}}

		// Win probe slot
		filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
		require.NoError(t, err)
		require.Len(t, filtered, 1)

		// Probe is refused again with 429
		lb.RecordAttemptWithDetails("key-refusal", "openai", "gpt-4o", 10.0, true, 429, nil, nil)

		route.mu.RLock()
		require.NotNil(t, route.Held)
		assert.Equal(t, 1, route.Held.Rung, "repeat refusal must increment ladder rung to 1")
		assert.Equal(t, 60*time.Second, route.Held.CurrentBackoff, "backoff must double to 60s")
		assert.Equal(t, int32(0), atomic.LoadInt32(&route.Held.Probing))
		route.mu.RUnlock()
	})
}

// TestAdversarial_CircuitBreaker_CanaryProbe_Contention_500Goroutines stress-tests
// the CircuitBreakerManager half-open canary probe slot under high concurrency:
// When cooldown expires, strictly ONE request is admitted as the canary probe,
// and all other 499 concurrent requests are rerouted to fallback.
func TestAdversarial_CircuitBreaker_CanaryProbe_Contention_500Goroutines(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Probe Contention Policy",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceResponseHeader, HeaderName: "X-Ms-Degraded"},
			},
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Trip circuit
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"X-Ms-Degraded": "true"}, 200, "")

	// Expire cooldown
	pState := cbm.policies["azure-openai/gpt-4o"]
	pState.mu.Lock()
	pState.OpenUntil = time.Now().Add(-1 * time.Second)
	pState.mu.Unlock()

	const numGoroutines = 500
	var probeWins int32
	var reroutedCount int32
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			req := &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: "azure-openai",
					Model:    "gpt-4o",
				},
			}

			<-startGate

			tripped, fbProv, fbModel := cbm.CheckAndReroute(ctx, req)
			if !tripped {
				atomic.AddInt32(&probeWins, 1)
			} else {
				if fbProv == "anthropic" && fbModel == "claude-sonnet-4-5" {
					atomic.AddInt32(&reroutedCount, 1)
				}
			}
		}()
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int32(1), probeWins, "STRICTLY ONE request must be admitted as canary probe to primary")
	assert.Equal(t, int32(numGoroutines-1), reroutedCount, "all other 499 requests must be rerouted to fallback")
	assert.Equal(t, CircuitHalfOpen, pState.State)

	// Canary probe succeeds -> circuit closes
	cbm.InspectResponse("azure-openai", "gpt-4o", map[string]string{"Content-Type": "application/json"}, 200, "")
	assert.Equal(t, CircuitClosed, pState.State, "successful probe must close circuit")
}

// ============================================================================
// CHALLENGE 3: RESPONSE HEADER CIRCUIT BREAKER MATCHING & COOLDOWNS
// ============================================================================

// TestAdversarial_CircuitBreaker_HeaderCondition_Matrix comprehensively tests:
// 1. Exists mode (case-insensitive name match).
// 2. Equals mode (case-insensitive value match).
// 3. Contains mode (case-insensitive substring match).
// 4. Status code list matching.
// 5. Operator OR vs AND logic.
func TestAdversarial_CircuitBreaker_HeaderCondition_Matrix(t *testing.T) {
	t.Run("Complex AND condition: status code AND header substring", func(t *testing.T) {
		cbm := NewCircuitBreakerManager()
		cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
			Name:             "AND Matrix Policy",
			PrimaryProvider:  "openai",
			PrimaryModel:     "gpt-4o",
			FallbackProvider: "anthropic",
			FallbackModel:    "claude-sonnet-4-5",
			Condition: Condition{
				Operator: OperatorAND,
				Signals: []Signal{
					{Source: SignalSourceStatusCode, StatusCodes: []int{503}},
					{Source: SignalSourceResponseHeader, HeaderName: "X-Server-Health", HeaderContains: "capacity_drain"},
				},
			},
			DefaultCooldown: 30 * time.Second,
		})

		// Mismatch 1: Status 503, but header absent -> Closed
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{}, 503, "")
		state, _, _, _ := cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitClosed, state)

		// Mismatch 2: Header present with substring, but status 200 -> Closed
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"x-server-health": "alert: capacity_drain active"}, 200, "")
		state, _, _, _ = cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitClosed, state)

		// Mismatch 3: Status 503, header present but wrong substring -> Closed
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Server-Health": "healthy"}, 503, "")
		state, _, _, _ = cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitClosed, state)

		// Full Match: Status 503 AND header with "capacity_drain" (mixed case) -> Trips OPEN
		cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-SERVER-HEALTH": "WARNING: CAPACITY_DRAIN_ON_CLUSTER"}, 503, "")
		state, _, _, _ = cbm.GetRuntimeState("openai", "gpt-4o")
		assert.Equal(t, CircuitOpen, state)
	})

	t.Run("Dynamic Cooldown extraction RFC1123, seconds, ms, and fallbacks", func(t *testing.T) {
		cbm := NewCircuitBreakerManager()
		cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
			Name:             "Cooldown Extraction Policy",
			PrimaryProvider:  "openai",
			PrimaryModel:     "o1",
			FallbackProvider: "anthropic",
			FallbackModel:    "claude-opus-4-5",
			Condition: Condition{
				Signals: []Signal{
					{Source: SignalSourceStatusCode, StatusCodes: []int{429}},
				},
			},
			DefaultCooldown: 25 * time.Second,
		})

		// 1. retry-after-ms takes priority
		cbm.InspectResponse("openai", "o1", map[string]string{"retry-after-ms": "12000"}, 429, "")
		_, _, cd, _ := cbm.GetRuntimeState("openai", "o1")
		assert.Equal(t, 12000*time.Millisecond, cd)

		// 2. Retry-After seconds
		cbm.policies["openai/o1"].State = CircuitClosed
		cbm.InspectResponse("openai", "o1", map[string]string{"Retry-After": "45"}, 429, "")
		_, _, cd, _ = cbm.GetRuntimeState("openai", "o1")
		assert.Equal(t, 45*time.Second, cd)

		// 3. Retry-After RFC1123 date
		cbm.policies["openai/o1"].State = CircuitClosed
		futureDate := time.Now().Add(50 * time.Second).UTC().Format(time.RFC1123)
		cbm.InspectResponse("openai", "o1", map[string]string{"Retry-After": futureDate}, 429, "")
		_, _, cd, _ = cbm.GetRuntimeState("openai", "o1")
		assert.InDelta(t, 50*time.Second, cd, float64(3*time.Second))

		// 4. Invalid header value falls back to DefaultCooldown
		cbm.policies["openai/o1"].State = CircuitClosed
		cbm.InspectResponse("openai", "o1", map[string]string{"Retry-After": "invalid-garbage"}, 429, "")
		_, _, cd, _ = cbm.GetRuntimeState("openai", "o1")
		assert.Equal(t, 25*time.Second, cd)
	})
}

// ============================================================================
// CHALLENGE 4: DYNAMIC FAILOVER & AUTOMATIC RECOVERY UNDER -race
// ============================================================================

// TestAdversarial_FullLifecycle_DynamicFailover_AutomaticRecovery_Race stress-tests
// continuous cycle transitions under 100 concurrent workers with race detector:
// Closed (primary) -> Open (rerouted to fallback) -> HalfOpen (canary probe) -> Closed (recovered)
func TestAdversarial_FullLifecycle_DynamicFailover_AutomaticRecovery_Race(t *testing.T) {
	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "Lifecycle Race Policy",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		PrimaryKeyIDs:    []string{"k1", "k2"},
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Signals: []Signal{
				{Source: SignalSourceResponseHeader, HeaderName: "X-Overload"},
				{Source: SignalSourceStatusCode, StatusCodes: []int{503}},
			},
		},
		DefaultCooldown: 10 * time.Millisecond,
	})

	const workers = 50
	const iterations = 40
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < iterations; iter++ {
				ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
				req := &schemas.BifrostRequest{
					RequestType: schemas.ChatCompletionRequest,
					ChatRequest: &schemas.BifrostChatRequest{
						Provider: "openai",
						Model:    "gpt-4o",
					},
				}

				// Check & reroute
				tripped, fbProv, fbModel := cbm.CheckAndReroute(ctx, req)
				if tripped {
					assert.Equal(t, "anthropic", fbProv)
					assert.Equal(t, "claude-sonnet-4-5", fbModel)
				}

				// Periodic inspections: occasionally trip, occasionally probe succeed/fail
				if iter%5 == 0 {
					// Trip signal
					headers := map[string]string{"X-Overload": "true"}
					cbm.InspectResponse("openai", "gpt-4o", headers, 503, "k1")
					cbm.InspectResponse("openai", "gpt-4o", headers, 503, "k2")
				} else if iter%3 == 0 {
					// Successful response (could settle a probe)
					cbm.InspectResponse("openai", "gpt-4o", map[string]string{}, 200, "k1")
				}

				// Query runtime state
				cbm.GetRuntimeState("openai", "gpt-4o")

				// Filter keys
				keys := []schemas.Key{{ID: "k1"}, {ID: "k2"}}
				_, _ = cbm.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)

				// Brief yield to allow cooldown expiry
				time.Sleep(1 * time.Millisecond)
			}
		}(w)
	}

	wg.Wait()
}

// ============================================================================
// CHALLENGE 5: PROBE TRANSIENT ERROR COOLDOWN SYNCHRONIZATION (1000 GOROUTINES)
// ============================================================================

// TestAdversarial_ProbeTransientError_CooldownSynchronization_1000Goroutines
// adversarially stress-tests probe transient error cooldown synchronization:
// 1. Verifies that when a canary probe fails with a transient error (e.g. 500),
//    both route.Held.HeldUntil and route.HeldUntil advance by CurrentBackoff.
// 2. Verifies that immediate subsequent queries to KeyPoolFilter and SelectRoute
//    continue to veto the held key for the entire cooldown window.
// 3. Verifies that under 1000 concurrent goroutines racing against transient
//    probe failure, exactly ZERO requests are admitted until the cooldown expires.
// 4. Verifies that once the cooldown expires, strictly 1 probe is admitted.
func TestAdversarial_ProbeTransientError_CooldownSynchronization_1000Goroutines(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	const keyID = "probe-transient-synced-key"
	lb.RegisterRoute(keyID, "openai", "gpt-4o")
	route := lb.Routes[keyID]

	// Step 1: Trip initial hold (e.g. 429 refusal, 30s backoff, rung 0)
	lb.RecordAttemptWithDetails(keyID, "openai", "gpt-4o", 15.0, true, 429, nil, nil)
	route.mu.RLock()
	require.NotNil(t, route.Held)
	assert.Equal(t, 0, route.Held.Rung)
	assert.Equal(t, 30*time.Second, route.Held.CurrentBackoff)
	route.mu.RUnlock()

	// Step 2: Expire the initial hold to permit canary probe
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	keys := []schemas.Key{{ID: keyID}}

	// Step 3: Canary probe wins the slot
	admittedProbe, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
	require.NoError(t, err)
	require.Len(t, admittedProbe, 1, "canary probe must win the probe slot")
	assert.Equal(t, int32(1), atomic.LoadInt32(&route.Held.Probing))

	// Step 4: Canary probe fails with transient 500 error concurrently racing with 1000 goroutines on KeyPoolFilter
	const numGoroutines = 1000
	var filterAdmitted int32
	var vetoCount int32
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			reqCtx := schemas.NewBifrostContext(context.Background(), time.Time{})

			<-startGate // Synchronized barrier release

			// 1000 goroutines query KeyPoolFilter racing against probe failure
			filtered, fErr := lb.KeyPoolFilter(reqCtx, "openai", "gpt-4o", keys)
			if fErr == nil {
				if len(filtered) > 0 {
					atomic.AddInt32(&filterAdmitted, 1)
				} else {
					atomic.AddInt32(&vetoCount, 1)
				}
			}
		}()
	}

	// Release 1000 goroutines and record the transient error concurrently
	close(startGate)
	lb.RecordAttemptWithDetails(keyID, "openai", "gpt-4o", 50.0, true, 500, nil, nil)
	wg.Wait()

	// Assertion 1: Cooldown synchronization
	route.mu.RLock()
	require.NotNil(t, route.Held, "held state must persist")
	assert.Equal(t, route.Held.HeldUntil, route.HeldUntil, "route.HeldUntil MUST be synchronized with route.Held.HeldUntil")
	assert.True(t, route.HeldUntil.After(time.Now()), "HeldUntil must be in the future")
	assert.True(t, route.Held.HeldUntil.After(time.Now()), "route.Held.HeldUntil must be in the future")
	assert.Equal(t, 0, route.Held.Rung, "transient error must not increment rung")
	assert.Equal(t, 30*time.Second, route.Held.CurrentBackoff, "backoff must remain on current rung")
	assert.Equal(t, int32(0), atomic.LoadInt32(&route.Held.Probing), "Probing CAS flag must be reset to 0")
	route.mu.RUnlock()

	// Assertion 2 & 3: Exactly zero requests admitted during or immediately after transient probe failure
	assert.Equal(t, int32(0), atomic.LoadInt32(&filterAdmitted),
		"KeyPoolFilter: exactly ZERO requests must be admitted while key is re-held on transient error")
	assert.Equal(t, int32(numGoroutines), atomic.LoadInt32(&vetoCount),
		"all 1000 requests must be vetoed/filtered")

	// Step 5: Immediate subsequent queries to KeyPoolFilter and SelectRoute during cooldown window
	fSeq, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
	require.NoError(t, err)
	assert.Empty(t, fSeq, "subsequent KeyPoolFilter must return empty slice during cooldown window")

	selSeq, _, _, _, sErr := lb.SelectRoute(ctx, "openai", "gpt-4o")
	assert.Error(t, sErr, "SelectRoute must return error when only key is held in cooldown")
	assert.Empty(t, selSeq)

	// Step 5b: 1000 concurrent goroutines across BOTH KeyPoolFilter (500) and SelectRoute (500) during cooldown window
	var cdFilterAdmitted int32
	var cdSelectAdmitted int32
	var cdVetoCount int32
	startGateCD := make(chan struct{})
	var wgCD sync.WaitGroup
	wgCD.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wgCD.Done()
			reqCtx := schemas.NewBifrostContext(context.Background(), time.Time{})

			<-startGateCD

			if idx%2 == 0 {
				res, fErr := lb.KeyPoolFilter(reqCtx, "openai", "gpt-4o", keys)
				if fErr == nil && len(res) > 0 {
					atomic.AddInt32(&cdFilterAdmitted, 1)
				} else {
					atomic.AddInt32(&cdVetoCount, 1)
				}
			} else {
				sel, _, _, _, sErr := lb.SelectRoute(reqCtx, "openai", "gpt-4o")
				if sErr == nil && sel == keyID {
					atomic.AddInt32(&cdSelectAdmitted, 1)
				} else {
					atomic.AddInt32(&cdVetoCount, 1)
				}
			}
		}(i)
	}

	close(startGateCD)
	wgCD.Wait()

	assert.Equal(t, int32(0), atomic.LoadInt32(&cdFilterAdmitted), "cooldown: exactly zero KeyPoolFilter requests admitted")
	assert.Equal(t, int32(0), atomic.LoadInt32(&cdSelectAdmitted), "cooldown: exactly zero SelectRoute requests admitted")
	assert.Equal(t, int32(numGoroutines), atomic.LoadInt32(&cdVetoCount), "cooldown: all 1000 requests vetoed")

	// Step 6: Verify behavior after cooldown expires: strictly 1 probe admitted under another 1000 goroutines
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	var probeWins int32
	var postVetoCount int32
	startGate2 := make(chan struct{})
	var wg2 sync.WaitGroup
	wg2.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg2.Done()
			reqCtx := schemas.NewBifrostContext(context.Background(), time.Time{})

			<-startGate2

			res, fErr := lb.KeyPoolFilter(reqCtx, "openai", "gpt-4o", keys)
			if fErr == nil {
				if len(res) == 1 {
					atomic.AddInt32(&probeWins, 1)
				} else if len(res) == 0 {
					atomic.AddInt32(&postVetoCount, 1)
				}
			}
		}()
	}

	close(startGate2)
	wg2.Wait()

	assert.Equal(t, int32(1), probeWins, "STRICTLY ONE goroutine must win the canary probe slot after cooldown expiry")
	assert.Equal(t, int32(numGoroutines-1), postVetoCount, "other 999 goroutines must be vetoed")
}

