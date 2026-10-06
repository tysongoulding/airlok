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

// TestLoadBalancer_Feature16_PeakEWMA_ContinuousDecay verifies:
// 1. Peak jump on high latency sample.
// 2. Discrete sample alpha = 0.2 smoothing on lower latency samples.
// 3. Continuous decay with 10s half-life (excess latency halves every 10s).
func TestLoadBalancer_Feature16_PeakEWMA_ContinuousDecay(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-1", "openai", "gpt-4o")
	route := lb.Routes["key-1"]

	// Initial route latency is 20ms baseline
	assert.Equal(t, 20.0, route.EWMALatencyMs)

	// Induce high latency spike (500ms)
	lb.RecordAttempt("key-1", 500.0, false, 0)
	assert.GreaterOrEqual(t, route.EWMALatencyMs, 100.0, "latency EWMA should jump up significantly on spike")
	initialEwma := route.EWMALatencyMs

	// Fast sample (20ms) smooths downward via alpha = 0.2
	lb.RecordAttempt("key-1", 20.0, false, 0)
	assert.Less(t, route.EWMALatencyMs, initialEwma, "faster sample should smooth EWMA downward")

	// Test continuous decay mathematical formulation:
	// Set baseline excess latency and simulate 10s elapsed time
	route.mu.Lock()
	route.EWMALatencyMs = 420.0 // Excess is 400.0 (420 - 20)
	route.LastUpdate = time.Now().Add(-10 * time.Second)
	route.mu.Unlock()

	lb.RecomputeWeights()

	route.mu.RLock()
	decayed := route.EWMALatencyMs
	route.mu.RUnlock()

	// Excess of 400 after 10s half-life should decay to ~200, so decayed latency ~220ms
	assert.InDelta(t, 220.0, decayed, 15.0, "10s elapsed time should halve excess latency via half-life decay")
}

// TestLoadBalancer_Feature16_MultiFactorScoring_Penalties verifies:
// Score = MaxWeight (10.0) - latencyPenalty - errorPenalty - utilizationPenalty
// Clamped between 10.0 and MinProbeWeight (0.1).
func TestLoadBalancer_Feature16_MultiFactorScoring_Penalties(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-fast", "openai", "gpt-4o")
	lb.RegisterRoute("key-slow", "openai", "gpt-4o")

	// Fast key: 10 requests with 15ms latency
	for i := 0; i < 10; i++ {
		lb.RecordAttempt("key-fast", 15.0, false, 0)
	}

	// Slow key: 10 requests with 400ms latency
	for i := 0; i < 10; i++ {
		lb.RecordAttempt("key-slow", 400.0, false, 0)
	}

	fastRoute := lb.Routes["key-fast"]
	slowRoute := lb.Routes["key-slow"]

	assert.Greater(t, fastRoute.Weight, slowRoute.Weight, "fast route must have higher weight than slow route")
	assert.Greater(t, fastRoute.Weight, 8.0, "fast route weight should be high")

	// Probe floor verification:
	lb.RegisterRoute("key-extreme", "openai", "gpt-4o")
	// Induce high latency and error
	lb.RecordAttempt("key-extreme", 2000.0, true, 500)
	extremeRoute := lb.Routes["key-extreme"]
	assert.GreaterOrEqual(t, extremeRoute.Weight, 0.1, "probe floor must be at least 0.1")
}

// TestLoadBalancer_Feature16_InFlight_ConcurrencyPenalty verifies that in-flight requests
// reduce the candidate key's effective weight and distribute load.
func TestLoadBalancer_Feature16_InFlight_ConcurrencyPenalty(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-a", "openai", "gpt-4o")
	lb.RegisterRoute("key-b", "openai", "gpt-4o")

	routeA := lb.Routes["key-a"]

	// Artificially increase InFlight on key-a
	routeA.InFlight.Store(40) // 40 * 0.2 = 8.0 penalty

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	keys := []schemas.Key{
		{ID: "key-a", Weight: 1.0},
		{ID: "key-b", Weight: 1.0},
	}

	// Over 100 selections, key-b should be selected far more often due to concurrency penalty on key-a
	selectedB := 0
	for i := 0; i < 100; i++ {
		sel, err := lb.SelectKey(ctx, keys, "openai", "gpt-4o")
		require.NoError(t, err)
		if sel.ID == "key-b" {
			selectedB++
		}
		// Release in-flight increment
		lb.ReleaseInFlight(sel.ID)
	}

	assert.Greater(t, selectedB, 70, "concurrency penalty should divert traffic away from busy key-a")
}

// TestLoadBalancer_Feature17_4TierRouteHealthStateMachine verifies:
// Healthy -> Degraded -> Failed -> Canary Probe -> Recovering (with ramp) -> Healthy
// and demotion on recovery failure.
func TestLoadBalancer_Feature17_4TierRouteHealthStateMachine(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-sm", "anthropic", "claude-sonnet-4-5")
	route := lb.Routes["key-sm"]

	// 1. Initial State: Healthy
	assert.Equal(t, RouteHealthy, route.State)

	// 2. Induce high latency (350ms > 250ms) -> Transitions to Degraded
	for i := 0; i < 15; i++ {
		lb.RecordAttempt("key-sm", 350.0, false, 0)
	}
	assert.Equal(t, RouteDegraded, route.State, "latency > 250ms should degrade route")
	assert.GreaterOrEqual(t, route.Weight, 0.1)

	// 3. Induce high error rate (> 50%) -> Transitions to Failed
	for i := 0; i < 20; i++ {
		lb.RecordAttempt("key-sm", 350.0, true, 500)
	}
	assert.Equal(t, RouteFailed, route.State, "errorRate > 0.50 should fail route")

	// 4. Recovery: Consecutive successful requests promote to Recovering
	lb.RecordAttempt("key-sm", 50.0, false, 0)
	assert.Equal(t, RouteRecovering, route.State, "success from failed non-held route moves to Recovering")

	// 5. Probationary weight ramp during recovery (5 successes needed)
	w1 := route.Weight
	for i := 0; i < 3; i++ {
		lb.RecordAttempt("key-sm", 50.0, false, 0)
	}
	assert.Equal(t, RouteRecovering, route.State)
	assert.Greater(t, route.Weight, w1, "probationary ramp should increase weight with each success")

	// Error during recovery immediately demotes back to Failed
	lb.RecordAttempt("key-sm", 50.0, true, 500)
	assert.Equal(t, RouteFailed, route.State, "error during recovery must immediately return to Failed")

	// Reset error count and simulate clean recovery to Healthy
	route.mu.Lock()
	route.ErrorCount = 0
	route.TotalRequests = 0
	route.ConsecutiveOk = 0
	route.EWMALatencyMs = 50.0
	route.State = RouteRecovering
	route.mu.Unlock()

	for i := 0; i < 5; i++ {
		lb.RecordAttempt("key-sm", 50.0, false, 0)
	}
	assert.Equal(t, RouteHealthy, route.State, "5 consecutive clean successes should promote to Healthy")
}

// TestLoadBalancer_Feature18_HeldKeys_BackoffLadder verifies:
// 1. Provider refusals (401, 402, 429) trip held key with Weight 0.0 and State Failed.
// 2. Ladder doubling: 30s -> 60s -> 120s ... up to reason-specific caps.
// 3. Rate-limit cap (2m), Credential cap (15m).
// 4. Flapping memory retains rung if refused within 10 minutes.
// 5. Retry-After header override enforces minimum 10-second floor.
func TestLoadBalancer_Feature18_HeldKeys_BackoffLadder(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-refused", "openai", "gpt-4o")
	route := lb.Routes["key-refused"]

	// Refusal 1: HTTP 401 Invalid Key
	lb.RecordAttempt("key-refused", 10.0, true, 401)
	assert.Equal(t, RouteFailed, route.State)
	assert.Equal(t, 0.0, route.Weight, "held key weight must be strictly 0.0")
	require.NotNil(t, route.Held)
	assert.Equal(t, 30*time.Second, route.Held.CurrentBackoff, "initial rung must be 30s")

	// Refusal 2: Double to 60s
	lb.RecordAttempt("key-refused", 10.0, true, 401)
	assert.Equal(t, 60*time.Second, route.Held.CurrentBackoff, "second rung must be 60s")

	// Refusal 3: Double to 120s
	lb.RecordAttempt("key-refused", 10.0, true, 401)
	assert.Equal(t, 120*time.Second, route.Held.CurrentBackoff, "third rung must be 120s")

	// Climb to cap (15 minutes for credential)
	for i := 0; i < 10; i++ {
		lb.RecordAttempt("key-refused", 10.0, true, 401)
	}
	assert.LessOrEqual(t, route.Held.CurrentBackoff, 15*time.Minute, "backoff must cap at 15 minutes")

	// Test RateLimit reason-specific cap (2m)
	lb.RegisterRoute("key-ratelimit", "openai", "gpt-4o")
	rateRoute := lb.Routes["key-ratelimit"]
	for i := 0; i < 10; i++ {
		lb.RecordAttempt("key-ratelimit", 10.0, true, 429)
	}
	assert.Equal(t, 2*time.Minute, rateRoute.Held.CurrentBackoff, "rate limit backoff must cap at 2 minutes")

	// Test Retry-After override with 10s minimum floor:
	lb.RegisterRoute("key-retryafter", "openai", "gpt-4o")
	retryRoute := lb.Routes["key-retryafter"]

	// Case A: Retry-After 60s -> wait 60s
	lb.RecordAttemptWithDetails("key-retryafter", "openai", "gpt-4o", 10.0, true, 429, nil, map[string]string{
		"Retry-After": "60",
	})
	assert.InDelta(t, 60*time.Second, time.Until(retryRoute.HeldUntil), float64(2*time.Second))

	// Case B: Retry-After 2s -> clamped to 10s floor
	lb.RecordAttemptWithDetails("key-retryafter", "openai", "gpt-4o", 10.0, true, 429, nil, map[string]string{
		"Retry-After": "2",
	})
	assert.InDelta(t, 10*time.Second, time.Until(retryRoute.HeldUntil), float64(2*time.Second), "Retry-After < 10s must be clamped to 10s floor")
}

// TestLoadBalancer_Feature18_CanaryProbe_AtomicCAS verifies:
// 1. Held keys before wait expiry are filtered out.
// 2. When wait expires, exactly ONE request wins the probe slot via atomic CAS.
// 3. Other concurrent requests continue to be filtered out.
func TestLoadBalancer_Feature18_CanaryProbe_AtomicCAS(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-probe", "openai", "gpt-4o")
	route := lb.Routes["key-probe"]

	// Trip hold
	lb.RecordAttempt("key-probe", 10.0, true, 401)
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	keys := []schemas.Key{{ID: "key-probe"}}

	// 1. While held: KeyPoolFilter returns empty
	filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
	require.NoError(t, err)
	assert.Empty(t, filtered, "held key must be filtered out while unexpired")

	// 2. Simulate wait expired
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	// 3. Concurrently invoke KeyPoolFilter across 20 goroutines
	var probeWins int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, fErr := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
			if fErr == nil && len(res) == 1 {
				atomic.AddInt32(&probeWins, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), probeWins, "exactly one concurrent request must win the canary probe slot via CAS")
}

// TestLoadBalancer_KeyPoolFilter_AllFiltered_Fallback verifies that when all keys are filtered,
// KeyPoolFilter returns an empty slice so Bifrost can trigger fallbacks.
func TestLoadBalancer_KeyPoolFilter_AllFiltered_Fallback(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("k1", "openai", "gpt-4o")
	lb.RegisterRoute("k2", "openai", "gpt-4o")

	// Fail both keys
	lb.RecordAttempt("k1", 10.0, true, 429)
	lb.RecordAttempt("k2", 10.0, true, 429)

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	keys := []schemas.Key{{ID: "k1"}, {ID: "k2"}}

	filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
	require.NoError(t, err)
	assert.Empty(t, filtered, "when all keys are held, filtered pool must be empty")
}

// TestLoadBalancer_ConcurrentAccess_RaceDetector executes rapid concurrent route selections
// and attempt recordings to ensure 100% race safety under -race.
func TestLoadBalancer_ConcurrentAccess_RaceDetector(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()

	for i := 0; i < 5; i++ {
		keyID := "key-" + string(rune('a'+i))
		lb.RegisterRoute(keyID, "openai", "gpt-4o")
	}

	keys := []schemas.Key{
		{ID: "key-a"}, {ID: "key-b"}, {ID: "key-c"}, {ID: "key-d"}, {ID: "key-e"},
	}

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	var wg sync.WaitGroup

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyID := keys[idx%len(keys)].ID
			for j := 0; j < 50; j++ {
				// Select
				sel, err := lb.SelectKey(ctx, keys, "openai", "gpt-4o")
				if err == nil {
					lb.ReleaseInFlight(sel.ID)
				}
				// Record attempt
				isErr := (j%5 == 0)
				refusal := 0
				if j%20 == 0 {
					refusal = 429
				}
				lb.RecordAttempt(keyID, float64(20+j*5), isErr, refusal)
				// Filter
				_, _ = lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
			}
		}(i)
	}

	wg.Wait()
}
