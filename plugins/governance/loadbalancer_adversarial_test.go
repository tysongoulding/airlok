package governance

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// EMPIRICAL CHALLENGER ADVERSARIAL SUITE: Milestone 3 AdaptiveLoadBalancer
// ============================================================================

// TestAdversarial_RapidFlapping_BurstAlternation stress-tests the route health state machine
// under 100 alternating cycles of error and success bursts with random latencies.
func TestAdversarial_RapidFlapping_BurstAlternation(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("flap-key", "openai", "gpt-4o")
	route := lb.Routes["flap-key"]

	for cycle := 0; cycle < 100; cycle++ {
		// Error burst: 5 errors with latency between 200ms and 1500ms
		for e := 0; e < 5; e++ {
			lat := 200.0 + float64(e*250)
			lb.RecordAttempt("flap-key", lat, true, 500)

			route.mu.RLock()
			st := route.State
			w := route.Weight
			ewma := route.EWMALatencyMs
			route.mu.RUnlock()

			assert.False(t, math.IsNaN(w), "Weight must never be NaN during error burst")
			assert.False(t, math.IsInf(w, 0), "Weight must never be Inf during error burst")
			assert.GreaterOrEqual(t, w, lb.MinProbeWeight, "Weight must never fall below MinProbeWeight")
			assert.LessOrEqual(t, w, lb.MaxWeight, "Weight must never exceed MaxWeight")
			assert.False(t, math.IsNaN(ewma), "EWMA must never be NaN")
			assert.Contains(t, []RouteState{RouteHealthy, RouteDegraded, RouteFailed}, st)
		}

		// Success burst: 10 successes with latency between 20ms and 80ms
		for s := 0; s < 10; s++ {
			lat := 20.0 + float64(s*6)
			lb.RecordAttempt("flap-key", lat, false, 0)

			route.mu.RLock()
			st := route.State
			w := route.Weight
			ewma := route.EWMALatencyMs
			route.mu.RUnlock()

			assert.False(t, math.IsNaN(w), "Weight must never be NaN during success burst")
			assert.False(t, math.IsInf(w, 0), "Weight must never be Inf during success burst")
			assert.GreaterOrEqual(t, w, lb.MinProbeWeight, "Weight must never fall below MinProbeWeight")
			assert.LessOrEqual(t, w, lb.MaxWeight, "Weight must never exceed MaxWeight")
			assert.False(t, math.IsNaN(ewma), "EWMA must never be NaN")
			assert.Contains(t, []RouteState{RouteHealthy, RouteDegraded, RouteRecovering, RouteFailed}, st)
		}
	}
}

// TestAdversarial_RapidFlapping_ProviderRefusals_FlappingMemory tests held keys backoff ladder,
// flapping memory retention across repeated refusals within the 10-minute window, and probationary ramps.
func TestAdversarial_RapidFlapping_ProviderRefusals_FlappingMemory(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("flap-held", "openai", "gpt-4o")
	route := lb.Routes["flap-held"]

	// Refusal 1: 429 RateLimit -> rung 0, 30s
	lb.RecordAttempt("flap-held", 25.0, true, 429)
	route.mu.RLock()
	assert.Equal(t, RouteFailed, route.State)
	assert.Equal(t, 0.0, route.Weight, "held key weight must strictly be 0.0")
	require.NotNil(t, route.Held)
	assert.Equal(t, 0, route.Held.Rung)
	assert.Equal(t, 30*time.Second, route.Held.CurrentBackoff)
	route.mu.RUnlock()

	// Wait expires -> simulate probe attempt
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	// Refusal 2: Another 429 on probe within 10m -> rung 1, 60s
	lb.RecordAttempt("flap-held", 25.0, true, 429)
	route.mu.RLock()
	assert.Equal(t, 1, route.Held.Rung, "flapping memory should advance to rung 1")
	assert.Equal(t, 60*time.Second, route.Held.CurrentBackoff, "backoff should double to 60s")
	route.mu.RUnlock()

	// Wait expires again -> simulate probe attempt
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	// Refusal 3: Another 429 on probe within 10m -> rung 2, 120s (capped at 2m for rate limit)
	lb.RecordAttempt("flap-held", 25.0, true, 429)
	route.mu.RLock()
	assert.Equal(t, 2, route.Held.Rung, "flapping memory should advance to rung 2")
	assert.Equal(t, 2*time.Minute, route.Held.CurrentBackoff, "rate limit backoff must cap at 2m")
	route.mu.RUnlock()

	// Simulate successful probe after wait expiry:
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	// Probe succeeds: should clear hold and promote to RouteRecovering
	lb.RecordAttempt("flap-held", 25.0, false, 0)
	route.mu.RLock()
	assert.Nil(t, route.Held, "successful probe must clear route.Held")
	assert.Equal(t, RouteRecovering, route.State, "successful probe promotes to RouteRecovering")
	assert.Greater(t, route.Weight, 0.0, "recovering route must have positive weight")
	route.mu.RUnlock()

	// Advance through probationary recovery: 4 more clean successes
	for i := 0; i < 4; i++ {
		lb.RecordAttempt("flap-held", 25.0, false, 0)
	}
	route.mu.RLock()
	assert.Equal(t, RouteHealthy, route.State, "5 consecutive clean successes promote to RouteHealthy")
	route.mu.RUnlock()

	// Immediate refusal again within 10-minute window:
	// Flapping memory MUST remember previous rung (2) and step up to rung 3 with 2m cap!
	lb.RecordAttempt("flap-held", 25.0, true, 429)
	route.mu.RLock()
	assert.Equal(t, RouteFailed, route.State)
	assert.Equal(t, 0.0, route.Weight)
	require.NotNil(t, route.Held)
	assert.Equal(t, 3, route.Held.Rung, "flapping memory must retain previous rung and increment to 3")
	assert.Equal(t, 2*time.Minute, route.Held.CurrentBackoff, "rate limit cap 2m maintained")
	route.mu.RUnlock()
}

// TestAdversarial_Recovery_DemotionOnError verifies that any error or excessive latency
// during the 5-success probationary window immediately demotes the route back to RouteFailed.
func TestAdversarial_Recovery_DemotionOnError(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("rec-key", "openai", "gpt-4o")
	route := lb.Routes["rec-key"]

	// Fail route via error rate
	for i := 0; i < 10; i++ {
		lb.RecordAttempt("rec-key", 200.0, true, 500)
	}
	assert.Equal(t, RouteFailed, route.State)

	// Step 1 into recovery: 1 success
	lb.RecordAttempt("rec-key", 30.0, false, 0)
	assert.Equal(t, RouteRecovering, route.State)
	assert.Equal(t, int64(1), route.ConsecutiveOk)

	// 3 more successes (total 4 consecutive successes)
	for i := 0; i < 3; i++ {
		lb.RecordAttempt("rec-key", 30.0, false, 0)
	}
	assert.Equal(t, RouteRecovering, route.State)
	assert.Equal(t, int64(4), route.ConsecutiveOk)

	// Single error on 5th attempt: immediate demotion to RouteFailed!
	lb.RecordAttempt("rec-key", 30.0, true, 500)
	route.mu.RLock()
	assert.Equal(t, RouteFailed, route.State, "error on probe 5 must demote immediately to RouteFailed")
	assert.Equal(t, lb.MinProbeWeight, route.Weight, "demoted failed route must have MinProbeWeight")
	assert.Equal(t, int64(0), route.ConsecutiveOk, "ConsecutiveOk must reset to 0")
	route.mu.RUnlock()

	// Recover again to 4 successes, then hit latency spike (> 1000ms FailedLatencyMs)
	for i := 0; i < 4; i++ {
		lb.RecordAttempt("rec-key", 30.0, false, 0)
	}
	assert.Equal(t, RouteRecovering, route.State)

	// Latency spike on 5th attempt: 1200ms
	lb.RecordAttempt("rec-key", 1200.0, false, 0)
	route.mu.RLock()
	assert.Equal(t, RouteFailed, route.State, "latency > 1000ms must demote recovering route to RouteFailed")
	route.mu.RUnlock()
}

// TestAdversarial_PeakEWMA_ContinuousDecay_MathematicalInvariants validates the continuous
// exponential decay formula against theoretical ground truth:
// L(t) = 20.0 + (L0 - 20.0) * exp(-dt / tau), where tau = 10 / ln(2).
func TestAdversarial_PeakEWMA_ContinuousDecay_MathematicalInvariants(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("decay-key", "openai", "gpt-4o")
	route := lb.Routes["decay-key"]

	tau := 10.0 / math.Ln2
	initialLatency := 820.0 // Excess is 800.0ms

	elapsedIntervals := []float64{0.0, 2.5, 5.0, 10.0, 15.0, 20.0, 30.0, 60.0, 120.0, 600.0}

	for _, dt := range elapsedIntervals {
		route.mu.Lock()
		route.EWMALatencyMs = initialLatency
		route.LastUpdate = time.Now().Add(-time.Duration(dt * float64(time.Second)))
		route.mu.Unlock()

		lb.RecomputeWeights()

		route.mu.RLock()
		actual := route.EWMALatencyMs
		route.mu.RUnlock()

		expectedDecayed := 20.0 + (initialLatency-20.0)*math.Exp(-dt/tau)
		if expectedDecayed < 20.0 {
			expectedDecayed = 20.0
		}

		assert.InDelta(t, expectedDecayed, actual, 0.05,
			fmt.Sprintf("Decay at dt=%.1fs must match theoretical continuous decay", dt))
		assert.GreaterOrEqual(t, actual, 20.0, "Latency EWMA must never decay below 20ms baseline floor")
	}

	// Clock step backwards (negative dt): verify no NaN, panic, or unphysical inflation
	route.mu.Lock()
	route.EWMALatencyMs = 100.0
	route.LastUpdate = time.Now().Add(10 * time.Second) // Future timestamp (NTP skew)
	route.mu.Unlock()

	lb.RecomputeWeights()

	route.mu.RLock()
	afterSkew := route.EWMALatencyMs
	route.mu.RUnlock()

	assert.Equal(t, 100.0, afterSkew, "Negative dt must be safely skipped without changing EWMA")
}

// TestAdversarial_PeakEWMA_SpikeJump_And_HybridDiscreteDecay verifies:
// 1. Instant jump on spike (Finagle Peak EWMA).
// 2. Continuous decay over idle interval + discrete sample update on next request.
func TestAdversarial_PeakEWMA_SpikeJump_And_HybridDiscreteDecay(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("spike-key", "openai", "gpt-4o")
	route := lb.Routes["spike-key"]

	// Step 1: Start at baseline 20ms
	assert.Equal(t, 20.0, route.EWMALatencyMs)

	// Step 2: Instant jump on 1000ms latency spike
	lb.RecordAttempt("spike-key", 1000.0, false, 0)
	assert.Equal(t, 1000.0, route.EWMALatencyMs, "spike must immediately jump EWMA to peak sample")

	// Step 3: Fast sample (20ms) arriving immediately (dt ~ 0):
	// Smoothed = alpha * 20 + (1 - alpha) * 1000 = 0.2 * 20 + 0.8 * 1000 = 804ms
	lb.RecordAttempt("spike-key", 20.0, false, 0)
	assert.InDelta(t, 804.0, route.EWMALatencyMs, 0.5, "discrete sample smoothing should yield 804ms")

	// Step 4: Simulate 10s idle time followed by a 50ms sample:
	// Prior EWMA was ~804ms (excess = 784ms).
	// Over 10s half-life, excess decays to 784 * 0.5 = 392ms -> decayed = 412ms.
	// On new sample 50ms: smoothed = 0.2 * 50 + 0.8 * 412 = 10 + 329.6 = 339.6ms.
	route.mu.Lock()
	route.LastUpdate = time.Now().Add(-10 * time.Second)
	route.mu.Unlock()

	lb.RecordAttempt("spike-key", 50.0, false, 0)
	assert.InDelta(t, 339.6, route.EWMALatencyMs, 1.5,
		"hybrid continuous-decay + discrete sample update must match Finagle calculation")
}

// TestAdversarial_HeavyConcurrency_500_Goroutines_KeySelector_KeyPoolFilter tests
// 500 concurrent goroutines executing SelectKey, ReleaseInFlight, KeyPoolFilter,
// RecordAttempt, and RecomputeWeights without race conditions or deadlocks.
func TestAdversarial_HeavyConcurrency_500_Goroutines_KeySelector_KeyPoolFilter(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()

	keyCount := 8
	keys := make([]schemas.Key, keyCount)
	for i := 0; i < keyCount; i++ {
		kID := fmt.Sprintf("k-conc-%d", i)
		keys[i] = schemas.Key{ID: kID, Weight: 1.0}
		lb.RegisterRoute(kID, "openai", "gpt-4o")
	}

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	goroutineCount := 500
	iterationsPerGoroutine := 60

	var wg sync.WaitGroup
	wg.Add(goroutineCount)

	for g := 0; g < goroutineCount; g++ {
		go func(gid int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(gid), uint64(time.Now().UnixNano())))

			for it := 0; it < iterationsPerGoroutine; it++ {
				op := it % 5
				switch op {
				case 0, 1:
					// SelectKey + ReleaseInFlight
					sel, err := lb.SelectKey(ctx, keys, "openai", "gpt-4o")
					if err == nil {
						assert.NotEmpty(t, sel.ID)
						lb.ReleaseInFlight(sel.ID)
					}
				case 2:
					// KeyPoolFilter
					filtered, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
					assert.NoError(t, err)
					assert.LessOrEqual(t, len(filtered), len(keys))
				case 3:
					// RecordAttempt (success or error)
					idx := r.IntN(keyCount)
					kID := keys[idx].ID
					isErr := (it%4 == 0)
					refusal := 0
					if it%20 == 0 {
						refusal = 429
					}
					lat := 10.0 + float64(r.IntN(300))
					lb.RecordAttempt(kID, lat, isErr, refusal)
				case 4:
					// Periodic weight recompute
					if gid%10 == 0 && it%10 == 0 {
						lb.RecomputeWeights()
					}
				}
			}
		}(g)
	}

	wg.Wait()

	// Validate post-test invariant integrity
	for _, k := range keys {
		route := lb.Routes[k.ID]
		route.mu.RLock()
		assert.False(t, math.IsNaN(route.Weight))
		assert.False(t, math.IsInf(route.Weight, 0))
		assert.False(t, math.IsNaN(route.EWMALatencyMs))
		assert.GreaterOrEqual(t, route.InFlight.Load(), int64(0), "InFlight counter must never be negative")
		route.mu.RUnlock()
	}
}

// TestAdversarial_HeavyConcurrency_1000_Goroutines_KeySelector stress-tests
// 1000 concurrent goroutines pounding KeySelector with in-flight penalties.
func TestAdversarial_HeavyConcurrency_1000_Goroutines_KeySelector(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()

	keyCount := 10
	keys := make([]schemas.Key, keyCount)
	for i := 0; i < keyCount; i++ {
		kID := fmt.Sprintf("k-1000-%d", i)
		keys[i] = schemas.Key{ID: kID, Weight: 1.0}
		lb.RegisterRoute(kID, "openai", "gpt-4o")
	}

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	goroutineCount := 1000
	var wg sync.WaitGroup
	wg.Add(goroutineCount)

	var successCount atomic.Int64

	for g := 0; g < goroutineCount; g++ {
		go func() {
			defer wg.Done()
			for it := 0; it < 30; it++ {
				sel, err := lb.SelectKey(ctx, keys, "openai", "gpt-4o")
				if err == nil && sel.ID != "" {
					successCount.Add(1)
					lb.ReleaseInFlight(sel.ID)
				}
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(goroutineCount*30), successCount.Load(),
		"All 30,000 concurrent SelectKey requests must succeed")
}

// TestAdversarial_HeldKeys_CanaryCAS_1000_Goroutines verifies that when a held key expires,
// among 1000 concurrent goroutines querying KeyPoolFilter, exactly ONE goroutine wins the CAS probe slot.
func TestAdversarial_HeldKeys_CanaryCAS_1000_Goroutines(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("cas-probe-key", "openai", "gpt-4o")
	route := lb.Routes["cas-probe-key"]

	// Trip hold
	lb.RecordAttempt("cas-probe-key", 20.0, true, 401)
	keys := []schemas.Key{{ID: "cas-probe-key"}}
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	// Wait expired
	route.mu.Lock()
	route.Held.HeldUntil = time.Now().Add(-1 * time.Second)
	route.HeldUntil = route.Held.HeldUntil
	route.mu.Unlock()

	goroutineCount := 1000
	var probeWinners atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutineCount)

	for g := 0; g < goroutineCount; g++ {
		go func() {
			defer wg.Done()
			admitted, err := lb.KeyPoolFilter(ctx, "openai", "gpt-4o", keys)
			if err == nil && len(admitted) == 1 {
				probeWinners.Add(1)
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(1), probeWinners.Load(),
		"Exactly 1 goroutine out of 1000 must win the canary probe slot via atomic CAS")
}

// TestAdversarial_InFlight_LittleLawPenalty verifies that the in-flight concurrency penalty
// dynamically diverts traffic across candidate keys according to Little's Law penalty.
func TestAdversarial_InFlight_LittleLawPenalty(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	lb.RegisterRoute("key-busy", "openai", "gpt-4o")
	lb.RegisterRoute("key-idle", "openai", "gpt-4o")

	busyRoute := lb.Routes["key-busy"]
	idleRoute := lb.Routes["key-idle"]

	// Set baseline weights
	busyRoute.Weight = 10.0
	idleRoute.Weight = 10.0

	// Store high in-flight load on busy route (30 in-flight * 0.2 penalty = 6.0 penalty)
	// Effective weight = 10.0 - 6.0 = 4.0
	// Idle route: 0 in-flight -> effective weight = 10.0
	busyRoute.InFlight.Store(30)
	idleRoute.InFlight.Store(0)

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	keys := []schemas.Key{{ID: "key-busy"}, {ID: "key-idle"}}

	var idlePicks int
	samples := 500
	for i := 0; i < samples; i++ {
		sel, err := lb.SelectKey(ctx, keys, "openai", "gpt-4o")
		require.NoError(t, err)
		if sel.ID == "key-idle" {
			idlePicks++
		}
		lb.ReleaseInFlight(sel.ID)
	}

	// Theoretical ratio: 10 / (10 + 4) = 71.4%
	ratio := float64(idlePicks) / float64(samples)
	assert.Greater(t, ratio, 0.60, "Idle key should be chosen roughly ~70% of the time")
	assert.Less(t, ratio, 0.85, "Busy key should still get ~30% of traffic (not starved)")
}

// TestAdversarial_BoundaryCases validates boundary conditions and pathological inputs.
func TestAdversarial_BoundaryCases(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

	// 1. Empty keys slice to SelectKey -> returns error
	_, err := lb.SelectKey(ctx, []schemas.Key{}, "openai", "gpt-4o")
	assert.Error(t, err, "SelectKey with empty keys must error")

	// 2. Single key -> returns immediately without error
	singleKey := []schemas.Key{{ID: "k-single"}}
	sel, err := lb.SelectKey(ctx, singleKey, "openai", "gpt-4o")
	assert.NoError(t, err)
	assert.Equal(t, "k-single", sel.ID)
	lb.ReleaseInFlight("k-single")

	// 3. Negative latency input to RecordAttempt -> handled gracefully without panic
	lb.RecordAttempt("k-single", -50.0, false, 0)
	route := lb.Routes["k-single"]
	assert.False(t, math.IsNaN(route.EWMALatencyMs))

	// 4. Extreme latency input -> capped at MaxWeight/MinProbeWeight limits
	lb.RecordAttempt("k-single", 1e9, false, 0)
	assert.Equal(t, lb.MinProbeWeight, route.Weight)

	// 5. ReleaseInFlight called more times than SelectKey -> clamps to 0, no negative value
	lb.ReleaseInFlight("k-single")
	lb.ReleaseInFlight("k-single")
	lb.ReleaseInFlight("k-single")
	assert.Equal(t, int64(0), route.InFlight.Load())

	// 6. Idempotent Close()
	lb.Close()
	lb.Close() // Second close must not panic
}

// TestAdversarial_SelectRoute_WithCircuitBreaker_500_Goroutines stress-tests
// the real AdaptiveLoadBalancer.SelectRoute integration with CircuitBreakerManager
// under 500 concurrent goroutines with dynamic tripping and failover rerouting.
func TestAdversarial_SelectRoute_WithCircuitBreaker_500_Goroutines(t *testing.T) {
	lb := NewAdaptiveLoadBalancer()
	defer lb.Close()
	lb.DisableJitter = true

	cbm := NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(CircuitBreakerPolicy{
		Name:             "OpenAI-To-Anthropic-Failover",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		Condition: Condition{
			Operator: OperatorOR,
			Signals: []Signal{
				{
					Source:     SignalSourceResponseHeader,
					HeaderName: "X-RateLimit-Exceeded",
					HeaderValue: "true",
				},
			},
		},
		DefaultCooldown: 50 * time.Millisecond,
	})
	lb.CircuitBreakers = cbm

	lb.RegisterRoute("k1", "openai", "gpt-4o")
	lb.RegisterRoute("k2", "openai", "gpt-4o")

	const goroutines = 500
	const iterations = 40
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var primaryCount atomic.Int64
	var fallbackCount atomic.Int64

	ctx := context.Background()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				// Periodically trip circuit
				if gid == 0 && it%10 == 0 {
					cbm.InspectResponse("openai", "gpt-4o", map[string]string{
						"X-RateLimit-Exceeded": "true",
					}, 429, "")
				}

				key, fbProv, fbModel, tripped, err := lb.SelectRoute(ctx, "openai", "gpt-4o")
				if err != nil {
					continue
				}

				if tripped {
					assert.Equal(t, "anthropic", fbProv)
					assert.Equal(t, "claude-sonnet-4-5", fbModel)
					fallbackCount.Add(1)
				} else {
					assert.Contains(t, []string{"k1", "k2"}, key)
					primaryCount.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()

	totalServiced := primaryCount.Load() + fallbackCount.Load()
	assert.Greater(t, totalServiced, int64(goroutines*iterations*9/10),
		"At least 90% of requests should be cleanly routed to primary or fallback")
	assert.Greater(t, fallbackCount.Load(), int64(1),
		"Circuit tripping must have rerouted requests to fallback")
}

