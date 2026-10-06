package enterprise

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ADVERSARIAL CHALLENGE: ENTERPRISE LOAD BALANCER & CIRCUIT BREAKER CONCURRENCY
// ============================================================================

// TestAdversarial_Enterprise_ConcurrentLoadBalancer_Failover verifies that under
// heavy concurrent traffic (500 goroutines), circuit tripping and cooldown transitions
// cleanly redirect all traffic to fallback targets without data races or dropped calls.
func TestAdversarial_Enterprise_ConcurrentLoadBalancer_Failover(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("primary-k1", "openai", "gpt-4o")
	lb.RegisterRoute("primary-k2", "openai", "gpt-4o")

	lb.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "OpenAI-To-Anthropic-Failover",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-RateLimit-Exceeded": "true",
		},
		DefaultCooldown: 50 * time.Millisecond,
	})

	const numGoroutines = 500
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var primaryCount atomic.Int64
	var fallbackCount atomic.Int64

	ctx := context.Background()

	// Launch concurrent traffic
	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				// Periodically trigger circuit trip
				if gid == 0 && it%10 == 0 {
					lb.InspectResponse("openai", "gpt-4o", map[string]string{
						"X-RateLimit-Exceeded": "true",
					})
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
					assert.Contains(t, []string{"primary-k1", "primary-k2"}, key)
					primaryCount.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()

	totalServiced := primaryCount.Load() + fallbackCount.Load()
	assert.Greater(t, totalServiced, int64(numGoroutines*iterations*9/10),
		"At least 90% of requests should be cleanly routed to primary or fallback")
	assert.Greater(t, fallbackCount.Load(), int64(1),
		"Circuit tripping must have rerouted requests to fallback")
}

// TestAdversarial_Enterprise_HeldKeys_RapidFlappingContention stress-tests
// multiple keys flapping between 429 rate limits, high latency, and recovery under 500 goroutines.
func TestAdversarial_Enterprise_HeldKeys_RapidFlappingContention(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	for i := 0; i < 5; i++ {
		lb.RegisterRoute(fmt.Sprintf("flap-k%d", i), "openai", "gpt-4o")
	}

	const goroutines = 500
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			kID := fmt.Sprintf("flap-k%d", gid%5)

			for it := 0; it < 30; it++ {
				if it%3 == 0 {
					// Refusal
					lb.RecordAttempt(kID, 30.0, true, 429)
				} else if it%2 == 0 {
					// High latency
					lb.RecordAttempt(kID, 500.0, false, 0)
				} else {
					// Fast success
					lb.RecordAttempt(kID, 15.0, false, 0)
				}

				_, _, _, _, _ = lb.SelectRoute(context.Background(), "openai", "gpt-4o")
			}
		}(g)
	}

	wg.Wait()

	// Invariant verification
	for i := 0; i < 5; i++ {
		kID := fmt.Sprintf("flap-k%d", i)
		route := lb.Routes[kID]
		require.NotNil(t, route)
		assert.False(t, route.Weight < 0, "Weight must never be negative")
		assert.LessOrEqual(t, route.Weight, 10.0, "Weight must not exceed max weight")
	}
}

// TestAdversarial_Enterprise_ConcurrentLoadBalancer_1000_Goroutines_Contention stress-tests
// 1000 concurrent goroutines executing SelectRoute(), RecordAttempt(), and InspectResponse()
// simultaneously with dynamic circuit tripping, half-open transitions, and flap recoveries.
func TestAdversarial_Enterprise_ConcurrentLoadBalancer_1000_Goroutines_Contention(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	for i := 0; i < 4; i++ {
		lb.RegisterRoute(fmt.Sprintf("prim-%d", i), "openai", "gpt-4o")
	}

	lb.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "OpenAI-Failover-1000G",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-RateLimit-Exceeded": "true",
		},
		DefaultCooldown: 10 * time.Millisecond,
	})

	const numGoroutines = 1000
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var primaryCount atomic.Int64
	var fallbackCount atomic.Int64
	var recordCount atomic.Int64
	var tripCount atomic.Int64

	ctx := context.Background()

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				op := (gid + it) % 4
				switch op {
				case 0, 3:
					// SelectRoute under contention
					key, fbProv, fbModel, tripped, err := lb.SelectRoute(ctx, "openai", "gpt-4o")
					if err == nil {
						if tripped {
							assert.Equal(t, "anthropic", fbProv)
							assert.Equal(t, "claude-sonnet-4-5", fbModel)
							fallbackCount.Add(1)
						} else {
							assert.NotEmpty(t, key)
							primaryCount.Add(1)
						}
					}
				case 1:
					// RecordAttempt: fluctuate between successes, high latency, and 429 refusals
					kID := fmt.Sprintf("prim-%d", (gid+it)%4)
					if it%5 == 0 {
						lb.RecordAttempt(kID, 20.0, true, 429)
					} else if it%3 == 0 {
						lb.RecordAttempt(kID, 400.0, true, 500)
					} else {
						lb.RecordAttempt(kID, 15.0, false, 0)
					}
					recordCount.Add(1)
				case 2:
					// InspectResponse: periodically trip circuit
					if gid%5 == 0 {
						lb.InspectResponse("openai", "gpt-4o", map[string]string{
							"X-RateLimit-Exceeded": "true",
						})
						tripCount.Add(1)
					}
				}
			}
		}(g)
	}

	wg.Wait()

	totalRouted := primaryCount.Load() + fallbackCount.Load()
	assert.Greater(t, totalRouted, int64(10000), "Significant volume of route selections must succeed")
	assert.Greater(t, recordCount.Load(), int64(5000), "Metric records must succeed under contention")
	assert.Greater(t, tripCount.Load(), int64(100), "Circuit trips must be injected")

	// Post-condition state integrity
	for i := 0; i < 4; i++ {
		kID := fmt.Sprintf("prim-%d", i)
		route := lb.Routes[kID]
		require.NotNil(t, route)
		assert.False(t, route.Weight < 0, "Weight must never be negative")
		assert.LessOrEqual(t, route.Weight, 10.0, "Weight must not exceed max weight")
		assert.False(t, route.EWMALatencyMs < 0, "EWMA latency must not be negative")
	}
}

// TestAdversarial_Enterprise_CircuitBreaker_HalfOpen_Stampede_1000_Goroutines
// specifically targets the data race location on line 229:
// 1000 goroutines simultaneously hit SelectRoute() precisely as the circuit cooldown expires,
// causing a stampede to transition policy.State from CircuitOpen to CircuitHalfOpen.
func TestAdversarial_Enterprise_CircuitBreaker_HalfOpen_Stampede_1000_Goroutines(t *testing.T) {
	for rep := 0; rep < 5; rep++ {
		lb := mock.NewMockAdaptiveLoadBalancer()
		lb.RegisterRoute("stampede-k1", "openai", "gpt-4o")
		lb.RegisterRoute("stampede-k2", "openai", "gpt-4o")

		lb.RegisterCircuitPolicy(mock.CircuitPolicy{
			Name:             "Stampede-Policy",
			PrimaryProvider:  "openai",
			PrimaryModel:     "gpt-4o",
			FallbackProvider: "anthropic",
			FallbackModel:    "claude-sonnet-4-5",
			TriggerHeaders: map[string]string{
				"X-Trip": "true",
			},
			DefaultCooldown: 5 * time.Millisecond,
		})

		// Trip circuit to CircuitOpen
		lb.InspectResponse("openai", "gpt-4o", map[string]string{"X-Trip": "true"})
		require.Equal(t, mock.CircuitOpen, lb.CircuitPolicies["openai/gpt-4o"].State)

		// Wait until cooldown expires so all subsequent callers hit the transition branch
		time.Sleep(10 * time.Millisecond)

		const stampedeGoroutines = 1000
		startGate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(stampedeGoroutines)

		var halfOpenObserved atomic.Int64
		var primaryChosen atomic.Int64
		ctx := context.Background()

		for g := 0; g < stampedeGoroutines; g++ {
			go func() {
				defer wg.Done()
				<-startGate // Synchronized release to trigger maximum lock contention

				key, fbProv, fbModel, tripped, err := lb.SelectRoute(ctx, "openai", "gpt-4o")
				if err == nil {
					if !tripped {
						primaryChosen.Add(1)
						assert.Contains(t, []string{"stampede-k1", "stampede-k2"}, key)
					} else {
						assert.Equal(t, "anthropic", fbProv)
						assert.Equal(t, "claude-sonnet-4-5", fbModel)
					}
				}
			}()
		}

		// Release all 1000 goroutines at the exact same instant
		close(startGate)
		wg.Wait()

		// Verify circuit policy transitioned to CircuitHalfOpen
		policy := lb.CircuitPolicies["openai/gpt-4o"]
		require.NotNil(t, policy)
		assert.Equal(t, mock.CircuitHalfOpen, policy.State,
			"Circuit must be in CircuitHalfOpen after cooldown expiration under 1000-goroutine stampede")
		assert.Equal(t, int64(stampedeGoroutines), primaryChosen.Load(),
			"All 1000 goroutines must successfully select healthy primary keys during half-open state")
		_ = halfOpenObserved
	}
}
