package enterprise

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// TIER 1: FEATURE COVERAGE (R3 Adaptive Load Balancing & Circuit Breakers)
// ============================================================================

func TestLoadBalancer_Tier1_MultiFactorScoring_LatencyEWMA(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
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

	selectedKey, _, _, _, err := lb.SelectRoute(context.Background(), "openai", "gpt-4o")
	if err != nil {
		t.Fatalf("route selection failed: %v", err)
	}

	if selectedKey != "key-fast" {
		t.Fatalf("expected key-fast with higher weight to be selected, got: %s", selectedKey)
	}

	slowRoute := lb.Routes["key-slow"]
	if slowRoute.Weight >= lb.Routes["key-fast"].Weight {
		t.Fatalf("expected key-slow weight to be strictly lower than key-fast weight")
	}
}

func TestLoadBalancer_Tier1_RouteHealthStateMachine_Transitions(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-1", "anthropic", "claude-sonnet-4-5")

	route := lb.Routes["key-1"]
	if route.State != mock.RouteHealthy {
		t.Fatalf("initial route state should be Healthy, got: %s", route.State)
	}

	// Induce high latency (350ms) -> should transition to Degraded
	for i := 0; i < 15; i++ {
		lb.RecordAttempt("key-1", 350.0, false, 0)
	}
	if route.State != mock.RouteDegraded {
		t.Fatalf("expected route state Degraded, got: %s (ewma=%f)", route.State, route.EWMALatencyMs)
	}

	// Induce high error rate (>50%) -> should transition to Failed
	for i := 0; i < 20; i++ {
		lb.RecordAttempt("key-1", 350.0, true, 500)
	}
	if route.State != mock.RouteFailed {
		t.Fatalf("expected route state Failed, got: %s", route.State)
	}
}

func TestLoadBalancer_Tier1_HeldKeys_ProviderRefusalBackoff(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-revoked", "openai", "gpt-4o")

	// Simulate HTTP 401 Invalid API Key refusal from provider
	lb.RecordAttempt("key-revoked", 50.0, true, 401)

	route := lb.Routes["key-revoked"]
	if route.State != mock.RouteFailed {
		t.Fatalf("expected held key state Failed, got: %s", route.State)
	}
	if route.Weight != 0.0 {
		t.Fatalf("expected held key weight to be 0.0, got: %v", route.Weight)
	}
	if route.HeldUntil.IsZero() {
		t.Fatalf("expected held key to have HeldUntil timestamp set")
	}

	// Route selection must skip this held key
	_, _, _, _, err := lb.SelectRoute(context.Background(), "openai", "gpt-4o")
	if err == nil {
		t.Fatalf("expected error when only route is held, but got selection")
	}
}

func TestLoadBalancer_Tier1_CircuitBreaker_HeaderSignalEvaluation(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-primary", "azure-openai", "gpt-4o")
	lb.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "Azure Spillover Breaker",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-Ms-Is-Spilled-Over": "true",
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Inspect normal response
	lb.InspectResponse("azure-openai", "gpt-4o", map[string]string{
		"Content-Type": "application/json",
	})
	policy := lb.CircuitPolicies["azure-openai/gpt-4o"]
	if policy.State != mock.CircuitClosed {
		t.Fatalf("circuit should remain closed for normal response")
	}

	// Inspect spillover response
	lb.InspectResponse("azure-openai", "gpt-4o", map[string]string{
		"X-Ms-Is-Spilled-Over": "true",
	})
	if policy.State != mock.CircuitOpen {
		t.Fatalf("circuit should open upon receiving X-Ms-Is-Spilled-Over header")
	}
}

func TestLoadBalancer_Tier1_CircuitBreaker_DynamicFailover(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-az", "azure-openai", "gpt-4o")
	lb.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "Spillover Failover",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-Ms-Is-Spilled-Over": "true",
		},
		DefaultCooldown: 10 * time.Second,
	})

	// Trip circuit
	lb.InspectResponse("azure-openai", "gpt-4o", map[string]string{
		"X-Ms-Is-Spilled-Over": "true",
	})

	// Select route -> should dynamically failover to fallback
	_, fbProv, fbModel, tripped, err := lb.SelectRoute(context.Background(), "azure-openai", "gpt-4o")
	if err != nil {
		t.Fatalf("unexpected error during failover: %v", err)
	}
	if !tripped {
		t.Fatalf("expected circuitTripped=true")
	}
	if fbProv != "anthropic" || fbModel != "claude-sonnet-4-5" {
		t.Fatalf("expected fallback to anthropic/claude-sonnet-4-5, got %s/%s", fbProv, fbModel)
	}
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (R3 Adaptive Load Balancing & Circuit Breakers)
// ============================================================================

func TestLoadBalancer_Tier2_SimultaneousFailure_AllPrimaryRoutes(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-1", "openai", "gpt-4o")
	lb.RegisterRoute("key-2", "openai", "gpt-4o")
	lb.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "Global OpenAI Fallback",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
	})

	// Fail both keys via provider refusal
	lb.RecordAttempt("key-1", 50.0, true, 429)
	lb.RecordAttempt("key-2", 50.0, true, 429)

	// Route selection should automatically failover to anthropic
	_, fbProv, fbModel, tripped, err := lb.SelectRoute(context.Background(), "openai", "gpt-4o")
	if err != nil {
		t.Fatalf("failover route should succeed when fallback is defined: %v", err)
	}
	if !tripped || fbProv != "anthropic" || fbModel != "claude-sonnet-4-5" {
		t.Fatalf("expected failover to anthropic/claude-sonnet-4-5, got %s/%s (tripped=%v)", fbProv, fbModel, tripped)
	}
}

func TestLoadBalancer_Tier2_ZeroTraffic_MinimumProbeWeight(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-zero-traffic", "openai", "gpt-4o")

	// Induce high latency and error penalty
	lb.RecordAttempt("key-zero-traffic", 2000.0, true, 500)

	route := lb.Routes["key-zero-traffic"]
	if route.Weight < 0.1 {
		t.Fatalf("minimum probe weight must be preserved (>=0.1), got %f", route.Weight)
	}
}

func TestLoadBalancer_Tier2_RapidFlapping_ErrorRateTransitions(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-flapping", "openai", "gpt-4o")

	// Rapid sequence of alternating successes and failures
	for i := 0; i < 50; i++ {
		isErr := (i%2 == 0)
		lb.RecordAttempt("key-flapping", 50.0, isErr, 0)
	}

	route := lb.Routes["key-flapping"]
	if route.Weight <= 0 {
		t.Fatalf("flapping route should retain non-zero weight, got %f", route.Weight)
	}
}

func TestLoadBalancer_Tier2_HeldKey_BackoffCap(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-capped", "openai", "gpt-4o")

	// Repeatedly refuse key to climb the backoff ladder
	for i := 0; i < 10; i++ {
		lb.RecordAttempt("key-capped", 10.0, true, 401)
	}

	route := lb.Routes["key-capped"]
	if route.BackoffLadder > 15*time.Minute {
		t.Fatalf("backoff ladder should cap at 15 minutes, got: %v", route.BackoffLadder)
	}
}

func TestLoadBalancer_Tier2_CircuitBreaker_CustomRetryAfterCooldown(t *testing.T) {
	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "RetryAfter Breaker",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-RateLimit-Exceeded": "true",
		},
		DefaultCooldown: 30 * time.Second,
	})

	// Header specifies Retry-After: 60s
	lb.InspectResponse("openai", "gpt-4o", map[string]string{
		"X-RateLimit-Exceeded": "true",
		"Retry-After":          "60",
	})

	policy := lb.CircuitPolicies["openai/gpt-4o"]
	remaining := time.Until(policy.OpenUntil)
	if remaining < 55*time.Second {
		t.Fatalf("expected cooldown duration to reflect 60s Retry-After header, remaining: %v", remaining)
	}
}
