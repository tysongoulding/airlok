package mock

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type RouteState string

const (
	RouteHealthy    RouteState = "healthy"
	RouteDegraded   RouteState = "degraded"
	RouteFailed     RouteState = "failed"
	RouteRecovering RouteState = "recovering"
)

type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

type RouteMetric struct {
	KeyID         string
	Provider      string
	Model         string
	State         RouteState
	Weight        float64
	EWMALatencyMs float64
	ErrorCount    int
	SuccessCount  int
	TotalRequests int
	ConsecutiveOk int
	Probing       int32
	HeldUntil     time.Time
	BackoffLadder time.Duration
	LastEvaluated time.Time
}

type CircuitPolicy struct {
	Name             string
	PrimaryProvider  string
	PrimaryModel     string
	FallbackProvider string
	FallbackModel    string
	TriggerHeaders   map[string]string // e.g. "X-Ms-Is-Spilled-Over": "true"
	DefaultCooldown  time.Duration
	State            CircuitState
	OpenUntil        time.Time
}

// MockAdaptiveLoadBalancer simulates multi-factor dynamic scoring, circuit breaking, and failover.
type MockAdaptiveLoadBalancer struct {
	mu              sync.RWMutex
	Alpha           float64
	Routes          map[string]*RouteMetric
	CircuitPolicies map[string]*CircuitPolicy
}

func NewMockAdaptiveLoadBalancer() *MockAdaptiveLoadBalancer {
	return &MockAdaptiveLoadBalancer{
		Alpha:           0.2, // standard EWMA alpha
		Routes:          make(map[string]*RouteMetric),
		CircuitPolicies: make(map[string]*CircuitPolicy),
	}
}

func (lb *MockAdaptiveLoadBalancer) RegisterRoute(keyID, provider, model string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.Routes[keyID] = &RouteMetric{
		KeyID:         keyID,
		Provider:      provider,
		Model:         model,
		State:         RouteHealthy,
		Weight:        10.0,
		EWMALatencyMs: 20.0,
		BackoffLadder: 30 * time.Second,
		LastEvaluated: time.Now(),
	}
}

func (lb *MockAdaptiveLoadBalancer) RegisterCircuitPolicy(policy CircuitPolicy) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if policy.DefaultCooldown == 0 {
		policy.DefaultCooldown = 30 * time.Second
	}
	policy.State = CircuitClosed
	key := fmt.Sprintf("%s/%s", policy.PrimaryProvider, policy.PrimaryModel)
	lb.CircuitPolicies[key] = &policy
}

// RecordAttempt updates EWMA latency and route state based on request outcome.
func (lb *MockAdaptiveLoadBalancer) RecordAttempt(keyID string, latencyMs float64, isError bool, refusalCode int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	route, exists := lb.Routes[keyID]
	if !exists {
		return
	}

	route.TotalRequests++

	// Provider refusal -> Held keys mechanism
	if refusalCode == 401 || refusalCode == 402 || refusalCode == 429 {
		route.State = RouteFailed
		route.ConsecutiveOk = 0
		route.HeldUntil = time.Now().Add(route.BackoffLadder)
		route.BackoffLadder *= 2
		if route.BackoffLadder > 15*time.Minute {
			route.BackoffLadder = 15 * time.Minute
		}
		route.Weight = 0.0
		return
	}

	if isError {
		route.ConsecutiveOk = 0
		route.ErrorCount++
		if route.State == RouteRecovering {
			route.State = RouteFailed
			route.Weight = 0.1
		}
	} else {
		route.ConsecutiveOk++
		route.SuccessCount++
		if !route.HeldUntil.IsZero() && time.Now().After(route.HeldUntil) {
			route.HeldUntil = time.Time{}
			route.State = RouteRecovering
		}
		// EWMA formula: Latency = alpha * new + (1 - alpha) * old
		route.EWMALatencyMs = (lb.Alpha * latencyMs) + ((1.0 - lb.Alpha) * route.EWMALatencyMs)
	}

	lb.evaluateRouteStateLocked(route)
}

func (lb *MockAdaptiveLoadBalancer) evaluateRouteStateLocked(route *RouteMetric) {
	now := time.Now()
	if !route.HeldUntil.IsZero() && now.Before(route.HeldUntil) {
		route.State = RouteFailed
		route.Weight = 0.0
		return
	}

	// Calculate multi-factor score
	errorRate := 0.0
	if route.TotalRequests > 0 {
		errorRate = float64(route.ErrorCount) / float64(route.TotalRequests)
	}

	// Dynamic weight calculation (0.0 to 10.0)
	latencyPenalty := route.EWMALatencyMs / 100.0 // higher latency -> higher penalty
	errorPenalty := errorRate * 10.0

	score := 10.0 - latencyPenalty - errorPenalty
	if score < 0.1 {
		score = 0.1 // Minimum probe weight
	}
	route.Weight = score

	if route.State == RouteRecovering {
		if errorRate > 0.15 || route.EWMALatencyMs > 250 {
			route.State = RouteFailed
			route.Weight = 0.1
		} else if route.ConsecutiveOk >= 5 && route.EWMALatencyMs <= 250 {
			route.State = RouteHealthy
			route.Weight = score
		} else {
			ramp := float64(route.ConsecutiveOk) / 5.0
			if ramp > 1.0 {
				ramp = 1.0
			}
			route.Weight = 0.1 + ramp*(score-0.1)
		}
		return
	}

	if errorRate > 0.5 || route.EWMALatencyMs > 1000 {
		route.State = RouteFailed
	} else if errorRate > 0.15 || route.EWMALatencyMs > 250 {
		route.State = RouteDegraded
	} else {
		route.State = RouteHealthy
	}
}

// InspectResponse inspects response headers to trip circuit breakers.
func (lb *MockAdaptiveLoadBalancer) InspectResponse(provider, model string, headers map[string]string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	key := fmt.Sprintf("%s/%s", provider, model)
	policy, exists := lb.CircuitPolicies[key]
	if !exists {
		return
	}

	for hKey, hVal := range policy.TriggerHeaders {
		if actual, ok := headers[hKey]; ok && actual == hVal {
			policy.State = CircuitOpen
			cooldown := policy.DefaultCooldown
			if cdHeader, hasCd := headers["Retry-After"]; hasCd {
				if sec, err := time.ParseDuration(cdHeader + "s"); err == nil {
					cooldown = sec
				}
			}
			policy.OpenUntil = time.Now().Add(cooldown)
			break
		}
	}
}

// SelectRoute chooses an active healthy route or handles failover.
func (lb *MockAdaptiveLoadBalancer) SelectRoute(ctx context.Context, provider, model string) (selectedKeyID string, fallbackProvider string, fallbackModel string, circuitTripped bool, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	key := fmt.Sprintf("%s/%s", provider, model)
	if policy, exists := lb.CircuitPolicies[key]; exists {
		if policy.State == CircuitOpen {
			if time.Now().After(policy.OpenUntil) {
				policy.State = CircuitHalfOpen
			} else {
				// Circuit is open -> Dynamic failover
				return "", policy.FallbackProvider, policy.FallbackModel, true, nil
			}
		}
	}

	var bestKey string
	var maxWeight float64 = -1.0
	now := time.Now()

	for _, route := range lb.Routes {
		if route.Provider == provider && route.Model == model {
			if !route.HeldUntil.IsZero() && now.Before(route.HeldUntil) {
				continue // Skip held keys
			}
			if route.Weight > maxWeight {
				maxWeight = route.Weight
				bestKey = route.KeyID
			}
		}
	}

	if bestKey == "" {
		// No available routes for primary -> Check fallback
		if policy, exists := lb.CircuitPolicies[key]; exists {
			return "", policy.FallbackProvider, policy.FallbackModel, true, nil
		}
		return "", "", "", false, fmt.Errorf("no healthy route available for %s/%s", provider, model)
	}

	return bestKey, "", "", false, nil
}
