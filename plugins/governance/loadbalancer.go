package governance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// RouteState represents the health status of a route within the 4-tier state machine.
type RouteState string

const (
	RouteHealthy    RouteState = "healthy"
	RouteDegraded   RouteState = "degraded"
	RouteFailed     RouteState = "failed"
	RouteRecovering RouteState = "recovering"
)

// HeldKeyScope indicates whether a hold applies to all models on a key or a single model.
type HeldKeyScope string

const (
	HeldKeyScopeAllModels HeldKeyScope = "all_models"
	HeldKeyScopeModel     HeldKeyScope = "model"
)

// HeldKeyEntry represents an actively suppressed key subject to exponential backoff.
type HeldKeyEntry struct {
	KeyID          string
	Provider       string
	Model          string // empty if HeldKeyScopeAllModels
	Scope          HeldKeyScope
	FailureClass   schemas.FailureClass
	Reason         string
	Message        string
	HeldAt         time.Time
	HeldUntil      time.Time
	CurrentBackoff time.Duration
	Rung           int
	Probing        int32 // atomic CAS: 0 = idle, 1 = probe in flight
	LastRefusalAt  time.Time
}

// RouteMetric tracks performance statistics, latency EWMA, and state transitions for a key/route.
type RouteMetric struct {
	mu              sync.RWMutex
	KeyID           string
	Provider        string
	Model           string
	State           RouteState
	Weight          float64
	EWMALatencyMs   float64
	ErrorCount      int64
	SuccessCount    int64
	TotalRequests   int64
	ConsecutiveOk   int64
	ConsecutiveErr  int64
	InFlight        atomic.Int64
	LastEvaluated   time.Time
	LastStateChange time.Time
	LastUpdate      time.Time
	HeldUntil       time.Time
	BackoffLadder   time.Duration

	Held *HeldKeyEntry
}

// HeldKeyManager manages fleet holds, flapping memory, and canary probe admission.
type HeldKeyManager struct {
	mu           sync.RWMutex
	holds        map[string]*HeldKeyEntry // key: keyID or provider:keyID
	flappingHist map[string]*HeldKeyEntry // key: provider:keyID:reason (10m window)
}

// AdaptiveLoadBalancer is the high-performance load balancing and health state engine.
type AdaptiveLoadBalancer struct {
	mu                sync.RWMutex
	Alpha             float64       // EWMA sample alpha (default 0.2)
	HalfLife          time.Duration // continuous decay half-life (default 10s)
	ConcurrencyWeight float64       // in-flight penalty coefficient (default 0.2)
	MinProbeWeight    float64       // minimum probe floor (default 0.1)
	MaxWeight         float64       // maximum route weight (default 10.0)
	DegradedLatencyMs float64       // latency threshold for Degraded state (default 250ms)
	FailedLatencyMs   float64       // latency threshold for Failed state (default 1000ms)
	DegradedErrRate   float64       // error rate threshold for Degraded state (default 0.15)
	FailedErrRate     float64       // error rate threshold for Failed state (default 0.50)
	RecoverySuccesses int64         // consecutive successes to promote Recovering -> Healthy (default 5)
	RecomputeInterval time.Duration // asynchronous weight recompute period (default 5s)
	DisableJitter     bool          // disable jitter for deterministic test execution

	Routes          map[string]*RouteMetric
	HeldKeys        *HeldKeyManager
	CircuitBreakers *CircuitBreakerManager

	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewAdaptiveLoadBalancer constructs an AdaptiveLoadBalancer and starts the 5s async recomputation loop.
func NewAdaptiveLoadBalancer() *AdaptiveLoadBalancer {
	lb := &AdaptiveLoadBalancer{
		Alpha:             0.2,
		HalfLife:          10 * time.Second,
		ConcurrencyWeight: 0.2,
		MinProbeWeight:    0.1,
		MaxWeight:         10.0,
		DegradedLatencyMs: 250.0,
		FailedLatencyMs:   1000.0,
		DegradedErrRate:   0.15,
		FailedErrRate:     0.50,
		RecoverySuccesses: 5,
		RecomputeInterval: 5 * time.Second,
		Routes:            make(map[string]*RouteMetric),
		HeldKeys: &HeldKeyManager{
			holds:        make(map[string]*HeldKeyEntry),
			flappingHist: make(map[string]*HeldKeyEntry),
		},
		stopCh: make(chan struct{}),
	}
	go lb.recomputeLoop()
	return lb
}

// Close gracefully stops the background weight recomputation loop.
func (lb *AdaptiveLoadBalancer) Close() {
	lb.closeOnce.Do(func() {
		close(lb.stopCh)
	})
}

func (lb *AdaptiveLoadBalancer) recomputeLoop() {
	ticker := time.NewTicker(lb.RecomputeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lb.stopCh:
			return
		case <-ticker.C:
			lb.RecomputeWeights()
		}
	}
}

// RegisterRoute initializes metric tracking for a given key, provider, and model.
func (lb *AdaptiveLoadBalancer) RegisterRoute(keyID, provider, model string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	now := time.Now()
	lb.Routes[keyID] = &RouteMetric{
		KeyID:           keyID,
		Provider:        provider,
		Model:           model,
		State:           RouteHealthy,
		Weight:          lb.MaxWeight,
		EWMALatencyMs:   20.0,
		BackoffLadder:   30 * time.Second,
		LastEvaluated:   now,
		LastStateChange: now,
		LastUpdate:      now,
	}
}

// RecordAttempt updates route latency EWMA, error counters, and evaluates state transitions.
func (lb *AdaptiveLoadBalancer) RecordAttempt(keyID string, latencyMs float64, isError bool, refusalCode int) {
	lb.RecordAttemptWithDetails(keyID, "", "", latencyMs, isError, refusalCode, nil, nil)
}

// RecordAttemptWithDetails updates route metrics with full failure classification and provider headers.
func (lb *AdaptiveLoadBalancer) RecordAttemptWithDetails(keyID, provider, model string, latencyMs float64, isError bool, refusalCode int, bifrostErr *schemas.BifrostError, headers map[string]string) {
	lb.mu.Lock()
	route, exists := lb.Routes[keyID]
	if !exists {
		now := time.Now()
		route = &RouteMetric{
			KeyID:           keyID,
			Provider:        provider,
			Model:           model,
			State:           RouteHealthy,
			Weight:          lb.MaxWeight,
			EWMALatencyMs:   20.0,
			BackoffLadder:   30 * time.Second,
			LastEvaluated:   now,
			LastStateChange: now,
			LastUpdate:      now,
		}
		lb.Routes[keyID] = route
	}
	lb.mu.Unlock()

	route.mu.Lock()
	defer route.mu.Unlock()

	route.TotalRequests++
	now := time.Now()

	// Check if this attempt was a probe on a held key
	isProbeCheck := false
	if route.Held != nil && now.After(route.Held.HeldUntil) {
		isProbeCheck = true
	}

	// Classify refusal
	var failureClass schemas.FailureClass
	if bifrostErr != nil {
		failureClass = bifrost.ClassifyFailure(bifrostErr)
	} else {
		switch refusalCode {
		case 401:
			failureClass = schemas.FailureClassCredential
		case 402:
			failureClass = schemas.FailureClassQuota
		case 429:
			failureClass = schemas.FailureClassRateLimit
		}
	}

	isRefusal := failureClass == schemas.FailureClassCredential ||
		failureClass == schemas.FailureClassQuota ||
		failureClass == schemas.FailureClassRateLimit ||
		failureClass == schemas.FailureClassModelAccess ||
		failureClass == schemas.FailureClassModelGone ||
		failureClass == schemas.FailureClassRegionBlocked ||
		refusalCode == 401 || refusalCode == 402 || refusalCode == 429

	if isRefusal {
		route.ConsecutiveOk = 0
		route.ConsecutiveErr++
		route.ErrorCount++

		lb.applyHoldLocked(route, failureClass, bifrostErr, headers)
		return
	}

	if isError {
		route.ConsecutiveOk = 0
		route.ConsecutiveErr++
		route.ErrorCount++

		// Transient error on probe: keep held on same rung
		if isProbeCheck && route.Held != nil {
			atomic.StoreInt32(&route.Held.Probing, 0)
			route.Held.HeldUntil = now.Add(route.Held.CurrentBackoff)
			route.HeldUntil = route.Held.HeldUntil
		} else if route.State == RouteRecovering {
			// Any error during recovery demotes back to RouteFailed
			route.State = RouteFailed
			route.Weight = lb.MinProbeWeight
			route.LastStateChange = now
		}
	} else {
		route.ConsecutiveErr = 0
		route.ConsecutiveOk++
		route.SuccessCount++

		// Continuous half-life decay calculation
		tau := lb.HalfLife.Seconds() / math.Ln2
		dt := now.Sub(route.LastUpdate).Seconds()
		decayedLatency := route.EWMALatencyMs
		if dt > 0 && !route.LastUpdate.IsZero() {
			w := math.Exp(-dt / tau)
			decayedLatency = 20.0 + (route.EWMALatencyMs-20.0)*w
			if decayedLatency < 20.0 {
				decayedLatency = 20.0
			}
		}

		// Finagle Peak EWMA: jump to peak on latency spikes, smooth on fast returns
		smoothed := (lb.Alpha * latencyMs) + ((1.0 - lb.Alpha) * decayedLatency)
		if latencyMs > decayedLatency {
			route.EWMALatencyMs = math.Max(latencyMs, smoothed)
		} else {
			route.EWMALatencyMs = smoothed
		}
		route.LastUpdate = now

		// Successful probe clears hold and promotes to RouteRecovering
		if route.Held != nil {
			atomic.StoreInt32(&route.Held.Probing, 0)
			route.Held = nil
			route.HeldUntil = time.Time{}
			route.State = RouteRecovering
			route.LastStateChange = now
		}
	}

	lb.evaluateRouteStateLocked(route)
}

func (lb *AdaptiveLoadBalancer) applyHoldLocked(route *RouteMetric, fc schemas.FailureClass, err *schemas.BifrostError, headers map[string]string) {
	now := time.Now()
	route.State = RouteFailed
	route.Weight = 0.0

	// Check provider Retry-After header override
	var providerWait time.Duration
	if err != nil && err.ExtraFields.RetryAfter > 0 {
		providerWait = time.Duration(err.ExtraFields.RetryAfter) * time.Millisecond
	} else if headers != nil {
		if cd, ok := headers["Retry-After"]; ok {
			if sec, parseErr := strconv.ParseInt(strings.TrimSpace(cd), 10, 64); parseErr == nil && sec > 0 {
				providerWait = time.Duration(sec) * time.Second
			} else if dur, parseErr := time.ParseDuration(cd + "s"); parseErr == nil && dur > 0 {
				providerWait = dur
			}
		} else if cd, ok := headers["retry-after-ms"]; ok {
			if ms, parseErr := strconv.ParseInt(strings.TrimSpace(cd), 10, 64); parseErr == nil && ms > 0 {
				providerWait = time.Duration(ms) * time.Millisecond
			}
		}
	}
	if providerWait > 0 && providerWait < 10*time.Second {
		providerWait = 10 * time.Second // Enforce 10s floor
	}

	// Reason-specific caps
	capDuration := 15 * time.Minute
	switch fc {
	case schemas.FailureClassRateLimit:
		capDuration = 2 * time.Minute
	case schemas.FailureClassModelAccess:
		capDuration = 5 * time.Minute
	case schemas.FailureClassQuota:
		capDuration = 5 * time.Minute
	case schemas.FailureClassModelGone:
		capDuration = 30 * time.Minute
	case schemas.FailureClassRegionBlocked:
		capDuration = 15 * time.Minute
	case schemas.FailureClassCredential:
		capDuration = 15 * time.Minute
	}

	rung := 0
	currentBackoff := 30 * time.Second

	// Check flapping memory (10m window)
	flapKey := fmt.Sprintf("%s:%s:%s", route.Provider, route.KeyID, string(fc))
	lb.HeldKeys.mu.Lock()
	if prev, ok := lb.HeldKeys.flappingHist[flapKey]; ok && now.Sub(prev.LastRefusalAt) < 10*time.Minute {
		rung = prev.Rung + 1
		currentBackoff = prev.CurrentBackoff * 2
	} else if route.Held != nil {
		rung = route.Held.Rung + 1
		currentBackoff = route.Held.CurrentBackoff * 2
	}

	if currentBackoff > capDuration {
		currentBackoff = capDuration
	}

	wait := currentBackoff
	if providerWait > 0 {
		wait = providerWait
	} else if !lb.DisableJitter {
		// +/- 10% jitter
		jitterFactor := 0.9 + (0.2 * rand.Float64())
		wait = time.Duration(float64(wait) * jitterFactor)
	}

	scope := HeldKeyScopeModel
	if fc.CoversAllModels() {
		scope = HeldKeyScopeAllModels
	}

	entry := &HeldKeyEntry{
		KeyID:          route.KeyID,
		Provider:       route.Provider,
		Model:          route.Model,
		Scope:          scope,
		FailureClass:   fc,
		HeldAt:         now,
		HeldUntil:      now.Add(wait),
		CurrentBackoff: currentBackoff,
		Rung:           rung,
		LastRefusalAt:  now,
	}

	route.Held = entry
	route.HeldUntil = entry.HeldUntil
	route.BackoffLadder = currentBackoff
	lb.HeldKeys.holds[route.KeyID] = entry
	lb.HeldKeys.flappingHist[flapKey] = entry
	lb.HeldKeys.mu.Unlock()
}

func (lb *AdaptiveLoadBalancer) evaluateRouteStateLocked(route *RouteMetric) {
	now := time.Now()

	// 1. Actively held key is strictly Failed and weight 0.0
	if route.Held != nil && now.Before(route.Held.HeldUntil) {
		route.State = RouteFailed
		route.Weight = 0.0
		return
	}

	// 2. Multi-factor score calculation
	errorRate := 0.0
	if route.TotalRequests > 0 {
		errorRate = float64(route.ErrorCount) / float64(route.TotalRequests)
	}

	latencyPenalty := route.EWMALatencyMs / 100.0
	errorPenalty := errorRate * 10.0
	score := lb.MaxWeight - latencyPenalty - errorPenalty
	if score < lb.MinProbeWeight {
		score = lb.MinProbeWeight
	}

	// 3. State transitions
	switch route.State {
	case RouteHealthy:
		if errorRate > lb.FailedErrRate || route.EWMALatencyMs > lb.FailedLatencyMs {
			route.State = RouteFailed
			route.Weight = lb.MinProbeWeight
			route.LastStateChange = now
		} else if errorRate > lb.DegradedErrRate || route.EWMALatencyMs > lb.DegradedLatencyMs {
			route.State = RouteDegraded
			route.Weight = score
			route.LastStateChange = now
		} else {
			route.Weight = score
		}

	case RouteDegraded:
		if errorRate > lb.FailedErrRate || route.EWMALatencyMs > lb.FailedLatencyMs {
			route.State = RouteFailed
			route.Weight = lb.MinProbeWeight
			route.LastStateChange = now
		} else if errorRate <= lb.DegradedErrRate && route.EWMALatencyMs <= lb.DegradedLatencyMs {
			route.State = RouteHealthy
			route.Weight = score
			route.LastStateChange = now
		} else {
			route.Weight = score
		}

	case RouteRecovering:
		if route.ConsecutiveErr > 0 || route.EWMALatencyMs > lb.FailedLatencyMs {
			route.State = RouteFailed
			route.Weight = lb.MinProbeWeight
			route.ConsecutiveOk = 0
			route.LastStateChange = now
		} else if route.ConsecutiveOk >= lb.RecoverySuccesses && route.EWMALatencyMs <= lb.DegradedLatencyMs {
			route.State = RouteHealthy
			route.ErrorCount = 0
			route.TotalRequests = route.ConsecutiveOk
			route.Weight = score
			route.LastStateChange = now
		} else {
			// Probationary weight ramp
			rampFactor := float64(route.ConsecutiveOk) / float64(lb.RecoverySuccesses)
			if rampFactor > 1.0 {
				rampFactor = 1.0
			}
			route.Weight = lb.MinProbeWeight + (rampFactor * (score - lb.MinProbeWeight))
		}

	case RouteFailed:
		if route.Held == nil && route.ConsecutiveOk > 0 {
			route.State = RouteRecovering
			rampFactor := float64(route.ConsecutiveOk) / float64(lb.RecoverySuccesses)
			if rampFactor > 1.0 {
				rampFactor = 1.0
			}
			route.Weight = lb.MinProbeWeight + (rampFactor * (score - lb.MinProbeWeight))
			route.LastStateChange = now
		} else {
			route.Weight = lb.MinProbeWeight
		}
	}
}

// RecomputeWeights executes continuous decay smoothing and re-evaluates multi-factor scores.
func (lb *AdaptiveLoadBalancer) RecomputeWeights() {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	now := time.Now()
	tau := lb.HalfLife.Seconds() / math.Ln2

	for _, route := range lb.Routes {
		route.mu.Lock()
		dt := now.Sub(route.LastUpdate).Seconds()
		if dt > 0 && !route.LastUpdate.IsZero() {
			w := math.Exp(-dt / tau)
			decayed := 20.0 + (route.EWMALatencyMs-20.0)*w
			if decayed < 20.0 {
				decayed = 20.0
			}
			route.EWMALatencyMs = decayed
			route.LastUpdate = now
		}
		lb.evaluateRouteStateLocked(route)
		route.mu.Unlock()
	}
}

// SelectKey picks an eligible key via weighted random selection including in-flight penalties.
func (lb *AdaptiveLoadBalancer) SelectKey(ctx *schemas.BifrostContext, keys []schemas.Key, provider schemas.ModelProvider, model string) (schemas.Key, error) {
	if len(keys) == 0 {
		return schemas.Key{}, errors.New("no available keys")
	}

	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(keys) == 1 {
		k := keys[0]
		if route, ok := lb.Routes[k.ID]; ok {
			route.InFlight.Add(1)
		}
		return k, nil
	}

	weights := make([]float64, len(keys))
	var totalWeight float64

	for i, k := range keys {
		route, ok := lb.Routes[k.ID]
		w := 10.0
		if ok {
			route.mu.RLock()
			baseW := route.Weight
			route.mu.RUnlock()

			inFlight := route.InFlight.Load()
			if inFlight < 0 {
				inFlight = 0
			}
			penalty := float64(inFlight) * lb.ConcurrencyWeight
			w = baseW - penalty
			if w < lb.MinProbeWeight {
				w = lb.MinProbeWeight
			}
		}
		weights[i] = w
		totalWeight += w
	}

	if totalWeight <= 0 {
		chosen := keys[rand.IntN(len(keys))]
		if route, ok := lb.Routes[chosen.ID]; ok {
			route.InFlight.Add(1)
		}
		return chosen, nil
	}

	target := rand.Float64() * totalWeight
	var cum float64
	for i, k := range keys {
		cum += weights[i]
		if target <= cum || i == len(keys)-1 {
			if route, ok := lb.Routes[k.ID]; ok {
				route.InFlight.Add(1)
			}
			return k, nil
		}
	}

	chosen := keys[len(keys)-1]
	if route, ok := lb.Routes[chosen.ID]; ok {
		route.InFlight.Add(1)
	}
	return chosen, nil
}

// KeyPoolFilter excludes held keys, admits due canary probes via atomic CAS, and filters sub-circuits.
func (lb *AdaptiveLoadBalancer) KeyPoolFilter(ctx *schemas.BifrostContext, provider schemas.ModelProvider, model string, keys []schemas.Key) ([]schemas.Key, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	now := time.Now()
	eligible := make([]schemas.Key, 0, len(keys))

	for _, k := range keys {
		route, exists := lb.Routes[k.ID]
		if !exists {
			eligible = append(eligible, k)
			continue
		}

		route.mu.RLock()
		held := route.Held
		heldUntil := route.HeldUntil
		state := route.State
		weight := route.Weight
		route.mu.RUnlock()

		if held != nil {
			if now.Before(heldUntil) {
				// Actively held: veto
				continue
			}
			// Wait expired: key is due for canary probe
			if atomic.CompareAndSwapInt32(&held.Probing, 0, 1) {
				// Won probe slot: admit for probationary check
				eligible = append(eligible, k)
				continue
			}
			// Another request is probing: veto
			continue
		}

		if state == RouteFailed && weight <= 0.0 {
			continue
		}

		eligible = append(eligible, k)
	}

	if lb.CircuitBreakers != nil {
		var err error
		eligible, err = lb.CircuitBreakers.KeyPoolFilter(ctx, provider, model, eligible)
		if err != nil {
			return eligible, err
		}
	}

	return eligible, nil
}

// ReleaseInFlight decrements the in-flight concurrency counter for a route.
func (lb *AdaptiveLoadBalancer) ReleaseInFlight(keyID string) {
	lb.mu.RLock()
	route, ok := lb.Routes[keyID]
	lb.mu.RUnlock()
	if ok {
		val := route.InFlight.Add(-1)
		if val < 0 {
			route.InFlight.Store(0)
		}
	}
}

// SelectRoute chooses an active healthy route or handles failover (mock and standalone compatibility).
func (lb *AdaptiveLoadBalancer) SelectRoute(ctx context.Context, provider, model string) (selectedKeyID string, fallbackProvider string, fallbackModel string, circuitTripped bool, err error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if lb.CircuitBreakers != nil {
		tripped, fbProv, fbModel := lb.CircuitBreakers.CheckRerouteForRoute(provider, model)
		if tripped {
			return "", fbProv, fbModel, true, nil
		}
	}

	var bestKey string
	var maxWeight float64 = -1.0
	now := time.Now()

	for _, route := range lb.Routes {
		route.mu.RLock()
		rProvider := route.Provider
		rModel := route.Model
		rKeyID := route.KeyID
		rHeld := route.Held
		rHeldUntil := route.HeldUntil
		rWeight := route.Weight
		rInFlight := route.InFlight.Load()
		route.mu.RUnlock()

		if rProvider == provider && rModel == model {
			if rHeld != nil && now.Before(rHeldUntil) {
				continue // Skip held keys
			}
			effectiveWeight := rWeight - (float64(rInFlight) * lb.ConcurrencyWeight)
			if effectiveWeight < lb.MinProbeWeight {
				effectiveWeight = lb.MinProbeWeight
			}
			if effectiveWeight > maxWeight {
				maxWeight = effectiveWeight
				bestKey = rKeyID
			}
		}
	}

	if bestKey == "" {
		if lb.CircuitBreakers != nil {
			if policy, ok := lb.CircuitBreakers.GetPolicy(provider, model); ok {
				return "", policy.FallbackProvider, policy.FallbackModel, true, nil
			}
		}
		return "", "", "", false, fmt.Errorf("no healthy route available for %s/%s", provider, model)
	}

	return bestKey, "", "", false, nil
}
