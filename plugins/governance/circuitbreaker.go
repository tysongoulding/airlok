package governance

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// CircuitState represents the operational state of a circuit breaker.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// SignalSource specifies where a circuit breaker signal is extracted from.
type SignalSource string

const (
	SignalSourceResponseHeader SignalSource = "response_header"
	SignalSourceStatusCode     SignalSource = "status_code"
)

// ConditionOperator defines the logical operator combining multiple signals.
type ConditionOperator string

const (
	OperatorOR  ConditionOperator = "OR"
	OperatorAND ConditionOperator = "AND"
)

// Signal specifies matching criteria against response headers or status codes.
type Signal struct {
	Source         SignalSource `json:"source"`
	HeaderName     string       `json:"header_name,omitempty"`
	HeaderValue    string       `json:"header_value,omitempty"`
	HeaderContains string       `json:"header_contains,omitempty"`
	StatusCodes    []int        `json:"status_codes,omitempty"`
}

// Matches tests whether an HTTP response matches this signal.
func (s *Signal) Matches(headers map[string]string, statusCode int) bool {
	if s.Source == SignalSourceStatusCode || len(s.StatusCodes) > 0 {
		for _, code := range s.StatusCodes {
			if code == statusCode {
				return true
			}
		}
		if s.Source == SignalSourceStatusCode {
			return false
		}
	}

	if s.Source == SignalSourceResponseHeader || s.HeaderName != "" {
		val := ""
		exists := false
		for k, v := range headers {
			if strings.EqualFold(k, s.HeaderName) {
				val = v
				exists = true
				break
			}
		}
		if !exists {
			return false
		}

		// Exists Mode: only header_name specified
		if s.HeaderValue == "" && s.HeaderContains == "" {
			return true
		}

		// Equals Mode: exact case-insensitive match
		if s.HeaderValue != "" {
			return strings.EqualFold(val, s.HeaderValue)
		}

		// Contains Mode: substring case-insensitive match
		if s.HeaderContains != "" {
			return strings.Contains(strings.ToLower(val), strings.ToLower(s.HeaderContains))
		}
	}

	return false
}

// Condition evaluates a group of signals combined by an OR or AND operator.
type Condition struct {
	Operator ConditionOperator `json:"operator"` // "OR" (default) or "AND"
	Signals  []Signal          `json:"signals"`
}

// Evaluate checks if the condition matches given headers and status code.
func (c *Condition) Evaluate(headers map[string]string, statusCode int) bool {
	if len(c.Signals) == 0 {
		return false
	}

	op := c.Operator
	if op == "" {
		op = OperatorOR
	}

	if op == OperatorAND {
		for _, sig := range c.Signals {
			if !sig.Matches(headers, statusCode) {
				return false
			}
		}
		return true
	}

	// Default: OperatorOR
	for _, sig := range c.Signals {
		if sig.Matches(headers, statusCode) {
			return true
		}
	}
	return false
}

// CircuitBreakerPolicy configures breaker conditions, cooldowns, and failover targets.
type CircuitBreakerPolicy struct {
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	PrimaryProvider  string            `json:"primary_provider"`
	PrimaryModel     string            `json:"primary_model"`
	PrimaryKeyIDs    []string          `json:"primary_key_ids,omitempty"`
	FallbackProvider string            `json:"fallback_provider"`
	FallbackModel    string            `json:"fallback_model"`
	Condition        Condition         `json:"condition"`
	TriggerHeaders   map[string]string `json:"trigger_headers,omitempty"` // For test/mock compatibility
	DefaultCooldown  time.Duration     `json:"default_cooldown"`          // default 30s
	CooldownHeader   string            `json:"cooldown_header,omitempty"`
}

// KeySubCircuitState tracks the circuit breaker state for a specific key.
type KeySubCircuitState struct {
	mu        sync.RWMutex
	KeyID     string
	State     CircuitState
	OpenedAt  time.Time
	Cooldown  time.Duration
	OpenUntil time.Time
}

// PolicyRuntimeState tracks real-time breaker trips, sub-circuits, and canary probe status.
type PolicyRuntimeState struct {
	mu          sync.RWMutex
	Policy      CircuitBreakerPolicy
	State       CircuitState
	OpenedAt    time.Time
	Cooldown    time.Duration
	OpenUntil   time.Time
	Probing     int32                          // atomic CAS guard: 0 = idle, 1 = probe in flight
	SubCircuits map[string]*KeySubCircuitState // keyed by keyID
}

func (prs *PolicyRuntimeState) resolveCooldown(headers map[string]string) time.Duration {
	cooldown := prs.Policy.DefaultCooldown
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}

	headerKey := prs.Policy.CooldownHeader
	if headerKey == "" {
		for k := range headers {
			if strings.EqualFold(k, "retry-after-ms") {
				headerKey = "retry-after-ms"
				break
			} else if strings.EqualFold(k, "Retry-After") {
				headerKey = "Retry-After"
				break
			}
		}
	}

	if headerKey != "" {
		for k, v := range headers {
			if strings.EqualFold(k, headerKey) {
				val := strings.TrimSpace(v)
				if val != "" {
					if strings.EqualFold(headerKey, "retry-after-ms") {
						if ms, err := strconv.ParseInt(val, 10, 64); err == nil && ms > 0 {
							return time.Duration(ms) * time.Millisecond
						}
					}
					if sec, err := strconv.ParseInt(val, 10, 64); err == nil && sec > 0 {
						return time.Duration(sec) * time.Second
					}
					if dur, err := time.ParseDuration(val + "s"); err == nil && dur > 0 {
						return dur
					}
					if t, err := time.Parse(time.RFC1123, val); err == nil {
						diff := time.Until(t)
						if diff > 0 {
							return diff
						}
					}
				}
				break
			}
		}
	}

	return cooldown
}

// CircuitBreakerManager coordinates circuit breaker policies, evaluations, and failovers.
type CircuitBreakerManager struct {
	mu       sync.RWMutex
	policies map[string]*PolicyRuntimeState // keyed by provider/model
	byName   map[string]*PolicyRuntimeState // keyed by policy.Name
}

// NewCircuitBreakerManager creates a new CircuitBreakerManager.
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		policies: make(map[string]*PolicyRuntimeState),
		byName:   make(map[string]*PolicyRuntimeState),
	}
}

// RegisterCircuitPolicy registers a circuit breaker policy.
func (cbm *CircuitBreakerManager) RegisterCircuitPolicy(policy CircuitBreakerPolicy) {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	if policy.DefaultCooldown <= 0 {
		policy.DefaultCooldown = 30 * time.Second
	}
	policy.Enabled = true

	subs := make(map[string]*KeySubCircuitState)
	for _, kID := range policy.PrimaryKeyIDs {
		subs[kID] = &KeySubCircuitState{
			KeyID: kID,
			State: CircuitClosed,
		}
	}

	state := &PolicyRuntimeState{
		Policy:      policy,
		State:       CircuitClosed,
		SubCircuits: subs,
	}

	key := fmt.Sprintf("%s/%s", policy.PrimaryProvider, policy.PrimaryModel)
	cbm.policies[key] = state
	if policy.Name != "" {
		cbm.byName[policy.Name] = state
	}
}

// InspectResponse inspects response headers and status codes to update circuit states.
func (cbm *CircuitBreakerManager) InspectResponse(provider, model string, headers map[string]string, statusCode int, keyID string) {
	cbm.mu.RLock()
	routeKey := fmt.Sprintf("%s/%s", provider, model)
	state, exists := cbm.policies[routeKey]
	cbm.mu.RUnlock()

	if !exists || !state.Policy.Enabled {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	matched := false
	if len(state.Policy.Condition.Signals) > 0 {
		matched = state.Policy.Condition.Evaluate(headers, statusCode)
	} else if len(state.Policy.TriggerHeaders) > 0 {
		for hKey, hVal := range state.Policy.TriggerHeaders {
			for k, v := range headers {
				if strings.EqualFold(k, hKey) && v == hVal {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}

	// Half-open canary probe evaluation
	if state.State == CircuitHalfOpen {
		atomic.StoreInt32(&state.Probing, 0)
		if matched {
			// Probe failed: reopen
			cooldown := state.resolveCooldown(headers)
			now := time.Now()
			state.State = CircuitOpen
			state.OpenedAt = now
			state.Cooldown = cooldown
			state.OpenUntil = now.Add(cooldown)
		} else {
			// Probe succeeded: close circuit
			state.State = CircuitClosed
			state.OpenedAt = time.Time{}
			state.OpenUntil = time.Time{}
		}
		return
	}

	if !matched {
		return
	}

	cooldown := state.resolveCooldown(headers)
	now := time.Now()

	// Key-level sub-circuits
	if len(state.Policy.PrimaryKeyIDs) > 0 && keyID != "" {
		sub, ok := state.SubCircuits[keyID]
		if ok {
			sub.mu.Lock()
			sub.State = CircuitOpen
			sub.OpenedAt = now
			sub.Cooldown = cooldown
			sub.OpenUntil = now.Add(cooldown)
			sub.mu.Unlock()
		}

		allTripped := true
		for _, kID := range state.Policy.PrimaryKeyIDs {
			kSub := state.SubCircuits[kID]
			if kSub != nil {
				kSub.mu.RLock()
				isOpen := kSub.State == CircuitOpen && now.Before(kSub.OpenUntil)
				kSub.mu.RUnlock()
				if !isOpen {
					allTripped = false
					break
				}
			}
		}

		if allTripped {
			state.State = CircuitOpen
			state.OpenedAt = now
			state.Cooldown = cooldown
			state.OpenUntil = now.Add(cooldown)
		}
		return
	}

	// Shared circuit trip
	state.State = CircuitOpen
	state.OpenedAt = now
	state.Cooldown = cooldown
	state.OpenUntil = now.Add(cooldown)
}

// CheckAndReroute inspects the circuit state and mutates req to the fallback target if open.
func (cbm *CircuitBreakerManager) CheckAndReroute(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (tripped bool, fallbackProvider string, fallbackModel string) {
	provider, model, _ := req.GetRequestFields()
	routeKey := fmt.Sprintf("%s/%s", provider, model)

	cbm.mu.RLock()
	state, exists := cbm.policies[routeKey]
	cbm.mu.RUnlock()

	if !exists || !state.Policy.Enabled {
		return false, "", ""
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now()
	if state.State == CircuitOpen {
		if now.After(state.OpenUntil) {
			// Cooldown expired -> Transition to Half-Open
			state.State = CircuitHalfOpen
			atomic.StoreInt32(&state.Probing, 1) // Admit single canary probe
			return false, "", ""                 // Let probe pass to primary
		}

		// Circuit is OPEN: Reroute to fallback target
		req.SetProvider(schemas.ModelProvider(state.Policy.FallbackProvider))
		req.SetModel(state.Policy.FallbackModel)

		if ctx != nil {
			ctx.SetValue(schemas.BifrostContextKey("circuit_breaker_tripped"), true)
			ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, schemas.LogLevelInfo,
				fmt.Sprintf("Circuit breaker %s is OPEN: rerouted %s/%s -> %s/%s",
					state.Policy.Name, state.Policy.PrimaryProvider, state.Policy.PrimaryModel,
					state.Policy.FallbackProvider, state.Policy.FallbackModel))
		}

		return true, state.Policy.FallbackProvider, state.Policy.FallbackModel
	}

	if state.State == CircuitHalfOpen {
		// Only one canary probe allowed through
		if atomic.CompareAndSwapInt32(&state.Probing, 0, 1) {
			return false, "", "" // This is the canary probe
		}
		// Subsequent requests while probe is in flight reroute to fallback
		req.SetProvider(schemas.ModelProvider(state.Policy.FallbackProvider))
		req.SetModel(state.Policy.FallbackModel)
		if ctx != nil {
			ctx.SetValue(schemas.BifrostContextKey("circuit_breaker_tripped"), true)
		}
		return true, state.Policy.FallbackProvider, state.Policy.FallbackModel
	}

	return false, "", ""
}

// CheckRerouteForRoute checks whether a route should be rerouted without a BifrostRequest object.
func (cbm *CircuitBreakerManager) CheckRerouteForRoute(provider, model string) (tripped bool, fallbackProvider string, fallbackModel string) {
	routeKey := fmt.Sprintf("%s/%s", provider, model)

	cbm.mu.RLock()
	state, exists := cbm.policies[routeKey]
	cbm.mu.RUnlock()

	if !exists || !state.Policy.Enabled {
		return false, "", ""
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now()
	if state.State == CircuitOpen {
		if now.After(state.OpenUntil) {
			state.State = CircuitHalfOpen
			atomic.StoreInt32(&state.Probing, 1)
			return false, "", ""
		}
		return true, state.Policy.FallbackProvider, state.Policy.FallbackModel
	}

	if state.State == CircuitHalfOpen {
		if atomic.CompareAndSwapInt32(&state.Probing, 0, 1) {
			return false, "", ""
		}
		return true, state.Policy.FallbackProvider, state.Policy.FallbackModel
	}

	return false, "", ""
}

// KeyPoolFilter excludes keys that have open sub-circuits while the main circuit is not fully open.
func (cbm *CircuitBreakerManager) KeyPoolFilter(ctx *schemas.BifrostContext, provider schemas.ModelProvider, model string, keys []schemas.Key) ([]schemas.Key, error) {
	routeKey := fmt.Sprintf("%s/%s", provider, model)

	cbm.mu.RLock()
	state, exists := cbm.policies[routeKey]
	cbm.mu.RUnlock()

	if !exists || !state.Policy.Enabled || len(state.Policy.PrimaryKeyIDs) == 0 {
		return keys, nil
	}

	now := time.Now()
	state.mu.RLock()
	defer state.mu.RUnlock()

	filtered := make([]schemas.Key, 0, len(keys))
	for _, k := range keys {
		sub, ok := state.SubCircuits[k.ID]
		if ok {
			sub.mu.RLock()
			isOpen := sub.State == CircuitOpen && now.Before(sub.OpenUntil)
			sub.mu.RUnlock()
			if isOpen {
				continue // Exclude tripped key
			}
		}
		filtered = append(filtered, k)
	}

	return filtered, nil
}

// GetPolicy returns the policy for the given provider and model.
func (cbm *CircuitBreakerManager) GetPolicy(provider, model string) (CircuitBreakerPolicy, bool) {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()
	routeKey := fmt.Sprintf("%s/%s", provider, model)
	if s, ok := cbm.policies[routeKey]; ok {
		return s.Policy, true
	}
	return CircuitBreakerPolicy{}, false
}

// GetRuntimeState returns a snapshot of the runtime state for a given route.
func (cbm *CircuitBreakerManager) GetRuntimeState(provider, model string) (CircuitState, time.Time, time.Duration, bool) {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()
	routeKey := fmt.Sprintf("%s/%s", provider, model)
	if s, ok := cbm.policies[routeKey]; ok {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.State, s.OpenUntil, s.Cooldown, true
	}
	return CircuitClosed, time.Time{}, 0, false
}
