package vault

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ResiliencePolicy manages stale-secret fallbacks and circuit breaker backoffs on upstream outages.
type ResiliencePolicy struct {
	mu                  sync.RWMutex
	failureThreshold    int
	cooldown            time.Duration
	consecutiveFailures int
	lastFailureTime     time.Time
	staleFallbackCount  int
}

// NewResiliencePolicy creates a new ResiliencePolicy.
func NewResiliencePolicy(failureThreshold int, cooldown time.Duration) *ResiliencePolicy {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &ResiliencePolicy{
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
	}
}

// RecordSuccess resets the consecutive failure count upon a successful upstream call.
func (r *ResiliencePolicy) RecordSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consecutiveFailures = 0
}

// RecordFailure notes an upstream error and updates circuit breaker state.
func (r *ResiliencePolicy) RecordFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consecutiveFailures++
	r.lastFailureTime = time.Now()
}

// IsCircuitOpen reports whether the circuit breaker is active.
func (r *ResiliencePolicy) IsCircuitOpen() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.consecutiveFailures >= r.failureThreshold {
		if time.Since(r.lastFailureTime) < r.cooldown {
			return true
		}
	}
	return false
}

// StaleFallbackCount returns the number of times stale fallback was invoked.
func (r *ResiliencePolicy) StaleFallbackCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.staleFallbackCount
}

// HandleFetchFailure attempts to serve an expired cached secret if present.
// Note: Serving a cached stale secret or short-circuiting on an open circuit is
// NOT an upstream failure; RecordFailure() must only be called on actual upstream fetch errors.
func (r *ResiliencePolicy) HandleFetchFailure(path string, upstreamErr error, entry *CacheEntry) (map[string]string, error) {
	if entry != nil && len(entry.Data) > 0 {
		r.mu.Lock()
		r.staleFallbackCount++
		r.mu.Unlock()

		log.Printf("vault: upstream outage fetching %s (%v); serving stale secret cached at %s",
			path, upstreamErr, entry.CachedAt.Format(time.RFC3339))

		entry.IsStale.Store(true)
		// Return copy of cached data
		res := make(map[string]string, len(entry.Data))
		for k, v := range entry.Data {
			res[k] = v
		}
		return res, nil
	}

	return nil, fmt.Errorf("vault: upstream outage and no stale secret available for %s: %w", path, upstreamErr)
}
