package vault

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// CacheEntry represents a cached secret payload.
type CacheEntry struct {
	Data        map[string]string
	CachedAt    time.Time
	ExpiresAt   time.Time
	LastFetched time.Time
	IsStale     atomic.Bool
}

// SecretCache provides a thread-safe, TTL-bounded in-memory secret cache protected against stampedes.
type SecretCache struct {
	mu         sync.RWMutex
	entries    map[string]*CacheEntry
	ttl        time.Duration
	provider   VaultProvider
	resilience *ResiliencePolicy
	sfGroup    singleflight.Group
	stopChan   chan struct{}
	closeOnce  sync.Once
}

// NewSecretCache initializes a SecretCache.
func NewSecretCache(provider VaultProvider, ttl time.Duration, resilience *ResiliencePolicy) *SecretCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if resilience == nil {
		resilience = NewResiliencePolicy(5, 30*time.Second)
	}
	return &SecretCache{
		entries:    make(map[string]*CacheEntry),
		ttl:        ttl,
		provider:   provider,
		resilience: resilience,
		stopChan:   make(chan struct{}),
	}
}

// Get retrieves the secret map for path, serving from cache if fresh or coalescing backend fetches.
func (c *SecretCache) Get(ctx context.Context, path string) (map[string]string, error) {
	now := time.Now()

	// 1. Fast path: check valid cached entry under read lock
	c.mu.RLock()
	entry, exists := c.entries[path]
	if exists && !entry.IsStale.Load() && now.Before(entry.ExpiresAt) {
		res := copyData(entry.Data)
		c.mu.RUnlock()
		return res, nil
	}
	c.mu.RUnlock()

	// 2. Slow path: singleflight coalescing to eliminate thundering herds
	return c.fetchAndStore(ctx, path)
}

// fetchAndStore retrieves secret from upstream provider and stores in cache, bypassing
// the unexpired fast path check. It uses singleflight to eliminate thundering herds.
func (c *SecretCache) fetchAndStore(ctx context.Context, path string) (map[string]string, error) {
	if c.provider == nil {
		return nil, ErrVaultDisabled
	}

	val, err, _ := c.sfGroup.Do(path, func() (interface{}, error) {
		// Double check under read lock: if another goroutine has refreshed the entry
		// such that remaining TTL is well above threshold, return cached data.
		threshold := c.ttl / 4
		c.mu.RLock()
		cur, curExists := c.entries[path]
		if curExists && !cur.IsStale.Load() && cur.ExpiresAt.Sub(time.Now()) >= threshold {
			res := copyData(cur.Data)
			c.mu.RUnlock()
			return res, nil
		}
		c.mu.RUnlock()

		// If circuit is open, attempt stale fallback directly before hitting provider
		if c.resilience.IsCircuitOpen() {
			c.mu.RLock()
			staleEntry := c.entries[path]
			c.mu.RUnlock()
			return c.resilience.HandleFetchFailure(path, ErrProviderUnreachable, staleEntry)
		}

		// Fetch from upstream provider
		data, fetchErr := c.provider.GetSecret(ctx, path)
		if fetchErr != nil {
			c.resilience.RecordFailure()
			c.mu.RLock()
			staleEntry := c.entries[path]
			c.mu.RUnlock()
			return c.resilience.HandleFetchFailure(path, fetchErr, staleEntry)
		}

		// Success: record and update cache
		c.resilience.RecordSuccess()
		fetchTime := time.Now()

		newEntry := &CacheEntry{
			Data:        copyData(data),
			CachedAt:    fetchTime,
			ExpiresAt:   fetchTime.Add(c.ttl),
			LastFetched: fetchTime,
		}

		c.mu.Lock()
		c.entries[path] = newEntry
		c.mu.Unlock()

		return copyData(data), nil
	})

	if err != nil {
		return nil, err
	}
	return val.(map[string]string), nil
}

// Put writes data to the provider and updates the cache.
func (c *SecretCache) Put(ctx context.Context, path string, data map[string]string) error {
	if c.provider == nil {
		return ErrVaultDisabled
	}
	if err := c.provider.PutSecret(ctx, path, data); err != nil {
		return err
	}

	now := time.Now()
	entry := &CacheEntry{
		Data:        copyData(data),
		CachedAt:    now,
		ExpiresAt:   now.Add(c.ttl),
		LastFetched: now,
	}

	c.mu.Lock()
	c.entries[path] = entry
	c.mu.Unlock()
	return nil
}

// Delete removes the secret from the provider and cache.
func (c *SecretCache) Delete(ctx context.Context, path string) error {
	if c.provider != nil {
		_ = c.provider.DeleteSecret(ctx, path)
	}

	c.mu.Lock()
	delete(c.entries, path)
	c.mu.Unlock()
	return nil
}

// Flush purges all cached entries immediately.
func (c *SecretCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// StartBackgroundRefresh proactively refreshes expiring secrets.
func (c *SecretCache) StartBackgroundRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-ticker.C:
				c.refreshExpiringEntries(ctx)
			}
		}
	}()
}

func (c *SecretCache) refreshExpiringEntries(ctx context.Context) {
	c.mu.RLock()
	pathsToRefresh := make([]string, 0)
	now := time.Now()
	// Refresh if less than 25% TTL remaining
	threshold := c.ttl / 4
	for path, entry := range c.entries {
		if !entry.IsStale.Load() && entry.ExpiresAt.Sub(now) < threshold {
			pathsToRefresh = append(pathsToRefresh, path)
		}
	}
	c.mu.RUnlock()

	for _, p := range pathsToRefresh {
		_, _ = c.fetchAndStore(ctx, p)
	}
}

// Close gracefully closes background workers.
func (c *SecretCache) Close() {
	c.closeOnce.Do(func() {
		close(c.stopChan)
		if c.provider != nil {
			_ = c.provider.Close()
		}
	})
}

func copyData(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
