package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/redis/go-redis/v9"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrInvalidLimit      = errors.New("rate limit capacity must be positive")
	ErrInvalidWindow     = errors.New("rate limit window must be positive")
	ErrClosed            = errors.New("rate limiter is closed")
)

// DistributedRateLimiter defines the cluster-wide rate limit synchronization contract satisfying AC-4.
type DistributedRateLimiter interface {
	// CheckAndCharge atomically checks if requested amount is available within the sliding window,
	// deducts it if allowed, and returns allowed=true with remaining capacity and reset duration.
	// If capacity is exceeded, returns allowed=false with current remaining capacity and reset duration.
	CheckAndCharge(ctx context.Context, key string, amount int64, window time.Duration, limit int64) (allowed bool, remaining int64, resetAfter time.Duration, err error)

	// GetRemaining returns the current remaining capacity and reset duration without deducting tokens.
	GetRemaining(ctx context.Context, key string, window time.Duration, limit int64) (remaining int64, resetAfter time.Duration, err error)

	// Reset clears or refills the rate limit for the given key.
	Reset(ctx context.Context, key string) error

	// Close shuts down background synchronization workers or connections.
	Close() error
}

// RateLimitBackend represents the storage engine for distributed rate limiting.
type RateLimitBackend string

const (
	BackendRedis RateLimitBackend = "redis"
	BackendP2P   RateLimitBackend = "p2p"
	BackendAuto  RateLimitBackend = "auto"
)

// RateLimiterConfig configures the distributed rate limiter.
type RateLimiterConfig struct {
	Backend      RateLimitBackend      `json:"backend"`
	KeyPrefix    string                `json:"key_prefix"`
	RedisClient  redis.UniversalClient `json:"-"`
	NodeID       string                `json:"node_id"`
	SyncInterval time.Duration         `json:"sync_interval"`
	Logger       schemas.Logger        `json:"-"`
}

// DefaultRateLimiterConfig provides production defaults.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Backend:      BackendAuto,
		KeyPrefix:    "airlok:rl:",
		SyncInterval: 20 * time.Millisecond,
	}
}

// InMemTokenBucket tracks an in-memory token bucket with precise window sliding and refill semantics.
type InMemTokenBucket struct {
	mu         sync.Mutex
	Key        string
	Capacity   int64
	Remaining  int64
	LastRefill time.Time
	Window     time.Duration
}

// NewInMemTokenBucket initializes a token bucket.
func NewInMemTokenBucket(key string, capacity int64, window time.Duration) *InMemTokenBucket {
	return &InMemTokenBucket{
		Key:        key,
		Capacity:   capacity,
		Remaining:  capacity,
		LastRefill: time.Now(),
		Window:     window,
	}
}

// CheckAndCharge evaluates and deducts tokens atomically, returning lastRefill under b.mu.Lock().
func (b *InMemTokenBucket) CheckAndCharge(now time.Time, amount int64, capacity int64, window time.Duration) (bool, int64, time.Duration, time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.Capacity = capacity
	b.Window = window

	// Window sliding refill: if current time past active window, reset to full capacity
	elapsed := now.Sub(b.LastRefill)
	if elapsed >= window {
		b.Remaining = capacity
		b.LastRefill = now
		elapsed = 0
	}

	resetAfter := window - elapsed
	if resetAfter < 0 {
		resetAfter = 0
	}

	if b.Remaining < amount {
		return false, b.Remaining, resetAfter, b.LastRefill
	}

	b.Remaining -= amount
	return true, b.Remaining, resetAfter, b.LastRefill
}

// UpdateReplica safely updates the follower's replica bucket remaining tokens under mutex lock.
func (b *InMemTokenBucket) UpdateReplica(remaining int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Remaining = remaining
}

// GetLastRefill returns the bucket's last refill timestamp under lock.
func (b *InMemTokenBucket) GetLastRefill() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.LastRefill
}

// GetRemaining returns the bucket's remaining capacity under lock.
func (b *InMemTokenBucket) GetRemaining() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Remaining
}

// UpdateRemoteSync updates the bucket from an incoming peer replication delta with clock jitter tolerance.
func (b *InMemTokenBucket) UpdateRemoteSync(remaining int64, lastRefill time.Time, window ...time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	win := b.Window
	if len(window) > 0 && window[0] > 0 {
		win = window[0]
		b.Window = win
	}
	if win <= 0 {
		win = time.Minute
	}

	now := time.Now()

	// Adaptive clock jitter tolerance: bounded between 5ms and 5s, proportional to win/4
	jitterTolerance := win / 4
	if jitterTolerance > 5*time.Second {
		jitterTolerance = 5 * time.Second
	}
	if jitterTolerance < 5*time.Millisecond {
		jitterTolerance = 5 * time.Millisecond
	}

	// Case 1: Advance to new window if remote refill is at least half a window ahead
	// or local bucket was uninitialized.
	if b.LastRefill.IsZero() || lastRefill.After(b.LastRefill.Add(win/2)) {
		b.Remaining = remaining
		b.LastRefill = lastRefill
		return
	}

	// Case 2: Local bucket is expired relative to current wall clock.
	if now.Sub(b.LastRefill) >= win && (now.Sub(lastRefill) < win+jitterTolerance || lastRefill.After(now)) {
		b.Remaining = remaining
		b.LastRefill = lastRefill
		return
	}

	// Case 3: Both nodes are within active sliding window (allowing clock jitter).
	withinRemote := now.Sub(lastRefill) < win+jitterTolerance && lastRefill.Sub(now) < jitterTolerance
	withinLocal := now.Sub(b.LastRefill) < win+jitterTolerance && b.LastRefill.Sub(now) < jitterTolerance

	if withinRemote && withinLocal {
		// Monotonically apply lower remaining capacity
		if remaining < b.Remaining {
			b.Remaining = remaining
		}
		// Synchronize refill boundary to peer's start if local is freshly initialized or remote is earlier
		if b.Remaining == b.Capacity || lastRefill.Before(b.LastRefill) {
			b.LastRefill = lastRefill
		}
	}
}

// NewDistributedRateLimiter instantiates the appropriate rate limiter based on configuration.
func NewDistributedRateLimiter(cfg RateLimiterConfig, coordinator ClusterCoordinator) (DistributedRateLimiter, error) {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "airlok:rl:"
	}
	if cfg.Backend == "" || cfg.Backend == BackendAuto {
		if cfg.RedisClient != nil {
			cfg.Backend = BackendRedis
		} else {
			cfg.Backend = BackendP2P
		}
	}

	switch cfg.Backend {
	case BackendRedis:
		if cfg.RedisClient == nil {
			return nil, fmt.Errorf("redis client is required for redis rate limiter backend")
		}
		return NewRedisRateLimiter(cfg.RedisClient, cfg.KeyPrefix, cfg.Logger)
	case BackendP2P:
		return NewP2PRateLimiter(cfg, coordinator)
	default:
		return nil, fmt.Errorf("unknown rate limiter backend: %s", cfg.Backend)
	}
}
