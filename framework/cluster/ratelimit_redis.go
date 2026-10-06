package cluster

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/redis/go-redis/v9"
)

// Redis Lua script for zero-drift atomic token bucket / sliding window check and charge.
const redisRateLimitLua = `
local key = KEYS[1]
local amount = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local window_ms = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])

local state = redis.call('HMGET', key, 'remaining', 'last_refill')
local remaining = tonumber(state[1])
local last_refill = tonumber(state[2])

if not remaining or not last_refill then
    remaining = capacity
    last_refill = now_ms
else
    local elapsed = now_ms - last_refill
    if elapsed >= window_ms then
        remaining = capacity
        last_refill = now_ms
    end
end

local reset_after_ms = window_ms - (now_ms - last_refill)
if reset_after_ms < 0 then
    reset_after_ms = 0
end

local allowed = 0
if remaining >= amount then
    allowed = 1
    remaining = remaining - amount
    redis.call('HMSET', key, 'remaining', remaining, 'last_refill', last_refill, 'capacity', capacity)
    local ttl_sec = math.ceil((window_ms * 2) / 1000)
    if ttl_sec < 1 then ttl_sec = 1 end
    redis.call('EXPIRE', key, ttl_sec)
end

return {allowed, remaining, reset_after_ms}
`

// RedisRateLimiter implements DistributedRateLimiter backed by Redis atomic Lua scripts.
type RedisRateLimiter struct {
	client    redis.UniversalClient
	keyPrefix string
	scriptSHA string
	logger    schemas.Logger
	mu        sync.RWMutex
}

// NewRedisRateLimiter creates a new RedisRateLimiter instance.
func NewRedisRateLimiter(client redis.UniversalClient, keyPrefix string, logger schemas.Logger) (*RedisRateLimiter, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sha, err := client.ScriptLoad(ctx, redisRateLimitLua).Result()
	if err != nil && logger != nil {
		logger.Warn(fmt.Sprintf("failed to preload redis rate limit lua script: %v", err))
	}

	return &RedisRateLimiter{
		client:    client,
		keyPrefix: keyPrefix,
		scriptSHA: sha,
		logger:    logger,
	}, nil
}

func (r *RedisRateLimiter) redisKey(key string) string {
	// Hash tag {...} ensures single-slot affinity in Redis Cluster topology
	return fmt.Sprintf("%s{%s}", r.keyPrefix, key)
}

func (r *RedisRateLimiter) CheckAndCharge(ctx context.Context, key string, amount int64, window time.Duration, limit int64) (bool, int64, time.Duration, error) {
	if limit <= 0 {
		return false, 0, 0, ErrInvalidLimit
	}
	if window <= 0 {
		return false, 0, 0, ErrInvalidWindow
	}

	rKey := r.redisKey(key)
	nowMs := time.Now().UnixMilli()
	windowMs := window.Milliseconds()

	var res interface{}
	var err error

	if r.scriptSHA != "" {
		res, err = r.client.EvalSha(ctx, r.scriptSHA, []string{rKey}, amount, limit, windowMs, nowMs).Result()
		if err != nil && (err.Error() == "NOSCRIPT No matching script. Please use EVAL." || redis.HasErrorPrefix(err, "NOSCRIPT")) {
			res, err = r.client.Eval(ctx, redisRateLimitLua, []string{rKey}, amount, limit, windowMs, nowMs).Result()
		}
	} else {
		res, err = r.client.Eval(ctx, redisRateLimitLua, []string{rKey}, amount, limit, windowMs, nowMs).Result()
	}

	if err != nil {
		return false, 0, 0, fmt.Errorf("redis rate limit execution failed: %w", err)
	}

	vals, ok := res.([]interface{})
	if !ok || len(vals) < 3 {
		return false, 0, 0, fmt.Errorf("unexpected redis rate limit response: %v", res)
	}

	allowedInt := toInt64(vals[0])
	remaining := toInt64(vals[1])
	resetAfterMs := toInt64(vals[2])

	allowed := allowedInt == 1
	resetAfter := time.Duration(resetAfterMs) * time.Millisecond

	return allowed, remaining, resetAfter, nil
}

func (r *RedisRateLimiter) GetRemaining(ctx context.Context, key string, window time.Duration, limit int64) (int64, time.Duration, error) {
	_, remaining, resetAfter, err := r.CheckAndCharge(ctx, key, 0, window, limit)
	return remaining, resetAfter, err
}

func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	rKey := r.redisKey(key)
	return r.client.Del(ctx, rKey).Err()
}

func (r *RedisRateLimiter) Close() error {
	return nil
}

func toInt64(val interface{}) int64 {
	switch v := val.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(math.Round(v))
	case string:
		var n int64
		_, _ = fmt.Sscanf(v, "%d", &n)
		return n
	default:
		return 0
	}
}
