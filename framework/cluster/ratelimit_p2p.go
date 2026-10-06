package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// RateLimitDeltaPayload encapsulates asynchronous delta broadcasts over the cluster state channel.
type RateLimitDeltaPayload struct {
	Key          string `json:"key"`
	Amount       int64  `json:"amount"`
	Remaining    int64  `json:"remaining"`
	Capacity     int64  `json:"capacity"`
	WindowMs     int64  `json:"window_ms"`
	LastRefillNs int64  `json:"last_refill_ns"`
	NodeID       string `json:"node_id"`
}

// P2PRateLimiter provides cluster-wide distributed rate limiting without Redis via consistent hash
// key ownership and peer delta synchronization.
type P2PRateLimiter struct {
	mu          sync.RWMutex
	buckets     map[string]*InMemTokenBucket
	coordinator ClusterCoordinator
	nodeID      string
	logger      schemas.Logger
	stopCh      chan struct{}
	closeOnce   sync.Once
}

// NewP2PRateLimiter instantiates a P2P distributed rate limiter.
func NewP2PRateLimiter(cfg RateLimiterConfig, coordinator ClusterCoordinator) (*P2PRateLimiter, error) {
	p := &P2PRateLimiter{
		buckets:     make(map[string]*InMemTokenBucket),
		coordinator: coordinator,
		nodeID:      cfg.NodeID,
		logger:      cfg.Logger,
		stopCh:      make(chan struct{}),
	}

	// Register entity handler for incoming rate limit deltas from peers
	if coordinator != nil {
		coordinator.RegisterStateReceiver(EntityRateLimitDelta, p.handleRemoteDelta)
	}

	return p, nil
}

func (p *P2PRateLimiter) getOrCreateBucket(key string, capacity int64, window time.Duration) *InMemTokenBucket {
	p.mu.Lock()
	defer p.mu.Unlock()

	bucket, exists := p.buckets[key]
	if !exists {
		bucket = NewInMemTokenBucket(key, capacity, window)
		p.buckets[key] = bucket
	}
	return bucket
}

// getNodeForKey resolves the primary node ID responsible for serializing charges for the key.
func (p *P2PRateLimiter) getNodeForKey(key string) string {
	if p.coordinator == nil {
		return p.nodeID
	}
	nodes := p.coordinator.GetAliveNodes()
	if len(nodes) == 0 {
		return p.nodeID
	}

	var aliveIDs []string
	for _, n := range nodes {
		if n.State == NodeStateAlive {
			aliveIDs = append(aliveIDs, n.NodeID)
		}
	}
	if len(aliveIDs) == 0 {
		return p.nodeID
	}
	sort.Strings(aliveIDs)

	h := fnv.New32a()
	h.Write([]byte(key))
	idx := int(h.Sum32()) % len(aliveIDs)
	return aliveIDs[idx]
}

func (p *P2PRateLimiter) CheckAndCharge(ctx context.Context, key string, amount int64, window time.Duration, limit int64) (bool, int64, time.Duration, error) {
	if limit <= 0 {
		return false, 0, 0, ErrInvalidLimit
	}
	if window <= 0 {
		return false, 0, 0, ErrInvalidWindow
	}

	primaryNode := p.getNodeForKey(key)
	now := time.Now()

	// If local node is primary or coordinator is unassigned, charge atomically in local bucket
	if primaryNode == p.nodeID || p.coordinator == nil {
		bucket := p.getOrCreateBucket(key, limit, window)
		allowed, remaining, resetAfter, lastRefill := bucket.CheckAndCharge(now, amount, limit, window)

		if allowed && amount > 0 && p.coordinator != nil {
			go p.broadcastDelta(key, amount, remaining, limit, window, lastRefill)
		}
		return allowed, remaining, resetAfter, nil
	}

	// Remote primary key dispatch
	return p.dispatchRemoteCharge(ctx, primaryNode, key, amount, window, limit)
}

func (p *P2PRateLimiter) dispatchRemoteCharge(ctx context.Context, targetNodeID, key string, amount int64, window time.Duration, limit int64) (bool, int64, time.Duration, error) {
	if p.coordinator != nil {
		req := RateLimitChargeRequest{
			Key:      key,
			Amount:   amount,
			Capacity: limit,
			WindowMs: window.Milliseconds(),
			NodeID:   p.nodeID,
		}
		resp, err := p.coordinator.ForwardRateLimitCharge(ctx, targetNodeID, req)
		if err == nil && resp != nil {
			if resp.Error != "" {
				return false, 0, 0, errors.New(resp.Error)
			}
			resetAfter := time.Duration(resp.ResetMs) * time.Millisecond
			// Update local replica with primary's authoritative remaining capacity
			bucket := p.getOrCreateBucket(key, limit, window)
			bucket.UpdateReplica(resp.Remaining)
			return resp.Allowed, resp.Remaining, resetAfter, nil
		}
	}

	// Graceful fallback to local bucket replica if coordinator/RPC fails (partition tolerance)
	bucket := p.getOrCreateBucket(key, limit, window)
	allowed, remaining, resetAfter, lastRefill := bucket.CheckAndCharge(time.Now(), amount, limit, window)

	if allowed && amount > 0 && p.coordinator != nil {
		go p.broadcastDelta(key, amount, remaining, limit, window, lastRefill)
	}
	return allowed, remaining, resetAfter, nil
}

// HandleLocalChargeRequest evaluates a forwarded rate limit charge from a peer node on the primary.
func (p *P2PRateLimiter) HandleLocalChargeRequest(ctx context.Context, req *RateLimitChargeRequest) *RateLimitChargeResponse {
	window := time.Duration(req.WindowMs) * time.Millisecond
	bucket := p.getOrCreateBucket(req.Key, req.Capacity, window)
	allowed, remaining, resetAfter, lastRefill := bucket.CheckAndCharge(time.Now(), req.Amount, req.Capacity, window)

	if allowed && req.Amount > 0 && p.coordinator != nil {
		go p.broadcastDelta(req.Key, req.Amount, remaining, req.Capacity, window, lastRefill)
	}

	return &RateLimitChargeResponse{
		Allowed:   allowed,
		Remaining: remaining,
		ResetMs:   resetAfter.Milliseconds(),
	}
}

func (p *P2PRateLimiter) broadcastDelta(key string, amount, remaining, capacity int64, window time.Duration, lastRefill time.Time) {
	delta := RateLimitDeltaPayload{
		Key:          key,
		Amount:       amount,
		Remaining:    remaining,
		Capacity:     capacity,
		WindowMs:     window.Milliseconds(),
		LastRefillNs: lastRefill.UnixNano(),
		NodeID:       p.nodeID,
	}

	payload, err := json.Marshal(delta)
	if err == nil && p.coordinator != nil {
		_ = p.coordinator.BroadcastState(EntityRateLimitDelta, payload)
	}
}

func (p *P2PRateLimiter) handleRemoteDelta(ctx context.Context, entityType string, payload []byte) error {
	var delta RateLimitDeltaPayload
	if err := json.Unmarshal(payload, &delta); err != nil {
		return err
	}

	// Ignore echoes from self
	if delta.NodeID == p.nodeID {
		return nil
	}

	window := time.Duration(delta.WindowMs) * time.Millisecond
	lastRefill := time.Unix(0, delta.LastRefillNs)

	bucket := p.getOrCreateBucket(delta.Key, delta.Capacity, window)
	bucket.UpdateRemoteSync(delta.Remaining, lastRefill, window)
	return nil
}

func (p *P2PRateLimiter) GetRemaining(ctx context.Context, key string, window time.Duration, limit int64) (int64, time.Duration, error) {
	_, remaining, resetAfter, err := p.CheckAndCharge(ctx, key, 0, window, limit)
	return remaining, resetAfter, err
}

func (p *P2PRateLimiter) Reset(ctx context.Context, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.buckets, key)
	return nil
}

func (p *P2PRateLimiter) Close() error {
	p.closeOnce.Do(func() {
		close(p.stopCh)
	})
	return nil
}
