package cluster

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// ADVERSARIAL CHALLENGER SUITE: MULTI-NODE BURST, VARIED CAPACITIES & ZERO DRIFT
// ============================================================================

// TestAdversarial_P2PRateLimiter_MultiNodeConcurrentBurst_StrictEquality
// Verifies exact equality: exactly 100 allowed, exactly 50 rejected, 0 remaining, 0 drift.
func TestAdversarial_P2PRateLimiter_MultiNodeConcurrentBurst_StrictEquality(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numNodes = 3
	coords := make([]*Coordinator, numNodes)

	for i := 0; i < numNodes; i++ {
		cfg := Config{
			NodeID: fmt.Sprintf("p2p-strict-node-%d", i+1),
			Region: "us-east-1",
			Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1", SecretKey: "adversarial-key"},
			GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
			RateLimit: RateLimitConfig{
				Backend: string(BackendP2P),
			},
		}
		c, err := NewCoordinator(cfg)
		if err != nil {
			t.Fatalf("failed to create node %d: %v", i+1, err)
		}
		if err := c.Start(ctx); err != nil {
			t.Fatalf("failed to start node %d: %v", i+1, err)
		}
		defer c.Stop()
		coords[i] = c
	}

	// Mesh join all nodes
	seedAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coords[0].GetLocalNode().GossipPort))
	for i := 1; i < numNodes; i++ {
		if err := coords[i].Join([]string{seedAddr}); err != nil {
			t.Fatalf("node %d failed to join: %v", i+1, err)
		}
	}

	// Allow roster convergence
	time.Sleep(350 * time.Millisecond)

	key := "strict-tenant-burst-limit"
	const totalCapacity int64 = 100
	window := 10 * time.Second

	const requestsPerNode = 50
	const totalRequests = numNodes * requestsPerNode

	var startGate sync.WaitGroup
	startGate.Add(1)

	var doneWg sync.WaitGroup
	var successes int64
	var rejections int64

	for nodeIdx := 0; nodeIdx < numNodes; nodeIdx++ {
		for req := 0; req < requestsPerNode; req++ {
			doneWg.Add(1)
			go func(c *Coordinator) {
				defer doneWg.Done()
				startGate.Wait()

				allowed, _, err := c.CheckAndChargeDistributedRateLimit(key, 1, totalCapacity, window)
				if err != nil {
					t.Errorf("unexpected error on charge: %v", err)
					return
				}
				if allowed {
					atomic.AddInt64(&successes, 1)
				} else {
					atomic.AddInt64(&rejections, 1)
				}
			}(coords[nodeIdx])
		}
	}

	startGate.Done()
	doneWg.Wait()

	t.Logf("Strict Multi-Node Burst: Total=%d, Successes=%d, Rejections=%d (Capacity=%d)",
		totalRequests, successes, rejections, totalCapacity)

	// Strict assertions on successes, rejections, and zero drift
	if successes != totalCapacity {
		t.Fatalf("STRICT ZERO-DRIFT VIOLATION: Expected exactly %d successes, got %d (drift=%d)",
			totalCapacity, successes, successes-totalCapacity)
	}
	if rejections != totalRequests-totalCapacity {
		t.Fatalf("STRICT REJECTION COUNT VIOLATION: Expected exactly %d rejections, got %d",
			totalRequests-totalCapacity, rejections)
	}

	// Wait 200ms for asynchronous deltas to settle across nodes
	time.Sleep(200 * time.Millisecond)

	// Invariant: All nodes must report exactly 0 remaining tokens
	for i, c := range coords {
		_, rem, err := c.CheckAndChargeDistributedRateLimit(key, 0, totalCapacity, window)
		if err != nil {
			t.Errorf("Node %d query error: %v", i+1, err)
		}
		t.Logf("Node %d reported remaining tokens: %d", i+1, rem)
		if rem != 0 {
			t.Errorf("Node %d reported remaining tokens %d, expected strictly 0", i+1, rem)
		}
	}
}

// TestAdversarial_P2PRateLimiter_VariedCapacities_ZeroDrift
// Tests rate limiter across different capacities and request counts.
func TestAdversarial_P2PRateLimiter_VariedCapacities_ZeroDrift(t *testing.T) {
	cases := []struct {
		name            string
		numNodes        int
		capacity        int64
		requestsPerNode int
		window          time.Duration
	}{
		{
			name:            "SmallCapacity_20_Total60",
			numNodes:        3,
			capacity:        20,
			requestsPerNode: 20, // 3 * 20 = 60 requests total, cap 20
			window:          10 * time.Second,
		},
		{
			name:            "LargerCapacity_150_Total300",
			numNodes:        3,
			capacity:        150,
			requestsPerNode: 100, // 3 * 100 = 300 requests total, cap 150
			window:          10 * time.Second,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			coords := make([]*Coordinator, tc.numNodes)
			for i := 0; i < tc.numNodes; i++ {
				cfg := Config{
					NodeID: fmt.Sprintf("p2p-var-node-%s-%d", tc.name, i+1),
					Region: "us-east-1",
					Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1", SecretKey: "adversarial-key"},
					GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
					RateLimit: RateLimitConfig{
						Backend: string(BackendP2P),
					},
				}
				c, err := NewCoordinator(cfg)
				if err != nil {
					t.Fatalf("failed to create node: %v", err)
				}
				if err := c.Start(ctx); err != nil {
					t.Fatalf("failed to start node: %v", err)
				}
				defer c.Stop()
				coords[i] = c
			}

			seedAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coords[0].GetLocalNode().GossipPort))
			for i := 1; i < tc.numNodes; i++ {
				if err := coords[i].Join([]string{seedAddr}); err != nil {
					t.Fatalf("node failed to join: %v", err)
				}
			}

			time.Sleep(300 * time.Millisecond)

			key := fmt.Sprintf("var-cap-key-%s", tc.name)
			totalRequests := tc.numNodes * tc.requestsPerNode

			var startGate sync.WaitGroup
			startGate.Add(1)

			var doneWg sync.WaitGroup
			var successes int64
			var rejections int64

			for nodeIdx := 0; nodeIdx < tc.numNodes; nodeIdx++ {
				for req := 0; req < tc.requestsPerNode; req++ {
					doneWg.Add(1)
					go func(c *Coordinator) {
						defer doneWg.Done()
						startGate.Wait()

						allowed, _, err := c.CheckAndChargeDistributedRateLimit(key, 1, tc.capacity, tc.window)
						if err != nil {
							t.Errorf("charge error: %v", err)
							return
						}
						if allowed {
							atomic.AddInt64(&successes, 1)
						} else {
							atomic.AddInt64(&rejections, 1)
						}
					}(coords[nodeIdx])
				}
			}

			startGate.Done()
			doneWg.Wait()

			t.Logf("[%s] Total=%d, Successes=%d, Rejections=%d, Capacity=%d",
				tc.name, totalRequests, successes, rejections, tc.capacity)

			if successes != tc.capacity {
				t.Fatalf("[%s] ZERO-DRIFT VIOLATION: Expected %d successes, got %d (drift=%d)",
					tc.name, tc.capacity, successes, successes-tc.capacity)
			}
			if rejections != int64(totalRequests)-tc.capacity {
				t.Fatalf("[%s] REJECTION VIOLATION: Expected %d rejections, got %d",
					tc.name, int64(totalRequests)-tc.capacity, rejections)
			}

			time.Sleep(200 * time.Millisecond)
			for i, c := range coords {
				_, rem, _ := c.CheckAndChargeDistributedRateLimit(key, 0, tc.capacity, tc.window)
				if rem != 0 {
					t.Errorf("[%s] Node %d remaining tokens = %d, expected 0", tc.name, i+1, rem)
				}
			}
		})
	}
}

// TestAdversarial_P2PRateLimiter_MultiKeyConcurrentBursts_ZeroDrift
// Tests concurrent bursts against multiple distinct keys that distribute across different primary nodes.
func TestAdversarial_P2PRateLimiter_MultiKeyConcurrentBursts_ZeroDrift(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numNodes = 3
	coords := make([]*Coordinator, numNodes)

	for i := 0; i < numNodes; i++ {
		cfg := Config{
			NodeID: fmt.Sprintf("p2p-mkey-node-%d", i+1),
			Region: "us-east-1",
			Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1", SecretKey: "adversarial-key"},
			GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
			RateLimit: RateLimitConfig{
				Backend: string(BackendP2P),
			},
		}
		c, err := NewCoordinator(cfg)
		if err != nil {
			t.Fatalf("failed to create node: %v", err)
		}
		if err := c.Start(ctx); err != nil {
			t.Fatalf("failed to start node: %v", err)
		}
		defer c.Stop()
		coords[i] = c
	}

	seedAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coords[0].GetLocalNode().GossipPort))
	for i := 1; i < numNodes; i++ {
		if err := coords[i].Join([]string{seedAddr}); err != nil {
			t.Fatalf("node failed to join: %v", err)
		}
	}

	time.Sleep(350 * time.Millisecond)

	keys := []string{"tenant-alpha", "tenant-beta", "tenant-gamma"}
	const capacityPerKey int64 = 40
	const requestsPerKeyPerNode = 25 // 3 nodes * 25 = 75 requests per key, cap 40 -> 40 allow, 35 reject
	window := 10 * time.Second

	var startGate sync.WaitGroup
	startGate.Add(1)

	var doneWg sync.WaitGroup
	type keyStats struct {
		successes  int64
		rejections int64
	}
	stats := make(map[string]*keyStats)
	for _, k := range keys {
		stats[k] = &keyStats{}
	}

	for _, k := range keys {
		keyName := k
		for nodeIdx := 0; nodeIdx < numNodes; nodeIdx++ {
			c := coords[nodeIdx]
			for req := 0; req < requestsPerKeyPerNode; req++ {
				doneWg.Add(1)
				go func(coord *Coordinator, key string) {
					defer doneWg.Done()
					startGate.Wait()

					allowed, _, err := coord.CheckAndChargeDistributedRateLimit(key, 1, capacityPerKey, window)
					if err != nil {
						t.Errorf("charge error on %s: %v", key, err)
						return
					}
					if allowed {
						atomic.AddInt64(&stats[key].successes, 1)
					} else {
						atomic.AddInt64(&stats[key].rejections, 1)
					}
				}(c, keyName)
			}
		}
	}

	startGate.Done()
	doneWg.Wait()

	totalPerKey := int64(numNodes * requestsPerKeyPerNode)
	for _, k := range keys {
		s := stats[k]
		succ := atomic.LoadInt64(&s.successes)
		rej := atomic.LoadInt64(&s.rejections)
		t.Logf("Multi-Key Burst [%s]: Total=%d, Successes=%d, Rejections=%d (Capacity=%d)",
			k, totalPerKey, succ, rej, capacityPerKey)

		if succ != capacityPerKey {
			t.Fatalf("[%s] ZERO-DRIFT VIOLATION: Expected %d successes, got %d (drift=%d)",
				k, capacityPerKey, succ, succ-capacityPerKey)
		}
		if rej != totalPerKey-capacityPerKey {
			t.Fatalf("[%s] REJECTION VIOLATION: Expected %d rejections, got %d",
				k, totalPerKey-capacityPerKey, rej)
		}
	}
}
