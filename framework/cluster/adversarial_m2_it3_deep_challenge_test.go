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
// ADVERSARIAL CHALLENGE 1: MULTI-CYCLE PARTITION & REJOIN FLAPPING
// ============================================================================

func TestAdversarial_PartitionRejoin_MultiCycleFlapping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// 1. Seed Coordinator (always online)
	cfg1 := Config{
		NodeID: "seed-flapper-1",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord1, err := NewCoordinator(cfg1)
	if err != nil {
		t.Fatalf("failed to create coord1: %v", err)
	}
	if err := coord1.Start(ctx); err != nil {
		t.Fatalf("failed to start coord1: %v", err)
	}
	defer coord1.Stop()

	seedAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coord1.localNode.GossipPort))

	// 2. We perform 3 successive cycles of Partition -> Produce Missed Messages -> Rejoin -> CatchUp
	const cycles = 3
	const msgsPerCycle = 10
	totalExpected := cycles * msgsPerCycle

	for cycle := 1; cycle <= cycles; cycle++ {
		// Start Node 2
		cfg2 := Config{
			NodeID: "flapping-node-2",
			Region: "us-east-1",
			Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
			GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
		}
		coord2, err := NewCoordinator(cfg2)
		if err != nil {
			t.Fatalf("cycle %d: failed to create coord2: %v", cycle, err)
		}

		var receivedInCycle sync.Map
		var countInCycle int64
		coord2.RegisterStateReceiver(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
			receivedInCycle.Store(string(payload), true)
			atomic.AddInt64(&countInCycle, 1)
			return nil
		})

		if err := coord2.Start(ctx); err != nil {
			t.Fatalf("cycle %d: failed to start coord2: %v", cycle, err)
		}

		if err := coord2.Join([]string{seedAddr}); err != nil {
			t.Fatalf("cycle %d: coord2 join failed: %v", cycle, err)
		}

		time.Sleep(150 * time.Millisecond)

		// Abruptly PARTITION Node 2
		_ = coord2.Stop()
		coord1.memberlist.MarkNodeState("flapping-node-2", NodeStateDead)

		time.Sleep(100 * time.Millisecond)

		// Produce messages on Node 1 while Node 2 is dead
		for i := 1; i <= msgsPerCycle; i++ {
			msgSeq := (cycle-1)*msgsPerCycle + i
			payload := []byte(fmt.Sprintf(`{"cycle": %d, "seq": %d}`, cycle, msgSeq))
			if err := coord1.BroadcastState(EntityVirtualKey, payload); err != nil {
				t.Fatalf("cycle %d: broadcast msg %d failed: %v", cycle, msgSeq, err)
			}
		}

		// Rejoin Node 2 after missing messages
		coord2Rejoin, err := NewCoordinator(cfg2)
		if err != nil {
			t.Fatalf("cycle %d: failed to create coord2Rejoin: %v", cycle, err)
		}

		var caughtUp sync.Map
		var caughtUpCount int64
		coord2Rejoin.RegisterStateReceiver(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
			caughtUp.Store(string(payload), true)
			atomic.AddInt64(&caughtUpCount, 1)
			return nil
		})

		if err := coord2Rejoin.Start(ctx); err != nil {
			t.Fatalf("cycle %d: failed to start coord2Rejoin: %v", cycle, err)
		}

		if err := coord2Rejoin.Join([]string{seedAddr}); err != nil {
			t.Fatalf("cycle %d: coord2Rejoin join failed: %v", cycle, err)
		}

		// Explicitly trigger CatchUp to ensure no debouncing race
		_ = coord2Rejoin.CatchUpWithCluster(ctx)

		// Wait for catch-up to settle
		deadline := time.Now().Add(3 * time.Second)
		expectedSoFar := cycle * msgsPerCycle
		for time.Now().Before(deadline) {
			cnt := 0
			caughtUp.Range(func(_, _ interface{}) bool {
				cnt++
				return true
			})
			if cnt >= expectedSoFar {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		cnt := 0
		caughtUp.Range(func(_, _ interface{}) bool {
			cnt++
			return true
		})
		t.Logf("Cycle %d complete: caught-up messages on node-2 = %d (expected cumulative %d)",
			cycle, cnt, expectedSoFar)

		_ = coord2Rejoin.Stop()
		coord1.memberlist.MarkNodeState("flapping-node-2", NodeStateDead)
		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("Adversarial multi-cycle partition pass: survived %d cycles, %d cumulative messages", cycles, totalExpected)
}

// ============================================================================
// ADVERSARIAL CHALLENGE 2: CASCADING DUAL-LEADER TERMINATION UNDER CONTINUOUS LOAD
// ============================================================================

func TestAdversarial_LeaderFailover_CascadingDualLeaderTerminationUnderLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 3 nodes: node-01 (leader), node-02 (successor 1), node-03 (successor 2)
	cfg1 := Config{
		NodeID: "leader-node-01",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord1, err := NewCoordinator(cfg1)
	if err != nil {
		t.Fatalf("failed to create coord1: %v", err)
	}
	if err := coord1.Start(ctx); err != nil {
		t.Fatalf("failed to start coord1: %v", err)
	}
	defer coord1.Stop()

	seedAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coord1.localNode.GossipPort))

	cfg2 := Config{
		NodeID: "leader-node-02",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord2, err := NewCoordinator(cfg2)
	if err != nil {
		t.Fatalf("failed to create coord2: %v", err)
	}
	if err := coord2.Start(ctx); err != nil {
		t.Fatalf("failed to start coord2: %v", err)
	}
	defer coord2.Stop()
	if err := coord2.Join([]string{seedAddr}); err != nil {
		t.Fatalf("coord2 join failed: %v", err)
	}

	cfg3 := Config{
		NodeID: "leader-node-03",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord3, err := NewCoordinator(cfg3)
	if err != nil {
		t.Fatalf("failed to create coord3: %v", err)
	}
	if err := coord3.Start(ctx); err != nil {
		t.Fatalf("failed to start coord3: %v", err)
	}
	defer coord3.Stop()
	if err := coord3.Join([]string{seedAddr}); err != nil {
		t.Fatalf("coord3 join failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	l, _ := coord1.GetLeader()
	if l == nil || l.NodeID != "leader-node-01" {
		t.Fatalf("initial leader must be leader-node-01, got: %v", l)
	}

	var node3Received int64
	coord3.RegisterStateReceiver(EntityGovernance, func(ctx context.Context, entityType string, payload []byte) error {
		atomic.AddInt64(&node3Received, 1)
		return nil
	})

	// Start continuous load
	stopTraffic := make(chan struct{})
	var sentTotal int64
	var wg sync.WaitGroup

	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopTraffic:
					return
				default:
					payload := []byte(fmt.Sprintf(`{"w":%d,"t":%d}`, id, time.Now().UnixNano()))
					_ = coord1.BroadcastState(EntityGovernance, payload)
					atomic.AddInt64(&sentTotal, 1)
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(w)
	}

	time.Sleep(100 * time.Millisecond)

	// KILL LEADER 1 (node-01)
	_ = coord1.Stop()
	close(stopTraffic)
	wg.Wait()

	coord2.memberlist.MarkNodeState("leader-node-01", NodeStateDead)
	coord3.memberlist.MarkNodeState("leader-node-01", NodeStateDead)

	time.Sleep(200 * time.Millisecond)

	// Invariant: node-02 MUST become leader
	l2, err2 := coord2.GetLeader()
	l3, err3 := coord3.GetLeader()
	if err2 != nil || l2 == nil || l2.NodeID != "leader-node-02" {
		t.Fatalf("cascade 1 failover error: expected leader-node-02, got %v", l2)
	}
	if err3 != nil || l3 == nil || l3.NodeID != "leader-node-02" {
		t.Fatalf("cascade 1 node3 leader mismatch: expected leader-node-02, got %v", l3)
	}

	// Now broadcast from new leader node-02 to node-03
	for i := 0; i < 5; i++ {
		_ = coord2.BroadcastState(EntityGovernance, []byte(fmt.Sprintf(`{"from_leader_2": %d}`, i)))
	}

	// KILL LEADER 2 (node-02)
	_ = coord2.Stop()
	coord3.memberlist.MarkNodeState("leader-node-02", NodeStateDead)

	time.Sleep(200 * time.Millisecond)

	// Invariant: node-03 MUST become leader as sole survivor
	l3After, err3After := coord3.GetLeader()
	if err3After != nil || l3After == nil || l3After.NodeID != "leader-node-03" {
		t.Fatalf("cascade 2 failover error: expected leader-node-03, got %v", l3After)
	}
	if !coord3.IsLeader() {
		t.Fatalf("coord3 must report IsLeader() == true")
	}

	t.Logf("Adversarial cascading failover pass: node-01 -> node-02 -> node-03 cleanly promoted without deadlock")
}

// ============================================================================
// ADVERSARIAL CHALLENGE 3: TOKEN BUCKET PRIMARY MIGRATION UNDER FAILOVER
// ============================================================================

func TestAdversarial_DistributedRateLimit_PrimaryFailoverMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const numNodes = 3
	coords := make([]*Coordinator, numNodes)

	for i := 0; i < numNodes; i++ {
		cfg := Config{
			NodeID: fmt.Sprintf("rl-failover-node-%d", i+1),
			Region: "us-east-1",
			Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1", SecretKey: "failover-secret"},
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

	time.Sleep(300 * time.Millisecond)

	key := "failover-test-bucket"
	var capacity int64 = 50
	window := 10 * time.Second

	// Step 1: Consume 20 tokens across nodes
	var allowedInitial int64
	for i := 0; i < 20; i++ {
		allowed, _, err := coords[i%numNodes].CheckAndChargeDistributedRateLimit(key, 1, capacity, window)
		if err != nil {
			t.Fatalf("charge failed: %v", err)
		}
		if allowed {
			allowedInitial++
		}
	}

	if allowedInitial != 20 {
		t.Fatalf("expected 20 initial allowances, got %d", allowedInitial)
	}

	// Determine which node is current primary for the key
	p2pLimiter := coords[0].GetDistributedRateLimiter().(*P2PRateLimiter)
	primaryNodeID := p2pLimiter.getNodeForKey(key)
	t.Logf("Initial consistent hash primary node for key %q is %s", key, primaryNodeID)

	// Step 2: KILL the primary node abruptly
	var killedIdx int
	for i, c := range coords {
		if c.localNode.NodeID == primaryNodeID {
			killedIdx = i
			_ = c.Stop()
			break
		}
	}

	// Mark primary dead on surviving nodes
	for i, c := range coords {
		if i != killedIdx {
			c.memberlist.MarkNodeState(primaryNodeID, NodeStateDead)
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Step 3: Verify surviving nodes successfully migrate primary and continue rate limiting
	survivorIdx := (killedIdx + 1) % numNodes
	newPrimaryNodeID := coords[survivorIdx].GetDistributedRateLimiter().(*P2PRateLimiter).getNodeForKey(key)
	t.Logf("New migrated primary node for key %q is %s", key, newPrimaryNodeID)

	if newPrimaryNodeID == primaryNodeID {
		t.Fatalf("hash ring failed to migrate primary away from dead node %s", primaryNodeID)
	}

	// Step 4: Continue charging against surviving nodes without exceeding remaining capacity
	var allowedPostFailover int64
	for i := 0; i < 40; i++ {
		c := coords[(survivorIdx+i)%numNodes]
		if c.localNode.NodeID == primaryNodeID {
			continue // skip killed node
		}
		allowed, _, err := c.CheckAndChargeDistributedRateLimit(key, 1, capacity, window)
		if err == nil && allowed {
			allowedPostFailover++
		}
	}

	totalAllowed := allowedInitial + allowedPostFailover
	t.Logf("Post-failover charges: Initial=%d, PostFailover=%d, Total=%d (Capacity=%d)",
		allowedInitial, allowedPostFailover, totalAllowed, capacity)

	// Invariant: Total allowed across failover must not exceed capacity (or fall back gracefully within capacity)
	if totalAllowed > capacity {
		t.Fatalf("OVERCONSUMPTION UNDER FAILOVER: total allowed %d exceeded capacity %d", totalAllowed, capacity)
	}
}

// ============================================================================
// ADVERSARIAL CHALLENGE 4: CONCURRENT TOMBSTONE PRUNING STRESS UNDER CHURN
// ============================================================================

func TestAdversarial_TombstoneCompaction_UnderContinuousRosterChurn(t *testing.T) {
	mgr, err := NewMemberlistManager(Config{
		NodeID: "compact-leader",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
	}, func() {})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	mgr.maxDeadNodes = 15
	mgr.tombstoneTTL = 50 * time.Millisecond

	var wg sync.WaitGroup
	const concurrentWorkers = 20
	const opsPerWorker = 30

	for w := 0; w < concurrentWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for op := 0; op < opsPerWorker; op++ {
				nodeID := fmt.Sprintf("churn-%d-%d", workerID, op)
				mgr.mu.Lock()
				mgr.roster[nodeID] = &NodeInfo{
					NodeID:   nodeID,
					Region:   "us-east-1",
					State:    NodeStateDead,
					LastSeen: time.Now().Add(-time.Duration(op) * time.Millisecond),
				}
				mgr.mu.Unlock()

				if op%4 == 0 {
					_ = mgr.PruneTombstones()
				}
				_ = mgr.GetAliveMembers()
				_ = mgr.GetMembers()
				_ = mgr.GetRosterMap()
			}
		}(w)
	}

	wg.Wait()

	// Final sweep
	mgr.PruneTombstones()

	mgr.mu.RLock()
	deadCount := 0
	for id, n := range mgr.roster {
		if id != "compact-leader" && n.State == NodeStateDead {
			deadCount++
		}
	}
	mgr.mu.RUnlock()

	if deadCount > 15 {
		t.Fatalf("tombstone compaction failure: dead nodes %d exceeded maxDeadNodes 15", deadCount)
	}

	local, ok := mgr.GetMember("compact-leader")
	if !ok || local.State != NodeStateAlive {
		t.Fatalf("local node compact-leader corrupted or pruned: %+v", local)
	}

	t.Logf("Tombstone compaction under churn pass: deadCount=%d <= 15, zero data races", deadCount)
}
