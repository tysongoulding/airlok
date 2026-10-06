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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ============================================================================
// CHALLENGE 1: NODE CHURN & FLAPPING UNDER RACE DETECTOR
// ============================================================================

func TestChallenge_NodeChurnAndFlapping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Seed coordinator
	seedCfg := Config{
		NodeID: "node-seed",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	seedCoord, err := NewCoordinator(seedCfg)
	if err != nil {
		t.Fatalf("failed to create seed coordinator: %v", err)
	}
	if err := seedCoord.Start(ctx); err != nil {
		t.Fatalf("failed to start seed coordinator: %v", err)
	}
	defer seedCoord.Stop()

	seedGossipAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(seedCoord.localNode.GossipPort))

	// Rapidly join and ungracefully stop 5 flapping nodes in concurrent loops
	var wg sync.WaitGroup
	flappingCount := 5
	iterationsPerNode := 3

	for i := 0; i < flappingCount; i++ {
		wg.Add(1)
		go func(nodeIdx int) {
			defer wg.Done()
			for iter := 0; iter < iterationsPerNode; iter++ {
				nodeID := fmt.Sprintf("churn-node-%d-%d", nodeIdx, iter)
				cfg := Config{
					NodeID: nodeID,
					Region: "us-east-1",
					Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
					GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
				}
				coord, err := NewCoordinator(cfg)
				if err != nil {
					t.Errorf("failed to create coord %s: %v", nodeID, err)
					return
				}
				if err := coord.Start(ctx); err != nil {
					t.Errorf("failed to start coord %s: %v", nodeID, err)
					return
				}

				// Join cluster
				if err := coord.Join([]string{seedGossipAddr}); err != nil {
					t.Logf("join error (expected under rapid churn): %v", err)
				}

				// Small jitter to simulate brief activity
				time.Sleep(50 * time.Millisecond)

				// Ungracefully kill the node (Stop without Leave)
				_ = coord.Stop()
			}
		}(i)
	}

	wg.Wait()

	// Ensure seed coordinator is still alive and responsive, no deadlocks
	nodes := seedCoord.GetNodes()
	t.Logf("Seed coordinator survived churn; roster size: %d", len(nodes))

	leader, err := seedCoord.GetLeader()
	if err != nil || leader == nil {
		t.Fatalf("seed coordinator lost leadership state: %v", err)
	}
	if leader.NodeID != "node-seed" && leader.State != NodeStateAlive {
		t.Fatalf("elected leader is dead or invalid: %+v", leader)
	}
}

// ============================================================================
// CHALLENGE 1B: SAME NODE ID FLAPPING & UNGRACEFUL REJOIN
// ============================================================================

func TestChallenge_SameNodeIDFlapping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	seedCfg := Config{
		NodeID: "seed-flapping",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: 22101, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: 22102, BindAddr: "127.0.0.1"},
	}
	seedCoord, err := NewCoordinator(seedCfg)
	if err != nil {
		t.Fatalf("failed to create seed coordinator: %v", err)
	}
	if err := seedCoord.Start(ctx); err != nil {
		t.Fatalf("failed to start seed coordinator: %v", err)
	}
	defer seedCoord.Stop()

	// Repeatedly start, crash, and restart a node with the EXACT same NodeID
	flapperID := "flapping-node"
	for round := 1; round <= 3; round++ {
		flapperCfg := Config{
			NodeID: flapperID,
			Region: "us-east-1",
			Gossip: GossipConfig{Port: 22201, BindAddr: "127.0.0.1"},
			GRPC:   GRPCConfig{Port: 22202, BindAddr: "127.0.0.1"},
		}
		flapperCoord, err := NewCoordinator(flapperCfg)
		if err != nil {
			t.Fatalf("round %d: failed to create flapper: %v", round, err)
		}
		if err := flapperCoord.Start(ctx); err != nil {
			t.Fatalf("round %d: failed to start flapper: %v", round, err)
		}

		if err := flapperCoord.Join([]string{"127.0.0.1:22101"}); err != nil {
			t.Logf("round %d join error: %v", round, err)
		}

		time.Sleep(100 * time.Millisecond)

		// Abrupt ungraceful termination
		_ = flapperCoord.Stop()
		time.Sleep(100 * time.Millisecond)
	}
}

// ============================================================================

func TestChallenge_LeaderFailoverUnderLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Node 1: "node-01" (Lexicographical Leader)
	cfg1 := Config{
		NodeID: "node-01",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: 21101, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: 21102, BindAddr: "127.0.0.1"},
	}
	coord1, err := NewCoordinator(cfg1)
	if err != nil {
		t.Fatalf("failed to create coord1: %v", err)
	}
	if err := coord1.Start(ctx); err != nil {
		t.Fatalf("failed to start coord1: %v", err)
	}
	defer coord1.Stop()

	addr1 := "127.0.0.1:21101"

	// Node 2: "node-02"
	cfg2 := Config{
		NodeID: "node-02",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: 21201, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: 21202, BindAddr: "127.0.0.1"},
	}
	coord2, err := NewCoordinator(cfg2)
	if err != nil {
		t.Fatalf("failed to create coord2: %v", err)
	}
	if err := coord2.Start(ctx); err != nil {
		t.Fatalf("failed to start coord2: %v", err)
	}
	defer coord2.Stop()
	if err := coord2.Join([]string{addr1}); err != nil {
		t.Fatalf("coord2 join failed: %v", err)
	}

	// Node 3: "node-03"
	cfg3 := Config{
		NodeID: "node-03",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: 21301, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: 21302, BindAddr: "127.0.0.1"},
	}
	coord3, err := NewCoordinator(cfg3)
	if err != nil {
		t.Fatalf("failed to create coord3: %v", err)
	}
	if err := coord3.Start(ctx); err != nil {
		t.Fatalf("failed to start coord3: %v", err)
	}
	defer coord3.Stop()
	if err := coord3.Join([]string{addr1}); err != nil {
		t.Fatalf("coord3 join failed: %v", err)
	}

	// Wait for convergence
	time.Sleep(300 * time.Millisecond)

	l1, _ := coord1.GetLeader()
	l2, _ := coord2.GetLeader()
	l3, _ := coord3.GetLeader()
	if l1 == nil || l2 == nil || l3 == nil || l1.NodeID != "node-01" || l2.NodeID != "node-01" || l3.NodeID != "node-01" {
		t.Fatalf("initial leader mismatch: l1=%v, l2=%v, l3=%v", l1, l2, l3)
	}

	// Track replicated state on surviving nodes
	var node2Count int64
	var node3Count int64
	coord2.RegisterStateReceiver(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
		atomic.AddInt64(&node2Count, 1)
		return nil
	})
	coord3.RegisterStateReceiver(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
		atomic.AddInt64(&node3Count, 1)
		return nil
	})

	// Start heavy in-flight broadcast traffic from node-01
	var broadcastWG sync.WaitGroup
	var broadcastSent int64
	stopBroadcast := make(chan struct{})

	for i := 0; i < 8; i++ {
		broadcastWG.Add(1)
		go func(workerID int) {
			defer broadcastWG.Done()
			for {
				select {
				case <-stopBroadcast:
					return
				default:
					payload := []byte(fmt.Sprintf(`{"worker": %d, "ts": %d}`, workerID, time.Now().UnixNano()))
					_ = coord1.BroadcastState(EntityVirtualKey, payload)
					atomic.AddInt64(&broadcastSent, 1)
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	// Let traffic ramp up
	time.Sleep(150 * time.Millisecond)

	// FORCIBLY TERMINATE LEADER (coord1)
	_ = coord1.Stop()
	close(stopBroadcast)
	broadcastWG.Wait()

	// Simulate memberlist failure detection on surviving nodes
	coord2.memberlist.MarkNodeState("node-01", NodeStateDead)
	coord3.memberlist.MarkNodeState("node-01", NodeStateDead)

	time.Sleep(200 * time.Millisecond)

	// Check leadership failover: successor MUST be "node-02"
	newL2, err2 := coord2.GetLeader()
	newL3, err3 := coord3.GetLeader()

	if err2 != nil || newL2 == nil || newL2.NodeID != "node-02" {
		t.Fatalf("coord2 failed to elect node-02 as successor: %v, leader=%v", err2, newL2)
	}
	if err3 != nil || newL3 == nil || newL3.NodeID != "node-02" {
		t.Fatalf("coord3 failed to elect node-02 as successor: %v, leader=%v", err3, newL3)
	}

	if !coord2.IsLeader() {
		t.Fatalf("coord2 should report IsLeader() == true")
	}
	if coord3.IsLeader() {
		t.Fatalf("coord3 should report IsLeader() == false")
	}

	// Verify new leader can broadcast without deadlock
	for _, m := range coord2.memberlist.GetMembers() {
		t.Logf("coord2 member: ID=%s, State=%s, Addr=%s, GRPCPort=%d", m.NodeID, m.State, m.Address, m.GRPCPort)
	}
	testPayload := []byte(`{"from": "new-leader-node-02"}`)
	if err := coord2.BroadcastState(EntityVirtualKey, testPayload); err != nil {
		t.Fatalf("new leader failed to broadcast: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	t.Logf("Leader failover succeeded under load. Sent: %d, Received on Node 2: %d, Node 3: %d",
		atomic.LoadInt64(&broadcastSent), atomic.LoadInt64(&node2Count), atomic.LoadInt64(&node3Count))
}

// ============================================================================
// CHALLENGE 3: CLUSTER PARTITION, SPLIT-BRAIN & HEALING
// ============================================================================

func TestChallenge_ClusterPartition_SplitBrainAndHealing(t *testing.T) {
	// 4 nodes in a single election manager simulation
	em1 := NewElectionManager("node-01", "us-east-1")
	em2 := NewElectionManager("node-02", "us-east-1")
	em3 := NewElectionManager("node-03", "us-east-1")
	em4 := NewElectionManager("node-04", "us-east-1")

	// Global initial roster
	fullRoster := map[string]*NodeInfo{
		"node-01": {NodeID: "node-01", Region: "us-east-1", State: NodeStateAlive},
		"node-02": {NodeID: "node-02", Region: "us-east-1", State: NodeStateAlive},
		"node-03": {NodeID: "node-03", Region: "us-east-1", State: NodeStateAlive},
		"node-04": {NodeID: "node-04", Region: "us-east-1", State: NodeStateAlive},
	}

	em1.Reevaluate(fullRoster)
	em2.Reevaluate(fullRoster)
	em3.Reevaluate(fullRoster)
	em4.Reevaluate(fullRoster)

	if em1.GetLeaderID() != "node-01" || em2.GetLeaderID() != "node-01" ||
		em3.GetLeaderID() != "node-01" || em4.GetLeaderID() != "node-01" {
		t.Fatalf("initial cluster leader must be node-01")
	}

	// PARTITION: Split into Side A {node-01, node-02} and Side B {node-03, node-04}
	rosterA := map[string]*NodeInfo{
		"node-01": {NodeID: "node-01", Region: "us-east-1", State: NodeStateAlive},
		"node-02": {NodeID: "node-02", Region: "us-east-1", State: NodeStateAlive},
		"node-03": {NodeID: "node-03", Region: "us-east-1", State: NodeStateDead}, // unreachable from A
		"node-04": {NodeID: "node-04", Region: "us-east-1", State: NodeStateDead}, // unreachable from A
	}

	rosterB := map[string]*NodeInfo{
		"node-01": {NodeID: "node-01", Region: "us-east-1", State: NodeStateDead}, // unreachable from B
		"node-02": {NodeID: "node-02", Region: "us-east-1", State: NodeStateDead}, // unreachable from B
		"node-03": {NodeID: "node-03", Region: "us-east-1", State: NodeStateAlive},
		"node-04": {NodeID: "node-04", Region: "us-east-1", State: NodeStateAlive},
	}

	em1.Reevaluate(rosterA)
	em2.Reevaluate(rosterA)
	em3.Reevaluate(rosterB)
	em4.Reevaluate(rosterB)

	// Side A should elect node-01
	if em1.GetLeaderID() != "node-01" || em2.GetLeaderID() != "node-01" {
		t.Fatalf("Partition A leader should be node-01, got %s and %s", em1.GetLeaderID(), em2.GetLeaderID())
	}
	// Side B should elect node-03
	if em3.GetLeaderID() != "node-03" || em4.GetLeaderID() != "node-03" {
		t.Fatalf("Partition B leader should be node-03, got %s and %s", em3.GetLeaderID(), em4.GetLeaderID())
	}

	// HEAL PARTITION: Network reconnects, all nodes see each other again
	healedRoster := map[string]*NodeInfo{
		"node-01": {NodeID: "node-01", Region: "us-east-1", State: NodeStateAlive},
		"node-02": {NodeID: "node-02", Region: "us-east-1", State: NodeStateAlive},
		"node-03": {NodeID: "node-03", Region: "us-east-1", State: NodeStateAlive},
		"node-04": {NodeID: "node-04", Region: "us-east-1", State: NodeStateAlive},
	}

	em1.Reevaluate(healedRoster)
	em2.Reevaluate(healedRoster)
	em3.Reevaluate(healedRoster)
	em4.Reevaluate(healedRoster)

	// All nodes MUST deterministically reconverge to node-01 with zero split brain
	if em1.GetLeaderID() != "node-01" || em2.GetLeaderID() != "node-01" ||
		em3.GetLeaderID() != "node-01" || em4.GetLeaderID() != "node-01" {
		t.Fatalf("Healed cluster failed to reconcile split-brain to single leader: em1=%s, em2=%s, em3=%s, em4=%s",
			em1.GetLeaderID(), em2.GetLeaderID(), em3.GetLeaderID(), em4.GetLeaderID())
	}
}

// ============================================================================
// CHALLENGE 4: HISTORY CATCH-UP RING BUFFER & REJOIN
// ============================================================================

func TestChallenge_HistoryCatchUpRingBuffer_DirectRPC(t *testing.T) {
	ctx := context.Background()

	// Server with history ring buffer
	serverNode := NewGRPCSyncManager("node-server", "us-east", -1, "127.0.0.1", 5*time.Minute)
	if err := serverNode.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer serverNode.Stop()

	// Record 10 messages into server history via BroadcastSyncMessage
	for i := 1; i <= 10; i++ {
		msg := NewSyncMessage("node-server", "us-east", EntityVirtualKey, fmt.Sprintf("vk-%d", i), ActionUpsert, []byte(fmt.Sprintf(`{"value": %d}`, i)))
		// Broadcast without peers records into s.history ring buffer
		_ = serverNode.BroadcastSyncMessage(ctx, msg, nil)
	}

	// Verify server has 10 messages in ring buffer
	serverNode.historyMu.RLock()
	histLen := len(serverNode.history)
	serverNode.historyMu.RUnlock()
	if histLen != 10 {
		t.Fatalf("expected 10 messages in history buffer, got %d", histLen)
	}

	// Dial server over gRPC and invoke /bifrost.cluster.v1.SyncService/CatchUp stream
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverNode.Port())
	conn, err := grpc.DialContext(ctx, serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "CatchUp",
		ServerStreams: true,
	}, "/bifrost.cluster.v1.SyncService/CatchUp")
	if err != nil {
		t.Fatalf("failed to open CatchUp stream: %v", err)
	}

	var replayedMsgs []*SyncMessage
	for {
		var data []byte
		err := stream.RecvMsg(&data)
		if err != nil {
			break // EOF
		}
		msg, err := UnmarshalSyncMessage(data)
		if err != nil {
			t.Fatalf("failed to unmarshal caught-up message: %v", err)
		}
		replayedMsgs = append(replayedMsgs, msg)
	}

	if len(replayedMsgs) != 10 {
		t.Fatalf("expected 10 replayed messages, got %d", len(replayedMsgs))
	}
	if replayedMsgs[0].EntityID != "vk-1" || replayedMsgs[9].EntityID != "vk-10" {
		t.Fatalf("unexpected message ordering in catch-up replay: first=%s, last=%s", replayedMsgs[0].EntityID, replayedMsgs[9].EntityID)
	}
}

// ============================================================================
// CHALLENGE 5: STATE CATCH-UP ON NODE REJOIN AFTER PARTITION
// ============================================================================

func TestChallenge_StateCatchUpOnNodeRejoinAfterPartition(t *testing.T) {
	ctx := context.Background()

	// Node 1 (online continuously)
	cfg1 := Config{
		NodeID: "node-1",
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

	addr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(coord1.localNode.GossipPort))

	// Node 2 (joins initially, then disconnects)
	cfg2 := Config{
		NodeID: "node-2",
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
	if err := coord2.Join([]string{addr1}); err != nil {
		t.Fatalf("coord2 initial join failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// PARTITION: Stop Node 2 completely
	_ = coord2.Stop()
	coord1.memberlist.MarkNodeState("node-2", NodeStateDead)

	// While Node 2 is offline, Node 1 produces 5 state updates
	for i := 1; i <= 5; i++ {
		payload := []byte(fmt.Sprintf(`{"update": %d}`, i))
		_ = coord1.BroadcastState(EntityVirtualKey, payload)
	}

	// Verify Node 1 recorded them in catch-up ring buffer
	coord1.syncGRPC.historyMu.RLock()
	hLen := len(coord1.syncGRPC.history)
	coord1.syncGRPC.historyMu.RUnlock()
	if hLen < 5 {
		t.Fatalf("expected at least 5 messages in coord1 history, got %d", hLen)
	}

	// REJOIN: Node 2 restarts and rejoins Node 1
	coord2Restarted, err := NewCoordinator(cfg2)
	if err != nil {
		t.Fatalf("failed to create coord2 restarted: %v", err)
	}
	var node2Received sync.Map
	coord2Restarted.RegisterStateReceiver(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
		node2Received.Store(string(payload), true)
		return nil
	})

	if err := coord2Restarted.Start(ctx); err != nil {
		t.Fatalf("failed to start coord2 restarted: %v", err)
	}
	defer coord2Restarted.Stop()

	if err := coord2Restarted.Join([]string{addr1}); err != nil {
		t.Fatalf("coord2 rejoin failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	// Check whether Node 2 received the missed messages
	receivedCount := 0
	node2Received.Range(func(key, value interface{}) bool {
		receivedCount++
		return true
	})

	t.Logf("Rejoined node-2 received %d of 5 missed messages automatically", receivedCount)
	if receivedCount < 5 {
		t.Errorf("adversarial challenge failure: rejoining node-2 failed to synchronize history via catch-up buffer; received %d/5 missed messages", receivedCount)
	}
}

// ============================================================================
// CHALLENGE 6: DISTRIBUTED RATE LIMITING UNDER CONCURRENT CHURN & PARTITION
// ============================================================================

func TestChallenge_RateLimit_UnderPartitionAndChurn(t *testing.T) {
	ctx := context.Background()

	// Mesh coordinator
	cfg := Config{
		NodeID: "rl-node-1",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: 23101, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: 23102, BindAddr: "127.0.0.1"},
	}
	coord, err := NewCoordinator(cfg)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}
	if err := coord.Start(ctx); err != nil {
		t.Fatalf("failed to start coordinator: %v", err)
	}
	defer coord.Stop()

	// Initialize P2PRateLimiter
	rlCfg := RateLimiterConfig{
		Backend:   BackendP2P,
		KeyPrefix: "airlok:rl:",
		NodeID:    "rl-node-1",
	}
	limiter, err := NewP2PRateLimiter(rlCfg, coord)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer limiter.Close()

	key := "stress-test-bucket"
	var totalCapacity int64 = 100
	window := 10 * time.Second

	// Concurrent burst of 150 requests against capacity 100 while marking peers dead/alive
	var wg sync.WaitGroup
	var allowedCount int64
	var mu sync.Mutex

	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%10 == 0 {
				// Simulate roster churn concurrently with rate-limiting
				coord.memberlist.MarkNodeState(fmt.Sprintf("churn-%d", idx), NodeStateDead)
			}
			allowed, _, _, err := limiter.CheckAndCharge(ctx, key, 1, window, totalCapacity)
			if err != nil {
				return
			}
			if allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if allowedCount > totalCapacity {
		t.Fatalf("rate limit oversubscribed under churn! Capacity: %d, Allowed: %d", totalCapacity, allowedCount)
	}
	t.Logf("Rate limit under churn: allowed %d / %d (strictly <= capacity)", allowedCount, totalCapacity)
}

