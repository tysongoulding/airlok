package cluster

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// FEATURE 10: P2P MEMBERLIST GOSSIP PROTOCOL & LIFECYCLE
// ============================================================================

func TestCluster_MemberlistGossip_JoinAndLiveness(t *testing.T) {
	// Node 1
	cfg1 := Config{
		NodeID: "node-01",
		Region: "us-east-1",
		Gossip: GossipConfig{
			Port:      -1, // Ephemeral port for test safety
			BindAddr:  "127.0.0.1",
			SecretKey: "super-secret-cluster-key",
		},
		GRPC: GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord1, err := NewCoordinator(cfg1)
	if err != nil {
		t.Fatalf("failed to create coord1: %v", err)
	}
	if err := coord1.Start(context.Background()); err != nil {
		t.Fatalf("failed to start coord1: %v", err)
	}
	defer coord1.Stop()

	// Node 2
	cfg2 := Config{
		NodeID: "node-02",
		Region: "us-east-1",
		Gossip: GossipConfig{
			Port:      -1,
			BindAddr:  "127.0.0.1",
			SecretKey: "super-secret-cluster-key",
		},
		GRPC: GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord2, err := NewCoordinator(cfg2)
	if err != nil {
		t.Fatalf("failed to create coord2: %v", err)
	}
	if err := coord2.Start(context.Background()); err != nil {
		t.Fatalf("failed to start coord2: %v", err)
	}
	defer coord2.Stop()

	// Join node2 to node1
	node1Addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coord1.localNode.GossipPort))
	if err := coord2.Join([]string{node1Addr}); err != nil {
		t.Fatalf("coord2 failed to join coord1: %v", err)
	}

	// Verify both nodes see each other in roster
	time.Sleep(300 * time.Millisecond)

	nodes1 := coord1.GetNodes()
	if len(nodes1) < 2 {
		t.Fatalf("expected coord1 to have at least 2 nodes, got %d", len(nodes1))
	}

	nodes2 := coord2.GetNodes()
	if len(nodes2) < 2 {
		t.Fatalf("expected coord2 to have at least 2 nodes, got %d", len(nodes2))
	}

	// Verify heartbeat
	if !coord1.Heartbeat("node-02") {
		t.Fatalf("heartbeat between node-01 and node-02 failed")
	}
}

// ============================================================================
// FEATURE 13: DETERMINISTIC LEADER ELECTION
// ============================================================================

func TestCluster_DeterministicLeaderElection(t *testing.T) {
	em := NewElectionManager("node-alpha", "us-west-2")

	nodes := map[string]*NodeInfo{
		"node-charlie": {NodeID: "node-charlie", Region: "us-west-2", State: NodeStateAlive},
		"node-alpha":   {NodeID: "node-alpha", Region: "us-west-2", State: NodeStateAlive},
		"node-bravo":   {NodeID: "node-bravo", Region: "us-west-2", State: NodeStateAlive},
	}

	changed, leader := em.Reevaluate(nodes)
	if !changed || leader == nil {
		t.Fatalf("expected leader election to produce a leader")
	}

	// Lexicographical ordering: node-alpha < node-bravo < node-charlie
	if leader.NodeID != "node-alpha" {
		t.Fatalf("expected node-alpha to be elected leader, got %s", leader.NodeID)
	}
	if !em.IsLeader() {
		t.Fatalf("expected em.IsLeader() to be true for node-alpha")
	}

	// Kill node-alpha
	nodes["node-alpha"].State = NodeStateDead
	changed, newLeader := em.Reevaluate(nodes)
	if !changed || newLeader == nil {
		t.Fatalf("expected leader re-election on node-alpha death")
	}
	if newLeader.NodeID != "node-bravo" {
		t.Fatalf("expected node-bravo to become leader, got %s", newLeader.NodeID)
	}

	// Kill node-bravo
	nodes["node-bravo"].State = NodeStateDead
	changed, nextLeader := em.Reevaluate(nodes)
	if !changed || nextLeader == nil {
		t.Fatalf("expected leader re-election on node-bravo death")
	}
	if nextLeader.NodeID != "node-charlie" {
		t.Fatalf("expected node-charlie to become leader, got %s", nextLeader.NodeID)
	}
}

func TestCluster_RegionalLeaderElection(t *testing.T) {
	em := NewElectionManager("node-us-1", "us-east")

	nodes := map[string]*NodeInfo{
		"node-us-2": {NodeID: "node-us-2", Region: "us-east", State: NodeStateAlive},
		"node-us-1": {NodeID: "node-us-1", Region: "us-east", State: NodeStateAlive},
		"node-eu-2": {NodeID: "node-eu-2", Region: "eu-west", State: NodeStateAlive},
		"node-eu-1": {NodeID: "node-eu-1", Region: "eu-west", State: NodeStateAlive},
	}

	em.Reevaluate(nodes)

	// In us-east: node-us-1 < node-us-2 -> node-us-1 is regional leader
	if em.GetRegionalLeaderID("us-east") != "node-us-1" {
		t.Fatalf("expected us-east regional leader to be node-us-1, got %s", em.GetRegionalLeaderID("us-east"))
	}
	// In eu-west: node-eu-1 < node-eu-2 -> node-eu-1 is regional leader
	if em.GetRegionalLeaderID("eu-west") != "node-eu-1" {
		t.Fatalf("expected eu-west regional leader to be node-eu-1, got %s", em.GetRegionalLeaderID("eu-west"))
	}
	if !em.IsRegionalLeader() {
		t.Fatalf("expected local node node-us-1 to be regional leader for us-east")
	}
}

// ============================================================================
// FEATURE 12: NODE AUTO-DISCOVERY PROVIDERS
// ============================================================================

func TestCluster_DiscoveryProviders(t *testing.T) {
	ctx := context.Background()

	// 1. Static Discovery
	static := NewStaticDiscovery([]string{"10.0.0.1:10101", "10.0.0.2:10101"})
	peers, err := static.Discover(ctx)
	if err != nil || len(peers) != 2 {
		t.Fatalf("static discovery failed: len=%d, err=%v", len(peers), err)
	}

	// 2. DNS Discovery
	dns := NewDNSDiscovery([]string{"127.0.0.1:10101"}, 10101)
	dnsPeers, err := dns.Discover(ctx)
	if err != nil {
		t.Fatalf("dns discovery error: %v", err)
	}
	if len(dnsPeers) == 0 {
		t.Fatalf("expected dns peers, got 0")
	}

	// 3. UDP Discovery
	udp := NewUDPDiscovery(10103, []string{"127.0.0.0/8"})
	_ = udp.Register(ctx, NodeInfo{Address: "127.0.0.1", GossipPort: 10101})
	udpPeers, err := udp.Discover(ctx)
	if err != nil || len(udpPeers) != 1 {
		t.Fatalf("udp discovery failed: len=%d, err=%v", len(udpPeers), err)
	}

	// 4. Kubernetes Discovery (in non-k8s fallback)
	k8s := NewKubernetesDiscovery("bifrost-cluster", "default", "app=bifrost", 10101)
	_, _ = k8s.Discover(ctx)

	// 5. Discovery Manager Adaptive Backoff
	dm := NewDiscoveryManager(DiscoveryConfig{
		Enabled:  true,
		DNSNames: []string{"127.0.0.1:10101"},
		BindPort: 10101,
	}, nil)
	defer dm.Close()

	allPeers, err := dm.DiscoverAll(ctx)
	if err != nil || len(allPeers) == 0 {
		t.Fatalf("discover all failed: len=%d, err=%v", len(allPeers), err)
	}
}

// ============================================================================
// FEATURE 11: gRPC APPLICATION STATE SYNC (PORT 10102) & CONFLICT RESOLUTION
// ============================================================================

func TestCluster_StateReplication_GRPCPort10102(t *testing.T) {
	ctx := context.Background()

	// Start Node 1 Sync Server on ephemeral port
	node1 := NewGRPCSyncManager("node-1", "us-east-1", -1, "127.0.0.1", 5*time.Minute)
	if err := node1.Start(); err != nil {
		t.Fatalf("failed to start node1 sync: %v", err)
	}
	defer node1.Stop()

	// Start Node 2 Sync Server on ephemeral port
	node2 := NewGRPCSyncManager("node-2", "us-east-1", -1, "127.0.0.1", 5*time.Minute)
	if err := node2.Start(); err != nil {
		t.Fatalf("failed to start node2 sync: %v", err)
	}
	defer node2.Stop()

	// Register entity handler on node 2
	var receivedPayload []byte
	var receivedMu sync.Mutex
	node2.RegisterHandler(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
		receivedMu.Lock()
		receivedPayload = payload
		receivedMu.Unlock()
		return nil
	})

	entityUpdate := []byte(`{"type": "virtual_key_update", "key_id": "vk-enterprise-1", "tpm": 500000}`)
	peerAddr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(node2.Port()))

	// Broadcast from node 1 to node 2
	if err := node1.BroadcastState(ctx, EntityVirtualKey, entityUpdate, []string{peerAddr2}); err != nil {
		t.Fatalf("broadcast failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	receivedMu.Lock()
	defer receivedMu.Unlock()
	if string(receivedPayload) != string(entityUpdate) {
		t.Fatalf("replicated payload mismatch: got %s, expected %s", string(receivedPayload), string(entityUpdate))
	}
}

func TestCluster_StateSync_DedupAndLWWConflictResolution(t *testing.T) {
	ctx := context.Background()
	mgr := NewGRPCSyncManager("local-node", "us-east", 0, "127.0.0.1", 5*time.Minute)

	handlerCount := 0
	mgr.RegisterHandler("virtual_key", func(ctx context.Context, entityType string, payload []byte) error {
		handlerCount++
		return nil
	})

	// 1. Initial write with timestamp T1
	msg1 := &SyncMessage{
		MessageID:   "msg-001",
		EntityType:  "virtual_key",
		EntityID:    "vk-1",
		TimestampNs: 1000,
		Payload:     []byte(`{"rate_limit": 100}`),
	}
	ack1 := mgr.ProcessIncomingMessage(ctx, msg1)
	if ack1.Status != AckStatusOK {
		t.Fatalf("expected msg1 status OK, got %d", ack1.Status)
	}
	if handlerCount != 1 {
		t.Fatalf("expected handler invoked once, got %d", handlerCount)
	}

	// 2. Duplicate write of msg1 (same MessageID) within 5-minute TTL -> must return AckStatusDuplicate
	ackDup := mgr.ProcessIncomingMessage(ctx, msg1)
	if ackDup.Status != AckStatusDuplicate {
		t.Fatalf("expected duplicate message to return AckStatusDuplicate, got %d", ackDup.Status)
	}
	if handlerCount != 1 {
		t.Fatalf("handler should not have been invoked for duplicate message")
	}

	// 3. Stale update for vk-1 with older timestamp T0 (500 < 1000) -> must reject under LWW
	msgStale := &SyncMessage{
		MessageID:   "msg-002",
		EntityType:  "virtual_key",
		EntityID:    "vk-1",
		TimestampNs: 500, // Older than 1000!
		Payload:     []byte(`{"rate_limit": 50}`),
	}
	ackStale := mgr.ProcessIncomingMessage(ctx, msgStale)
	if ackStale.Status != AckStatusStale {
		t.Fatalf("expected older timestamp update to return AckStatusStale under LWW, got %d", ackStale.Status)
	}

	// 4. Newer update for vk-1 with timestamp T2 (2000 > 1000) -> must succeed under LWW
	msgNew := &SyncMessage{
		MessageID:   "msg-003",
		EntityType:  "virtual_key",
		EntityID:    "vk-1",
		TimestampNs: 2000,
		Payload:     []byte(`{"rate_limit": 200}`),
	}
	ackNew := mgr.ProcessIncomingMessage(ctx, msgNew)
	if ackNew.Status != AckStatusOK {
		t.Fatalf("expected newer timestamp update to succeed under LWW, got %d", ackNew.Status)
	}
	if handlerCount != 2 {
		t.Fatalf("expected handler invoked for newer update, got %d", handlerCount)
	}
}

// ============================================================================
// FEATURE 14: CENTRALIZED BROKER RELAY MODE (PORT 50051)
// ============================================================================

func TestCluster_BrokerRelayMode_7TrafficLanes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Broker Server on ephemeral port
	broker := NewBrokerServer(0, "127.0.0.1", "broker-auth-secret")
	if err := broker.Start(); err != nil {
		t.Fatalf("failed to start broker: %v", err)
	}
	defer broker.Stop()

	brokerAddr := fmt.Sprintf("127.0.0.1:%d", broker.Port())

	var client2Received sync.Map

	// Connect Client 1 (outbound only)
	client1 := NewBrokerClient(brokerAddr, "node-client-1", "serverless", "broker-auth-secret", false, nil, nil)
	if err := client1.Connect(ctx); err != nil {
		t.Fatalf("client1 connect failed: %v", err)
	}
	defer client1.Close()

	// Connect Client 2 (outbound only)
	client2 := NewBrokerClient(brokerAddr, "node-client-2", "serverless", "broker-auth-secret", false, func(msg *SyncMessage) {
		client2Received.Store(msg.EntityType, string(msg.Payload))
	}, nil)
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("client2 connect failed: %v", err)
	}
	defer client2.Close()

	time.Sleep(300 * time.Millisecond)

	// Send messages across all 7 traffic lanes from Client 1
	lanes := []TrafficLane{
		LaneGeneral,
		LaneHeartbeat,
		LaneGovernance,
		LaneKVStore,
		LaneCircuitBreaker,
		LaneLoadBalancer,
		LaneDiagnostic,
	}

	for _, lane := range lanes {
		msg := NewSyncMessage("node-client-1", "serverless", fmt.Sprintf("entity-%s", lane.String()), "id", ActionUpsert, []byte(lane.String()))
		if err := client1.SendMessage(lane, msg); err != nil {
			t.Fatalf("failed to send message on lane %s: %v", lane.String(), err)
		}
	}

	time.Sleep(400 * time.Millisecond)

	// Verify Client 2 received messages
	for _, lane := range lanes {
		entity := fmt.Sprintf("entity-%s", lane.String())
		val, ok := client2Received.Load(entity)
		if !ok || val.(string) != lane.String() {
			t.Fatalf("client2 did not receive payload on lane %s", lane.String())
		}
	}
}

// ============================================================================
// FEATURE 15: DISTRIBUTED RATE-LIMIT SYNCHRONIZATION WITHOUT DRIFT
// ============================================================================

func TestCluster_DistributedRateLimit_TokenBucketMath(t *testing.T) {
	bucket := NewInMemTokenBucket("vk-test", 1000, 1*time.Minute)
	now := time.Now()

	// Consume 600
	allowed, rem, _, _ := bucket.CheckAndCharge(now, 600, 1000, 1*time.Minute)
	if !allowed || rem != 400 {
		t.Fatalf("charge 600 failed: allowed=%v, rem=%d", allowed, rem)
	}

	// Consume 300 -> remaining drops to 100
	allowed, rem, _, _ = bucket.CheckAndCharge(now, 300, 1000, 1*time.Minute)
	if !allowed || rem != 100 {
		t.Fatalf("charge 300 failed: allowed=%v, rem=%d", allowed, rem)
	}

	// Consume 200 -> rejected (only 100 left)
	allowed, rem, _, _ = bucket.CheckAndCharge(now, 200, 1000, 1*time.Minute)
	if allowed || rem != 100 {
		t.Fatalf("excess charge allowed=%v, rem=%d", allowed, rem)
	}

	// Advance past window -> bucket refills to 1000
	future := now.Add(65 * time.Second)
	allowed, rem, _, _ = bucket.CheckAndCharge(future, 100, 1000, 1*time.Minute)
	if !allowed || rem != 900 {
		t.Fatalf("refilled charge failed: allowed=%v, rem=%d", allowed, rem)
	}
}

func TestCluster_DistributedRateLimit_ConcurrentBursts(t *testing.T) {
	bucket := NewInMemTokenBucket("burst-key", 50, 10*time.Second)
	now := time.Now()

	var wg sync.WaitGroup
	var successCount int64
	var mu sync.Mutex

	// Fire 60 concurrent requests for capacity 50
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, _, _ := bucket.CheckAndCharge(now, 1, 50, 10*time.Second)
			if allowed {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if successCount != 50 {
		t.Fatalf("expected strictly 50 concurrent requests allowed, got %d", successCount)
	}
}

func TestCluster_P2PRateLimiter_ConsistentHashAndDelta(t *testing.T) {
	cfg := RateLimiterConfig{
		Backend:   BackendP2P,
		KeyPrefix: "airlok:rl:",
		NodeID:    "node-primary",
	}
	limiter, err := NewP2PRateLimiter(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create P2PRateLimiter: %v", err)
	}
	defer limiter.Close()

	ctx := context.Background()
	key := "vk-tenant-100:tpm"
	var totalCapacity int64 = 1000
	window := 1 * time.Minute

	// Charge 600
	allowed, rem, _, err := limiter.CheckAndCharge(ctx, key, 600, window, totalCapacity)
	if err != nil || !allowed || rem != 400 {
		t.Fatalf("charge failed: allowed=%v, rem=%d, err=%v", allowed, rem, err)
	}

	// Charge 300
	allowed, rem, _, err = limiter.CheckAndCharge(ctx, key, 300, window, totalCapacity)
	if err != nil || !allowed || rem != 100 {
		t.Fatalf("charge failed: allowed=%v, rem=%d, err=%v", allowed, rem, err)
	}

	// Charge 200 (exceeds)
	allowed, rem, _, err = limiter.CheckAndCharge(ctx, key, 200, window, totalCapacity)
	if allowed || rem != 100 {
		t.Fatalf("excess charge allowed=%v, rem=%d", allowed, rem)
	}
}

// ============================================================================
// KVSTORE DELEGATE INTEGRATION
// ============================================================================

func TestCluster_KVStoreDelegate(t *testing.T) {
	cfg := Config{
		NodeID: "delegate-node",
		Region: "us-east",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
	}
	coord, err := NewCoordinator(cfg)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}
	if err := coord.Start(context.Background()); err != nil {
		t.Fatalf("failed to start coordinator: %v", err)
	}
	defer coord.Stop()

	delegate := NewClusterKVStoreDelegate(coord)
	delegate.OnSet("cache:key1", []byte(`"value1"`), time.Now().UnixNano(), 0)
	delegate.OnDelete("cache:key1", time.Now().UnixNano())
}

// ============================================================================
// ADAPTIVE CLOCK JITTER TOLERANCE & MULTI-NODE P2P SYNC
// ============================================================================

func TestCluster_InMemTokenBucket_ClockJitterTolerance(t *testing.T) {
	window := 1 * time.Minute
	var capacity int64 = 1000
	now := time.Now()

	// Bucket on Node A created at now
	bucketA := NewInMemTokenBucket("vk-jitter-test", capacity, window)
	bucketA.LastRefill = now

	// Bucket on Node B created with 50ms clock offset
	bucketB := NewInMemTokenBucket("vk-jitter-test", capacity, window)
	bucketB.LastRefill = now.Add(50 * time.Millisecond)

	// Node A charges 600 tokens -> remaining = 400
	allowedA, remA, _, _ := bucketA.CheckAndCharge(now, 600, capacity, window)
	if !allowedA || remA != 400 {
		t.Fatalf("node A charge failed: rem=%d", remA)
	}

	// Node B receives Node A's delta with LastRefill = now (50ms before bucketB.LastRefill)
	bucketB.UpdateRemoteSync(remA, bucketA.LastRefill, window)

	// Verify bucket B accepted delta despite clock offset
	if bucketB.Remaining != 400 {
		t.Fatalf("expected bucket B to accept delta and have 400 remaining, got %d", bucketB.Remaining)
	}

	// Node B charges 300 tokens -> remaining = 100
	allowedB, remB, _, _ := bucketB.CheckAndCharge(now.Add(100*time.Millisecond), 300, capacity, window)
	if !allowedB || remB != 100 {
		t.Fatalf("node B charge failed: rem=%d", remB)
	}

	// Node A receives Node B's delta -> remaining = 100
	bucketA.UpdateRemoteSync(remB, bucketB.LastRefill, window)
	if bucketA.Remaining != 100 {
		t.Fatalf("expected bucket A to accept delta and have 100 remaining, got %d", bucketA.Remaining)
	}

	// Node A attempts 200 charge -> rejected (only 100 remaining)
	allowedExcess, remExcess, _, _ := bucketA.CheckAndCharge(now.Add(200*time.Millisecond), 200, capacity, window)
	if allowedExcess || remExcess != 100 {
		t.Fatalf("expected excess charge rejection: allowed=%v, rem=%d", allowedExcess, remExcess)
	}
}

func TestCluster_P2PRateLimiter_MultiNodeSync(t *testing.T) {
	ctx := context.Background()

	cfg1 := Config{
		NodeID: "node-rl-1",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1", SecretKey: "test-secret"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
		RateLimit: RateLimitConfig{
			Backend: string(BackendP2P),
		},
	}
	coord1, err := NewCoordinator(cfg1)
	if err != nil {
		t.Fatalf("failed to create coord1: %v", err)
	}
	if err := coord1.Start(ctx); err != nil {
		t.Fatalf("failed to start coord1: %v", err)
	}
	defer coord1.Stop()

	cfg2 := Config{
		NodeID: "node-rl-2",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1", SecretKey: "test-secret"},
		GRPC:   GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
		RateLimit: RateLimitConfig{
			Backend: string(BackendP2P),
		},
	}
	coord2, err := NewCoordinator(cfg2)
	if err != nil {
		t.Fatalf("failed to create coord2: %v", err)
	}
	if err := coord2.Start(ctx); err != nil {
		t.Fatalf("failed to start coord2: %v", err)
	}
	defer coord2.Stop()

	coord1Addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(coord1.localNode.GossipPort))
	if err := coord2.Join([]string{coord1Addr}); err != nil {
		t.Fatalf("coord2 failed to join coord1: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	key := "vk-cluster-p2p:tpm"
	var totalCapacity int64 = 1000
	window := 1 * time.Minute

	// Charge 600 on node 1
	allowed1, rem1, err := coord1.CheckAndChargeDistributedRateLimit(key, 600, totalCapacity, window)
	if err != nil || !allowed1 || rem1 != 400 {
		t.Fatalf("node 1 charge failed: allowed=%v, rem=%d, err=%v", allowed1, rem1, err)
	}

	// Verify delta propagates to node 2 within 100ms
	deadline := time.Now().Add(100 * time.Millisecond)
	var observedRem2 int64
	for time.Now().Before(deadline) {
		_, rem, _ := coord2.CheckAndChargeDistributedRateLimit(key, 0, totalCapacity, window)
		observedRem2 = rem
		if observedRem2 == 400 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if observedRem2 != 400 {
		t.Fatalf("expected node 2 to see 400 remaining after delta, got %d", observedRem2)
	}

	// Charge 300 on node 2 -> should deduct from 400 to 100
	allowed2, rem2, err := coord2.CheckAndChargeDistributedRateLimit(key, 300, totalCapacity, window)
	if err != nil || !allowed2 || rem2 != 100 {
		t.Fatalf("node 2 charge failed: allowed=%v, rem=%d, err=%v", allowed2, rem2, err)
	}

	// Verify delta propagates back to node 1 within 100ms
	deadline = time.Now().Add(100 * time.Millisecond)
	var observedRem1 int64
	for time.Now().Before(deadline) {
		_, rem, _ := coord1.CheckAndChargeDistributedRateLimit(key, 0, totalCapacity, window)
		observedRem1 = rem
		if observedRem1 == 100 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if observedRem1 != 100 {
		t.Fatalf("expected node 1 to see 100 remaining after delta, got %d", observedRem1)
	}

	// Excess charge of 200 on node 1 -> should fail (remaining is 100)
	allowedExcess, remExcess, _ := coord1.CheckAndChargeDistributedRateLimit(key, 200, totalCapacity, window)
	if allowedExcess || remExcess != 100 {
		t.Fatalf("expected charge rejection: allowed=%v, rem=%d", allowedExcess, remExcess)
	}
}

func TestCluster_InMemTokenBucket_ConcurrentCheckAndChargeAndUpdateRemoteSync_RaceFree(t *testing.T) {
	bucket := NewInMemTokenBucket("race-free-key", 100, 10*time.Second)
	const numOps = 500
	var wg sync.WaitGroup

	// Goroutines performing CheckAndCharge
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				_, _, _, refill := bucket.CheckAndCharge(time.Now(), 1, 100, 10*time.Second)
				_ = refill.UnixNano()
			}
		}()
	}

	// Goroutines performing UpdateRemoteSync
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				bucket.UpdateRemoteSync(int64(j%100), time.Now(), 10*time.Second)
			}
		}()
	}

	// Goroutines reading GetLastRefill and GetRemaining
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				_ = bucket.GetLastRefill()
				_ = bucket.GetRemaining()
			}
		}()
	}

	wg.Wait()
}
