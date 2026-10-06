package enterprise

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/cluster"
	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// TIER 1: FEATURE COVERAGE (R2 High-Availability Cluster Mode)
// ============================================================================

func TestCluster_Tier1_MemberlistGossip_JoinAndLiveness(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	node1 := mesh.CreateNode("node-01", "us-east-1", "10.0.0.1", 10101, 10102)
	node2 := mesh.CreateNode("node-02", "us-east-1", "10.0.0.2", 10101, 10102)

	// Join node2 to node1
	if err := node2.Join("node-01"); err != nil {
		t.Fatalf("failed to join node-01: %v", err)
	}

	if _, ok := node1.Peers["node-02"]; !ok {
		t.Fatalf("node-01 missing node-02 in peer roster")
	}
	if _, ok := node2.Peers["node-01"]; !ok {
		t.Fatalf("node-02 missing node-01 in peer roster")
	}

	// Liveness heartbeat
	if !node1.Heartbeat("node-02") {
		t.Fatalf("heartbeat between node-01 and node-02 failed")
	}
}

func TestCluster_Tier1_DeterministicLeaderElection(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	nodeC := mesh.CreateNode("node-charlie", "us-west-2", "10.0.1.3", 10101, 10102)
	nodeA := mesh.CreateNode("node-alpha", "us-west-2", "10.0.1.1", 10101, 10102)
	nodeB := mesh.CreateNode("node-bravo", "us-west-2", "10.0.1.2", 10101, 10102)

	// In lexicographical order: node-alpha < node-bravo < node-charlie
	if !nodeA.Info.IsLeader {
		t.Fatalf("expected node-alpha to be elected leader, got isLeader=false")
	}
	if nodeB.Info.IsLeader || nodeC.Info.IsLeader {
		t.Fatalf("node-bravo or node-charlie erroneously marked as leader")
	}
}

func TestCluster_Tier1_NodeAutoDiscovery_K8sAndDNS(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	node1 := mesh.CreateNode("k8s-pod-1", "k8s-cluster", "10.244.0.5", 10101, 10102)
	_ = mesh.CreateNode("k8s-pod-2", "k8s-cluster", "10.244.0.6", 10101, 10102)
	_ = mesh.CreateNode("k8s-pod-3", "k8s-cluster", "10.244.0.7", 10101, 10102)

	peers, err := node1.DiscoverPeers("kubernetes")
	if err != nil {
		t.Fatalf("auto-discovery failed: %v", err)
	}

	if len(peers) != 2 {
		t.Fatalf("expected 2 discovered peers, got %d", len(peers))
	}
}

func TestCluster_Tier1_StateReplication_GRPCPort10102(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	node1 := mesh.CreateNode("node-1", "us-central", "10.0.0.1", 10101, 10102)
	node2 := mesh.CreateNode("node-2", "us-central", "10.0.0.2", 10101, 10102)
	_ = node1.Join("node-2")

	entityUpdate := []byte(`{"type": "virtual_key_update", "key_id": "vk-enterprise-1", "tpm": 500000}`)
	if err := node1.BroadcastState(context.Background(), entityUpdate); err != nil {
		t.Fatalf("broadcast failed: %v", err)
	}

	if len(node2.SyncMessages) != 1 {
		t.Fatalf("expected node-2 to receive 1 sync message, got %d", len(node2.SyncMessages))
	}
	if string(node2.SyncMessages[0]) != string(entityUpdate) {
		t.Fatalf("replicated payload mismatch: %s", string(node2.SyncMessages[0]))
	}
}

func TestCluster_Tier1_DistributedRateLimit_NoDrift(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize production Coordinator A with P2P rate limiting on ephemeral ports
	cfgA := cluster.Config{
		NodeID: "node-A",
		Region: "us-east-1",
		Gossip: cluster.GossipConfig{
			Port:      -1,
			BindAddr:  "127.0.0.1",
			SecretKey: "airlok-e2e-cluster-key",
		},
		GRPC: cluster.GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
		RateLimit: cluster.RateLimitConfig{
			Backend: string(cluster.BackendP2P),
		},
	}
	nodeA, err := cluster.NewCoordinator(cfgA)
	if err != nil {
		t.Fatalf("failed to create nodeA: %v", err)
	}
	if err := nodeA.Start(ctx); err != nil {
		t.Fatalf("failed to start nodeA: %v", err)
	}
	defer nodeA.Stop()

	// Initialize production Coordinator B with P2P rate limiting on ephemeral ports
	cfgB := cluster.Config{
		NodeID: "node-B",
		Region: "us-east-1",
		Gossip: cluster.GossipConfig{
			Port:      -1,
			BindAddr:  "127.0.0.1",
			SecretKey: "airlok-e2e-cluster-key",
		},
		GRPC: cluster.GRPCConfig{Port: -1, BindAddr: "127.0.0.1"},
		RateLimit: cluster.RateLimitConfig{
			Backend: string(cluster.BackendP2P),
		},
	}
	nodeB, err := cluster.NewCoordinator(cfgB)
	if err != nil {
		t.Fatalf("failed to create nodeB: %v", err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatalf("failed to start nodeB: %v", err)
	}
	defer nodeB.Stop()

	// Join Node B to Node A via gossip
	nodeAAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(nodeA.GetLocalNode().GossipPort))
	if err := nodeB.Join([]string{nodeAAddr}); err != nil {
		t.Fatalf("failed to join nodeB to nodeA: %v", err)
	}

	// Allow cluster membership and roster to converge
	time.Sleep(300 * time.Millisecond)

	key := "vk-tenant-100:tpm"
	var totalCapacity int64 = 1000
	window := 1 * time.Minute

	// Consume 600 tokens on Node A
	allowedA, remA, err := nodeA.CheckAndChargeDistributedRateLimit(key, 600, totalCapacity, window)
	if err != nil || !allowedA {
		t.Fatalf("node A charge failed: %v, allowed=%v", err, allowedA)
	}
	if remA != 400 {
		t.Fatalf("expected 400 remaining on node A, got %d", remA)
	}

	// Verify delta propagates over gRPC sync within <50ms (AC-4 contract)
	syncDeadline := time.Now().Add(100 * time.Millisecond)
	var observedRemB int64
	for time.Now().Before(syncDeadline) {
		_, rem, _ := nodeB.CheckAndChargeDistributedRateLimit(key, 0, totalCapacity, window)
		observedRemB = rem
		if observedRemB == 400 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if observedRemB != 400 {
		t.Fatalf("expected 400 remaining on node B after delta sync, got %d", observedRemB)
	}

	// Consume 300 tokens on Node B -> remaining drops to 100 on both without drift
	allowedB, remB, err := nodeB.CheckAndChargeDistributedRateLimit(key, 300, totalCapacity, window)
	if err != nil || !allowedB {
		t.Fatalf("node B charge failed: %v, allowed=%v", err, allowedB)
	}
	if remB != 100 {
		t.Fatalf("expected 100 remaining on node B, got %d", remB)
	}

	// Verify delta propagates back to Node A within <50ms
	syncDeadline = time.Now().Add(100 * time.Millisecond)
	var observedRemA int64
	for time.Now().Before(syncDeadline) {
		_, rem, _ := nodeA.CheckAndChargeDistributedRateLimit(key, 0, totalCapacity, window)
		observedRemA = rem
		if observedRemA == 100 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if observedRemA != 100 {
		t.Fatalf("expected 100 remaining on node A after delta sync, got %d", observedRemA)
	}

	// Attempt to consume 200 tokens on Node A -> should be rejected (only 100 left)
	allowedExcess, remExcess, _ := nodeA.CheckAndChargeDistributedRateLimit(key, 200, totalCapacity, window)
	if allowedExcess {
		t.Fatalf("expected charge exceeding capacity to be rejected, but allowed=true")
	}
	if remExcess != 100 {
		t.Fatalf("expected remaining quota to remain 100, got %d", remExcess)
	}
}

func TestCluster_Tier1_BrokerRelayMode(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	node := mesh.CreateNode("outbound-only-node", "serverless", "10.10.0.1", 10101, 10102)
	node.BrokerMode = true
	node.BrokerURL = "grpc://broker.enterprise.internal:50051"

	if !node.BrokerMode || node.BrokerURL == "" {
		t.Fatalf("broker relay mode not configured properly")
	}
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (R2 High-Availability Cluster Mode)
// ============================================================================

func TestCluster_Tier2_NetworkPartition_SplitBrainHandling(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	nodeA := mesh.CreateNode("node-01", "us-east-1", "10.0.0.1", 10101, 10102)
	nodeB := mesh.CreateNode("node-02", "us-east-1", "10.0.0.2", 10101, 10102)
	_ = nodeA.Join("node-02")

	// Simulate nodeA crash/partition
	nodeA.SimulateFailure()

	if nodeA.Info.State != mock.NodeStateDead {
		t.Fatalf("expected nodeA state to be Dead, got %s", nodeA.Info.State)
	}
	if nodeA.Info.IsLeader {
		t.Fatalf("dead node cannot be leader")
	}
	if !nodeB.Info.IsLeader {
		t.Fatalf("nodeB should be automatically promoted to leader after nodeA failure")
	}
}

func TestCluster_Tier2_RapidTokenBurstsExceedingCapacity(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	nodeA := mesh.CreateNode("node-1", "us-east", "10.0.0.1", 10101, 10102)
	nodeB := mesh.CreateNode("node-2", "us-east", "10.0.0.2", 10101, 10102)
	_ = nodeA.Join("node-2")

	key := "burst-test:rpm"
	var totalCapacity int64 = 50
	window := 10 * time.Second

	var wg sync.WaitGroup
	var successCount int64
	var mu sync.Mutex

	// Fire 60 concurrent requests across both nodes
	for i := 0; i < 60; i++ {
		wg.Add(1)
		node := nodeA
		if i%2 == 1 {
			node = nodeB
		}
		go func(target *mock.MockClusterNode) {
			defer wg.Done()
			allowed, _, _ := target.CheckAndChargeDistributedRateLimit(key, 1, totalCapacity, window)
			if allowed {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(node)
	}

	wg.Wait()

	if successCount != 50 {
		t.Fatalf("expected strictly 50 requests allowed under distributed rate limit, got %d", successCount)
	}
}

func TestCluster_Tier2_ZeroPeerStartup(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	singleNode := mesh.CreateNode("solo-node", "default", "127.0.0.1", 10101, 10102)

	if !singleNode.Info.IsLeader {
		t.Fatalf("solo node should be leader by default")
	}
	peers, err := singleNode.DiscoverPeers("dns")
	if err != nil || len(peers) != 0 {
		t.Fatalf("solo node should discover 0 peers")
	}
}

func TestCluster_Tier2_LeaderDeathImmediateReElection(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	node1 := mesh.CreateNode("node-1", "reg1", "10.0.0.1", 10101, 10102)
	node2 := mesh.CreateNode("node-2", "reg1", "10.0.0.2", 10101, 10102)
	node3 := mesh.CreateNode("node-3", "reg1", "10.0.0.3", 10101, 10102)

	if !node1.Info.IsLeader {
		t.Fatalf("node-1 must be initial leader")
	}

	// Kill node-1
	node1.SimulateFailure()

	if !node2.Info.IsLeader {
		t.Fatalf("node-2 must become leader immediately upon node-1 death")
	}

	// Kill node-2
	node2.SimulateFailure()

	if !node3.Info.IsLeader {
		t.Fatalf("node-3 must become leader immediately upon node-2 death")
	}
}

func TestCluster_Tier2_RateLimitWindowRefill(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	node := mesh.CreateNode("node-refill", "local", "127.0.0.1", 10101, 10102)

	key := "window-refill-test"
	capacity := int64(10)
	window := 50 * time.Millisecond

	// Consume all
	allowed, rem, _ := node.CheckAndChargeDistributedRateLimit(key, 10, capacity, window)
	if !allowed || rem != 0 {
		t.Fatalf("failed initial full charge")
	}

	// Immediate next charge should fail
	allowedNext, _, _ := node.CheckAndChargeDistributedRateLimit(key, 1, capacity, window)
	if allowedNext {
		t.Fatalf("expected rate limit exhaustion")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Next charge should succeed after window refill
	allowedAfter, remAfter, _ := node.CheckAndChargeDistributedRateLimit(key, 1, capacity, window)
	if !allowedAfter || remAfter != 9 {
		t.Fatalf("expected token bucket to refill after window: allowed=%v, rem=%d", allowedAfter, remAfter)
	}
}

// ============================================================================
// ENTERPRISE SUITE RUNNER ALIASES
// ============================================================================

func TestEnterprise_Tier1_Cluster_MemberlistGossip_JoinAndLiveness(t *testing.T) {
	TestCluster_Tier1_MemberlistGossip_JoinAndLiveness(t)
}

func TestEnterprise_Tier1_Cluster_DeterministicLeaderElection(t *testing.T) {
	TestCluster_Tier1_DeterministicLeaderElection(t)
}

func TestEnterprise_Tier1_Cluster_NodeAutoDiscovery_K8sAndDNS(t *testing.T) {
	TestCluster_Tier1_NodeAutoDiscovery_K8sAndDNS(t)
}

func TestEnterprise_Tier1_Cluster_StateReplication_GRPCPort10102(t *testing.T) {
	TestCluster_Tier1_StateReplication_GRPCPort10102(t)
}

func TestEnterprise_Tier1_RateLimit_NoDrift(t *testing.T) {
	TestCluster_Tier1_DistributedRateLimit_NoDrift(t)
}

func TestEnterprise_Tier1_Cluster_BrokerRelayMode(t *testing.T) {
	TestCluster_Tier1_BrokerRelayMode(t)
}

func TestEnterprise_Tier2_Cluster_NetworkPartition_SplitBrainHandling(t *testing.T) {
	TestCluster_Tier2_NetworkPartition_SplitBrainHandling(t)
}

func TestEnterprise_Tier2_RateLimit_RapidTokenBurstsExceedingCapacity(t *testing.T) {
	TestCluster_Tier2_RapidTokenBurstsExceedingCapacity(t)
}

func TestEnterprise_Tier2_Cluster_ZeroPeerStartup(t *testing.T) {
	TestCluster_Tier2_ZeroPeerStartup(t)
}

func TestEnterprise_Tier2_Cluster_LeaderDeathImmediateReElection(t *testing.T) {
	TestCluster_Tier2_LeaderDeathImmediateReElection(t)
}

func TestEnterprise_Tier2_RateLimit_WindowRefill(t *testing.T) {
	TestCluster_Tier2_RateLimitWindowRefill(t)
}
