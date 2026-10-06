package enterprise

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// ADVERSARIAL CHALLENGE 1: ZERO-DRIFT INVARIANT UNDER 5-NODE CONCURRENT BURST
// ============================================================================

func TestAdversarial_ZeroDrift_5NodeConcurrentBurst(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	const numNodes = 5
	nodes := make([]*mock.MockClusterNode, numNodes)

	for i := 0; i < numNodes; i++ {
		nodeID := fmt.Sprintf("node-%02d", i+1)
		nodes[i] = mesh.CreateNode(nodeID, "us-east-1", fmt.Sprintf("10.0.0.%d", i+1), 10101, 10102)
	}

	// Full mesh join
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i != j {
				if err := nodes[i].Join(nodes[j].Info.NodeID); err != nil {
					t.Fatalf("node %s failed to join node %s: %v", nodes[i].Info.NodeID, nodes[j].Info.NodeID, err)
				}
			}
		}
	}

	key := "adversarial-shared-bucket:tpm"
	const totalCapacity int64 = 100
	window := 10 * time.Second

	const requestsPerNode = 50
	const totalRequests = numNodes * requestsPerNode // 250 concurrent requests against 100 limit

	var startGate sync.WaitGroup
	startGate.Add(1)

	var doneWg sync.WaitGroup
	var successCount int64
	var rejectedCount int64

	for nodeIdx := 0; nodeIdx < numNodes; nodeIdx++ {
		for reqIdx := 0; reqIdx < requestsPerNode; reqIdx++ {
			doneWg.Add(1)
			go func(targetNode *mock.MockClusterNode) {
				defer doneWg.Done()
				startGate.Wait() // Synchronize all 250 goroutines to burst simultaneously

				allowed, _, err := targetNode.CheckAndChargeDistributedRateLimit(key, 1, totalCapacity, window)
				if err != nil {
					t.Errorf("unexpected error on charge: %v", err)
					return
				}
				if allowed {
					atomic.AddInt64(&successCount, 1)
				} else {
					atomic.AddInt64(&rejectedCount, 1)
				}
			}(nodes[nodeIdx])
		}
	}

	// Release all 250 concurrent requests simultaneously across all 5 nodes
	startGate.Done()
	doneWg.Wait()

	t.Logf("Empirical Burst Results: Successes=%d, Rejections=%d (Total=%d, Capacity=%d)",
		successCount, rejectedCount, totalRequests, totalCapacity)

	// Invariant 1: Exactly totalCapacity requests succeeded
	if successCount != totalCapacity {
		t.Fatalf("VIOLATION: Expected exactly %d successes, got %d (drift=%d)",
			totalCapacity, successCount, successCount-totalCapacity)
	}

	// Invariant 2: Exactly (totalRequests - totalCapacity) requests were rejected
	expectedRejections := int64(totalRequests) - totalCapacity
	if rejectedCount != expectedRejections {
		t.Fatalf("VIOLATION: Expected exactly %d rejections, got %d", expectedRejections, rejectedCount)
	}

	// Invariant 3: Zero-drift across all 5 nodes — querying remaining on every node must return 0
	for i, node := range nodes {
		_, rem, err := node.CheckAndChargeDistributedRateLimit(key, 0, totalCapacity, window)
		if err != nil {
			t.Fatalf("VIOLATION: Failed to query remaining on node %d: %v", i+1, err)
		}
		if rem != 0 {
			t.Fatalf("VIOLATION: Node %d has non-zero remaining tokens: %d (expected 0, drift detected)",
				i+1, rem)
		}
	}

	// Invariant 4: 101st request from ANY node MUST be rejected with remaining 0
	for _, node := range nodes {
		allowed, rem, err := node.CheckAndChargeDistributedRateLimit(key, 1, totalCapacity, window)
		if err != nil {
			t.Fatalf("unexpected error on 101st request check: %v", err)
		}
		if allowed {
			t.Fatalf("VIOLATION: Post-burst 101st request succeeded on node %s! (allowed=true, rem=%d)",
				node.Info.NodeID, rem)
		}
		if rem != 0 {
			t.Fatalf("VIOLATION: Post-burst remaining quota on node %s is %d, expected 0",
				node.Info.NodeID, rem)
		}
	}
}

// ============================================================================
// ADVERSARIAL CHALLENGE 2: CROSS-NODE SYNC DELAY VERIFICATION (<50MS)
// ============================================================================

func TestAdversarial_CrossNodeSyncDelay_Under50ms(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	nodeA := mesh.CreateNode("node-sync-A", "us-east-1", "10.0.0.1", 10101, 10102)
	nodeB := mesh.CreateNode("node-sync-B", "us-east-1", "10.0.0.2", 10101, 10102)
	nodeC := mesh.CreateNode("node-sync-C", "us-west-2", "10.0.0.3", 10101, 10102)
	_ = nodeA.Join("node-sync-B", "node-sync-C")

	key := "sync-delay-verification:rpm"
	const capacity int64 = 100
	window := 1 * time.Minute

	// Sequential charges measuring replication delay to remote nodes
	steps := []struct {
		chargingNode *mock.MockClusterNode
		chargeAmount int64
		expectedRem  int64
	}{
		{nodeA, 25, 75},
		{nodeB, 30, 45},
		{nodeC, 20, 25},
		{nodeA, 25, 0},
	}

	for stepIdx, step := range steps {
		t0 := time.Now()
		allowed, remLocal, err := step.chargingNode.CheckAndChargeDistributedRateLimit(key, step.chargeAmount, capacity, window)
		if err != nil || !allowed {
			t.Fatalf("step %d charge failed: allowed=%v, err=%v", stepIdx+1, allowed, err)
		}
		if remLocal != step.expectedRem {
			t.Fatalf("step %d local remaining mismatch: got %d, expected %d", stepIdx+1, remLocal, step.expectedRem)
		}

		// Verify remote nodes reflect the new remaining quota within <50ms
		remoteNodes := []*mock.MockClusterNode{nodeA, nodeB, nodeC}
		for _, remote := range remoteNodes {
			syncDeadline := time.Now().Add(50 * time.Millisecond)
			synced := false
			var observedRem int64

			for time.Now().Before(syncDeadline) {
				_, rem, err := remote.CheckAndChargeDistributedRateLimit(key, 0, capacity, window)
				if err == nil && rem == step.expectedRem {
					observedRem = rem
					synced = true
					break
				}
				time.Sleep(100 * time.Microsecond)
			}

			syncDelay := time.Since(t0)
			t.Logf("Step %d -> Remote node %s sync delay: %v (observed=%d, expected=%d)",
				stepIdx+1, remote.Info.NodeID, syncDelay, observedRem, step.expectedRem)

			if !synced {
				t.Fatalf("VIOLATION: Remote node %s failed to synchronize rate limit within 50ms (delay=%v, observed=%d, expected=%d)",
					remote.Info.NodeID, syncDelay, observedRem, step.expectedRem)
			}
			if syncDelay >= 50*time.Millisecond {
				t.Fatalf("VIOLATION: Sync delay exceeded 50ms threshold: %v", syncDelay)
			}
		}
	}
}
