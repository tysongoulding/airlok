package mock

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type NodeState string

const (
	NodeStateAlive   NodeState = "alive"
	NodeStateSuspect NodeState = "suspect"
	NodeStateDead    NodeState = "dead"
)

type NodeInfo struct {
	NodeID     string    `json:"node_id"`
	Address    string    `json:"address"`
	GossipPort int       `json:"gossip_port"`
	GRPCPort   int       `json:"grpc_port"`
	Region     string    `json:"region"`
	State      NodeState `json:"state"`
	IsLeader   bool      `json:"is_leader"`
	LastSeen   time.Time `json:"last_seen"`
}

// TokenBucket tracks distributed rate limits.
type TokenBucket struct {
	Key        string
	Capacity   int64
	Remaining  int64
	LastRefill time.Time
	Window     time.Duration
}

// MockClusterNode represents an individual gateway node in the cluster mesh.
type MockClusterNode struct {
	mu           sync.RWMutex
	Info         NodeInfo
	Peers        map[string]*NodeInfo
	BrokerMode   bool
	BrokerURL    string
	RateLimits   map[string]*TokenBucket
	SyncMessages [][]byte
	mesh         *MockClusterMesh
}

// MockClusterMesh coordinates horizontal multi-node test environments.
type MockClusterMesh struct {
	mu    sync.RWMutex
	nodes map[string]*MockClusterNode
}

func NewMockClusterMesh() *MockClusterMesh {
	return &MockClusterMesh{
		nodes: make(map[string]*MockClusterNode),
	}
}

// CreateNode adds a node to the mesh with default gossip (10101) and gRPC (10102) configuration.
func (m *MockClusterMesh) CreateNode(nodeID, region, address string, gossipPort, grpcPort int) *MockClusterNode {
	m.mu.Lock()
	defer m.mu.Unlock()

	node := &MockClusterNode{
		Info: NodeInfo{
			NodeID:     nodeID,
			Address:    address,
			GossipPort: gossipPort,
			GRPCPort:   grpcPort,
			Region:     region,
			State:      NodeStateAlive,
			LastSeen:   time.Now(),
		},
		Peers:      make(map[string]*NodeInfo),
		RateLimits: make(map[string]*TokenBucket),
		mesh:       m,
	}
	m.nodes[nodeID] = node
	m.recomputeLeadershipLocked()
	return node
}

func (m *MockClusterMesh) GetNode(nodeID string) (*MockClusterNode, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, exists := m.nodes[nodeID]
	return node, exists
}

func (m *MockClusterMesh) GetAllNodes() []*MockClusterNode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*MockClusterNode, 0, len(m.nodes))
	for _, n := range m.nodes {
		list = append(list, n)
	}
	return list
}

func (m *MockClusterMesh) recomputeLeadershipLocked() {
	var aliveIDs []string
	for id, n := range m.nodes {
		if n.Info.State == NodeStateAlive {
			aliveIDs = append(aliveIDs, id)
		}
		n.Info.IsLeader = false
	}
	if len(aliveIDs) == 0 {
		return
	}
	sort.Strings(aliveIDs)
	leaderID := aliveIDs[0] // Lexicographical deterministic election
	if leader, ok := m.nodes[leaderID]; ok {
		leader.Info.IsLeader = true
	}
}

// Join connects this node with peer addresses via simulated gossip discovery.
func (n *MockClusterNode) Join(peerNodeIDs ...string) error {
	n.mesh.mu.Lock()
	defer n.mesh.mu.Unlock()

	for _, pid := range peerNodeIDs {
		peerNode, exists := n.mesh.nodes[pid]
		if !exists {
			return fmt.Errorf("peer node %s not found in mesh", pid)
		}
		n.Peers[pid] = &peerNode.Info
		peerNode.Peers[n.Info.NodeID] = &n.Info
	}
	n.mesh.recomputeLeadershipLocked()
	return nil
}

// DiscoverPeers simulates automated discovery (e.g., DNS, K8s, UDP).
func (n *MockClusterNode) DiscoverPeers(discoveryType string) ([]string, error) {
	n.mesh.mu.RLock()
	defer n.mesh.mu.RUnlock()

	discovered := make([]string, 0)
	for id, peer := range n.mesh.nodes {
		if id != n.Info.NodeID && peer.Info.State == NodeStateAlive {
			discovered = append(discovered, id)
		}
	}
	return discovered, nil
}

// Heartbeat simulates periodic gossip ping.
func (n *MockClusterNode) Heartbeat(peerID string) bool {
	n.mesh.mu.RLock()
	defer n.mesh.mu.RUnlock()

	peer, ok := n.mesh.nodes[peerID]
	if !ok || peer.Info.State == NodeStateDead {
		return false
	}
	peer.Info.LastSeen = time.Now()
	return true
}

// SimulateFailure marks node as dead and triggers cluster re-election.
func (n *MockClusterNode) SimulateFailure() {
	n.mesh.mu.Lock()
	defer n.mesh.mu.Unlock()

	n.Info.State = NodeStateDead
	n.Info.IsLeader = false
	n.mesh.recomputeLeadershipLocked()
}

// BroadcastState replicates entity updates across active peers over simulated gRPC port 10102.
func (n *MockClusterNode) BroadcastState(ctx context.Context, payload []byte) error {
	n.mesh.mu.RLock()
	defer n.mesh.mu.RUnlock()

	for _, peer := range n.mesh.nodes {
		if peer.Info.NodeID != n.Info.NodeID && peer.Info.State == NodeStateAlive {
			peer.mu.Lock()
			peer.SyncMessages = append(peer.SyncMessages, payload)
			peer.mu.Unlock()
		}
	}
	return nil
}

// CheckAndChargeDistributedRateLimit provides distributed token bucket sync across nodes.
func (n *MockClusterNode) CheckAndChargeDistributedRateLimit(key string, amount int64, capacity int64, window time.Duration) (bool, int64, error) {
	n.mesh.mu.Lock()
	defer n.mesh.mu.Unlock()

	now := time.Now()
	bucket, exists := n.RateLimits[key]
	if !exists {
		bucket = &TokenBucket{
			Key:        key,
			Capacity:   capacity,
			Remaining:  capacity,
			LastRefill: now,
			Window:     window,
		}
		n.RateLimits[key] = bucket
	}

	// Refill if window passed
	if now.Sub(bucket.LastRefill) >= bucket.Window {
		bucket.Remaining = bucket.Capacity
		bucket.LastRefill = now
	}

	if bucket.Remaining < amount {
		return false, bucket.Remaining, nil
	}

	bucket.Remaining -= amount

	// Synchronize to all nodes in mesh without drift
	for _, peer := range n.mesh.nodes {
		if peer.Info.NodeID != n.Info.NodeID && peer.Info.State == NodeStateAlive {
			peer.mu.Lock()
			peerBucket, pExists := peer.RateLimits[key]
			if !pExists {
				peer.RateLimits[key] = &TokenBucket{
					Key:        key,
					Capacity:   capacity,
					Remaining:  bucket.Remaining,
					LastRefill: bucket.LastRefill,
					Window:     window,
				}
			} else {
				peerBucket.Remaining = bucket.Remaining
				peerBucket.LastRefill = bucket.LastRefill
			}
			peer.mu.Unlock()
		}
	}

	return true, bucket.Remaining, nil
}
