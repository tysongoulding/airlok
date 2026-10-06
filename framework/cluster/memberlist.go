package cluster

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// MemberlistManager encapsulates the HashiCorp memberlist gossip engine on port 10101,
// maintaining cluster liveness, node lifecycle, and encryption.
type MemberlistManager struct {
	mu             sync.RWMutex
	cfg            Config
	ml             *memberlist.Memberlist
	roster         map[string]*NodeInfo // node_id -> NodeInfo
	localNode      NodeInfo
	listeners      []MembershipListener
	onRosterChange func()
	stopCh         chan struct{}
	closeOnce      sync.Once

	// Tombstone pruning parameters
	tombstoneTTL  time.Duration
	maxDeadNodes  int
	pruneInterval time.Duration
}

// NewMemberlistManager initializes memberlist configuration and delegates.
func NewMemberlistManager(cfg Config, onRosterChange func()) (*MemberlistManager, error) {
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("node_id is required")
	}

	gossipPort := cfg.Gossip.Port
	if gossipPort == 0 {
		gossipPort = 10101
	} else if gossipPort < 0 {
		gossipPort = 0
	}

	grpcPort := cfg.GRPC.Port
	if grpcPort == 0 {
		grpcPort = 10102
	} else if grpcPort < 0 {
		grpcPort = 0
	}

	bindAddr := cfg.Gossip.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	tombstoneTTL := 5 * time.Minute
	if cfg.Gossip.Config.TombstoneTTLSeconds > 0 {
		tombstoneTTL = time.Duration(cfg.Gossip.Config.TombstoneTTLSeconds) * time.Second
	}

	maxDeadNodes := 100
	if cfg.Gossip.Config.MaxDeadNodes > 0 {
		maxDeadNodes = cfg.Gossip.Config.MaxDeadNodes
	}

	pruneInterval := 30 * time.Second
	if cfg.Gossip.Config.PruneIntervalSeconds > 0 {
		pruneInterval = time.Duration(cfg.Gossip.Config.PruneIntervalSeconds) * time.Second
	}

	mgr := &MemberlistManager{
		cfg:    cfg,
		roster: make(map[string]*NodeInfo),
		localNode: NodeInfo{
			NodeID:       cfg.NodeID,
			Address:      bindAddr,
			GossipPort:   gossipPort,
			GRPCPort:     grpcPort,
			Region:       cfg.Region,
			State:        NodeStateAlive,
			LastSeen:     time.Now(),
			Capabilities: []string{"ack:v1"},
		},
		onRosterChange: onRosterChange,
		stopCh:         make(chan struct{}),
		tombstoneTTL:  tombstoneTTL,
		maxDeadNodes:  maxDeadNodes,
		pruneInterval: pruneInterval,
	}

	// Always seed local node into roster
	mgr.roster[cfg.NodeID] = &mgr.localNode

	return mgr, nil
}

// Start binds memberlist sockets and starts gossip communication.
func (m *MemberlistManager) Start() error {
	mlConfig := memberlist.DefaultLANConfig()
	mlConfig.Name = m.cfg.NodeID

	if m.cfg.Gossip.BindAddr != "" {
		mlConfig.BindAddr = m.cfg.Gossip.BindAddr
	}
	bindPort := m.cfg.Gossip.Port
	if bindPort <= 0 {
		freePort, err := getFreePort(m.cfg.Gossip.BindAddr)
		if err == nil {
			bindPort = freePort
		} else {
			bindPort = 10101
		}
	}
	mlConfig.BindPort = bindPort
	if m.cfg.Gossip.AdvertiseAddr != "" {
		mlConfig.AdvertiseAddr = m.cfg.Gossip.AdvertiseAddr
	}
	if m.cfg.Gossip.AdvertisePort != 0 {
		mlConfig.AdvertisePort = m.cfg.Gossip.AdvertisePort
	}

	// Configure cluster encryption if secret key provided
	if m.cfg.Gossip.SecretKey != "" {
		key := deriveEncryptionKey(m.cfg.Gossip.SecretKey)
		mlConfig.SecretKey = key
	}

	// Timing thresholds
	if m.cfg.Gossip.Config.TimeoutSeconds > 0 {
		mlConfig.ProbeTimeout = time.Duration(m.cfg.Gossip.Config.TimeoutSeconds) * time.Second
	}

	// Delegates
	mlConfig.Delegate = &clusterDelegate{mgr: m}
	mlConfig.Events = &clusterEventDelegate{mgr: m}
	mlConfig.Conflict = &clusterConflictDelegate{mgr: m}

	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return fmt.Errorf("failed to create memberlist on port %d: %w", mlConfig.BindPort, err)
	}
	m.ml = ml

	// Update local node address with actual bound port if dynamic
	m.mu.Lock()
	m.localNode.GossipPort = int(ml.LocalNode().Port)
	if ml.LocalNode().Addr != nil {
		m.localNode.Address = ml.LocalNode().Addr.String()
	}
	m.mu.Unlock()

	// Launch background tombstone prune loop
	go m.pruneLoop()

	return nil
}

func (m *MemberlistManager) pruneLoop() {
	if m.pruneInterval <= 0 {
		return
	}
	ticker := time.NewTicker(m.pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.PruneTombstones()
		}
	}
}

// PruneTombstones evicts dead and departed nodes that exceed tombstone TTL or capacity limits.
// Returns the count of evicted nodes.
func (m *MemberlistManager) PruneTombstones() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var pruned int
	var deadNodes []*NodeInfo

	// 1. Time-based TTL sweep
	for id, n := range m.roster {
		if id == m.localNode.NodeID {
			continue // Never prune local node
		}
		if n.State == NodeStateDead || n.State == NodeStateLeft {
			if m.tombstoneTTL > 0 && now.Sub(n.LastSeen) >= m.tombstoneTTL {
				delete(m.roster, id)
				pruned++
			} else {
				deadNodes = append(deadNodes, n)
			}
		}
	}

	// 2. Capacity-based max dead nodes eviction (oldest first)
	if m.maxDeadNodes > 0 && len(deadNodes) > m.maxDeadNodes {
		sort.Slice(deadNodes, func(i, j int) bool {
			return deadNodes[i].LastSeen.Before(deadNodes[j].LastSeen)
		})
		excess := len(deadNodes) - m.maxDeadNodes
		for i := 0; i < excess; i++ {
			delete(m.roster, deadNodes[i].NodeID)
			pruned++
		}
	}

	if pruned > 0 && m.onRosterChange != nil {
		go m.onRosterChange()
	}

	return pruned
}

// Join connects to seed peer addresses.
func (m *MemberlistManager) Join(peers []string) error {
	if m.ml == nil {
		return fmt.Errorf("memberlist not started")
	}
	if len(peers) == 0 {
		return nil
	}

	numJoined, err := m.ml.Join(peers)
	if err != nil {
		return fmt.Errorf("failed to join memberlist peers %v (joined %d): %w", peers, numJoined, err)
	}

	// Update roster from memberlist members
	m.syncRosterFromMemberlist()
	return nil
}

// Leave initiates graceful node departure from the cluster.
func (m *MemberlistManager) Leave(timeout time.Duration) error {
	m.mu.Lock()
	m.localNode.State = NodeStateLeft
	m.mu.Unlock()

	if m.ml != nil {
		if err := m.ml.Leave(timeout); err != nil {
			return err
		}
		return m.ml.Shutdown()
	}
	return nil
}

// Stop shuts down the gossip engine.
func (m *MemberlistManager) Stop() error {
	m.closeOnce.Do(func() {
		close(m.stopCh)
	})
	if m.ml != nil {
		return m.ml.Shutdown()
	}
	return nil
}

// GetMembers returns all nodes currently in the roster.
func (m *MemberlistManager) GetMembers() []NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]NodeInfo, 0, len(m.roster))
	for _, n := range m.roster {
		res = append(res, *n)
	}
	return res
}

// GetAliveMembers returns only nodes currently in NodeStateAlive.
func (m *MemberlistManager) GetAliveMembers() []NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]NodeInfo, 0, len(m.roster))
	for _, n := range m.roster {
		if n.State == NodeStateAlive {
			res = append(res, *n)
		}
	}
	return res
}

// UpdateGRPCPort updates the advertised gRPC port for the local node and re-advertises via memberlist.
func (m *MemberlistManager) UpdateGRPCPort(port int) {
	m.mu.Lock()
	m.localNode.GRPCPort = port
	if node, ok := m.roster[m.localNode.NodeID]; ok {
		node.GRPCPort = port
	}
	ml := m.ml
	m.mu.Unlock()

	if ml != nil {
		_ = ml.UpdateNode(1 * time.Second)
	}
}

// GetMember retrieves a single member by node ID.
func (m *MemberlistManager) GetMember(nodeID string) (*NodeInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, exists := m.roster[nodeID]
	if !exists {
		return nil, false
	}
	copied := *n
	return &copied, true
}

// GetRosterMap returns a snapshot map of node pointers for leader election recomputation.
func (m *MemberlistManager) GetRosterMap() map[string]*NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]*NodeInfo, len(m.roster))
	for k, v := range m.roster {
		cp := *v
		out[k] = &cp
	}
	return out
}

// Heartbeat verifies node liveness and updates LastSeen.
func (m *MemberlistManager) Heartbeat(peerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, ok := m.roster[peerID]
	if !ok || peer.State == NodeStateDead || peer.State == NodeStateLeft {
		return false
	}
	peer.LastSeen = time.Now()
	return true
}

// AddMembershipListener registers a membership event callback.
func (m *MemberlistManager) AddMembershipListener(l MembershipListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, l)
}

// MarkNodeState manually updates a node's state (e.g. for partition simulation).
func (m *MemberlistManager) MarkNodeState(nodeID string, state NodeState) {
	m.mu.Lock()
	if n, ok := m.roster[nodeID]; ok {
		n.State = state
		if state == NodeStateDead || state == NodeStateLeft {
			n.IsLeader = false
			n.IsRegLeader = false
		}
	}
	m.mu.Unlock()

	if m.onRosterChange != nil {
		go m.onRosterChange()
	}
}

func (m *MemberlistManager) handleNodeEvent(node *memberlist.Node, state NodeState) {
	var meta NodeMetadata
	if len(node.Meta) > 0 {
		_ = json.Unmarshal(node.Meta, &meta)
	}

	nodeID := meta.NodeID
	if nodeID == "" {
		nodeID = node.Name
	}

	grpcPort := meta.GRPCPort
	if grpcPort == 0 {
		grpcPort = 10102
	}

	region := meta.Region
	if region == "" {
		region = "unknown"
	}

	addr := ""
	if node.Addr != nil {
		addr = node.Addr.String()
	}

	m.mu.Lock()
	existing, ok := m.roster[nodeID]
	if !ok {
		existing = &NodeInfo{
			NodeID:       nodeID,
			Address:      addr,
			GossipPort:   int(node.Port),
			GRPCPort:     grpcPort,
			Region:       region,
			State:        state,
			LastSeen:     time.Now(),
			Capabilities: meta.Capabilities,
			Metadata:     meta.Metadata,
		}
		m.roster[nodeID] = existing
	} else {
		existing.Address = addr
		existing.GossipPort = int(node.Port)
		existing.GRPCPort = grpcPort
		existing.Region = region
		existing.State = state
		existing.LastSeen = time.Now()
		if len(meta.Capabilities) > 0 {
			existing.Capabilities = meta.Capabilities
		}
		if meta.Metadata != nil {
			existing.Metadata = meta.Metadata
		}
	}
	infoCopy := *existing

	// Inline capacity check under rapid churn
	if m.maxDeadNodes > 0 && (state == NodeStateDead || state == NodeStateLeft) {
		var deadCount int
		for id, n := range m.roster {
			if id != m.localNode.NodeID && (n.State == NodeStateDead || n.State == NodeStateLeft) {
				deadCount++
			}
		}
		if deadCount > m.maxDeadNodes {
			var deadList []*NodeInfo
			for id, n := range m.roster {
				if id != m.localNode.NodeID && (n.State == NodeStateDead || n.State == NodeStateLeft) {
					deadList = append(deadList, n)
				}
			}
			sort.Slice(deadList, func(i, j int) bool {
				return deadList[i].LastSeen.Before(deadList[j].LastSeen)
			})
			excess := deadCount - m.maxDeadNodes
			for i := 0; i < excess; i++ {
				delete(m.roster, deadList[i].NodeID)
			}
		}
	}
	m.mu.Unlock()

	// Notify listeners
	for _, l := range m.listeners {
		switch state {
		case NodeStateAlive:
			if ok {
				l.OnNodeUpdate(infoCopy)
			} else {
				l.OnNodeJoin(infoCopy)
			}
		case NodeStateDead, NodeStateLeft:
			l.OnNodeLeave(infoCopy)
		}
	}

	if m.onRosterChange != nil {
		go m.onRosterChange()
	}
}

func (m *MemberlistManager) syncRosterFromMemberlist() {
	if m.ml == nil {
		return
	}
	for _, member := range m.ml.Members() {
		m.handleNodeEvent(member, NodeStateAlive)
	}
}

// deriveEncryptionKey hashes or adjusts the provided secret key to an exact 32-byte AES-256 key.
func deriveEncryptionKey(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}

// clusterDelegate implements memberlist.Delegate.
type clusterDelegate struct {
	mgr *MemberlistManager
}

func (d *clusterDelegate) NodeMeta(limit int) []byte {
	d.mgr.mu.RLock()
	defer d.mgr.mu.RUnlock()

	meta := NodeMetadata{
		NodeID:       d.mgr.localNode.NodeID,
		Address:      d.mgr.localNode.Address,
		GRPCPort:     d.mgr.localNode.GRPCPort,
		Region:       d.mgr.localNode.Region,
		Capabilities: []string{"ack:v1"},
	}
	bytes, _ := json.Marshal(meta)
	if len(bytes) > limit {
		return bytes[:limit]
	}
	return bytes
}

func (d *clusterDelegate) NotifyMsg(msg []byte) {}

func (d *clusterDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	return nil
}

func (d *clusterDelegate) LocalState(join bool) []byte {
	return nil
}

func (d *clusterDelegate) MergeRemoteState(buf []byte, join bool) {}

// clusterEventDelegate implements memberlist.EventDelegate.
type clusterEventDelegate struct {
	mgr *MemberlistManager
}

func (e *clusterEventDelegate) NotifyJoin(node *memberlist.Node) {
	e.mgr.handleNodeEvent(node, NodeStateAlive)
}

func (e *clusterEventDelegate) NotifyLeave(node *memberlist.Node) {
	e.mgr.handleNodeEvent(node, NodeStateDead)
}

func (e *clusterEventDelegate) NotifyUpdate(node *memberlist.Node) {
	e.mgr.handleNodeEvent(node, NodeStateAlive)
}

// clusterConflictDelegate implements memberlist.ConflictDelegate.
type clusterConflictDelegate struct {
	mgr *MemberlistManager
}

func (c *clusterConflictDelegate) NotifyConflict(existing, other *memberlist.Node) {
	// Memberlist handles conflict via incarnation numbers
}

func getFreePort(addr string) (int, error) {
	if addr == "" || addr == "0.0.0.0" {
		addr = "127.0.0.1"
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:0", addr))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

