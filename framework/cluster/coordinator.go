package cluster

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ClusterCoordinator defines the central gateway cluster coordination interface.
type ClusterCoordinator interface {
	Start(ctx context.Context) error
	Stop() error
	Join(peers []string) error
	Leave() error

	GetNodes() []ClusterNode
	GetAliveNodes() []ClusterNode
	GetNode(nodeID string) (ClusterNode, bool)
	GetLocalNode() ClusterNode
	GetLeader() (*ClusterNode, error)
	GetRegionalLeader(region string) (*ClusterNode, error)
	IsLeader() bool
	IsRegionalLeader() bool

	DiscoverPeers(discoveryType string) ([]string, error)
	BroadcastState(entity string, payload []byte) error
	RegisterStateReceiver(entity string, handler StateHandler)

	AddMembershipListener(listener MembershipListener)
	AddLeadershipListener(listener LeadershipListener)
	Heartbeat(peerID string) bool

	GetDistributedRateLimiter() DistributedRateLimiter
	CheckAndChargeDistributedRateLimit(key string, amount int64, capacity int64, window time.Duration) (bool, int64, error)
	ForwardRateLimitCharge(ctx context.Context, targetNodeID string, req RateLimitChargeRequest) (*RateLimitChargeResponse, error)
}

// Coordinator implements ClusterCoordinator across mesh and broker topologies.
type Coordinator struct {
	mu           sync.RWMutex
	cfg          Config
	localNode    NodeInfo
	memberlist   *MemberlistManager
	syncGRPC     *GRPCSyncManager
	discovery    *DiscoveryManager
	election     *ElectionManager
	brokerClient *BrokerClient
	brokerServer *BrokerServer
	rateLimiter  DistributedRateLimiter
	started      bool
	ctx          context.Context
	cancel       context.CancelFunc
	closeOnce    sync.Once
	catchUpMu    sync.Mutex
	isCatchingUp bool
	lastCatchUp  time.Time
}

// NewCoordinator instantiates a new cluster coordinator from configuration.
func NewCoordinator(cfg Config) (*Coordinator, error) {
	if cfg.NodeID == "" {
		cfg.NodeID = fmt.Sprintf("node-%s", uuid.New().String()[:8])
	}
	if cfg.Region == "" {
		cfg.Region = "unknown"
	}
	if cfg.Type == "" {
		cfg.Type = ClusterModeMesh
	}
	if cfg.Gossip.Port == 0 {
		cfg.Gossip.Port = 10101
	}
	if cfg.GRPC.Port == 0 {
		cfg.GRPC.Port = 10102
	}

	c := &Coordinator{
		cfg: cfg,
		localNode: NodeInfo{
			NodeID:       cfg.NodeID,
			Address:      cfg.Gossip.BindAddr,
			GossipPort:   cfg.Gossip.Port,
			GRPCPort:     cfg.GRPC.Port,
			Region:       cfg.Region,
			State:        NodeStateAlive,
			IsLeader:     true, // Solo node default
			LastSeen:     time.Now(),
			Capabilities: []string{"ack:v1"},
		},
	}

	// Election manager
	c.election = NewElectionManager(cfg.NodeID, cfg.Region)

	// In broker mode
	if cfg.Type == ClusterModeBroker {
		c.brokerClient = NewBrokerClient(
			cfg.Broker.Address,
			cfg.NodeID,
			cfg.Region,
			cfg.Broker.AuthToken,
			cfg.Broker.TLS,
			c.handleBrokerIncomingMessage,
			c.handleBrokerRosterUpdate,
		)
	} else {
		// In mesh mode: initialize Memberlist and gRPC state sync
		mlMgr, err := NewMemberlistManager(cfg, c.onRosterChanged)
		if err != nil {
			return nil, fmt.Errorf("failed to init memberlist: %w", err)
		}
		c.memberlist = mlMgr

		grpcMgr := NewGRPCSyncManager(cfg.NodeID, cfg.Region, cfg.GRPC.Port, cfg.GRPC.BindAddr, time.Duration(cfg.GRPC.DedupTTLSeconds)*time.Second)
		c.syncGRPC = grpcMgr
	}

	// Discovery manager
	c.discovery = NewDiscoveryManager(cfg.Discovery, func(peers []string) {
		_ = c.Join(peers)
	})

	return c, nil
}

// Start boots all cluster subcomponents.
func (c *Coordinator) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return nil
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.started = true
	c.mu.Unlock()

	if c.cfg.Type == ClusterModeBroker {
		if err := c.brokerClient.Connect(c.ctx); err != nil {
			return fmt.Errorf("failed to connect broker client: %w", err)
		}
	} else {
		// Mesh mode: Start gRPC sync server first to determine actual bound port
		if err := c.syncGRPC.Start(); err != nil {
			return err
		}
		boundGRPCPort := c.syncGRPC.Port()
		c.memberlist.UpdateGRPCPort(boundGRPCPort)

		// Start memberlist gossip with accurate GRPCPort in metadata
		if err := c.memberlist.Start(); err != nil {
			c.syncGRPC.Stop()
			return err
		}

		// Update local node ports with actual bound ports
		c.mu.Lock()
		c.localNode = c.memberlist.localNode
		c.localNode.GRPCPort = boundGRPCPort
		c.mu.Unlock()

		// Start election periodic ticker
		c.election.StartPeriodicTicker(func() {
			c.onRosterChanged()
		})
	}

	// Rate limiter initialization
	rlCfg := RateLimiterConfig{
		Backend:      RateLimitBackend(c.cfg.RateLimit.Backend),
		KeyPrefix:    c.cfg.RateLimit.KeyPrefix,
		NodeID:       c.cfg.NodeID,
		SyncInterval: c.cfg.RateLimit.SyncInterval,
	}
	rl, err := NewDistributedRateLimiter(rlCfg, c)
	if err == nil {
		c.mu.Lock()
		c.rateLimiter = rl
		c.mu.Unlock()
		if p2p, ok := rl.(*P2PRateLimiter); ok && c.syncGRPC != nil {
			c.syncGRPC.RegisterChargeHandler(p2p.HandleLocalChargeRequest)
		}
	}

	// Auto-discovery
	if c.cfg.Discovery.Enabled {
		c.discovery.StartAdaptiveLoop(c.ctx)
		// Perform initial discovery query
		go func() {
			peers, _ := c.discovery.DiscoverAll(c.ctx)
			if len(peers) > 0 {
				_ = c.Join(peers)
			}
		}()
	}

	// Join configured seed peers
	if len(c.cfg.Peers) > 0 {
		go func() {
			_ = c.Join(c.cfg.Peers)
		}()
	}

	c.onRosterChanged()
	return nil
}

// Stop gracefully terminates all cluster services.
func (c *Coordinator) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.discovery != nil {
			c.discovery.Close()
		}
		if c.election != nil {
			c.election.Close()
		}
		if c.rateLimiter != nil {
			_ = c.rateLimiter.Close()
		}
		if c.brokerClient != nil {
			c.brokerClient.Close()
		}
		if c.syncGRPC != nil {
			c.syncGRPC.Stop()
		}
		if c.memberlist != nil {
			_ = c.memberlist.Stop()
		}
		if c.brokerServer != nil {
			c.brokerServer.Stop()
		}
		c.started = false
	})
	return nil
}

// Join connects to seed peer addresses.
func (c *Coordinator) Join(peers []string) error {
	if len(peers) == 0 {
		return nil
	}
	if c.memberlist != nil {
		if err := c.memberlist.Join(peers); err != nil {
			return err
		}
		c.onRosterChanged()
		go func() {
			_ = c.CatchUpWithCluster(c.ctx)
		}()
	}
	return nil
}

// Leave marks local node as left and exits cluster.
func (c *Coordinator) Leave() error {
	if c.memberlist != nil {
		return c.memberlist.Leave(5 * time.Second)
	}
	return nil
}

// GetNodes returns all current nodes in the cluster.
func (c *Coordinator) GetNodes() []ClusterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getNodesLocked()
}

func (c *Coordinator) getNodesLocked() []ClusterNode {
	if c.cfg.Type == ClusterModeBroker && c.brokerClient != nil {
		return c.brokerClient.GetRoster()
	}
	if c.memberlist != nil {
		return c.memberlist.GetMembers()
	}
	return []ClusterNode{c.localNode}
}

// GetAliveNodes returns only nodes currently in NodeStateAlive.
func (c *Coordinator) GetAliveNodes() []ClusterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getAliveNodesLocked()
}

func (c *Coordinator) getAliveNodesLocked() []ClusterNode {
	if c.cfg.Type == ClusterModeBroker && c.brokerClient != nil {
		all := c.brokerClient.GetRoster()
		var alive []ClusterNode
		for _, n := range all {
			if n.State == NodeStateAlive {
				alive = append(alive, n)
			}
		}
		return alive
	}
	if c.memberlist != nil {
		return c.memberlist.GetAliveMembers()
	}
	return []ClusterNode{c.localNode}
}

// GetNode retrieves a single node by ID.
func (c *Coordinator) GetNode(nodeID string) (ClusterNode, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getNodeLocked(nodeID)
}

func (c *Coordinator) getNodeLocked(nodeID string) (ClusterNode, bool) {
	nodes := c.getNodesLocked()
	for _, n := range nodes {
		if n.NodeID == nodeID {
			return n, true
		}
	}
	return ClusterNode{}, false
}

// GetLocalNode returns the local node metadata.
func (c *Coordinator) GetLocalNode() ClusterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.localNode
}

// GetLeader returns the currently elected cluster leader.
func (c *Coordinator) GetLeader() (*ClusterNode, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	leaderID := ""
	if c.cfg.Type == ClusterModeBroker && c.brokerClient != nil {
		leaderID = c.brokerClient.GetLeaderID()
	} else if c.election != nil {
		leaderID = c.election.GetLeaderID()
	}

	if leaderID == "" {
		return &c.localNode, nil
	}

	node, exists := c.getNodeLocked(leaderID)
	if exists {
		return &node, nil
	}
	return &c.localNode, nil
}

// GetRegionalLeader returns the leader for a specified region.
func (c *Coordinator) GetRegionalLeader(region string) (*ClusterNode, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.election == nil {
		return &c.localNode, nil
	}
	regLeaderID := c.election.GetRegionalLeaderID(region)
	if regLeaderID == "" {
		return &c.localNode, nil
	}

	node, exists := c.getNodeLocked(regLeaderID)
	if exists {
		return &node, nil
	}
	return &c.localNode, nil
}

// IsLeader checks if local node is cluster leader.
func (c *Coordinator) IsLeader() bool {
	leader, err := c.GetLeader()
	if err != nil || leader == nil {
		return false
	}
	return leader.NodeID == c.cfg.NodeID
}

// IsRegionalLeader checks if local node is regional leader.
func (c *Coordinator) IsRegionalLeader() bool {
	if c.election != nil {
		return c.election.IsRegionalLeader()
	}
	return false
}

// DiscoverPeers runs a specific discovery provider or all providers.
func (c *Coordinator) DiscoverPeers(discoveryType string) ([]string, error) {
	if c.discovery == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if discoveryType == "" {
		return c.discovery.DiscoverAll(ctx)
	}

	c.discovery.mu.RLock()
	p, ok := c.discovery.providers[discoveryType]
	c.discovery.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	return p.Discover(ctx)
}

// BroadcastState broadcasts an entity update to all peers in the cluster.
func (c *Coordinator) BroadcastState(entity string, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if c.cfg.Type == ClusterModeBroker && c.brokerClient != nil {
		msg := NewSyncMessage(c.cfg.NodeID, c.cfg.Region, entity, "", ActionUpsert, payload)
		return c.brokerClient.SendMessage(LaneGovernance, msg)
	}

	if c.syncGRPC != nil && c.memberlist != nil {
		// Collect peer gRPC addresses
		members := c.memberlist.GetMembers()
		var peerAddrs []string
		for _, m := range members {
			if m.NodeID == c.cfg.NodeID || m.State != NodeStateAlive {
				continue
			}
			addr := m.Address
			if addr == "" || addr == "0.0.0.0" {
				addr = "127.0.0.1"
			}
			peerAddrs = append(peerAddrs, net.JoinHostPort(addr, strconv.Itoa(m.GRPCPort)))
		}
		return c.syncGRPC.BroadcastState(ctx, entity, payload, peerAddrs)
	}

	return nil
}

// RegisterStateReceiver registers a consumer for incoming entity updates.
func (c *Coordinator) RegisterStateReceiver(entity string, handler StateHandler) {
	if c.syncGRPC != nil {
		c.syncGRPC.RegisterHandler(entity, handler)
	}
}

// AddMembershipListener registers a membership listener.
func (c *Coordinator) AddMembershipListener(listener MembershipListener) {
	if c.memberlist != nil {
		c.memberlist.AddMembershipListener(listener)
	}
}

// AddLeadershipListener registers a leadership listener.
func (c *Coordinator) AddLeadershipListener(listener LeadershipListener) {
	if c.election != nil {
		c.election.AddLeadershipListener(listener)
	}
}

// Heartbeat checks peer liveness.
func (c *Coordinator) Heartbeat(peerID string) bool {
	if c.memberlist != nil {
		return c.memberlist.Heartbeat(peerID)
	}
	return true
}

// GetDistributedRateLimiter returns the active distributed rate limiter instance.
func (c *Coordinator) GetDistributedRateLimiter() DistributedRateLimiter {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rateLimiter
}

// CheckAndChargeDistributedRateLimit provides direct token bucket sync matching E2E test signature.
func (c *Coordinator) CheckAndChargeDistributedRateLimit(key string, amount int64, capacity int64, window time.Duration) (bool, int64, error) {
	rl := c.GetDistributedRateLimiter()
	if rl == nil {
		// In-memory fallback if not started
		return true, capacity - amount, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	allowed, rem, _, err := rl.CheckAndCharge(ctx, key, amount, window, capacity)
	return allowed, rem, err
}

// ForwardRateLimitCharge forwards a rate limit charge to the primary node owning the consistent hash key.
func (c *Coordinator) ForwardRateLimitCharge(ctx context.Context, targetNodeID string, req RateLimitChargeRequest) (*RateLimitChargeResponse, error) {
	c.mu.RLock()
	isLocal := targetNodeID == c.localNode.NodeID
	c.mu.RUnlock()

	if isLocal {
		rl := c.GetDistributedRateLimiter()
		if p2p, ok := rl.(*P2PRateLimiter); ok {
			return p2p.HandleLocalChargeRequest(ctx, &req), nil
		}
	}

	if c.syncGRPC != nil && c.memberlist != nil {
		targetNode, found := c.memberlist.GetMember(targetNodeID)
		if !found || targetNode.State != NodeStateAlive {
			return nil, fmt.Errorf("target node %s is not alive or unknown", targetNodeID)
		}
		addr := targetNode.Address
		if addr == "" || addr == "0.0.0.0" {
			addr = "127.0.0.1"
		}
		targetAddr := net.JoinHostPort(addr, strconv.Itoa(targetNode.GRPCPort))
		return c.syncGRPC.SendChargeRPC(ctx, targetAddr, &req)
	}

	return nil, fmt.Errorf("no RPC transport available for target node %s", targetNodeID)
}

// CatchUpWithCluster synchronizes missed state updates from the cluster leader or peers.
func (c *Coordinator) CatchUpWithCluster(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.catchUpMu.Lock()
	if c.isCatchingUp {
		c.catchUpMu.Unlock()
		return nil
	}
	// Debounce: prevent spamming peers more than once every 100ms
	if time.Since(c.lastCatchUp) < 100*time.Millisecond {
		c.catchUpMu.Unlock()
		return nil
	}
	c.isCatchingUp = true
	c.catchUpMu.Unlock()

	defer func() {
		c.catchUpMu.Lock()
		c.isCatchingUp = false
		c.lastCatchUp = time.Now()
		c.catchUpMu.Unlock()
	}()

	if c.syncGRPC == nil || c.memberlist == nil {
		return nil
	}

	var targets []string
	leader, _ := c.GetLeader()
	isLeader := (leader != nil && leader.NodeID == c.cfg.NodeID)

	if !isLeader && leader != nil && leader.State == NodeStateAlive && leader.GRPCPort > 0 {
		// Non-leader follower: query cluster leader first
		addr := leader.Address
		if addr == "" || addr == "0.0.0.0" {
			addr = "127.0.0.1"
		}
		targets = append(targets, net.JoinHostPort(addr, strconv.Itoa(leader.GRPCPort)))
	} else if isLeader {
		// Leader merging into existing cluster: query alive peers with valid ports
		for _, m := range c.memberlist.GetMembers() {
			if m.NodeID == c.cfg.NodeID || m.State != NodeStateAlive || m.GRPCPort <= 0 {
				continue
			}
			addr := m.Address
			if addr == "" || addr == "0.0.0.0" {
				addr = "127.0.0.1"
			}
			targets = append(targets, net.JoinHostPort(addr, strconv.Itoa(m.GRPCPort)))
		}
	}

	if len(targets) == 0 {
		return nil
	}

	for _, target := range targets {
		cCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := c.syncGRPC.FetchCatchUp(cCtx, target)
		cancel()
		if err == nil {
			return nil
		}
	}
	return nil
}

func (c *Coordinator) onRosterChanged() {
	if c.memberlist == nil || c.election == nil {
		return
	}
	roster := c.memberlist.GetRosterMap()
	c.election.Reevaluate(roster)

	// Update local node state & leadership status
	c.mu.Lock()
	isLeader := c.election.IsLeader()
	c.localNode.IsLeader = isLeader
	c.localNode.IsRegLeader = c.election.IsRegionalLeader()
	c.mu.Unlock()

	// Rejoining / follower nodes synchronize history from cluster leader
	if !isLeader && len(roster) > 1 {
		go func() {
			_ = c.CatchUpWithCluster(c.ctx)
		}()
	}
}

func (c *Coordinator) handleBrokerIncomingMessage(msg *SyncMessage) {
	if c.syncGRPC != nil {
		_ = c.syncGRPC.ProcessIncomingMessage(context.Background(), msg)
	}
}

func (c *Coordinator) handleBrokerRosterUpdate(roster *RosterPayload) {
	c.mu.Lock()
	c.localNode.IsLeader = (c.cfg.NodeID == roster.LeaderNodeID)
	c.mu.Unlock()
}
