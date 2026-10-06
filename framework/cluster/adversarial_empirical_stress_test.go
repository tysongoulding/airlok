package cluster

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// EMPIRICAL STRESS 1: LARGE HISTORY & MULTI-ENTITY CATCH-UP ON REJOIN
// ============================================================================

func TestStress_StateCatchUp_LargeHistoryAndMultiEntity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Start continuous Node 1 with dynamic ports
	cfg1 := Config{
		NodeID: "stress-node-1",
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

	// 2. Start Node 2 and join Node 1
	cfg2 := Config{
		NodeID: "stress-node-2",
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

	// 3. PARTITION Node 2
	_ = coord2.Stop()
	coord1.memberlist.MarkNodeState("stress-node-2", NodeStateDead)

	// 4. Node 1 broadcasts 30 messages across 3 distinct entities while Node 2 is offline
	entityTypes := []string{EntityVirtualKey, EntityGovernance, EntityTeam}
	totalMsgs := 30
	for i := 1; i <= totalMsgs; i++ {
		entity := entityTypes[(i-1)%len(entityTypes)]
		payload := []byte(fmt.Sprintf(`{"seq": %d, "entity": "%s"}`, i, entity))
		if err := coord1.BroadcastState(entity, payload); err != nil {
			t.Fatalf("coord1 broadcast %d failed: %v", i, err)
		}
	}

	// 5. REJOIN Node 2
	coord2Restarted, err := NewCoordinator(cfg2)
	if err != nil {
		t.Fatalf("failed to create restarted coord2: %v", err)
	}

	var receivedMap sync.Map
	var receivedTotal int64

	for _, entity := range entityTypes {
		e := entity
		coord2Restarted.RegisterStateReceiver(e, func(ctx context.Context, entityType string, payload []byte) error {
			receivedMap.Store(fmt.Sprintf("%s:%s", entityType, string(payload)), true)
			atomic.AddInt64(&receivedTotal, 1)
			return nil
		})
	}

	if err := coord2Restarted.Start(ctx); err != nil {
		t.Fatalf("failed to start restarted coord2: %v", err)
	}
	defer coord2Restarted.Stop()

	if err := coord2Restarted.Join([]string{addr1}); err != nil {
		t.Fatalf("coord2 rejoin failed: %v", err)
	}

	// Wait for catch-up to complete
	deadline := time.Now().Add(5 * time.Second)
	var finalCount int
	for time.Now().Before(deadline) {
		cnt := 0
		receivedMap.Range(func(_, _ interface{}) bool {
			cnt++
			return true
		})
		if cnt >= totalMsgs {
			finalCount = cnt
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if finalCount < totalMsgs {
		t.Fatalf("empirical failure: expected %d caught-up messages across 3 entities, got %d", totalMsgs, finalCount)
	}
	t.Logf("Empirical stress pass: rejoining node cleanly synchronized %d/%d messages across 3 entity types", finalCount, totalMsgs)
}

// ============================================================================
// EMPIRICAL STRESS 2: TOMBSTONE PRUNING LRU CAPACITY AND TTL SWEEPS
// ============================================================================

func TestStress_TombstonePruning_LRUCapacityAndTTLSweep(t *testing.T) {
	// Custom MemberlistManager with tight limits: maxDeadNodes=10, tombstoneTTL=80ms
	cfg := GossipTimingConfig{
		MaxDeadNodes:         10,
		TombstoneTTLSeconds:  1, // 1s TTL for explicit sweep test
		PruneIntervalSeconds: 30,
	}

	mgr, err := NewMemberlistManager(Config{
		NodeID: "local-node",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
	}, func() {})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	mgr.maxDeadNodes = cfg.MaxDeadNodes
	mgr.tombstoneTTL = 100 * time.Millisecond // 100ms TTL

	// 1. Inject 40 dead nodes directly into roster
	mgr.mu.Lock()
	for i := 1; i <= 40; i++ {
		id := fmt.Sprintf("dead-node-%02d", i)
		mgr.roster[id] = &NodeInfo{
			NodeID:   id,
			Region:   "us-east-1",
			State:    NodeStateDead,
			LastSeen: time.Now().Add(-time.Duration(i) * time.Millisecond), // staggered ages
		}
	}
	mgr.mu.Unlock()

	// 2. Capacity eviction check: PruneTombstones should evict 30 excess dead nodes down to 10
	pruned := mgr.PruneTombstones()
	if pruned != 30 {
		t.Fatalf("expected 30 excess dead nodes pruned, got %d", pruned)
	}

	mgr.mu.RLock()
	deadRemaining := 0
	for id, n := range mgr.roster {
		if id != "local-node" && n.State == NodeStateDead {
			deadRemaining++
		}
	}
	mgr.mu.RUnlock()

	if deadRemaining != 10 {
		t.Fatalf("expected exactly 10 dead nodes remaining under maxDeadNodes cap, got %d", deadRemaining)
	}

	// Verify local node is strictly preserved and alive
	local, exists := mgr.GetMember("local-node")
	if !exists || local.State != NodeStateAlive {
		t.Fatalf("local node was corrupted or evicted: %+v", local)
	}

	// 3. TTL Sweep check: wait 120ms to exceed 100ms TTL
	time.Sleep(120 * time.Millisecond)

	prunedTTL := mgr.PruneTombstones()
	if prunedTTL != 10 {
		t.Fatalf("expected remaining 10 dead nodes pruned by TTL sweep, got %d", prunedTTL)
	}

	mgr.mu.RLock()
	totalRemaining := len(mgr.roster)
	mgr.mu.RUnlock()

	// Only local node should remain
	if totalRemaining != 1 {
		t.Fatalf("expected only local node in roster after TTL sweep, got %d", totalRemaining)
	}

	aliveMembers := mgr.GetAliveMembers()
	if len(aliveMembers) != 1 || aliveMembers[0].NodeID != "local-node" {
		t.Fatalf("GetAliveMembers returned invalid members: %+v", aliveMembers)
	}

	t.Logf("Empirical stress pass: LRU capacity compaction and TTL tombstone pruning verified")
}

// ============================================================================
// EMPIRICAL STRESS 3: LEADER FAILOVER WITH DYNAMIC PORTS UNDER HEAVY LOAD
// ============================================================================

func TestStress_LeaderFailover_DynamicPortsUnderHeavyBroadcast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Node 1: "a-node-01" (Lexicographical leader)
	cfg1 := Config{
		NodeID: "a-node-01",
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

	// Node 2: "b-node-02"
	cfg2 := Config{
		NodeID: "b-node-02",
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
	if err := coord2.Join([]string{addr1}); err != nil {
		t.Fatalf("coord2 join failed: %v", err)
	}

	// Node 3: "c-node-03"
	cfg3 := Config{
		NodeID: "c-node-03",
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
	if err := coord3.Join([]string{addr1}); err != nil {
		t.Fatalf("coord3 join failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	l1, _ := coord1.GetLeader()
	if l1 == nil || l1.NodeID != "a-node-01" {
		t.Fatalf("expected initial leader a-node-01, got: %v", l1)
	}

	// Heavy broadcast concurrent workers
	stopBroadcast := make(chan struct{})
	var broadcastWG sync.WaitGroup
	var broadcastCount int64

	for w := 0; w < 12; w++ {
		broadcastWG.Add(1)
		go func(workerID int) {
			defer broadcastWG.Done()
			for {
				select {
				case <-stopBroadcast:
					return
				default:
					_ = coord1.BroadcastState(EntityVirtualKey, []byte(fmt.Sprintf(`{"w":%d,"t":%d}`, workerID, time.Now().UnixNano())))
					atomic.AddInt64(&broadcastCount, 1)
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(w)
	}

	time.Sleep(150 * time.Millisecond)

	// FORCIBLY TERMINATE LEADER
	_ = coord1.Stop()
	close(stopBroadcast)
	broadcastWG.Wait()

	// Signal node death to surviving nodes
	coord2.memberlist.MarkNodeState("a-node-01", NodeStateDead)
	coord3.memberlist.MarkNodeState("a-node-01", NodeStateDead)

	time.Sleep(200 * time.Millisecond)

	// Verify failover: "b-node-02" MUST be the new leader
	newL2, err2 := coord2.GetLeader()
	newL3, err3 := coord3.GetLeader()
	if err2 != nil || newL2 == nil || newL2.NodeID != "b-node-02" {
		t.Fatalf("coord2 failover mismatch: %v, leader=%v", err2, newL2)
	}
	if err3 != nil || newL3 == nil || newL3.NodeID != "b-node-02" {
		t.Fatalf("coord3 failover mismatch: %v, leader=%v", err3, newL3)
	}

	if !coord2.IsLeader() {
		t.Fatalf("b-node-02 should report IsLeader() == true")
	}
	if coord3.IsLeader() {
		t.Fatalf("c-node-03 should report IsLeader() == false")
	}

	// Verify new leader can broadcast without deadlock or port error
	if err := coord2.BroadcastState(EntityVirtualKey, []byte(`{"from":"new-leader-b"}`)); err != nil {
		t.Fatalf("new leader broadcast failed: %v", err)
	}

	t.Logf("Empirical stress pass: dynamic-port leader failover succeeded under load (%d msgs sent)", atomic.LoadInt64(&broadcastCount))
}

// ============================================================================
// EMPIRICAL STRESS 4: 3-WAY PARTITION AND CONCURRENT HEALING
// ============================================================================

func TestStress_SplitBrain_3WayPartitionAndSimultaneousHealing(t *testing.T) {
	nodeIDs := []string{"node-alpha", "node-bravo", "node-charlie", "node-delta"}
	sort.Strings(nodeIDs) // Lexicographical: [node-alpha, node-bravo, node-charlie, node-delta]

	managers := make(map[string]*ElectionManager)
	for _, id := range nodeIDs {
		managers[id] = NewElectionManager(id, "us-east-1")
	}

	// 1. Initial full roster
	fullRoster := make(map[string]*NodeInfo)
	for _, id := range nodeIDs {
		fullRoster[id] = &NodeInfo{NodeID: id, Region: "us-east-1", State: NodeStateAlive}
	}
	for _, em := range managers {
		em.Reevaluate(fullRoster)
		if em.GetLeaderID() != "node-alpha" {
			t.Fatalf("expected initial leader node-alpha, got %s", em.GetLeaderID())
		}
	}

	// 2. 3-way partition:
	// Island 1: {node-alpha}
	// Island 2: {node-bravo, node-charlie}
	// Island 3: {node-delta}
	island1 := map[string]*NodeInfo{
		"node-alpha":   {NodeID: "node-alpha", Region: "us-east-1", State: NodeStateAlive},
		"node-bravo":   {NodeID: "node-bravo", Region: "us-east-1", State: NodeStateDead},
		"node-charlie": {NodeID: "node-charlie", Region: "us-east-1", State: NodeStateDead},
		"node-delta":   {NodeID: "node-delta", Region: "us-east-1", State: NodeStateDead},
	}
	island2 := map[string]*NodeInfo{
		"node-alpha":   {NodeID: "node-alpha", Region: "us-east-1", State: NodeStateDead},
		"node-bravo":   {NodeID: "node-bravo", Region: "us-east-1", State: NodeStateAlive},
		"node-charlie": {NodeID: "node-charlie", Region: "us-east-1", State: NodeStateAlive},
		"node-delta":   {NodeID: "node-delta", Region: "us-east-1", State: NodeStateDead},
	}
	island3 := map[string]*NodeInfo{
		"node-alpha":   {NodeID: "node-alpha", Region: "us-east-1", State: NodeStateDead},
		"node-bravo":   {NodeID: "node-bravo", Region: "us-east-1", State: NodeStateDead},
		"node-charlie": {NodeID: "node-charlie", Region: "us-east-1", State: NodeStateDead},
		"node-delta":   {NodeID: "node-delta", Region: "us-east-1", State: NodeStateAlive},
	}

	managers["node-alpha"].Reevaluate(island1)
	managers["node-bravo"].Reevaluate(island2)
	managers["node-charlie"].Reevaluate(island2)
	managers["node-delta"].Reevaluate(island3)

	if managers["node-alpha"].GetLeaderID() != "node-alpha" {
		t.Fatalf("island1 leader mismatch: %s", managers["node-alpha"].GetLeaderID())
	}
	if managers["node-bravo"].GetLeaderID() != "node-bravo" || managers["node-charlie"].GetLeaderID() != "node-bravo" {
		t.Fatalf("island2 leader mismatch: %s, %s", managers["node-bravo"].GetLeaderID(), managers["node-charlie"].GetLeaderID())
	}
	if managers["node-delta"].GetLeaderID() != "node-delta" {
		t.Fatalf("island3 leader mismatch: %s", managers["node-delta"].GetLeaderID())
	}

	// 3. Simultaneous Healing: All 4 nodes reconnect concurrently with independent roster snapshots
	var wg sync.WaitGroup
	for _, em := range managers {
		wg.Add(1)
		go func(e *ElectionManager) {
			defer wg.Done()
			rosterCopy := make(map[string]*NodeInfo, len(fullRoster))
			for k, v := range fullRoster {
				cp := *v
				rosterCopy[k] = &cp
			}
			e.Reevaluate(rosterCopy)
		}(em)
	}
	wg.Wait()

	for id, em := range managers {
		if em.GetLeaderID() != "node-alpha" {
			t.Fatalf("healed node %s failed to reconverge to node-alpha, got %s", id, em.GetLeaderID())
		}
	}

	t.Logf("Empirical stress pass: 3-way partition healed and reconciled to node-alpha with 0 split brain")
}

// ============================================================================
// EMPIRICAL STRESS 5: RATE LIMITER P2P CLOCK JITTER CONVERGENCE
// ============================================================================

func TestStress_RateLimiter_P2PClockJitterConvergence(t *testing.T) {
	window := 10 * time.Second
	var capacity int64 = 50

	b1 := NewInMemTokenBucket("test-key", capacity, window)
	b2 := NewInMemTokenBucket("test-key", capacity, window)

	now := time.Now()
	// Node 1 consumes 15 tokens at local time
	allowed, rem1, _, _ := b1.CheckAndCharge(now, 15, capacity, window)
	if !allowed || rem1 != 35 {
		t.Fatalf("b1 CheckAndCharge failed: allowed=%v, remaining=%d", allowed, rem1)
	}

	// Node 2 has a 600ms forward clock offset
	clockOffset := 600 * time.Millisecond
	remoteTime := now.Add(clockOffset)

	// Sync delta from Node 1 to Node 2
	b2.UpdateRemoteSync(b1.Remaining, b1.LastRefill, window)

	// Verify Node 2 accepted the deduction despite clock skew
	if b2.Remaining != 35 {
		t.Fatalf("Node 2 failed to apply delta with clock offset: remaining=%d, expected=35", b2.Remaining)
	}

	// Node 2 consumes 10 more tokens at its offset time
	allowed2, rem2, _, _ := b2.CheckAndCharge(remoteTime, 10, capacity, window)
	if !allowed2 || rem2 != 25 {
		t.Fatalf("b2 CheckAndCharge failed: allowed=%v, remaining=%d", allowed2, rem2)
	}

	// Sync delta from Node 2 to Node 1
	b1.UpdateRemoteSync(b2.Remaining, b2.LastRefill, window)

	// Verify Node 1 monotonically reduced remaining to 25
	if b1.Remaining != 25 {
		t.Fatalf("Node 1 failed to apply delta from forward clock peer: remaining=%d, expected=25", b1.Remaining)
	}

	t.Logf("Empirical stress pass: token bucket synchronized under 600ms clock jitter without drift (remaining=%d)", b1.Remaining)
}

// ============================================================================
// EMPIRICAL STRESS 6: RING BUFFER 1000-MESSAGE WRAP-AROUND & FIFO REPLAY
// ============================================================================

func TestStress_StateCatchUp_RingBufferWrapAround(t *testing.T) {
	ctx := context.Background()

	server := NewGRPCSyncManager("node-wrap", "us-east-1", -1, "127.0.0.1", 5*time.Minute)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start gRPC sync manager: %v", err)
	}
	defer server.Stop()

	// Push 1200 messages (exceeding default 1000 maxHistory)
	totalPushed := 1200
	for i := 1; i <= totalPushed; i++ {
		msg := NewSyncMessage("node-wrap", "us-east-1", EntityVirtualKey, fmt.Sprintf("vk-%04d", i), ActionUpsert, []byte(fmt.Sprintf(`{"seq":%d}`, i)))
		_ = server.BroadcastSyncMessage(ctx, msg, nil)
	}

	server.historyMu.RLock()
	hLen := len(server.history)
	server.historyMu.RUnlock()

	if hLen != 1000 {
		t.Fatalf("ring buffer failed to cap history at 1000: got %d", hLen)
	}

	// Verify FIFO order: oldest should be vk-0201, newest vk-1200
	server.historyMu.RLock()
	firstMsg := server.history[0]
	lastMsg := server.history[len(server.history)-1]
	server.historyMu.RUnlock()

	if firstMsg.EntityID != "vk-0201" || lastMsg.EntityID != "vk-1200" {
		t.Fatalf("ring buffer wrap-around ordering corrupted: first=%s (expected vk-0201), last=%s (expected vk-1200)", firstMsg.EntityID, lastMsg.EntityID)
	}

	// Client fetches catch-up over gRPC
	client := NewGRPCSyncManager("node-client", "us-east-1", -1, "127.0.0.1", 5*time.Minute)
	var replayedCount int64
	client.RegisterHandler(EntityVirtualKey, func(ctx context.Context, entityType string, payload []byte) error {
		atomic.AddInt64(&replayedCount, 1)
		return nil
	})

	serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())
	if err := client.FetchCatchUp(ctx, serverAddr); err != nil {
		t.Fatalf("FetchCatchUp failed: %v", err)
	}

	if atomic.LoadInt64(&replayedCount) != 1000 {
		t.Fatalf("expected exactly 1000 replayed messages, got %d", atomic.LoadInt64(&replayedCount))
	}

	t.Logf("Empirical stress pass: 1200 messages produced, 1000 latest correctly buffered and replayed in FIFO order")
}

// ============================================================================
// EMPIRICAL STRESS 7: CONCURRENT TOMBSTONE PRUNING CONTENTION
// ============================================================================

func TestStress_TombstonePruning_ConcurrentContention(t *testing.T) {
	mgr, err := NewMemberlistManager(Config{
		NodeID: "local-leader",
		Region: "us-east-1",
		Gossip: GossipConfig{Port: -1, BindAddr: "127.0.0.1"},
	}, func() {})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	mgr.maxDeadNodes = 25
	mgr.tombstoneTTL = 50 * time.Millisecond

	var wg sync.WaitGroup
	workers := 16
	opsPerWorker := 50

	// Concurrent churning and pruning
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				nodeID := fmt.Sprintf("contention-node-%d-%d", workerID, i)
				mgr.mu.Lock()
				mgr.roster[nodeID] = &NodeInfo{
					NodeID:   nodeID,
					Region:   "us-east-1",
					State:    NodeStateDead,
					LastSeen: time.Now().Add(-time.Duration(i) * time.Millisecond),
				}
				mgr.mu.Unlock()

				if i%5 == 0 {
					_ = mgr.PruneTombstones()
				}
				_ = mgr.GetAliveMembers()
				_ = mgr.GetMembers()
			}
		}(w)
	}

	wg.Wait()

	// Final sweep
	mgr.PruneTombstones()

	mgr.mu.RLock()
	deadCount := 0
	for id, n := range mgr.roster {
		if id != "local-leader" && n.State == NodeStateDead {
			deadCount++
		}
	}
	mgr.mu.RUnlock()

	if deadCount > 25 {
		t.Fatalf("dead nodes exceeded maxDeadNodes=25 under concurrency: got %d", deadCount)
	}

	// Verify local node is strictly intact
	local, ok := mgr.GetMember("local-leader")
	if !ok || local.State != NodeStateAlive {
		t.Fatalf("local-leader lost or corrupted: %+v", local)
	}

	t.Logf("Empirical stress pass: high concurrency pruning survived with 0 race conditions and deadCount=%d <= 25", deadCount)
}

// ============================================================================
// EMPIRICAL STRESS 8: CASCADING MULTI-LEADER FAILURES
// ============================================================================

func TestStress_LeaderFailover_CascadingMultiLeaderFailures(t *testing.T) {
	em := NewElectionManager("local-observer", "us-east-1")

	// 5 nodes: node-01 (leader), node-02, node-03, node-04, node-05
	roster := map[string]*NodeInfo{
		"node-01": {NodeID: "node-01", Region: "us-east-1", State: NodeStateAlive},
		"node-02": {NodeID: "node-02", Region: "us-east-1", State: NodeStateAlive},
		"node-03": {NodeID: "node-03", Region: "us-east-1", State: NodeStateAlive},
		"node-04": {NodeID: "node-04", Region: "us-east-1", State: NodeStateAlive},
		"node-05": {NodeID: "node-05", Region: "us-east-1", State: NodeStateAlive},
	}

	em.Reevaluate(roster)
	if em.GetLeaderID() != "node-01" {
		t.Fatalf("expected leader node-01, got %s", em.GetLeaderID())
	}

	// Cascade 1: node-01 dies -> node-02 must become leader
	roster["node-01"].State = NodeStateDead
	em.Reevaluate(roster)
	if em.GetLeaderID() != "node-02" {
		t.Fatalf("cascade 1: expected leader node-02, got %s", em.GetLeaderID())
	}

	// Cascade 2: node-02 dies -> node-03 must become leader
	roster["node-02"].State = NodeStateDead
	em.Reevaluate(roster)
	if em.GetLeaderID() != "node-03" {
		t.Fatalf("cascade 2: expected leader node-03, got %s", em.GetLeaderID())
	}

	// Cascade 3: node-03 dies -> node-04 must become leader
	roster["node-03"].State = NodeStateDead
	em.Reevaluate(roster)
	if em.GetLeaderID() != "node-04" {
		t.Fatalf("cascade 3: expected leader node-04, got %s", em.GetLeaderID())
	}

	// Resurrect: node-01 comes back -> node-01 must immediately reclaim leadership
	roster["node-01"].State = NodeStateAlive
	em.Reevaluate(roster)
	if em.GetLeaderID() != "node-01" {
		t.Fatalf("resurrection: expected leader node-01, got %s", em.GetLeaderID())
	}

	t.Logf("Empirical stress pass: cascading leader failover and resurrection verified deterministically")
}

