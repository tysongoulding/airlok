package cluster

import (
	"sort"
	"sync"
	"time"
)

// ElectionManager performs deterministic lexicographical leader election for the cluster
// and per-region leadership roles with sub-millisecond local failover.
type ElectionManager struct {
	mu            sync.RWMutex
	localNodeID   string
	localRegion   string
	leaderNodeID  string
	regLeaderIDs  map[string]string // region -> leaderNodeID
	listeners     []LeadershipListener
	stopCh        chan struct{}
	closeOnce     sync.Once
}

// NewElectionManager initializes a new ElectionManager for the local node.
func NewElectionManager(localNodeID, localRegion string) *ElectionManager {
	return &ElectionManager{
		localNodeID:  localNodeID,
		localRegion:  localRegion,
		regLeaderIDs: make(map[string]string),
		stopCh:       make(chan struct{}),
	}
}

// AddLeadershipListener registers a listener for leadership changes.
func (e *ElectionManager) AddLeadershipListener(l LeadershipListener) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listeners = append(e.listeners, l)
}

// GetLeaderID returns the current elected cluster leader ID.
func (e *ElectionManager) GetLeaderID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leaderNodeID
}

// GetRegionalLeaderID returns the current elected leader ID for a given region.
func (e *ElectionManager) GetRegionalLeaderID(region string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.regLeaderIDs[region]
}

// IsLeader returns true if the local node is the cluster leader.
func (e *ElectionManager) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leaderNodeID == e.localNodeID && e.leaderNodeID != ""
}

// IsRegionalLeader returns true if the local node is the regional leader for its region.
func (e *ElectionManager) IsRegionalLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.regLeaderIDs[e.localRegion] == e.localNodeID && e.localNodeID != ""
}

// Reevaluate recomputes both cluster-wide and regional leadership based on the current roster of alive nodes.
func (e *ElectionManager) Reevaluate(nodes map[string]*NodeInfo) (leaderChanged bool, newLeader *NodeInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var aliveIDs []string
	regAliveIDs := make(map[string][]string)

	// Collect alive node IDs and clear previous leadership flags
	for id, n := range nodes {
		n.IsLeader = false
		n.IsRegLeader = false
		if n.State == NodeStateAlive {
			aliveIDs = append(aliveIDs, id)
			reg := n.Region
			if reg == "" {
				reg = "unknown"
			}
			regAliveIDs[reg] = append(regAliveIDs[reg], id)
		}
	}

	prevLeader := e.leaderNodeID
	newLeaderID := ""

	if len(aliveIDs) > 0 {
		sort.Strings(aliveIDs)
		newLeaderID = aliveIDs[0] // Lexicographically smallest alive node ID wins
		e.leaderNodeID = newLeaderID
		if node, ok := nodes[newLeaderID]; ok {
			node.IsLeader = true
			newLeader = node
		}
	} else {
		e.leaderNodeID = ""
	}

	// Recompute regional leaders
	for region, rIDs := range regAliveIDs {
		if len(rIDs) > 0 {
			sort.Strings(rIDs)
			regLeader := rIDs[0]
			e.regLeaderIDs[region] = regLeader
			if node, ok := nodes[regLeader]; ok {
				node.IsRegLeader = true
			}
		} else {
			delete(e.regLeaderIDs, region)
		}
	}

	leaderChanged = prevLeader != newLeaderID

	// Notify listeners if leader changed or newly elected
	if newLeader != nil && leaderChanged {
		isLocal := (newLeaderID == e.localNodeID)
		leaderCopy := *newLeader
		for _, l := range e.listeners {
			go l.OnLeaderElected(leaderCopy, isLocal)
		}
	}

	// Regional notifications
	for region, rLeaderID := range e.regLeaderIDs {
		if node, ok := nodes[rLeaderID]; ok {
			isLocal := (rLeaderID == e.localNodeID)
			rCopy := *node
			for _, l := range e.listeners {
				go l.OnRegionalLeaderElected(region, rCopy, isLocal)
			}
		}
	}

	return leaderChanged, newLeader
}

// StartPeriodicTicker runs a safety background ticker (every 30 seconds) to ensure eventual consistency.
func (e *ElectionManager) StartPeriodicTicker(recalcFunc func()) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.stopCh:
				return
			case <-ticker.C:
				recalcFunc()
			}
		}
	}()
}

// Close stops the periodic ticker.
func (e *ElectionManager) Close() {
	e.closeOnce.Do(func() {
		close(e.stopCh)
	})
}
