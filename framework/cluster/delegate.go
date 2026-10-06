package cluster

import (
	"encoding/json"
)

// ClusterKVStoreDelegate bridges kvstore.Store mutations to cluster-wide broadcast replication.
type ClusterKVStoreDelegate struct {
	coordinator ClusterCoordinator
}

// NewClusterKVStoreDelegate creates a delegate bridging KV store updates to the cluster coordinator.
func NewClusterKVStoreDelegate(coordinator ClusterCoordinator) *ClusterKVStoreDelegate {
	return &ClusterKVStoreDelegate{
		coordinator: coordinator,
	}
}

// OnSet broadcasts a SET operation across the cluster with nanosecond timestamps for LWW conflict resolution.
func (d *ClusterKVStoreDelegate) OnSet(key string, valueJSON []byte, writtenAt int64, expiresAt int64) {
	if d.coordinator == nil {
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"key":        key,
		"value":      string(valueJSON),
		"written_at": writtenAt,
		"expires_at": expiresAt,
	})
	if err == nil {
		_ = d.coordinator.BroadcastState(EntityKVStore, payload)
	}
}

// OnDelete broadcasts a DELETE operation across the cluster.
func (d *ClusterKVStoreDelegate) OnDelete(key string, deletedAt int64) {
	if d.coordinator == nil {
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"key":        key,
		"deleted_at": deletedAt,
	})
	if err == nil {
		_ = d.coordinator.BroadcastState(EntityKVStore, payload)
	}
}
