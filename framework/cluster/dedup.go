package cluster

import (
	"sync"
	"time"
)

// DedupCache provides a high-performance in-memory deduplication cache with a configurable TTL (default 5 minutes),
// and tracks entity-level Last-Write-Wins (LWW) nanosecond timestamps.
type DedupCache struct {
	mu           sync.RWMutex
	seenMessages map[string]int64 // message_id -> expiry_ns
	entityLWW    map[string]int64 // entity_key -> latest_timestamp_ns
	ttl          time.Duration
	stopCh       chan struct{}
	closeOnce    sync.Once
}

// NewDedupCache creates and starts a new DedupCache.
func NewDedupCache(ttl time.Duration) *DedupCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c := &DedupCache{
		seenMessages: make(map[string]int64),
		entityLWW:    make(map[string]int64),
		ttl:          ttl,
		stopCh:       make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// CheckAndRecord checks if a message ID has been seen within the TTL window.
// Returns true if the message is a duplicate, or false if it is new (recording it).
func (c *DedupCache) CheckAndRecord(messageID string) bool {
	if messageID == "" {
		return false
	}
	now := time.Now().UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()

	if expiry, ok := c.seenMessages[messageID]; ok && expiry > now {
		return true // Duplicate message
	}

	c.seenMessages[messageID] = now + c.ttl.Nanoseconds()
	return false
}

// CheckLWW checks if the incoming timestamp is newer than or equal to the last seen timestamp
// for the given entity key (Last-Write-Wins nanosecond resolution).
// Returns true if the update is accepted (newer or equal), and updates the stored timestamp.
// Returns false if the incoming update is stale (an older update).
func (c *DedupCache) CheckLWW(entityKey string, timestampNs int64) bool {
	if entityKey == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	lastTs, exists := c.entityLWW[entityKey]
	if exists && lastTs > timestampNs {
		return false // Stale write rejected under LWW
	}

	c.entityLWW[entityKey] = timestampNs
	return true
}

// Invalidate removes a message ID from the cache.
func (c *DedupCache) Invalidate(messageID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seenMessages, messageID)
}

// Clear flushes all entries.
func (c *DedupCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seenMessages = make(map[string]int64)
	c.entityLWW = make(map[string]int64)
}

// cleanupLoop periodically evicts expired message IDs.
func (c *DedupCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			c.mu.Lock()
			for id, expiry := range c.seenMessages {
				if expiry <= now {
					delete(c.seenMessages, id)
				}
			}
			c.mu.Unlock()
		}
	}
}

// Close stops the cleanup goroutine.
func (c *DedupCache) Close() {
	c.closeOnce.Do(func() {
		close(c.stopCh)
	})
}
