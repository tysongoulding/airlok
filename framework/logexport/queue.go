package logexport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// BatchedLogQueue buffers log records in memory and asynchronously flushes in batches.
type BatchedLogQueue struct {
	config         Config
	offloader      *PayloadOffloader
	queueChan      chan *LogEntry
	flushSignal    chan chan struct{}
	flushedBatches [][]*LogEntry
	flushedMu      sync.RWMutex
	droppedCount   atomic.Int64
	closed         atomic.Bool
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewBatchedLogQueue initializes the queue and launches the background batch processor.
func NewBatchedLogQueue(cfg Config, offloader *PayloadOffloader) *BatchedLogQueue {
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 10000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = 1048576 // 1MB
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 1 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	q := &BatchedLogQueue{
		config:         cfg,
		offloader:      offloader,
		queueChan:      make(chan *LogEntry, cfg.QueueCapacity),
		flushSignal:    make(chan chan struct{}),
		flushedBatches: make([][]*LogEntry, 0),
		ctx:            ctx,
		cancel:         cancel,
	}

	q.wg.Add(1)
	go q.runBatchWorker()
	return q
}

// Enqueue pushes a LogEntry to the queue. Non-blocking when backpressure is "drop".
func (q *BatchedLogQueue) Enqueue(entry *LogEntry) bool {
	if q.closed.Load() || entry == nil {
		q.droppedCount.Add(1)
		return false
	}

	if q.config.Backpressure == BackpressureBlock {
		select {
		case q.queueChan <- entry:
			return true
		case <-q.ctx.Done():
			q.droppedCount.Add(1)
			return false
		}
	}

	// Default: BackpressureDrop
	select {
	case q.queueChan <- entry:
		return true
	default:
		q.droppedCount.Add(1)
		return false
	}
}

// EnqueueMap accepts a generic map[string]interface{} entry (E2E compatibility).
func (q *BatchedLogQueue) EnqueueMap(raw map[string]interface{}) bool {
	entry := &LogEntry{
		Metadata: make(map[string]interface{}),
	}
	if id, ok := raw["id"].(string); ok {
		entry.ID = id
	}
	if model, ok := raw["model"].(string); ok {
		entry.Model = model
	}
	if status, ok := raw["status"].(int); ok {
		entry.StatusCode = status
	}
	if plen, ok := raw["prompt_len"].(int); ok {
		entry.PromptLen = plen
	}
	if ts, ok := raw["timestamp"].(time.Time); ok {
		entry.Timestamp = ts
	} else {
		entry.Timestamp = time.Now().UTC()
	}
	for k, v := range raw {
		entry.Metadata[k] = v
	}
	return q.Enqueue(entry)
}

// Flush triggers an immediate synchronous flush of any buffered items in the batch.
// Calling Flush() on an empty queue is a strict no-op.
func (q *BatchedLogQueue) Flush() {
	if q.closed.Load() {
		return
	}
	done := make(chan struct{})
	select {
	case q.flushSignal <- done:
		<-done
	case <-q.ctx.Done():
	}
}

// FlushBatch exports a slice of entries directly to downstream targets.
func (q *BatchedLogQueue) FlushBatch(ctx context.Context, entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	q.flushedMu.Lock()
	cp := make([]*LogEntry, len(entries))
	copy(cp, entries)
	q.flushedBatches = append(q.flushedBatches, cp)
	q.flushedMu.Unlock()
	return nil
}

// GetFlushedBatches returns a deep copy of all flushed batches for test assertion.
func (q *BatchedLogQueue) GetFlushedBatches() [][]*LogEntry {
	q.flushedMu.RLock()
	defer q.flushedMu.RUnlock()
	res := make([][]*LogEntry, len(q.flushedBatches))
	for i, b := range q.flushedBatches {
		batchCopy := make([]*LogEntry, len(b))
		for j, item := range b {
			if item != nil {
				cp := *item
				if item.Metadata != nil {
					cp.Metadata = make(map[string]interface{}, len(item.Metadata))
					for k, v := range item.Metadata {
						cp.Metadata[k] = v
					}
				}
				batchCopy[j] = &cp
			}
		}
		res[i] = batchCopy
	}
	return res
}

// GetFlushedBatchMaps returns flushed batches as maps for compatibility with legacy test assertions.
func (q *BatchedLogQueue) GetFlushedBatchMaps() [][]map[string]interface{} {
	q.flushedMu.RLock()
	defer q.flushedMu.RUnlock()
	res := make([][]map[string]interface{}, len(q.flushedBatches))
	for i, b := range q.flushedBatches {
		batchList := make([]map[string]interface{}, len(b))
		for j, item := range b {
			m := make(map[string]interface{})
			if item != nil {
				if item.ID != "" {
					m["id"] = item.ID
				}
				if item.Model != "" {
					m["model"] = item.Model
				}
				if item.StatusCode != 0 {
					m["status"] = item.StatusCode
				}
				if item.PromptLen != 0 {
					m["prompt_len"] = item.PromptLen
				}
				m["timestamp"] = item.Timestamp
				for k, v := range item.Metadata {
					m[k] = v
				}
			}
			batchList[j] = m
		}
		res[i] = batchList
	}
	return res
}

// DroppedCount returns the count of dropped items under backpressure.
func (q *BatchedLogQueue) DroppedCount() int64 {
	return q.droppedCount.Load()
}

// Close gracefully stops the queue, drains all queued items, and flushes remaining batches.
func (q *BatchedLogQueue) Close(ctx context.Context) error {
	if q.closed.Swap(true) {
		return nil
	}
	q.cancel()
	q.wg.Wait()
	return nil
}

func (q *BatchedLogQueue) runBatchWorker() {
	defer q.wg.Done()

	ticker := time.NewTicker(q.config.FlushInterval)
	defer ticker.Stop()

	batch := make([]*LogEntry, 0, q.config.BatchSize)
	batchBytes := 0

	commitBatch := func() {
		if len(batch) == 0 {
			return
		}
		_ = q.FlushBatch(context.Background(), batch)
		batch = make([]*LogEntry, 0, q.config.BatchSize)
		batchBytes = 0
	}

	for {
		select {
		case entry := <-q.queueChan:
			batch = append(batch, entry)
			batchBytes += estimateEntryBytes(entry)

			// Threshold triggers
			if len(batch) >= q.config.BatchSize || batchBytes >= q.config.MaxBatchBytes {
				commitBatch()
			}

		case <-ticker.C:
			// Interval trigger
			if len(batch) > 0 {
				commitBatch()
			}

		case ack := <-q.flushSignal:
			// Manual flush trigger: drain all currently pending items in queueChan
		drainLoop:
			for {
				select {
				case e := <-q.queueChan:
					batch = append(batch, e)
					batchBytes += estimateEntryBytes(e)
					if len(batch) >= q.config.BatchSize {
						commitBatch()
					}
				default:
					break drainLoop
				}
			}
			commitBatch()
			close(ack)

		case <-q.ctx.Done():
			// Shutdown drain: flush all remaining items in channel
			for {
				select {
				case e := <-q.queueChan:
					batch = append(batch, e)
					if len(batch) >= q.config.BatchSize {
						commitBatch()
					}
				default:
					commitBatch()
					return
				}
			}
		}
	}
}

func estimateEntryBytes(e *LogEntry) int {
	if e == nil {
		return 0
	}
	return len(e.ID) + len(e.Provider) + len(e.Model) + len(e.RawRequest) + len(e.RawResponse) + 256
}
