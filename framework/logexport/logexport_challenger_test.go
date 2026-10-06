package logexport

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/objectstore"
)

// ============================================================================
// 1. BATCHED LOG QUEUE: EMPTY FLUSH NO-OP, THRESHOLDS, CONCURRENCY
// ============================================================================

// TestLogExport_Queue_EmptyFlush_StrictNoOp verifies that calling Flush()
// on an empty queue (or repeatedly) never generates phantom batches.
func TestLogExport_Queue_EmptyFlush_StrictNoOp(t *testing.T) {
	cfg := Config{
		QueueCapacity: 1000,
		BatchSize:     10,
		FlushInterval: 1 * time.Hour, // do not trigger by interval
	}
	q := NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	// 1. Immediate flush on clean queue
	q.Flush()
	if len(q.GetFlushedBatches()) != 0 {
		t.Fatalf("expected 0 flushed batches on clean queue, got %d", len(q.GetFlushedBatches()))
	}

	// 2. Multiple consecutive flushes on empty queue
	for i := 0; i < 5; i++ {
		q.Flush()
	}
	if len(q.GetFlushedBatches()) != 0 {
		t.Fatalf("expected 0 flushed batches after repeated flushes on empty queue, got %d", len(q.GetFlushedBatches()))
	}

	// 3. Enqueue 2 items (below batch size 10), then flush
	q.Enqueue(&LogEntry{ID: "e1"})
	q.Enqueue(&LogEntry{ID: "e2"})
	q.Flush()

	batches := q.GetFlushedBatches()
	if len(batches) != 1 {
		t.Fatalf("expected exactly 1 batch after manual flush with items, got %d", len(batches))
	}
	if len(batches[0]) != 2 {
		t.Fatalf("expected 2 items in batch, got %d", len(batches[0]))
	}

	// 4. Flush again immediately: queue is empty now -> must NOT create a 2nd batch!
	q.Flush()
	batchesAfter := q.GetFlushedBatches()
	if len(batchesAfter) != 1 {
		t.Fatalf("expected still exactly 1 batch after flush on newly drained queue, got %d", len(batchesAfter))
	}
}

// TestLogExport_Queue_BackpressureDrop verifies that when queue capacity is saturated
// and BackpressureDrop is selected, excess items are dropped and DroppedCount increments.
func TestLogExport_Queue_BackpressureDrop(t *testing.T) {
	cfg := Config{
		QueueCapacity: 5,
		BatchSize:     100, // Large batch size so worker won't drain immediately on count
		FlushInterval: 1 * time.Hour,
		Backpressure:  BackpressureDrop,
	}
	q := NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	// Quickly burst 50 items into capacity-5 queue
	accepted := 0
	dropped := 0
	for i := 0; i < 50; i++ {
		ok := q.Enqueue(&LogEntry{ID: fmt.Sprintf("burst-%d", i)})
		if ok {
			accepted++
		} else {
			dropped++
		}
	}

	if dropped == 0 {
		t.Fatalf("expected drops under BackpressureDrop on saturated queue")
	}
	if q.DroppedCount() != int64(dropped) {
		t.Fatalf("expected DroppedCount() == %d, got %d", dropped, q.DroppedCount())
	}
}

// TestLogExport_Queue_BackpressureBlock verifies that BackpressureBlock slows down
// producers to match consumer pace without dropping items.
func TestLogExport_Queue_BackpressureBlock(t *testing.T) {
	cfg := Config{
		QueueCapacity: 5,
		BatchSize:     5,
		FlushInterval: 10 * time.Millisecond, // Worker drains quickly
		Backpressure:  BackpressureBlock,
	}
	q := NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	const numItems = 25
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for i := 0; i < numItems; i++ {
			ok := q.Enqueue(&LogEntry{ID: fmt.Sprintf("block-%d", i)})
			if !ok {
				t.Errorf("expected Enqueue with BackpressureBlock to succeed, failed at %d", i)
			}
		}
	}()

	wg.Wait()
	q.Flush()

	if q.DroppedCount() != 0 {
		t.Fatalf("expected 0 dropped items under BackpressureBlock, got %d", q.DroppedCount())
	}

	batches := q.GetFlushedBatches()
	totalReceived := 0
	for _, b := range batches {
		totalReceived += len(b)
	}
	if totalReceived != numItems {
		t.Fatalf("expected all %d items delivered, got %d", numItems, totalReceived)
	}
}

// TestLogExport_Queue_BackpressureBlock_CloseUnblocks verifies that closing a queue
// cleanly unblocks any goroutine blocked on BackpressureBlock without hanging,
// and subsequent enqueues on the closed queue are strictly rejected.
func TestLogExport_Queue_BackpressureBlock_CloseUnblocks(t *testing.T) {
	cfg := Config{
		QueueCapacity: 2,
		BatchSize:     100,
		FlushInterval: 1 * time.Hour,
		Backpressure:  BackpressureBlock,
	}
	q := NewBatchedLogQueue(cfg, nil)

	// Fill queue to capacity
	q.Enqueue(&LogEntry{ID: "fill-1"})
	q.Enqueue(&LogEntry{ID: "fill-2"})

	unblocked := make(chan bool)
	go func() {
		// This will block because queue is full (cap=2) and worker won't drain (batchSize=100)
		ok := q.Enqueue(&LogEntry{ID: "blocked-item"})
		unblocked <- ok
	}()

	// Brief pause to ensure goroutine is blocked on select
	time.Sleep(20 * time.Millisecond)

	// Close queue
	_ = q.Close(context.Background())

	select {
	case <-unblocked:
		// Succeeded in unblocking promptly (either drained into batch or returned false)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("deadlock: Close did not unblock waiting producer in BackpressureBlock")
	}

	// Any subsequent enqueue on the closed queue must strictly be rejected
	postCloseOk := q.Enqueue(&LogEntry{ID: "post-close-item"})
	if postCloseOk {
		t.Fatalf("expected Enqueue on closed queue to return false")
	}
}

// TestLogExport_Queue_HeavyConcurrency_500Goroutines runs 500 concurrent producers
// under race detector to verify thread-safety and queue integrity.
func TestLogExport_Queue_HeavyConcurrency_500Goroutines(t *testing.T) {
	cfg := Config{
		QueueCapacity: 5000,
		BatchSize:     50,
		FlushInterval: 20 * time.Millisecond,
		Backpressure:  BackpressureDrop,
	}
	q := NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	const totalGoroutines = 500
	const itemsPerRoutine = 10
	var wg sync.WaitGroup
	wg.Add(totalGoroutines)

	startBarrier := make(chan struct{})

	for g := 0; g < totalGoroutines; g++ {
		go func(routineID int) {
			defer wg.Done()
			<-startBarrier

			for i := 0; i < itemsPerRoutine; i++ {
				q.Enqueue(&LogEntry{
					ID:        fmt.Sprintf("g%d-%d", routineID, i),
					Timestamp: time.Now().UTC(),
					Model:     "gpt-4o",
					LatencyMs: 45.2,
				})
			}
		}(g)
	}

	close(startBarrier)
	wg.Wait()

	q.Flush()

	batches := q.GetFlushedBatches()
	totalFlushed := 0
	for _, b := range batches {
		totalFlushed += len(b)
	}
	totalDropped := q.DroppedCount()

	if totalFlushed+int(totalDropped) != totalGoroutines*itemsPerRoutine {
		t.Fatalf("accounting mismatch: flushed (%d) + dropped (%d) != %d total enqueued",
			totalFlushed, totalDropped, totalGoroutines*itemsPerRoutine)
	}
}

// ============================================================================
// 2. DATADOG STREAMER: ZERO TRACE RETENTION & MEMORY LEAK VERIFICATION
// ============================================================================

// TestLogExport_Datadog_ZeroTraceRetention verifies that DatadogStreamer never
// stores or retains any pointer/reference to *schemas.Trace after Inject returns.
func TestLogExport_Datadog_ZeroTraceRetention(t *testing.T) {
	streamer := NewDatadogStreamer(DatadogConfig{
		Enabled:     true,
		ServiceName: "bifrost-zero-retention",
		Env:         "test",
	})

	now := time.Now().UTC()
	originalTraceID := "trace-immutable-123"
	originalModel := "claude-3-5-sonnet"

	trace := &schemas.Trace{
		RequestID:  "req-zr-1",
		TraceID:    originalTraceID,
		InternalID: "span-zr-1",
		StartTime:  now.Add(-100 * time.Millisecond),
		EndTime:    now,
		Attributes: map[string]any{
			"gen_ai.usage.input_tokens":  200,
			"gen_ai.usage.output_tokens": 100,
			"gen_ai.usage.total_tokens":  300,
		},
		RootSpan: &schemas.Span{
			Name: "chat.completion",
			Attributes: map[string]any{
				"model": originalModel,
			},
		},
	}

	// 1. Inject trace
	if err := streamer.Inject(context.Background(), trace); err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// 2. Mutate trace fields violently to simulate reuse / pool corruption
	trace.TraceID = "corrupted-trace-id"
	trace.InternalID = "corrupted-span-id"
	trace.Attributes["gen_ai.usage.input_tokens"] = 999999
	trace.RootSpan.Attributes["model"] = "hacked-model"
	trace.RootSpan = nil
	trace.Attributes = nil
	trace.Reset()

	// 3. Inspect captured spans inside streamer
	captured := streamer.GetCapturedSpans()
	if len(captured) == 0 {
		t.Fatalf("expected captured span")
	}

	span := captured[0]
	// Verify captured span has independent copy unaffected by trace mutation
	if span.Meta["model"] != originalModel {
		t.Fatalf("retained pointer leak! Expected model %s, got %s", originalModel, span.Meta["model"])
	}
	if span.Metrics["llm.prompt_tokens"] != 200 {
		t.Fatalf("retained pointer leak! Expected prompt tokens 200, got %v", span.Metrics["llm.prompt_tokens"])
	}
	if span.TraceID == hashStringToUint64("corrupted-trace-id") {
		t.Fatalf("retained pointer leak! TraceID updated to corrupted value")
	}
}

// TestLogExport_Datadog_TraceGarbageCollection verifies that *schemas.Trace
// can be garbage-collected immediately after Inject returns, proving no retention.
func TestLogExport_Datadog_TraceGarbageCollection(t *testing.T) {
	streamer := NewDatadogStreamer(DatadogConfig{
		Enabled:     true,
		ServiceName: "bifrost-gc-test",
	})

	var collected atomic.Bool

	injectAndDropTrace := func() {
		now := time.Now().UTC()
		tObj := &schemas.Trace{
			RequestID:  "req-gc-1",
			TraceID:    "trace-gc-1",
			InternalID: "span-gc-1",
			StartTime:  now.Add(-50 * time.Millisecond),
			EndTime:    now,
			RootSpan: &schemas.Span{
				Name: "chat.completion",
				Attributes: map[string]any{
					"model": "gpt-4o",
				},
			},
		}

		// Register finalizer
		runtime.SetFinalizer(tObj, func(tr *schemas.Trace) {
			collected.Store(true)
		})

		_ = streamer.Inject(context.Background(), tObj)
		// tObj falls out of scope here
	}

	injectAndDropTrace()

	// Trigger GC multiple times to collect unreachable objects
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		if collected.Load() {
			break
		}
	}

	if !collected.Load() {
		t.Fatalf("memory leak: *schemas.Trace was NOT garbage collected after Inject returned!")
	}
}

// TestLogExport_Datadog_EdgeCases verifies edge case handling for invalid/nil traces.
func TestLogExport_Datadog_EdgeCases(t *testing.T) {
	streamer := NewDatadogStreamer(DatadogConfig{
		Enabled:     true,
		ServiceName: "bifrost-edge",
	})

	ctx := context.Background()

	// 1. Nil trace -> graceful no-op
	if err := streamer.Inject(ctx, nil); err != nil {
		t.Fatalf("expected nil trace to return nil error, got: %v", err)
	}

	// 2. Trace with nil RootSpan & nil Attributes
	emptyTrace := &schemas.Trace{
		RequestID: "empty-req",
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	if err := streamer.Inject(ctx, emptyTrace); err != nil {
		t.Fatalf("expected empty trace to succeed, got: %v", err)
	}

	// 3. Negative duration trace (EndTime before StartTime)
	now := time.Now()
	reversedTrace := &schemas.Trace{
		RequestID: "reversed-time",
		StartTime: now,
		EndTime:   now.Add(-10 * time.Second),
		RootSpan:  &schemas.Span{Name: "test"},
	}
	if err := streamer.Inject(ctx, reversedTrace); err != nil {
		t.Fatalf("expected reversed trace to succeed, got: %v", err)
	}
	spans := streamer.GetCapturedSpans()
	lastSpan := spans[len(spans)-1]
	if lastSpan.Duration <= 0 {
		t.Fatalf("expected normalized positive duration for negative span duration, got %d", lastSpan.Duration)
	}
}

// ============================================================================
// 3. PAYLOAD OFFLOADER: THRESHOLD BOUNDARIES & URI PARSING (FEATURES 36 & 37)
// ============================================================================

func TestLogExport_Offloader_ThresholdBoundaries(t *testing.T) {
	store := objectstore.NewInMemoryObjectStore()
	const threshold = 100
	offloader := NewPayloadOffloader(store, threshold, "test", false)

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Below threshold (99 bytes) -> NOT offloaded
	below := []byte(strings.Repeat("a", threshold-1))
	offloaded, uri, err := offloader.OffloadIfLarge(ctx, "s3", now, "id-1", "req", below)
	if err != nil || offloaded || uri != string(below) {
		t.Fatalf("expected below threshold NOT offloaded: offloaded=%v, uri=%s", offloaded, uri)
	}

	// 2. Exactly threshold (100 bytes) -> OFFLOADED
	exact := []byte(strings.Repeat("b", threshold))
	offloaded, uri, err = offloader.OffloadIfLarge(ctx, "s3", now, "id-2", "req", exact)
	if err != nil || !offloaded || !strings.HasPrefix(uri, "s3://") {
		t.Fatalf("expected exact threshold to be offloaded: offloaded=%v, uri=%s", offloaded, uri)
	}

	// 3. GCS URI scheme check ("gs://")
	offloaded, gcsURI, err := offloader.OffloadIfLarge(ctx, "gcs", now, "id-3", "resp", exact)
	if err != nil || !offloaded || !strings.HasPrefix(gcsURI, "gs://") {
		t.Fatalf("expected GCS URI prefix 'gs://', got %s", gcsURI)
	}

	// 4. Fetch non-existent URI -> returns error
	_, err = offloader.FetchOffloadedPayload(ctx, "s3://non-existent-key")
	if err == nil {
		t.Fatalf("expected error fetching non-existent offloaded payload")
	}
}
