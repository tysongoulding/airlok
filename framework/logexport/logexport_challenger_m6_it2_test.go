package logexport

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/objectstore"
)

// TestChallenger_Queue_ExtremeConcurrency_500Goroutines exercises
// 500 concurrent producers and 5 concurrent manual flushers under BackpressureDrop.
func TestChallenger_Queue_ExtremeConcurrency_500Goroutines(t *testing.T) {
	cfg := Config{
		QueueCapacity: 2000,
		BatchSize:     25,
		FlushInterval: 10 * time.Millisecond,
		Backpressure:  BackpressureDrop,
	}
	q := NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	const producers = 500
	const itemsPerProducer = 10
	var wg sync.WaitGroup
	wg.Add(producers + 5)

	startBarrier := make(chan struct{})

	// 500 producers
	for p := 0; p < producers; p++ {
		go func(id int) {
			defer wg.Done()
			<-startBarrier
			for i := 0; i < itemsPerProducer; i++ {
				q.Enqueue(&LogEntry{
					ID:        fmt.Sprintf("e-%d-%d", id, i),
					Timestamp: time.Now().UTC(),
					Model:     "gpt-4o",
					LatencyMs: 12.5,
				})
			}
		}(p)
	}

	// 5 concurrent flushers
	for f := 0; f < 5; f++ {
		go func(fid int) {
			defer wg.Done()
			<-startBarrier
			for i := 0; i < 5; i++ {
				q.Flush()
				time.Sleep(5 * time.Millisecond)
			}
		}(f)
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

	if totalFlushed+int(totalDropped) != producers*itemsPerProducer {
		t.Fatalf("accounting mismatch: flushed=%d, dropped=%d, total=%d",
			totalFlushed, totalDropped, producers*itemsPerProducer)
	}
}

// TestChallenger_Datadog_ConcurrentInject500Goroutines exercises
// 500 concurrent goroutines calling DatadogStreamer.Inject simultaneously.
func TestChallenger_Datadog_ConcurrentInject500Goroutines(t *testing.T) {
	streamer := NewDatadogStreamer(DatadogConfig{
		Enabled:     true,
		ServiceName: "bifrost-adv-500",
		Env:         "test",
	})

	const totalGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(totalGoroutines)

	startBarrier := make(chan struct{})

	for g := 0; g < totalGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			<-startBarrier

			now := time.Now().UTC()
			trace := &schemas.Trace{
				RequestID:  fmt.Sprintf("req-%d", id),
				TraceID:    fmt.Sprintf("trace-%d", id),
				InternalID: fmt.Sprintf("span-%d", id),
				StartTime:  now.Add(-50 * time.Millisecond),
				EndTime:    now,
				Attributes: map[string]any{
					"gen_ai.usage.input_tokens":  id * 10,
					"gen_ai.usage.output_tokens": id * 5,
				},
				RootSpan: &schemas.Span{
					Name: "chat.completion",
					Attributes: map[string]any{
						"model": fmt.Sprintf("model-%d", id),
					},
				},
			}

			_ = streamer.Inject(context.Background(), trace)
			// Immediate trace wipe to verify zero retention under concurrency
			trace.Attributes = nil
			trace.RootSpan = nil
		}(g)
	}

	close(startBarrier)
	wg.Wait()

	captured := streamer.GetCapturedSpans()
	if len(captured) != totalGoroutines {
		t.Fatalf("expected %d captured spans, got %d", totalGoroutines, len(captured))
	}
}

// TestChallenger_Offloader_ExhaustiveBoundaries tests edge cases on offloader.
func TestChallenger_Offloader_ExhaustiveBoundaries(t *testing.T) {
	store := objectstore.NewInMemoryObjectStore()
	const threshold = 256
	offloader := NewPayloadOffloader(store, threshold, "test-offload", false)

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Empty payload (0 bytes) -> NOT offloaded
	offloaded, uri, err := offloader.OffloadIfLarge(ctx, "s3", now, "zero", "req", []byte{})
	if err != nil || offloaded || uri != "" {
		t.Fatalf("expected empty payload NOT offloaded, got offloaded=%v, uri=%s", offloaded, uri)
	}

	// 2. Exactly threshold - 1 bytes -> NOT offloaded
	sub := []byte(strings.Repeat("z", threshold-1))
	offloaded, uri, err = offloader.OffloadIfLarge(ctx, "s3", now, "sub", "req", sub)
	if err != nil || offloaded || uri != string(sub) {
		t.Fatalf("expected sub-threshold NOT offloaded")
	}

	// 3. Exactly threshold bytes -> OFFLOADED
	exact := []byte(strings.Repeat("z", threshold))
	offloaded, uri, err = offloader.OffloadIfLarge(ctx, "s3", now, "exact", "req", exact)
	if err != nil || !offloaded || !strings.HasPrefix(uri, "s3://") {
		t.Fatalf("expected exact threshold offloaded to S3")
	}

	// 4. Large payload (1 MB) -> OFFLOADED
	large := []byte(strings.Repeat("Q", 1024*1024))
	offloaded, uri, err = offloader.OffloadIfLarge(ctx, "gcs", now, "large", "resp", large)
	if err != nil || !offloaded || !strings.HasPrefix(uri, "gs://") {
		t.Fatalf("expected large payload offloaded to GCS")
	}

	// 5. Hydrate large payload
	fetched, err := offloader.FetchOffloadedPayload(ctx, uri)
	if err != nil || len(fetched) != len(large) {
		t.Fatalf("failed to fetch large payload: %v", err)
	}
}

// TestChallenger_Queue_CloseGracefulDrain verifies that Close drains the queue
// and never drops in-flight items that were already accepted.
func TestChallenger_Queue_CloseGracefulDrain(t *testing.T) {
	cfg := Config{
		QueueCapacity: 50,
		BatchSize:     10,
		FlushInterval: 1 * time.Hour, // don't flush automatically
		Backpressure:  BackpressureDrop,
	}
	q := NewBatchedLogQueue(cfg, nil)

	for i := 0; i < 25; i++ {
		ok := q.Enqueue(&LogEntry{ID: fmt.Sprintf("drain-%d", i)})
		if !ok {
			t.Fatalf("enqueue %d failed", i)
		}
	}

	// Close queue
	err := q.Close(context.Background())
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	batches := q.GetFlushedBatches()
	totalFlushed := 0
	for _, b := range batches {
		totalFlushed += len(b)
	}

	if totalFlushed != 25 {
		t.Fatalf("expected all 25 items drained on Close, got %d", totalFlushed)
	}
}
