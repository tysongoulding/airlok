package logexport_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/logexport"
	"github.com/maximhq/bifrost/framework/objectstore"
)

func TestLogExport_BatchedQueue_CountFlush(t *testing.T) {
	cfg := logexport.Config{
		BatchSize:     5,
		FlushInterval: 10 * time.Second, // high interval so only count triggers
	}
	q := logexport.NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	// Enqueue 4 items -> no flush
	for i := 0; i < 4; i++ {
		q.EnqueueMap(map[string]interface{}{"index": i})
	}

	time.Sleep(20 * time.Millisecond)
	if len(q.GetFlushedBatches()) != 0 {
		t.Fatalf("expected 0 flushed batches before reaching threshold, got %d", len(q.GetFlushedBatches()))
	}

	// Enqueue 5th item -> triggers flush
	q.EnqueueMap(map[string]interface{}{"index": 4})
	time.Sleep(50 * time.Millisecond)

	batches := q.GetFlushedBatches()
	if len(batches) != 1 {
		t.Fatalf("expected 1 flushed batch, got %d", len(batches))
	}
	if len(batches[0]) != 5 {
		t.Fatalf("expected 5 items in flushed batch, got %d", len(batches[0]))
	}
}

func TestLogExport_BatchedQueue_EmptyFlush_NoOp(t *testing.T) {
	cfg := logexport.Config{
		BatchSize:     10,
		FlushInterval: 10 * time.Second,
	}
	q := logexport.NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	q.Flush()
	if len(q.GetFlushedBatches()) != 0 {
		t.Fatalf("empty queue flush must be a no-op, got %d batches", len(q.GetFlushedBatches()))
	}
}

func TestLogExport_BatchedQueue_ManualFlush(t *testing.T) {
	cfg := logexport.Config{
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
	}
	q := logexport.NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	for i := 0; i < 3; i++ {
		q.Enqueue(&logexport.LogEntry{ID: fmt.Sprintf("id-%d", i)})
	}

	q.Flush()
	batches := q.GetFlushedBatches()
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch after manual flush, got %d", len(batches))
	}
	if len(batches[0]) != 3 {
		t.Fatalf("expected 3 entries in batch, got %d", len(batches[0]))
	}
}

func TestLogExport_PayloadOffloader_ThresholdAndFetch(t *testing.T) {
	store := objectstore.NewInMemoryObjectStore()
	offloader := logexport.NewPayloadOffloader(store, 1024, "bifrost", true)

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Small payload (< 1024 bytes) -> not offloaded
	smallData := []byte("small payload that is well below 1KB")
	offloaded, uri, err := offloader.OffloadIfLarge(ctx, "s3", now, "req-1", "request", smallData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if offloaded {
		t.Fatalf("expected small payload NOT to be offloaded")
	}
	if uri != string(smallData) {
		t.Fatalf("expected original string returned, got %s", uri)
	}

	// 2. Large payload (>= 1024 bytes) -> offloaded
	largeData := []byte(strings.Repeat("Large payload data chunk to exceed 1KB...\n", 50))
	offloaded, uri, err = offloader.OffloadIfLarge(ctx, "s3", now, "req-2", "response", largeData)
	if err != nil {
		t.Fatalf("unexpected offload error: %v", err)
	}
	if !offloaded {
		t.Fatalf("expected large payload to be offloaded")
	}
	if !strings.HasPrefix(uri, "s3://") {
		t.Fatalf("expected s3:// URI prefix, got: %s", uri)
	}

	// 3. Fetch and transparently decompress
	fetched, err := offloader.FetchOffloadedPayload(ctx, uri)
	if err != nil {
		t.Fatalf("fetch offloaded payload failed: %v", err)
	}
	if string(fetched) != string(largeData) {
		t.Fatalf("fetched payload content mismatch")
	}

	// 4. Test direct offload compatibility
	directKey := "s3://bifrost-logs/2026/10/06/chatcmpl-large.json.gz"
	directPayload := []byte("some direct payload")
	if err := offloader.OffloadPayloadToS3(directKey, directPayload); err != nil {
		t.Fatalf("direct offload failed: %v", err)
	}
	mem := offloader.GetOffloadedMap()
	if string(mem[directKey]) != string(directPayload) {
		t.Fatalf("direct offload memory map missing entry")
	}
}

func TestLogExport_DatadogStreamer_ZeroRetentionAndMapping(t *testing.T) {
	streamer := logexport.NewDatadogStreamer(logexport.DatadogConfig{
		Enabled:     true,
		ServiceName: "bifrost-enterprise",
		Env:         "production",
		Version:     "1.0.0",
		CustomTags:  map[string]string{"team": "ai-infra"},
	})

	now := time.Now().UTC()
	trace := &schemas.Trace{
		RequestID:  "req-dd-123",
		TraceID:    "trace-abc-456",
		InternalID: "span-root-789",
		StartTime:  now.Add(-200 * time.Millisecond),
		EndTime:    now,
		Attributes: map[string]any{
			"gen_ai.usage.input_tokens":  150,
			"gen_ai.usage.output_tokens": 75,
			"gen_ai.usage.total_tokens":  225,
		},
		RootSpan: &schemas.Span{
			Name: "chat.completion",
			Attributes: map[string]any{
				"model":    "gpt-4o",
				"provider": "openai",
			},
		},
	}

	ctx := context.Background()
	// Inject trace
	if err := streamer.Inject(ctx, trace); err != nil {
		t.Fatalf("streamer inject error: %v", err)
	}

	// Verify captured spans
	spans := streamer.GetCapturedSpans()
	if len(spans) == 0 {
		t.Fatalf("expected captured spans")
	}

	rootSpan := spans[0]
	if rootSpan.Service != "bifrost-enterprise" {
		t.Fatalf("expected service bifrost-enterprise, got %s", rootSpan.Service)
	}
	if rootSpan.Meta["model"] != "gpt-4o" {
		t.Fatalf("expected model gpt-4o, got %s", rootSpan.Meta["model"])
	}
	if rootSpan.Metrics["llm.prompt_tokens"] != 150 {
		t.Fatalf("expected 150 prompt tokens, got %v", rootSpan.Metrics["llm.prompt_tokens"])
	}
	if rootSpan.Metrics["llm.completion_tokens"] != 75 {
		t.Fatalf("expected 75 completion tokens, got %v", rootSpan.Metrics["llm.completion_tokens"])
	}
	if rootSpan.Metrics["llm.total_tokens"] != 225 {
		t.Fatalf("expected 225 total tokens, got %v", rootSpan.Metrics["llm.total_tokens"])
	}
	if rootSpan.Metrics["llm.latency_ms"] <= 0 {
		t.Fatalf("expected positive latency ms")
	}

	// Reset trace to simulate pool release -> verify streamer's captured data was not corrupted
	trace.Reset()
	if rootSpan.Service != "bifrost-enterprise" || rootSpan.Meta["model"] != "gpt-4o" {
		t.Fatalf("streamer retained pooled pointer instead of copying")
	}
}

func TestLogExport_DatadogStreamer_LiveAgentDispatch(t *testing.T) {
	var receivedPayload bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v0.4/traces" && r.Method == http.MethodPut {
			receivedPayload = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	streamer := logexport.NewDatadogStreamer(logexport.DatadogConfig{
		Enabled:     true,
		ServiceName: "live-test-bifrost",
		AgentAddr:   host,
	})

	now := time.Now().UTC()
	trace := &schemas.Trace{
		RequestID:  "req-live-1",
		TraceID:    "trace-live-1",
		InternalID: "span-live-1",
		StartTime:  now.Add(-50 * time.Millisecond),
		EndTime:    now,
		RootSpan: &schemas.Span{
			Name: "chat.completion",
			Attributes: map[string]any{
				"model": "claude-3-7-sonnet",
			},
		},
	}

	if err := streamer.Inject(context.Background(), trace); err != nil {
		t.Fatalf("inject error: %v", err)
	}

	if !receivedPayload {
		t.Fatalf("expected HTTP payload to be delivered to agent")
	}
}

func TestLogExport_WindowedArchival_PartRollingAndCommit(t *testing.T) {
	store := objectstore.NewInMemoryObjectStore()
	archiver := logexport.NewWindowedArchiver(logexport.ArchiveConfig{
		Interval:       1 * time.Hour,
		GracePeriod:    5 * time.Minute,
		MaxObjectBytes: 250, // Small limit forces multiple parts
		Compress:       true,
		Prefix:         "test-vault",
		TargetPrefix:   "logs",
	}, store, time.Now().Add(-3*time.Hour))

	windowStart := time.Now().UTC().Add(-2 * time.Hour)
	windowEnd := windowStart.Add(1 * time.Hour)

	rows := make([][]byte, 20)
	for i := 0; i < 20; i++ {
		rows[i] = []byte(fmt.Sprintf(`{"id":"entry-%d","msg":"log message content"}`, i))
	}

	manifest, err := archiver.ArchiveWindow(context.Background(), windowStart, windowEnd, rows)
	if err != nil {
		t.Fatalf("archival error: %v", err)
	}

	if manifest.EventCount != 20 {
		t.Fatalf("expected 20 events, got %d", manifest.EventCount)
	}
	if len(manifest.Parts) < 2 {
		t.Fatalf("expected at least 2 parts rolled, got %d", len(manifest.Parts))
	}
	if !archiver.GetWatermark().Equal(windowEnd) {
		t.Fatalf("watermark did not advance to windowEnd")
	}
}

func TestLogExport_ConcurrentQueueing_RaceDetector(t *testing.T) {
	cfg := logexport.Config{
		QueueCapacity: 5000,
		BatchSize:     50,
		FlushInterval: 50 * time.Millisecond,
		Backpressure:  logexport.BackpressureDrop,
	}
	q := logexport.NewBatchedLogQueue(cfg, nil)
	defer q.Close(context.Background())

	workers := 15
	perWorker := 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				q.Enqueue(&logexport.LogEntry{
					ID:        fmt.Sprintf("w%d-%d", id, i),
					Timestamp: time.Now(),
					Model:     "gpt-4o",
				})
			}
		}(w)
	}

	wg.Wait()
	q.Flush()

	batches := q.GetFlushedBatches()
	totalCount := 0
	for _, b := range batches {
		totalCount += len(b)
	}
	if totalCount == 0 {
		t.Fatalf("expected flushed items")
	}
}
