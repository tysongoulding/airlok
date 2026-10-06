package governance

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ADVERSARIAL TARGET 1: CONTEXT DEADLINE ENFORCEABILITY (50ms TIMEOUT BOUNDS)
// ============================================================================

// TestAdversarial_It2_AllCloudAdapters_50msDeadlineEnforced validates that
// when caller context has a 50ms deadline, ALL hanging cloud adapters (Bedrock,
// Azure standard, Azure jailbreak shield, and Model Armor) terminate and return
// within <= 60ms without blocking worker threads.
func TestAdversarial_It2_AllCloudAdapters_50msDeadlineEnforced(t *testing.T) {
	// A mock server that hangs for 500ms before replying
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"NONE"}`))
	}))
	defer slowServer.Close()

	adapters := []struct {
		name    string
		adapter CloudGuardrailAdapter
	}{
		{
			name: "BedrockAdapter",
			adapter: func() CloudGuardrailAdapter {
				a, err := NewBedrockAdapter(BedrockConfig{
					BaseURL:          slowServer.URL,
					GuardrailARN:     "test-arn",
					GuardrailVersion: "1",
					SkipAuth:         true,
					Timeout:          30,
				}, nil)
				require.NoError(t, err)
				return a
			}(),
		},
		{
			name: "AzureAdapter-Standard",
			adapter: func() CloudGuardrailAdapter {
				a, err := NewAzureAdapter(AzureContentSafetyConfig{
					Endpoint: slowServer.URL,
					APIKey:   "test-key",
					Timeout:  30,
				}, nil)
				require.NoError(t, err)
				return a
			}(),
		},
		{
			name: "AzureAdapter-WithJailbreakShield",
			adapter: func() CloudGuardrailAdapter {
				a, err := NewAzureAdapter(AzureContentSafetyConfig{
					Endpoint:               slowServer.URL,
					APIKey:                 "test-key",
					Timeout:                30,
					JailbreakShieldEnabled: true,
				}, nil)
				require.NoError(t, err)
				return a
			}(),
		},
		{
			name: "ModelArmorAdapter",
			adapter: func() CloudGuardrailAdapter {
				a, err := NewModelArmorAdapter(ModelArmorConfig{
					BaseURL:    slowServer.URL,
					ProjectID:  "test-proj",
					Location:   "us-central1",
					TemplateID: "test-tmpl",
					SkipAuth:   true,
					Timeout:    30,
				}, nil)
				require.NoError(t, err)
				return a
			}(),
		},
	}

	for _, tc := range adapters {
		t.Run(tc.name, func(t *testing.T) {
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()

			bifrostCtx := schemas.NewBifrostContext(ctxTimeout, time.Now().Add(50*time.Millisecond))

			start := time.Now()
			resp, err := tc.adapter.InspectContent(bifrostCtx, &CloudSafetyRequest{
				Phase: "input",
				Text:  "Adversarial deadline enforcement test string",
			})
			elapsed := time.Since(start)

			t.Logf("[%s] Completed in %v, err=%v, resp=%v", tc.name, elapsed, err, resp)

			// Target bound: <= 60ms (allow 65ms margin for scheduler/context tick granularity)
			assert.LessOrEqual(t, elapsed, 65*time.Millisecond,
				"Adapter %s must terminate within <=60ms on 50ms context deadline, took %v", tc.name, elapsed)
			assert.Error(t, err, "Adapter %s must return an error on context deadline", tc.name)
			assert.Contains(t, err.Error(), "context deadline exceeded",
				"Adapter %s error should indicate context deadline exceeded", tc.name)
		})
	}
}

// ============================================================================
// ADVERSARIAL TARGET 2: NETWORK PARTITIONS, EOFS & TRUNCATED RESPONSES
// ============================================================================

// TestAdversarial_It2_AllCloudAdapters_NetworkPartitionsAndEOFs validates that
// truncated HTTP responses, abrupt EOFs, connection closures, malformed JSON,
// and 5xx server errors across Bedrock, Azure, and Model Armor return proper
// errors without crashing or panicking.
func TestAdversarial_It2_AllCloudAdapters_NetworkPartitionsAndEOFs(t *testing.T) {
	// Scenario 1: Immediate Connection Close (EOF)
	dropServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer dropServer.Close()

	// Scenario 2: Truncated HTTP Response (Header sent, partial body, conn closed)
	truncatedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, buf, _ := hj.Hijack()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/json\r\n\r\n{\"action\":")
			_ = buf.Flush()
			conn.Close()
		}
	}))
	defer truncatedServer.Close()

	// Scenario 3: Malformed / Garbage JSON
	garbageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{<<<NOT_VALID_JSON>>>}`))
	}))
	defer garbageServer.Close()

	// Scenario 4: HTTP 503 Service Unavailable
	unavailableServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream service unavailable", http.StatusServiceUnavailable)
	}))
	defer unavailableServer.Close()

	// Scenario 5: Empty 200 OK Body
	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer emptyServer.Close()

	serverEndpoints := map[string]string{
		"EOF":         dropServer.URL,
		"Truncated":   truncatedServer.URL,
		"GarbageJSON": garbageServer.URL,
		"HTTP503":     unavailableServer.URL,
		"EmptyBody":   emptyServer.URL,
	}

	for faultType, endpointURL := range serverEndpoints {
		t.Run("Bedrock-"+faultType, func(t *testing.T) {
			adapter, err := NewBedrockAdapter(BedrockConfig{
				BaseURL:          endpointURL,
				GuardrailARN:     "test-arn",
				GuardrailVersion: "1",
				SkipAuth:         true,
			}, nil)
			require.NoError(t, err)

			assert.NotPanics(t, func() {
				_, err := adapter.InspectContent(nil, &CloudSafetyRequest{Text: "test payload"})
				assert.Error(t, err, "Fault %s must return an error", faultType)
			})
		})

		t.Run("Azure-"+faultType, func(t *testing.T) {
			adapter, err := NewAzureAdapter(AzureContentSafetyConfig{
				Endpoint: endpointURL,
				APIKey:   "test-key",
			}, nil)
			require.NoError(t, err)

			assert.NotPanics(t, func() {
				_, err := adapter.InspectContent(nil, &CloudSafetyRequest{Text: "test payload"})
				assert.Error(t, err, "Fault %s must return an error", faultType)
			})
		})

		t.Run("ModelArmor-"+faultType, func(t *testing.T) {
			adapter, err := NewModelArmorAdapter(ModelArmorConfig{
				BaseURL:    endpointURL,
				ProjectID:  "test-proj",
				Location:   "us-central1",
				TemplateID: "test-tmpl",
				SkipAuth:   true,
			}, nil)
			require.NoError(t, err)

			assert.NotPanics(t, func() {
				_, err := adapter.InspectContent(nil, &CloudSafetyRequest{Text: "test payload"})
				assert.Error(t, err, "Fault %s must return an error", faultType)
			})
		})
	}
}

// ============================================================================
// ADVERSARIAL TARGET 3: STREAM ID ISOLATION (100 CONCURRENT STREAMS)
// ============================================================================

// TestAdversarial_It2_StreamID_100ConcurrentStreams_ZeroCollision verifies that
// 100 concurrent streams running simultaneously without caller-specified request IDs:
// 1. Each receive a unique, isolated stream ID (zero collisions across 100 streams).
// 2. Never cross-contaminate buffers or leak data across streams.
// 3. Are cleanly evicted/deleted from StreamInspector upon stream completion.
// 4. Exhibit zero data races under -race.
func TestAdversarial_It2_StreamID_100ConcurrentStreams_ZeroCollision(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	const numStreams = 100
	const chunksPerStream = 5

	var wg sync.WaitGroup
	var mu sync.Mutex
	generatedStreamIDs := make(map[string]int)
	reconstructedStreams := make(map[int]string)

	for s := 0; s < numStreams; s++ {
		wg.Add(1)
		go func(streamIdx int) {
			defer wg.Done()

			// Fresh context with NO request ID set — forces UUID generation
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})

			var streamOutput strings.Builder

			for c := 0; c < chunksPerStream; c++ {
				chunkText := fmt.Sprintf("Stream%03d-token%d ", streamIdx, c)
				isFinished := (c == chunksPerStream-1)
				finishReason := "stop"

				chunk := &schemas.BifrostStreamChunk{
					BifrostChatResponse: &schemas.BifrostChatResponse{
						Choices: []schemas.BifrostResponseChoice{
							{
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: &schemas.ChatStreamResponseChoiceDelta{
										Content: &chunkText,
									},
								},
							},
						},
					},
				}
				if isFinished {
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
				}

				inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
				assert.NoError(t, err)
				if inspected != nil {
					delta, _ := extractChunkDelta(inspected)
					streamOutput.WriteString(delta)
				}
			}

			// Capture the assigned stream ID from context
			assignedID := bifrostGetString(ctx, schemas.BifrostContextKeyRequestID)

			mu.Lock()
			generatedStreamIDs[assignedID]++
			reconstructedStreams[streamIdx] = streamOutput.String()
			mu.Unlock()
		}(s)
	}

	wg.Wait()

	// 1. Verify that 100 distinct stream IDs were generated with ZERO collisions
	assert.Equal(t, numStreams, len(generatedStreamIDs),
		"Expected %d unique stream IDs generated, got %d", numStreams, len(generatedStreamIDs))
	for id, count := range generatedStreamIDs {
		assert.Equal(t, 1, count, "Stream ID %s was collided/used by %d goroutines", id, count)
		assert.False(t, strings.EqualFold(id, "default_stream"), "default_stream must NEVER be assigned")
	}

	// 2. Verify buffer isolation: each stream output must contain ONLY its own tokens
	for streamIdx, output := range reconstructedStreams {
		// Output must contain tokens from its own stream
		expectedSelfToken := fmt.Sprintf("Stream%03d-token", streamIdx)
		assert.Contains(t, output, expectedSelfToken,
			"Stream %d output should contain its own tokens", streamIdx)

		// Output must NOT contain tokens from any other stream
		for otherIdx := 0; otherIdx < numStreams; otherIdx++ {
			if otherIdx == streamIdx {
				continue
			}
			foreignToken := fmt.Sprintf("Stream%03d-", otherIdx)
			assert.NotContains(t, output, foreignToken,
				"STREAM ISOLATION VIOLATION: Stream %d buffer contaminated with data from Stream %d! Output: %q",
				streamIdx, otherIdx, output)
		}
	}

	// 3. Verify clean eviction: all 100 streams finished, so inspector.streams must be empty
	inspector.mu.RLock()
	activeCount := len(inspector.streams)
	inspector.mu.RUnlock()
	assert.Equal(t, 0, activeCount,
		"All finished streams should be deleted from accumulator map, found %d active", activeCount)
}
