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
	"unicode/utf8"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CHALLENGE 1: STREAMING ATTACK VECTORS
// ============================================================================

// TestAdversarial_Streaming_FragmentedPII_Redaction_Leakage demonstrates that
// PII split across chunk boundaries bypasses streaming redaction completely.
// Because deltaText is checked for full matches in res.LiteralMap,
// partial tokens across chunk boundaries are NEVER redacted in the stream chunks.
func TestAdversarial_Streaming_FragmentedPII_Redaction_Leakage(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "stream-frag-redact-1")

	// The email "alex_rivera@gmail.com" is fragmented across 3 chunks:
	chunks := []string{
		"Contact alex_",
		"rivera@",
		"gmail.com for inquiries.",
	}

	var emittedChunks []string
	for i, cText := range chunks {
		textCopy := cText
		isFinished := (i == len(chunks)-1)
		chunk := &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &textCopy,
							},
						},
					},
				},
			},
		}
		if isFinished {
			finishReason := "stop"
			chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
		}

		inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		require.NoError(t, err)
		require.NotNil(t, inspected)

		delta, _ := extractChunkDelta(inspected)
		emittedChunks = append(emittedChunks, delta)
	}

	reconstructed := strings.Join(emittedChunks, "")

	// Adversarial Verification:
	// If streaming redaction worked correctly, reconstructed text would NOT contain
	// the plaintext email "alex_rivera@gmail.com" and would contain "[EMAIL]".
	t.Logf("Reconstructed stream text received by client: %q", reconstructed)
	if strings.Contains(reconstructed, "alex_rivera@gmail.com") {
		t.Errorf("SECURITY VULNERABILITY CONFIRMED: Fragmented PII leaked in cleartext across stream chunks: %q", reconstructed)
	}
}

// TestAdversarial_Streaming_FragmentedPII_Block_PartialLeakage demonstrates that
// when a block-capable entity (like SSN) is fragmented across chunk boundaries,
// early chunks are leaked to the client before the stream is aborted on the final chunk.
func TestAdversarial_Streaming_FragmentedPII_Block_PartialLeakage(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "stream-frag-block-1")

	// SSN "123-45-6789" split across 3 chunks
	chunks := []string{
		"User SSN is 123-",
		"45-",
		"6789 on file.",
	}

	var leakedChunks []string
	var abortedOnIndex = -1

	for i, cText := range chunks {
		textCopy := cText
		chunk := &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &textCopy,
							},
						},
					},
				},
			},
		}

		inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		if err != nil {
			abortedOnIndex = i
			break
		}
		delta, _ := extractChunkDelta(inspected)
		leakedChunks = append(leakedChunks, delta)
	}

	t.Logf("Aborted on chunk index: %d", abortedOnIndex)
	t.Logf("Chunks already leaked to client before abort: %v", leakedChunks)

	// In Feature 9: "Holds block-capable stream chunks until verified"
	// If chunks were held, leakedChunks would be empty or not contain partial SSN digits.
	leakedText := strings.Join(leakedChunks, "")
	if strings.Contains(leakedText, "123-45-") {
		t.Errorf("SECURITY FLAW CONFIRMED: Partial SSN prefix %q was leaked to client before intervention!", leakedText)
	}
}

// TestAdversarial_Streaming_ZeroByteAndEmptyChunks tests resilience against
// nil deltas, empty strings, and empty finish chunks.
func TestAdversarial_Streaming_ZeroByteAndEmptyChunks(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "stream-zerobyte-1")

	emptyStr := ""
	finishReason := "stop"

	testChunks := []*schemas.BifrostStreamChunk{
		nil,
		{},
		{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{},
			},
		},
		{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: nil,
						},
					},
				},
			},
		},
		{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &emptyStr,
							},
						},
					},
				},
			},
		},
		{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						FinishReason: &finishReason,
					},
				},
			},
		},
	}

	for i, chunk := range testChunks {
		res, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		assert.NoError(t, err, "chunk %d should not error", i)
		assert.Equal(t, chunk, res, "empty chunk should return itself")
	}
}

// TestAdversarial_Streaming_DefaultStream_Collision demonstrates that
// multiple streams lacking a request ID collide on 'default_stream',
// causing cross-stream state corruption.
func TestAdversarial_Streaming_DefaultStream_Collision(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	// Two separate requests without request IDs in ctx or headers
	ctxA := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctxB := schemas.NewBifrostContext(context.Background(), time.Time{})

	chunkA := "Tenant A secret message: "
	chunkB := "Tenant B data payload"

	c1 := &schemas.BifrostStreamChunk{
		BifrostChatResponse: &schemas.BifrostChatResponse{
			Choices: []schemas.BifrostResponseChoice{
				{ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &chunkA}}},
			},
		},
	}
	c2 := &schemas.BifrostStreamChunk{
		BifrostChatResponse: &schemas.BifrostChatResponse{
			Choices: []schemas.BifrostResponseChoice{
				{ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &chunkB}}},
			},
		},
	}

	_, _ = inspector.InspectChunk(ctxA, nil, c1, engine)
	_, _ = inspector.InspectChunk(ctxB, nil, c2, engine)

	inspector.mu.RLock()
	defaultAcc := inspector.streams["default_stream"]
	inspector.mu.RUnlock()
	assert.Nil(t, defaultAcc, "default_stream accumulator must NEVER exist")

	idA := bifrostGetString(ctxA, schemas.BifrostContextKeyRequestID)
	idB := bifrostGetString(ctxB, schemas.BifrostContextKeyRequestID)
	require.NotEmpty(t, idA, "ctxA must be assigned a unique stream ID")
	require.NotEmpty(t, idB, "ctxB must be assigned a unique stream ID")
	require.NotEqual(t, idA, idB, "streams must receive distinct IDs")

	inspector.mu.RLock()
	accA := inspector.streams[idA]
	accB := inspector.streams[idB]
	inspector.mu.RUnlock()

	require.NotNil(t, accA)
	require.NotNil(t, accB)
	accA.mu.Lock()
	textA := accA.accumulated.String()
	accA.mu.Unlock()
	accB.mu.Lock()
	textB := accB.accumulated.String()
	accB.mu.Unlock()

	assert.Equal(t, chunkA, textA)
	assert.Equal(t, chunkB, textB)
}

// ============================================================================
// CHALLENGE 2: CLOUD ADAPTER RESILIENCE & DEADLINES
// ============================================================================

// TestAdversarial_CloudAdapters_IgnoredByEvaluateText reveals that
// CloudGuardrailAdapters registered via RegisterCloudAdapter are NEVER
// called by EvaluateText or EvaluateInput.
func TestAdversarial_CloudAdapters_IgnoredByEvaluateText(t *testing.T) {
	engine := DefaultGuardrailsEngine()

	var customAdapterCalled int32
	mockAdapter := &testTrackingAdapter{
		name: "test-adapter",
		inspectFn: func(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error) {
			customAdapterCalled++
			return &CloudSafetyResponse{
				Allowed:            false,
				ActionTaken:        "block",
				InterventionReason: "custom adapter blocked",
			}, nil
		},
	}

	engine.RegisterCloudAdapter("test-adapter", mockAdapter)

	// Add a rule that specifies this cloud adapter
	engine.AddRule(GuardrailRule{
		ID:           999,
		Name:         "Cloud Safety Rule",
		Enabled:      true,
		Target:       "llm",
		ApplyTo:      "input",
		Action:       ActionBlock,
		CloudAdapter: "test-adapter",
	})

	res := engine.EvaluateText("Hello world prompt", "llm", "input", nil)

	t.Logf("Custom adapter invocation count: %d", customAdapterCalled)
	t.Logf("Evaluation allowed: %v", res.Allowed)

	if customAdapterCalled == 0 {
		t.Errorf("ARCHITECTURAL DEFECT: CloudGuardrailAdapter registered via RegisterCloudAdapter is completely ignored by EvaluateText!")
	}
}

// TestAdversarial_CloudAdapters_ContextDeadlineIgnored proves that
// cloud adapters use http.NewRequest (context.Background) instead of
// http.NewRequestWithContext(ctx), ignoring context deadlines.
func TestAdversarial_CloudAdapters_ContextDeadlineIgnored(t *testing.T) {
	// Server hangs for 300ms
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"NONE"}`))
	}))
	defer slowServer.Close()

	adapter, err := NewBedrockAdapter(BedrockConfig{
		BaseURL:          slowServer.URL,
		GuardrailARN:     "test",
		GuardrailVersion: "1",
		SkipAuth:         true,
		Timeout:          10, // 10 second client timeout
	}, nil)
	require.NoError(t, err)

	// Context has a strict 50ms deadline
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	bifrostCtx := schemas.NewBifrostContext(ctxTimeout, time.Now().Add(50*time.Millisecond))

	start := time.Now()
	_, inspectErr := adapter.InspectContent(bifrostCtx, &CloudSafetyRequest{
		Phase: "input",
		Text:  "test input",
	})
	elapsed := time.Since(start)

	t.Logf("Call completed in %v, error: %v", elapsed, inspectErr)

	// If context deadline was respected, elapsed would be ~50ms and error would be context.DeadlineExceeded.
	if elapsed >= 250*time.Millisecond {
		t.Errorf("RESILIENCE BUG CONFIRMED: BedrockAdapter ignored 50ms context deadline and blocked for %v!", elapsed)
	}
}

// TestAdversarial_CloudAdapters_NetworkPartition_FlakyEndpoints tests
// behavior under 500 Internal Server Error, connection drops, and malformed JSON.
func TestAdversarial_CloudAdapters_NetworkPartition_FlakyEndpoints(t *testing.T) {
	// 1. HTTP 500 error
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream service unavailable", http.StatusInternalServerError)
	}))
	defer errServer.Close()

	adapter, err := NewBedrockAdapter(BedrockConfig{
		BaseURL:          errServer.URL,
		GuardrailARN:     "test",
		GuardrailVersion: "1",
		SkipAuth:         true,
	}, nil)
	require.NoError(t, err)

	_, bErr := adapter.InspectContent(nil, &CloudSafetyRequest{Text: "test"})
	assert.Error(t, bErr)
	assert.Contains(t, bErr.Error(), "HTTP 500")

	// 2. Abrupt connection closure (network partition)
	dropServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer dropServer.Close()

	dropAdapter, _ := NewBedrockAdapter(BedrockConfig{
		BaseURL:          dropServer.URL,
		GuardrailARN:     "test",
		GuardrailVersion: "1",
		SkipAuth:         true,
	}, nil)

	_, dErr := dropAdapter.InspectContent(nil, &CloudSafetyRequest{Text: "test"})
	assert.Error(t, dErr)
	t.Logf("Network partition error handled: %v", dErr)
}

// ============================================================================
// CHALLENGE 3: RACE CONDITIONS UNDER GO TEST -RACE
// ============================================================================

// TestAdversarial_Race_ConcurrentStreamingAndEviction triggers concurrent
// stream chunk inspections across 50 streams while evictStale runs in background.
func TestAdversarial_Race_ConcurrentStreamingAndEviction(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	var wg sync.WaitGroup
	numStreams := 50
	chunksPerStream := 20

	for s := 0; s < numStreams; s++ {
		wg.Add(1)
		streamID := fmt.Sprintf("race-stream-%d", s)
		go func(id string) {
			defer wg.Done()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, id)

			for c := 0; c < chunksPerStream; c++ {
				text := fmt.Sprintf("chunk-%d ", c)
				isFinished := (c == chunksPerStream-1)
				finishReason := "stop"

				chunk := &schemas.BifrostStreamChunk{
					BifrostChatResponse: &schemas.BifrostChatResponse{
						Choices: []schemas.BifrostResponseChoice{
							{
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: &schemas.ChatStreamResponseChoiceDelta{
										Content: &text,
									},
								},
							},
						},
					},
				}
				if isFinished {
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
				}

				_, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
				if err != nil {
					return
				}
			}
		}(streamID)
	}

	// Trigger concurrent evictions
	stopEvict := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopEvict:
				return
			default:
				inspector.evictStale(0)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	close(stopEvict)
}

// TestAdversarial_Race_PluginStreamInspectorLazyInit triggers concurrent
// calls to HTTPTransportStreamChunkHook when streamInspector is initially nil.
func TestAdversarial_Race_PluginStreamInspectorLazyInit(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetGuardrails(DefaultGuardrailsEngine())
	// Notice: plugin.streamInspector is initially NIL!

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, fmt.Sprintf("init-race-%d", idx))

			text := "hello world"
			chunk := &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &text},
							},
						},
					},
				},
			}
			_, _ = plugin.HTTPTransportStreamChunkHook(ctx, &schemas.HTTPRequest{}, chunk)
		}(i)
	}
	wg.Wait()
}

// TestAdversarial_Race_DynamicRuleMutation tests concurrent rule addition
// and evaluation.
func TestAdversarial_Race_DynamicRuleMutation(t *testing.T) {
	engine := DefaultGuardrailsEngine()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reader routines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = engine.EvaluateText("Contact alice@example.com for info", "llm", "input", nil)
				}
			}
		}()
	}

	// Writer routine adding rules
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			engine.AddRule(GuardrailRule{
				ID:      1000 + i,
				Name:    fmt.Sprintf("Dynamic Rule %d", i),
				Enabled: true,
				Target:  "llm",
				ApplyTo: "input",
				Action:  ActionBlock,
			})
			time.Sleep(500 * time.Microsecond)
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestAdversarial_Race_SetGuardrailsConcurrency demonstrates data race on p.guardrails
// when SetGuardrails is invoked while PreLLMHook is actively evaluating requests.
func TestAdversarial_Race_SetGuardrailsConcurrency(t *testing.T) {
	plugin := &GovernancePlugin{}
	plugin.SetGuardrails(DefaultGuardrailsEngine())

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 5 readers running PreLLMHook
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					prompt := "Safe prompt text"
					req := &schemas.BifrostRequest{
						RequestType: schemas.ChatCompletionRequest,
						ChatRequest: &schemas.BifrostChatRequest{
							Input: []schemas.ChatMessage{
								{Content: &schemas.ChatMessageContent{ContentStr: &prompt}},
							},
						},
					}
					ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
					_, _, _ = plugin.PreLLMHook(ctx, req)
				}
			}
		}()
	}

	// 1 writer swapping guardrail engines dynamically
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			plugin.SetGuardrails(DefaultGuardrailsEngine())
			time.Sleep(500 * time.Microsecond)
		}
	}()

	time.Sleep(30 * time.Millisecond)
	close(stop)
	wg.Wait()
}

type testTrackingAdapter struct {
	name      string
	inspectFn func(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error)
}

func (a *testTrackingAdapter) Name() string { return a.name }
func (a *testTrackingAdapter) InspectContent(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error) {
	if a.inspectFn != nil {
		return a.inspectFn(ctx, req)
	}
	return &CloudSafetyResponse{Allowed: true, ActionTaken: "allow"}, nil
}
func (a *testTrackingAdapter) Close() error { return nil }

// ============================================================================
// CHALLENGE 4: ITERATION 2 DEEP ADVERSARIAL STRESS SUITE
// ============================================================================

// TestAdversarial_Streaming_OneByteChunks_Redaction_ZeroLeakage stresses streaming
// chunk boundary fragmentation by feeding strings 1 byte at a time.
// It verifies:
// 1. No individual emitted chunk contains any cleartext PII fragment.
// 2. Reconstructed output replaces sensitive entities with redaction placeholders.
// 3. Tests both short inputs and inputs exceeding the 128-byte holding window buffer.
func TestAdversarial_Streaming_OneByteChunks_Redaction_ZeroLeakage(t *testing.T) {
	engine := DefaultGuardrailsEngine()

	t.Run("ShortText_OneByteChunks", func(t *testing.T) {
		inspector := NewStreamInspector()
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyRequestID, "one-byte-redact-short")

		rawText := "Contact alex_rivera@gmail.com or 555-867-5309 for support."
		var emittedChunks []string

		for i := 0; i < len(rawText); i++ {
			byteChar := string(rawText[i])
			isLast := (i == len(rawText) - 1)
			chunk := &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{
									Content: &byteChar,
								},
							},
						},
					},
				},
			}
			if isLast {
				finish := "stop"
				chunk.BifrostChatResponse.Choices[0].FinishReason = &finish
			}

			inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
			require.NoError(t, err)
			require.NotNil(t, inspected)

			delta, _ := extractChunkDelta(inspected)
			emittedChunks = append(emittedChunks, delta)

			// Adversarial check: No single chunk should leak cleartext sensitive fragments
			assert.NotContains(t, delta, "alex_rivera@gmail.com")
			assert.NotContains(t, delta, "555-867-5309")
		}

		reconstructed := strings.Join(emittedChunks, "")
		t.Logf("Short stream reconstructed text: %q", reconstructed)

		assert.Contains(t, reconstructed, "[EMAIL]")
		assert.Contains(t, reconstructed, "[PHONE_NUMBER]")
		assert.NotContains(t, reconstructed, "alex_rivera@gmail.com")
		assert.NotContains(t, reconstructed, "555-867-5309")
	})

	t.Run("PaddedText_ExceedingHoldingWindow_OneByteChunks", func(t *testing.T) {
		inspector := NewStreamInspector()
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyRequestID, "one-byte-redact-padded")

		// 200+ bytes preamble before the sensitive email
		preamble := "System audit log header with safe prefix text: " + strings.Repeat("LOG_ENTRY ", 15)
		rawText := preamble + "reach out to security_admin@corp.internal for keys."
		var emittedChunks []string

		for i := 0; i < len(rawText); i++ {
			byteChar := string(rawText[i])
			isLast := (i == len(rawText) - 1)
			chunk := &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{
									Content: &byteChar,
								},
							},
						},
					},
				},
			}
			if isLast {
				finish := "stop"
				chunk.BifrostChatResponse.Choices[0].FinishReason = &finish
			}

			inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
			require.NoError(t, err)
			require.NotNil(t, inspected)

			delta, _ := extractChunkDelta(inspected)
			emittedChunks = append(emittedChunks, delta)

			// Zero-leakage check on each emitted chunk
			assert.NotContains(t, delta, "security_admin@corp.internal")
		}

		reconstructed := strings.Join(emittedChunks, "")
		t.Logf("Padded stream reconstructed text: %q", reconstructed)

		assert.Contains(t, reconstructed, "[EMAIL]")
		assert.NotContains(t, reconstructed, "security_admin@corp.internal")
		assert.True(t, strings.HasPrefix(reconstructed, "System audit log header"))
	})
}

// TestAdversarial_Streaming_OneByteChunks_Block_ZeroLeakage tests that splitting
// a block-capable entity (SSN) 1 byte at a time triggers HTTP 422 intervention
// and leaks ZERO sensitive digits or prefixes.
func TestAdversarial_Streaming_OneByteChunks_Block_ZeroLeakage(t *testing.T) {
	engine := DefaultGuardrailsEngine()

	t.Run("ShortSSN_OneByteChunks", func(t *testing.T) {
		inspector := NewStreamInspector()
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyRequestID, "one-byte-block-short")

		rawText := "User SSN is 123-45-6789 on file."
		var emittedDeltas []string
		var interceptedErr error

		for i := 0; i < len(rawText); i++ {
			byteChar := string(rawText[i])
			chunk := &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{
									Content: &byteChar,
								},
							},
						},
					},
				},
			}

			inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
			if err != nil {
				interceptedErr = err
				break
			}
			delta, _ := extractChunkDelta(inspected)
			emittedDeltas = append(emittedDeltas, delta)
		}

		require.Error(t, interceptedErr, "Stream must be intercepted with block error")
		streamErr, ok := interceptedErr.(*schemas.StreamInterceptionError)
		require.True(t, ok)
		require.NotNil(t, streamErr.BifrostError)
		assert.Equal(t, 422, *streamErr.BifrostError.StatusCode)

		leakedText := strings.Join(emittedDeltas, "")
		t.Logf("Emitted deltas prior to intervention: %q", leakedText)

		// Zero-leakage invariant: No part of the SSN should have reached the client
		assert.NotContains(t, leakedText, "123-45-6789")
		assert.NotContains(t, leakedText, "123-45-")
		assert.NotContains(t, leakedText, "123-")
	})

	t.Run("PaddedSSN_ExceedingHoldingWindow_OneByteChunks", func(t *testing.T) {
		inspector := NewStreamInspector()
		ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
		ctx.SetValue(schemas.BifrostContextKeyRequestID, "one-byte-block-padded")

		preamble := "Preceding safe stream text with extensive padding: " + strings.Repeat("STATUS_OK ", 15)
		rawText := preamble + "classified SSN: 987-65-4321 end of record."
		var emittedDeltas []string
		var interceptedErr error

		for i := 0; i < len(rawText); i++ {
			byteChar := string(rawText[i])
			chunk := &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{
									Content: &byteChar,
								},
							},
						},
					},
				},
			}

			inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
			if err != nil {
				interceptedErr = err
				break
			}
			delta, _ := extractChunkDelta(inspected)
			emittedDeltas = append(emittedDeltas, delta)
		}

		require.Error(t, interceptedErr, "Stream must be intercepted with block error")
		streamErr, ok := interceptedErr.(*schemas.StreamInterceptionError)
		require.True(t, ok)
		assert.Equal(t, 422, *streamErr.BifrostError.StatusCode)

		leakedText := strings.Join(emittedDeltas, "")
		t.Logf("Padded stream emitted deltas prior to intervention: %q", leakedText)

		// Zero-leakage invariant: Preceding preamble can be emitted, but ZERO SSN digits
		assert.NotContains(t, leakedText, "987-65-4321")
		assert.NotContains(t, leakedText, "987-65-")
		assert.NotContains(t, leakedText, "987-")
	})
}

// TestAdversarial_Streaming_UTF8_RuneSplitting_Stress checks multi-byte UTF-8
// integrity across chunk boundaries for 2-byte, 3-byte, and 4-byte runes.
func TestAdversarial_Streaming_UTF8_RuneSplitting_Stress(t *testing.T) {
	engine := DefaultGuardrailsEngine()

	testSentences := []struct {
		name string
		text string
	}{
		{
			name: "Latin1_2ByteRunes",
			text: "L'été à Paris coûte très cher en fête: café, crème, naïf.",
		},
		{
			name: "CJK_3ByteRunes",
			text: "世界平和と繁栄を祈ります。技術革新と人工知能の調和。",
		},
		{
			name: "Emoji_4ByteRunes",
			text: "Rocket 🚀 Lock 🔒 Party 🎉 Fire 🔥 Unicorn 🦄 Shield 🛡️ Sparkles ✨",
		},
		{
			name: "MixedRunesWithRedaction",
			text: "Bonjour! Contactez contact_fr@societe.fr s'il vous plaît 🚀 pour aide.",
		},
	}

	for _, tc := range testSentences {
		t.Run(tc.name, func(t *testing.T) {
			inspector := NewStreamInspector()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, "utf8-test-"+tc.name)

			rawBytes := []byte(tc.text)
			var emittedChunks []string

			for i := 0; i < len(rawBytes); i++ {
				singleByte := string(rawBytes[i : i+1])
				isLast := (i == len(rawBytes)-1)

				chunk := &schemas.BifrostStreamChunk{
					BifrostChatResponse: &schemas.BifrostChatResponse{
						Choices: []schemas.BifrostResponseChoice{
							{
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: &schemas.ChatStreamResponseChoiceDelta{
										Content: &singleByte,
									},
								},
							},
						},
					},
				}
				if isLast {
					finish := "stop"
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finish
				}

				inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
				require.NoError(t, err)
				require.NotNil(t, inspected)

				delta, _ := extractChunkDelta(inspected)
				emittedChunks = append(emittedChunks, delta)
			}

			reconstructed := strings.Join(emittedChunks, "")
			t.Logf("UTF-8 [%s] reconstructed: %q", tc.name, reconstructed)

			// Assert UTF-8 validity
			assert.True(t, utf8.ValidString(reconstructed), "Reconstructed stream text must be valid UTF-8")
			assert.NotContains(t, reconstructed, "\ufffd", "Reconstructed text must not contain unicode replacement character")

			if strings.Contains(tc.text, "@") {
				assert.Contains(t, reconstructed, "[EMAIL]")
				assert.NotContains(t, reconstructed, "contact_fr@societe.fr")
			} else {
				assert.Equal(t, tc.text, reconstructed, "Non-sensitive text with multi-byte runes must match exactly")
			}
		})
	}

	// Varying holding window sizes with UTF-8 runes (using window size >= entity length)
	windowSizes := []int{32, 64, 128}
	for _, ws := range windowSizes {
		t.Run(fmt.Sprintf("WindowSize_%d", ws), func(t *testing.T) {
			inspector := NewStreamInspector()
			inspector.SetHoldingWindowSize(ws)

			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, fmt.Sprintf("utf8-window-%d", ws))

			sentence := "Testing window size with runes: 🚀 世界 🌍 and email test@example.com done."
			rawBytes := []byte(sentence)
			var emittedChunks []string

			for i := 0; i < len(rawBytes); i++ {
				singleByte := string(rawBytes[i : i+1])
				isLast := (i == len(rawBytes)-1)
				chunk := &schemas.BifrostStreamChunk{
					BifrostChatResponse: &schemas.BifrostChatResponse{
						Choices: []schemas.BifrostResponseChoice{
							{
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &singleByte},
								},
							},
						},
					},
				}
				if isLast {
					finish := "stop"
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finish
				}

				inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
				require.NoError(t, err)
				delta, _ := extractChunkDelta(inspected)
				emittedChunks = append(emittedChunks, delta)
			}

			reconstructed := strings.Join(emittedChunks, "")
			assert.True(t, utf8.ValidString(reconstructed))
			assert.Contains(t, reconstructed, "[EMAIL]")
			assert.NotContains(t, reconstructed, "test@example.com")
		})
	}
}

// TestAdversarial_Streaming_FinishOnlyAndMetadataChunks_Stress tests that
// finish-only, usage metadata, and nil-pointer chunks never cause nil dereferences.
func TestAdversarial_Streaming_FinishOnlyAndMetadataChunks_Stress(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "finish-metadata-stress")

	finishStop := "stop"
	finishLength := "length"
	finishTool := "tool_calls"
	emptyText := ""

	testCases := []struct {
		name  string
		chunk *schemas.BifrostStreamChunk
	}{
		{
			name:  "NilChunk",
			chunk: nil,
		},
		{
			name:  "EmptyChunk",
			chunk: &schemas.BifrostStreamChunk{},
		},
		{
			name: "FinishOnly_ChatStream_NilDelta",
			chunk: &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							FinishReason: &finishStop,
						},
					},
				},
			},
		},
		{
			name: "FinishOnly_ChatStream_NilDeltaContent",
			chunk: &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							FinishReason: &finishLength,
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{
									Content: nil,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "FinishOnly_ChatStream_EmptyStringContent",
			chunk: &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							FinishReason: &finishTool,
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{
									Content: &emptyText,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "UsageMetadataOnly_EmptyChoices",
			chunk: &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{
					Choices: []schemas.BifrostResponseChoice{},
					Usage: &schemas.BifrostLLMUsage{
						PromptTokens:     10,
						CompletionTokens: 20,
						TotalTokens:      30,
					},
				},
			},
		},
		{
			name: "TextCompletion_FinishOnly_NilTextChoice",
			chunk: &schemas.BifrostStreamChunk{
				BifrostTextCompletionResponse: &schemas.BifrostTextCompletionResponse{
					Choices: []schemas.BifrostResponseChoice{
						{
							FinishReason: &finishStop,
						},
					},
				},
			},
		},
		{
			name: "ResponsesStream_Completed_NilDelta",
			chunk: &schemas.BifrostStreamChunk{
				BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
					Type: schemas.ResponsesStreamResponseTypeCompleted,
				},
			},
		},
		{
			name: "ResponsesStream_OutputTextDone_NilDelta",
			chunk: &schemas.BifrostStreamChunk{
				BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
					Type: schemas.ResponsesStreamResponseTypeOutputTextDone,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, tc.chunk, engine)
			assert.NoError(t, err)
			assert.Equal(t, tc.chunk, res)
		})
	}
}

// TestAdversarial_Streaming_Race_Stress50Streams verifies concurrency safety
// under high-load parallel 1-byte streaming and background stale eviction.
func TestAdversarial_Streaming_Race_Stress50Streams(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	var wg sync.WaitGroup
	numStreams := 30

	for s := 0; s < numStreams; s++ {
		wg.Add(1)
		streamID := fmt.Sprintf("race-onebyte-%d", s)
		go func(id string, streamIdx int) {
			defer wg.Done()
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, id)

			content := fmt.Sprintf("Stream %d says hello 🚀 to user%d@test.com and finishes.", streamIdx, streamIdx)
			for i := 0; i < len(content); i++ {
				byteChar := string(content[i])
				isLast := (i == len(content)-1)

				chunk := &schemas.BifrostStreamChunk{
					BifrostChatResponse: &schemas.BifrostChatResponse{
						Choices: []schemas.BifrostResponseChoice{
							{
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: &schemas.ChatStreamResponseChoiceDelta{
										Content: &byteChar,
									},
								},
							},
						},
					},
				}
				if isLast {
					finish := "stop"
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finish
				}

				_, _ = inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
			}
		}(streamID, s)
	}

	// Concurrent evictions
	stopEvict := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopEvict:
				return
			default:
				inspector.evictStale(0)
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	close(stopEvict)
}

// TestAdversarial_Streaming_LongSecret_JWT_BoundaryLeakage tests whether a secret (like a JWT)
// whose length exceeds the 128-byte holding window buffer leaks prefix cleartext bytes
// before matching the full pattern and aborting.
func TestAdversarial_Streaming_LongSecret_JWT_BoundaryLeakage(t *testing.T) {
	engine := DefaultGuardrailsEngine()
	inspector := NewStreamInspector()

	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "jwt-boundary-leakage-test")

	// Standard JWT: 179 characters (> 128 byte default holding window)
	jwtHeader := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	jwtPayload := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9"
	jwtSig := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	rawJWT := jwtHeader + "." + jwtPayload + "." + jwtSig

	t.Logf("JWT length: %d bytes (holding window: 128 bytes)", len(rawJWT))

	streamInput := "Authorization Bearer: " + rawJWT + " in auth header."
	var emittedDeltas []string
	var abortedOnIndex = -1

	for i := 0; i < len(streamInput); i++ {
		byteChar := string(streamInput[i])
		chunk := &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				Choices: []schemas.BifrostResponseChoice{
					{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{
								Content: &byteChar,
							},
						},
					},
				},
			},
		}

		inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
		if err != nil {
			abortedOnIndex = i
			break
		}
		delta, _ := extractChunkDelta(inspected)
		emittedDeltas = append(emittedDeltas, delta)
	}

	leakedText := strings.Join(emittedDeltas, "")
	t.Logf("Aborted on chunk index: %d", abortedOnIndex)
	t.Logf("Deltas emitted prior to abort: %q", leakedText)

	// Check if any cleartext portion of the JWT was leaked to client before intervention
	if strings.Contains(leakedText, "eyJ") {
		t.Logf("OBSERVATION: Secret prefix %q leaked before block because JWT length (%d) exceeds holding window (128)", leakedText, len(rawJWT))
	} else {
		t.Logf("SUCCESS: Zero JWT characters leaked prior to abort")
	}
}


