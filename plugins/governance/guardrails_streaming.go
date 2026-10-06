package governance

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// StreamInspector tracks and inspects streaming chunks for guardrail violations.
type StreamInspector struct {
	mu                sync.RWMutex
	streams           map[string]*streamAccumulator
	holdingWindowSize int // default: 128
}

type streamAccumulator struct {
	mu          sync.Mutex
	accumulated strings.Builder
	lastSeen    time.Time
	emittedLen  int // number of characters of TransformedText already emitted
}

// NewStreamInspector creates a new streaming guardrails inspector.
func NewStreamInspector() *StreamInspector {
	inspector := &StreamInspector{
		streams:           make(map[string]*streamAccumulator),
		holdingWindowSize: 128,
	}

	// Background routine to evict stale accumulators older than 5 minutes
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for range ticker.C {
			inspector.evictStale(5 * time.Minute)
		}
	}()

	return inspector
}

// SetHoldingWindowSize configures the sliding window byte size for candidate token delay.
func (si *StreamInspector) SetHoldingWindowSize(size int) {
	si.mu.Lock()
	defer si.mu.Unlock()
	if size > 0 {
		si.holdingWindowSize = size
	}
}

func (si *StreamInspector) evictStale(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)

	si.mu.RLock()
	var staleIDs []string
	for id, acc := range si.streams {
		acc.mu.Lock()
		isStale := acc.lastSeen.Before(cutoff)
		acc.mu.Unlock()
		if isStale {
			staleIDs = append(staleIDs, id)
		}
	}
	si.mu.RUnlock()

	if len(staleIDs) > 0 {
		si.mu.Lock()
		for _, id := range staleIDs {
			delete(si.streams, id)
		}
		si.mu.Unlock()
	}
}

// computeSafeCut calculates the verified emission boundary delimiter-aligned with holding window.
func computeSafeCut(transformedText string, emittedLen int, holdingWindow int, isFinished bool) int {
	totalLen := len(transformedText)
	if isFinished {
		return totalLen
	}

	targetCut := totalLen - holdingWindow
	if targetCut <= emittedLen {
		return emittedLen
	}

	// Find the last word/token boundary delimiter in [emittedLen, targetCut]
	candidate := transformedText[emittedLen:targetCut]
	lastDelim := strings.LastIndexAny(candidate, " \t\r\n.,;:!?()[]{}<>-/\\")
	if lastDelim != -1 {
		return emittedLen + lastDelim + 1
	}

	// Ensure targetCut does not split a multi-byte UTF-8 rune
	for targetCut > emittedLen && !utf8.RuneStart(transformedText[targetCut]) {
		targetCut--
	}

	return targetCut
}

// InspectChunk evaluates a stream chunk against the guardrails engine.
// If a blocking violation occurs, it returns (nil, *schemas.StreamInterceptionError) with HTTP 422.
// If a redact rule applies, it redacts the text in-flight before chunk emission.
func (si *StreamInspector) InspectChunk(
	ctx *schemas.BifrostContext,
	req *schemas.HTTPRequest,
	chunk *schemas.BifrostStreamChunk,
	engine GuardrailEvaluator,
) (*schemas.BifrostStreamChunk, error) {
	if chunk == nil || engine == nil {
		return chunk, nil
	}

	deltaText, isFinished := extractChunkDelta(chunk)
	if deltaText == "" && !isFinished {
		return chunk, nil
	}

	// 1. Resolve isolated stream ID without default_stream collision
	streamID := ""
	if ctx != nil {
		streamID = bifrostGetString(ctx, schemas.BifrostContextKeyRequestID)
	}
	if streamID == "" && req != nil && req.Headers != nil {
		streamID = req.Headers["x-request-id"]
	}
	if streamID == "" {
		streamID = "stream-" + uuid.NewString()
		if ctx != nil {
			ctx.SetValue(schemas.BifrostContextKeyRequestID, streamID)
		}
		if req != nil {
			if req.Headers == nil {
				req.Headers = make(map[string]string)
			}
			req.Headers["x-request-id"] = streamID
		}
	}

	// 2. Fetch or initialize stream accumulator
	si.mu.Lock()
	acc, ok := si.streams[streamID]
	if !ok {
		acc = &streamAccumulator{lastSeen: time.Now()}
		si.streams[streamID] = acc
	}
	holdingWindow := si.holdingWindowSize
	si.mu.Unlock()

	acc.mu.Lock()
	acc.lastSeen = time.Now()
	acc.accumulated.WriteString(deltaText)
	cumulativeRaw := acc.accumulated.String()
	emittedLen := acc.emittedLen
	acc.mu.Unlock()

	// 3. Evaluate cumulative text across rules and cloud adapters
	res := engine.EvaluateTextWithContext(ctx, cumulativeRaw, "llm", "output", nil)

	// 4. Handle ActionBlock mid-stream intervention (HTTP 422)
	if res != nil && !res.Allowed {
		// Clean up stream accumulator
		si.mu.Lock()
		delete(si.streams, streamID)
		si.mu.Unlock()

		reason := res.Reason
		if reason == "" {
			reason = res.InterventionReason
		}
		if reason == "" {
			reason = "Output blocked by guardrail policy"
		}

		return nil, &schemas.StreamInterceptionError{
			BifrostError: &schemas.BifrostError{
				IsBifrostError: true,
				StatusCode:     bifrost.Ptr(422),
				Type:           bifrost.Ptr("guardrail_violation"),
				AllowFallbacks: bifrost.Ptr(false),
				Error: &schemas.ErrorField{
					Message: fmt.Sprintf("Guardrail violation: %s", reason),
					Type:    bifrost.Ptr("guardrail_violation"),
					Code:    bifrost.Ptr("guardrail_intervention"),
					Param: map[string]interface{}{
						"action":            "block",
						"reason":            reason,
						"detected_entities": res.DetectedEntities,
					},
				},
			},
		}
	}

	// 5. Determine transformed text with cumulative redactions
	transformedText := cumulativeRaw
	if res != nil && res.TransformedText != "" {
		transformedText = res.TransformedText
	}

	// 6. Compute safe cut and emission delta
	safeCut := computeSafeCut(transformedText, emittedLen, holdingWindow, isFinished)
	toEmit := ""
	if safeCut > emittedLen {
		toEmit = transformedText[emittedLen:safeCut]
		acc.mu.Lock()
		acc.emittedLen = safeCut
		acc.mu.Unlock()
	}

	// 7. Apply emission delta to chunk
	applyChunkDelta(chunk, toEmit)

	// 8. Clean up upon finish
	if isFinished {
		si.mu.Lock()
		delete(si.streams, streamID)
		si.mu.Unlock()
	}

	return chunk, nil
}

// extractChunkDelta retrieves the text delta and finish indicator from a chunk.
func extractChunkDelta(chunk *schemas.BifrostStreamChunk) (string, bool) {
	if chunk == nil {
		return "", false
	}

	if chunk.BifrostChatResponse != nil {
		isFinished := false
		var sb strings.Builder
		for _, choice := range chunk.BifrostChatResponse.Choices {
			if choice.FinishReason != nil {
				isFinished = true
			}
			// Safe check: verify ChatStreamResponseChoice is not nil before accessing Delta
			if choice.ChatStreamResponseChoice != nil &&
				choice.ChatStreamResponseChoice.Delta != nil &&
				choice.ChatStreamResponseChoice.Delta.Content != nil {
				sb.WriteString(*choice.ChatStreamResponseChoice.Delta.Content)
			}
		}
		return sb.String(), isFinished
	}

	if chunk.BifrostTextCompletionResponse != nil {
		isFinished := false
		var sb strings.Builder
		for _, choice := range chunk.BifrostTextCompletionResponse.Choices {
			if choice.FinishReason != nil {
				isFinished = true
			}
			if choice.TextCompletionResponseChoice != nil &&
				choice.TextCompletionResponseChoice.Text != nil {
				sb.WriteString(*choice.TextCompletionResponseChoice.Text)
			}
		}
		return sb.String(), isFinished
	}

	if chunk.BifrostResponsesStreamResponse != nil {
		isFinished := false
		switch chunk.BifrostResponsesStreamResponse.Type {
		case schemas.ResponsesStreamResponseTypeCompleted,
			schemas.ResponsesStreamResponseTypeOutputTextDone,
			schemas.ResponsesStreamResponseTypeOutputItemDone:
			isFinished = true
		}
		if chunk.BifrostResponsesStreamResponse.Delta != nil {
			return *chunk.BifrostResponsesStreamResponse.Delta, isFinished
		}
		if chunk.BifrostResponsesStreamResponse.Text != nil {
			return *chunk.BifrostResponsesStreamResponse.Text, isFinished
		}
		return "", isFinished
	}

	return "", false
}

// applyChunkDelta overwrites the chunk delta text with transformed text.
func applyChunkDelta(chunk *schemas.BifrostStreamChunk, text string) {
	if chunk == nil {
		return
	}

	if chunk.BifrostChatResponse != nil {
		for i := range chunk.BifrostChatResponse.Choices {
			choice := &chunk.BifrostChatResponse.Choices[i]
			if choice.ChatStreamResponseChoice != nil {
				if choice.ChatStreamResponseChoice.Delta != nil {
					choice.ChatStreamResponseChoice.Delta.Content = &text
				} else if text != "" {
					choice.ChatStreamResponseChoice.Delta = &schemas.ChatStreamResponseChoiceDelta{
						Content: &text,
					}
				}
			} else if choice.ChatStreamResponseChoice == nil && text != "" {
				choice.ChatStreamResponseChoice = &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{
						Content: &text,
					},
				}
			}
		}
	} else if chunk.BifrostTextCompletionResponse != nil {
		for i := range chunk.BifrostTextCompletionResponse.Choices {
			choice := &chunk.BifrostTextCompletionResponse.Choices[i]
			if choice.TextCompletionResponseChoice != nil {
				choice.Text = &text
			} else if text != "" {
				choice.TextCompletionResponseChoice = &schemas.TextCompletionResponseChoice{
					Text: &text,
				}
			}
		}
	} else if chunk.BifrostResponsesStreamResponse != nil {
		if chunk.BifrostResponsesStreamResponse.Delta != nil {
			chunk.BifrostResponsesStreamResponse.Delta = &text
		} else if chunk.BifrostResponsesStreamResponse.Text != nil {
			chunk.BifrostResponsesStreamResponse.Text = &text
		} else if text != "" {
			chunk.BifrostResponsesStreamResponse.Delta = &text
		}
	}
}
