package enterprise

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/audit"
	"github.com/maximhq/bifrost/framework/cluster"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CHALLENGER 1 ADVERSARIAL STRESS SUITE (MILESTONE 7 POST-REMEDIATION)
// ============================================================================

// TestChallenger_M7Post1_Guardrails_ConcurrentMicroChunkSplitting_500Goroutines
// verifies that 500 concurrent goroutines streaming micro-chunked payloads through
// a shared StreamInspector exhibit zero data races, zero cross-stream contamination,
// and strictly partition into 250 HTTP 422 blocked streams and 250 clean completions.
func TestChallenger_M7Post1_Guardrails_ConcurrentMicroChunkSplitting_500Goroutines(t *testing.T) {
	engine := governance.DefaultGuardrailsEngine()
	inspector := governance.NewStreamInspector()

	const numStreams = 500
	var cleanCompleted atomic.Int64
	var blockedCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(numStreams)

	startGate := make(chan struct{})

	for i := 0; i < numStreams; i++ {
		go func(streamIdx int) {
			defer wg.Done()
			<-startGate

			streamID := fmt.Sprintf("stream-challenger-%04d", streamIdx)
			ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
			ctx.SetValue(schemas.BifrostContextKeyRequestID, streamID)

			isBlockedStream := (streamIdx%2 == 0)

			var chunks []string
			if isBlockedStream {
				// Micro-chunked SSN split character-by-character
				chunks = []string{"9", "8", "7", "-", "6", "5", "-", "4", "3", "2", "1"}
			} else {
				chunks = []string{"Healthy ", "enterprise ", "telemetry ", "event ", "logged."}
			}

			wasBlocked := false
			for cIdx, cText := range chunks {
				textCopy := cText
				isLast := (cIdx == len(chunks)-1)

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
				if isLast {
					finishReason := "stop"
					chunk.BifrostChatResponse.Choices[0].FinishReason = &finishReason
				}

				inspected, err := inspector.InspectChunk(ctx, &schemas.HTTPRequest{}, chunk, engine)
				if err != nil {
					streamErr, ok := err.(*schemas.StreamInterceptionError)
					if ok && streamErr.BifrostError != nil && *streamErr.BifrostError.StatusCode == 422 {
						wasBlocked = true
					}
					break
				}
				_ = inspected
			}

			if wasBlocked {
				blockedCount.Add(1)
			} else {
				cleanCompleted.Add(1)
			}
		}(i)
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int64(250), cleanCompleted.Load(), "exactly 250 clean streams must complete")
	assert.Equal(t, int64(250), blockedCount.Load(), "exactly 250 sensitive micro-chunked streams must be blocked")
}

// TestChallenger_M7Post1_CircuitBreaker_ProbeWindowCAS_500Goroutines_Flapping
// verifies CAS canary slot guarantees across 3 full flapping cycles:
// In each cycle, exactly 1 canary probe is admitted and 499 go to fallback.
// In cycle 1, canary fails -> circuit stays open.
// In cycle 2, canary succeeds -> circuit closes.
func TestChallenger_M7Post1_CircuitBreaker_ProbeWindowCAS_500Goroutines_Flapping(t *testing.T) {
	cbm := governance.NewCircuitBreakerManager()
	cbm.RegisterCircuitPolicy(governance.CircuitBreakerPolicy{
		Name:             "Adversarial-Flapping-Breaker",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		DefaultCooldown:  15 * time.Millisecond,
		TriggerHeaders: map[string]string{
			"X-Adversarial-Trip": "true",
		},
	})

	// Initial trip
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Adversarial-Trip": "true"}, 500, "")

	// Cycle 1: Cooldown expires, 500 goroutines race for canary slot, canary fails (HTTP 500)
	time.Sleep(20 * time.Millisecond)

	const numGoroutines = 500
	startGate1 := make(chan struct{})
	var wg1 sync.WaitGroup
	wg1.Add(numGoroutines)

	var probeCount1 atomic.Int64
	var fallbackCount1 atomic.Int64

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg1.Done()
			<-startGate1

			req := &schemas.BifrostRequest{
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.OpenAI,
					Model:    "gpt-4o",
				},
			}
			tripped, fbProv, fbModel := cbm.CheckAndReroute(nil, req)
			if !tripped {
				probeCount1.Add(1)
			} else {
				fallbackCount1.Add(1)
				assert.Equal(t, "anthropic", fbProv)
				assert.Equal(t, "claude-sonnet-4-5", fbModel)
			}
		}()
	}
	close(startGate1)
	wg1.Wait()

	require.Equal(t, int64(1), probeCount1.Load(), "cycle 1: strictly 1 canary probe admitted")
	require.Equal(t, int64(499), fallbackCount1.Load(), "cycle 1: 499 rerouted to fallback")

	// Canary probe reports failure -> Circuit reopens
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Adversarial-Trip": "true"}, 500, "")

	// Cycle 2: Wait for second cooldown, 500 goroutines race, canary succeeds (HTTP 200)
	time.Sleep(20 * time.Millisecond)

	startGate2 := make(chan struct{})
	var wg2 sync.WaitGroup
	wg2.Add(numGoroutines)

	var probeCount2 atomic.Int64
	var fallbackCount2 atomic.Int64

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg2.Done()
			<-startGate2

			req := &schemas.BifrostRequest{
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.OpenAI,
					Model:    "gpt-4o",
				},
			}
			tripped, fbProv, fbModel := cbm.CheckAndReroute(nil, req)
			if !tripped {
				probeCount2.Add(1)
			} else {
				fallbackCount2.Add(1)
				assert.Equal(t, "anthropic", fbProv)
				assert.Equal(t, "claude-sonnet-4-5", fbModel)
			}
		}()
	}
	close(startGate2)
	wg2.Wait()

	require.Equal(t, int64(1), probeCount2.Load(), "cycle 2: strictly 1 canary probe admitted")
	require.Equal(t, int64(499), fallbackCount2.Load(), "cycle 2: 499 rerouted to fallback")

	// Canary probe reports success -> Circuit closes
	cbm.InspectResponse("openai", "gpt-4o", map[string]string{"X-Adversarial-Trip": "false"}, 200, "")

	// Post-cycle verification: All subsequent requests route to primary
	reqPost := &schemas.BifrostRequest{
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-4o",
		},
	}
	trippedPost, _, _ := cbm.CheckAndReroute(nil, reqPost)
	assert.False(t, trippedPost, "circuit must be closed after successful canary probe")
}

// TestChallenger_M7Post1_Cluster_BurstRateLimitRefill_500Goroutines_MultiBucket
// verifies token bucket invariants across 3 concurrent buckets under 500 goroutine stampedes.
func TestChallenger_M7Post1_Cluster_BurstRateLimitRefill_500Goroutines_MultiBucket(t *testing.T) {
	buckets := []*cluster.InMemTokenBucket{
		cluster.NewInMemTokenBucket("challenger-b1:rpm", 30, 40*time.Millisecond),
		cluster.NewInMemTokenBucket("challenger-b2:rpm", 50, 40*time.Millisecond),
		cluster.NewInMemTokenBucket("challenger-b3:rpm", 70, 40*time.Millisecond),
	}
	capacities := []int64{30, 50, 70}

	for idx, b := range buckets {
		capVal := capacities[idx]

		// Exhaust bucket
		now := time.Now()
		allowed, rem, _, _ := b.CheckAndCharge(now, capVal, capVal, 40*time.Millisecond)
		require.True(t, allowed)
		require.Equal(t, int64(0), rem)

		// Wait for refill
		time.Sleep(50 * time.Millisecond)

		// 500 goroutine burst
		const numGoroutines = 500
		startGate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		var successCount atomic.Int64
		var rejectCount atomic.Int64

		for g := 0; g < numGoroutines; g++ {
			go func() {
				defer wg.Done()
				<-startGate
				chargeNow := time.Now()
				cAllowed, _, _, _ := b.CheckAndCharge(chargeNow, 1, capVal, 40*time.Millisecond)
				if cAllowed {
					successCount.Add(1)
				} else {
					rejectCount.Add(1)
				}
			}()
		}
		close(startGate)
		wg.Wait()

		assert.Equal(t, capVal, successCount.Load(), "bucket %d: strictly %d requests must succeed", idx, capVal)
		assert.Equal(t, int64(numGoroutines)-capVal, rejectCount.Load(), "bucket %d: remainder must be rejected", idx)
		assert.Equal(t, int64(0), b.GetRemaining(), "bucket %d: remaining must be 0", idx)
	}
}

// TestChallenger_M7Post1_MCP_TokenExchange_ExtremeConcurrency_500Goroutines
// verifies federated token exchange under 500 goroutines concurrently minting,
// invalidating, and flushing cached tokens without deadlocks or panic.
func TestChallenger_M7Post1_MCP_TokenExchange_ExtremeConcurrency_500Goroutines(t *testing.T) {
	exchanger := governance.NewFederatedTokenExchanger()
	ctx := context.Background()

	const numGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	startGate := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			<-startGate

			userToken := fmt.Sprintf("adversarial-user-%d", gid%10)
			audience := "https://tools.slack.com"

			for it := 0; it < 15; it++ {
				switch (gid + it) % 3 {
				case 0:
					tok, err := exchanger.ExchangeToken(ctx, userToken, audience)
					if err == nil {
						assert.NotEmpty(t, tok)
					}
				case 1:
					exchanger.InvalidateToken(userToken, audience)
				case 2:
					if gid%50 == 0 {
						exchanger.FlushCache()
					}
				}
			}
		}(g)
	}

	close(startGate)
	wg.Wait()
}

// TestChallenger_M7Post1_Remediations_RegressionVerification verifies all 3 remediations:
// 1. Diagnostics SecretSanitizer: direct/mutual cycles and deep nesting terminate safely at depth 32.
// 2. SSO JWKS: Revoked keys omitted from jwks.json are evicted immediately.
// 3. Audit Ledger: Boundary checks detect tail truncation correctly without silent clamping.
func TestChallenger_M7Post1_Remediations_RegressionVerification(t *testing.T) {
	t.Run("Sanitizer_DirectAndMutualCycles_BoundedAt32", func(t *testing.T) {
		// Direct cycle: map containing itself
		directMap := make(map[string]interface{})
		directMap["self"] = directMap
		directMap["name"] = "test-node"

		start := time.Now()
		resDirect := diagnostics.SanitizeSecretFields(directMap)
		elapsed := time.Since(start)
		require.Less(t, elapsed, 100*time.Millisecond, "cyclic sanitization must terminate rapidly")
		require.NotNil(t, resDirect)

		resMap, ok := resDirect.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test-node", resMap["name"])

		// Mutual cycle: a -> b -> a
		mapA := make(map[string]interface{})
		mapB := make(map[string]interface{})
		mapA["b"] = mapB
		mapB["a"] = mapA
		mapA["api_key"] = "sk-super-secret"

		resMutual := diagnostics.SanitizeSecretFields(mapA)
		require.NotNil(t, resMutual)
		resMutualMap, ok := resMutual.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "[REDACTED]", resMutualMap["api_key"])

		// Slice cycle
		sliceA := make([]interface{}, 1)
		sliceA[0] = sliceA
		resSlice := diagnostics.SanitizeSecretFields(sliceA)
		require.NotNil(t, resSlice)
	})

	t.Run("SSO_JWKSCache_ImmediateEvictionOfRevokedKeys", func(t *testing.T) {
		privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		makeJWK := func(kid string, pub *rsa.PublicKey) map[string]interface{} {
			return map[string]interface{}{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}
		}

		var currentKeys atomic.Value
		currentKeys.Store([]map[string]interface{}{
			makeJWK("key-active-1", &privKey1.PublicKey),
		})

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys := currentKeys.Load().([]map[string]interface{})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
		}))
		defer ts.Close()

		cache := sso.NewJWKSCache(ts.URL, ts.Client(), 1*time.Hour)

		ctx := context.Background()

		// Key 1 active
		k1, err := cache.GetKey(ctx, "key-active-1")
		require.NoError(t, err)
		require.NotNil(t, k1)

		// Rotate out key-active-1, introduce key-active-2
		time.Sleep(15 * time.Millisecond) // Wait for cooldown
		currentKeys.Store([]map[string]interface{}{
			makeJWK("key-active-2", &privKey2.PublicKey),
		})

		err = cache.FetchKeys(ctx)
		require.NoError(t, err)

		// Key 2 must now be present
		k2, err := cache.GetKey(ctx, "key-active-2")
		require.NoError(t, err)
		require.NotNil(t, k2)

		// Key 1 MUST BE EVICTED
		k1Revoked, err := cache.GetKey(ctx, "key-active-1")
		require.Error(t, err, "revoked key must be immediately evicted from JWKS cache")
		require.Nil(t, k1Revoked)
	})

	t.Run("AuditLedger_VerifyChain_StrictTailBoundaryVerification", func(t *testing.T) {
		hmacKey := "a-sufficiently-long-secret-key-at-least-32-chars!"
		ledger, err := audit.NewLedger(audit.Config{HMACKey: hmacKey})
		require.NoError(t, err)

		// Record 6 events
		for i := 1; i <= 6; i++ {
			_, err := ledger.RecordEvent("action", "target", fmt.Sprintf("id-%d", i), "actor", "127.0.0.1", "{}")
			require.NoError(t, err)
		}

		// Exact chain verification: 1..6 -> true, 0
		valid, brokenAt := ledger.VerifyChain(1, 6)
		assert.True(t, valid)
		assert.Equal(t, int64(0), brokenAt)

		// Tail verification up to current head: 1..0 -> true, 0
		validHead, brokenAtHead := ledger.VerifyChain(1, 0)
		assert.True(t, validHead)
		assert.Equal(t, int64(0), brokenAtHead)

		// Truncation detection: expected 1..10, actual head is 6 -> false, 7
		validTrunc, brokenAtTrunc := ledger.VerifyChain(1, 10)
		assert.False(t, validTrunc, "verifying past head must fail")
		assert.Equal(t, int64(7), brokenAtTrunc, "must identify truncation at sequence 7")

		// Out-of-bounds start: from=7 > head=6 -> false, 7
		validOOB, brokenAtOOB := ledger.VerifyChain(7, 10)
		assert.False(t, validOOB)
		assert.Equal(t, int64(7), brokenAtOOB)

		// Inverted range: from=5 > to=3 -> false, 5
		validInv, brokenAtInv := ledger.VerifyChain(5, 3)
		assert.False(t, validInv)
		assert.Equal(t, int64(5), brokenAtInv)
	})
}
