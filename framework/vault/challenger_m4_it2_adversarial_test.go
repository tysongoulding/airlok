package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// CHALLENGE 1: STALE SECRET FALLBACK CONCURRENCY UNDER 1,000 GOROUTINES
// ============================================================================

// TestAdversarial_M4_It2_StaleFallback_1000GoroutinesConcurrently verifies:
// 1,000 concurrent goroutines querying an expired secret during an upstream outage.
// Zero data races on entry.IsStale (atomic.Bool) and all 1,000 callers receive the stale secret.
func TestAdversarial_M4_It2_StaleFallback_1000GoroutinesConcurrently(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/gpt4", map[string]string{
		"token": "sk-gpt4-stale-token-1000",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Millisecond,
	}, driver)

	// 1. Prime cache
	val0, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/gpt4")
	require.NoError(t, err)
	require.Equal(t, "sk-gpt4-stale-token-1000", val0)

	// 2. Wait for TTL to expire
	time.Sleep(25 * time.Millisecond)

	// 3. Trip upstream outage
	driver.SetOutage(true)

	const numGoroutines = 1000
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	results := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			<-startCh
			val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/gpt4")
			results[idx] = val
			errors[idx] = err
		}()
	}

	// Release all 1,000 goroutines simultaneously
	close(startCh)
	wg.Wait()

	for i, err := range errors {
		require.NoError(t, err, "goroutine %d failed under concurrent stale fallback", i)
	}
	for i, val := range results {
		assert.Equal(t, "sk-gpt4-stale-token-1000", val, "goroutine %d got wrong stale secret", i)
	}
}

// TestAdversarial_M4_It2_StaleFallback_MultiKeyOutage_1000Goroutines verifies:
// 5 distinct keys queried by 200 goroutines each (1,000 total) during an upstream outage.
// All keys return their respective stale secrets without cross-key data bleeding or races.
func TestAdversarial_M4_It2_StaleFallback_MultiKeyOutage_1000Goroutines(t *testing.T) {
	driver := NewMockVaultDriver()
	const numKeys = 5
	const goroutinesPerKey = 200

	for k := 0; k < numKeys; k++ {
		driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/provider-%d", k), map[string]string{
			"token": fmt.Sprintf("stale-token-provider-%d", k),
		})
	}

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 15 * time.Millisecond,
	}, driver)

	// Prime all keys in cache
	for k := 0; k < numKeys; k++ {
		val, err := resolver.Resolve(context.Background(), fmt.Sprintf("vault.bifrost/keys/provider-%d", k))
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("stale-token-provider-%d", k), val)
	}

	// Expire TTL and trigger outage
	time.Sleep(30 * time.Millisecond)
	driver.SetOutage(true)

	totalGoroutines := numKeys * goroutinesPerKey
	type resultItem struct {
		keyIdx int
		val    string
		err    error
	}
	results := make([]resultItem, totalGoroutines)

	var wg sync.WaitGroup
	startCh := make(chan struct{})

	for k := 0; k < numKeys; k++ {
		for g := 0; g < goroutinesPerKey; g++ {
			wg.Add(1)
			index := k*goroutinesPerKey + g
			keyNum := k
			go func() {
				defer wg.Done()
				<-startCh
				ref := fmt.Sprintf("vault.bifrost/keys/provider-%d", keyNum)
				val, err := resolver.Resolve(context.Background(), ref)
				results[index] = resultItem{keyIdx: keyNum, val: val, err: err}
			}()
		}
	}

	close(startCh)
	wg.Wait()

	for i, res := range results {
		require.NoError(t, res.err, "request %d failed", i)
		expected := fmt.Sprintf("stale-token-provider-%d", res.keyIdx)
		assert.Equal(t, expected, res.val, "request %d received wrong secret", i)
	}
}

// TestAdversarial_M4_It2_CircuitBreaker_LivelockUnderContinuousTraffic demonstrates:
// When continuous traffic arrives after a circuit trips, each call to HandleFetchFailure
// invokes RecordFailure(), resetting lastFailureTime = time.Now().
// This prevents time.Since(lastFailureTime) from ever exceeding cooldown, trapping the
// gateway in a permanent open-circuit livelock where it never probes upstream to recover.
func TestAdversarial_M4_It2_CircuitBreaker_LivelockUnderContinuousTraffic(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/livelock", map[string]string{
		"token": "initial-token",
	})

	// Circuit breaker threshold: 2 failures, cooldown: 50ms
	policy := NewResiliencePolicy(2, 50*time.Millisecond)
	cache := NewSecretCache(driver, 10*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 10 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// 1. Prime cache
	_, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/livelock")
	require.NoError(t, err)

	// Expire TTL
	time.Sleep(15 * time.Millisecond)

	// Upstream outage
	driver.SetOutage(true)

	// Trip circuit: 2 failures
	_, _ = resolver.Resolve(context.Background(), "vault.bifrost/keys/livelock")
	_, _ = resolver.Resolve(context.Background(), "vault.bifrost/keys/livelock")
	require.True(t, policy.IsCircuitOpen())

	// Upstream recovers immediately!
	driver.SetOutage(false)
	driver.PutSecret(context.Background(), "bifrost/keys/livelock", map[string]string{
		"token": "recovered-token",
	})

	// Now simulate continuous traffic with requests arriving every 10ms for 150ms (3x cooldown).
	// In a correct circuit breaker, after 50ms (cooldown), the circuit should probe upstream,
	// succeed, and recover.
	// But because HandleFetchFailure calls RecordFailure(), lastFailureTime is reset every 10ms,
	// so time.Since(lastFailureTime) is always <= 10ms (< 50ms cooldown).
	for i := 0; i < 15; i++ {
		time.Sleep(10 * time.Millisecond)
		_, _ = resolver.Resolve(context.Background(), "vault.bifrost/keys/livelock")
	}

	// Check if circuit recovered
	assert.False(t, policy.IsCircuitOpen(), "circuit breaker should recover under traffic once cooldown passes")
	val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/livelock")
	require.NoError(t, err)
	assert.Equal(t, "recovered-token", val, "should receive recovered token once upstream is healthy")
}

// TestAdversarial_M4_It2_StaleFallback_NeverCachedSecret_1000Goroutines verifies:
// 1,000 goroutines querying a key that was NEVER cached during an outage safely receive errors.
func TestAdversarial_M4_It2_StaleFallback_NeverCachedSecret_1000Goroutines(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.SetOutage(true)

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	const numGoroutines = 1000
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			<-startCh
			_, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/non-existent-secret")
			errors[idx] = err
		}()
	}

	close(startCh)
	wg.Wait()

	for i, err := range errors {
		require.Error(t, err, "goroutine %d should have received an error", i)
	}
}

// ============================================================================
// CHALLENGE 2: THUNDERING HERD STAMPEDE SUPPRESSION
// ============================================================================

// TestAdversarial_M4_It2_ThunderingHerd_ColdCache_1000Goroutines verifies:
// Exactly 1 backend fetch occurs when 1,000 goroutines hit an unprimed cold cache.
func TestAdversarial_M4_It2_ThunderingHerd_ColdCache_1000Goroutines(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/stampede-cold", map[string]string{
		"token": "cold-cache-secret-1000",
	})
	driver.SetLatency(30 * time.Millisecond)

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	const numGoroutines = 1000
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	results := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			<-startCh
			val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/stampede-cold")
			results[idx] = val
			errors[idx] = err
		}()
	}

	close(startCh)
	wg.Wait()

	for i, err := range errors {
		require.NoError(t, err, "goroutine %d failed", i)
	}
	for i, val := range results {
		assert.Equal(t, "cold-cache-secret-1000", val, "goroutine %d got wrong value", i)
	}

	// Crucial singleflight assertion: exactly 1 upstream call
	assert.Equal(t, 1, driver.BackendCalls(), "singleflight must coalesce 1000 cold requests into exactly 1 backend call")
}

// TestAdversarial_M4_It2_ThunderingHerd_MultiKey_1000Goroutines verifies:
// 10 distinct keys queried on cold cache by 100 goroutines each (1,000 total).
// Upstream driver is queried exactly 10 times (1 per distinct key).
func TestAdversarial_M4_It2_ThunderingHerd_MultiKey_1000Goroutines(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.SetLatency(25 * time.Millisecond)

	const numKeys = 10
	const goroutinesPerKey = 100

	for k := 0; k < numKeys; k++ {
		driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/cold-key-%d", k), map[string]string{
			"token": fmt.Sprintf("val-key-%d", k),
		})
	}

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	totalGoroutines := numKeys * goroutinesPerKey
	type resultItem struct {
		keyIdx int
		val    string
		err    error
	}
	results := make([]resultItem, totalGoroutines)

	var wg sync.WaitGroup
	startCh := make(chan struct{})

	for k := 0; k < numKeys; k++ {
		for g := 0; g < goroutinesPerKey; g++ {
			wg.Add(1)
			index := k*goroutinesPerKey + g
			keyNum := k
			go func() {
				defer wg.Done()
				<-startCh
				ref := fmt.Sprintf("vault.bifrost/keys/cold-key-%d", keyNum)
				val, err := resolver.Resolve(context.Background(), ref)
				results[index] = resultItem{keyIdx: keyNum, val: val, err: err}
			}()
		}
	}

	close(startCh)
	wg.Wait()

	for i, res := range results {
		require.NoError(t, res.err, "goroutine %d failed", i)
		assert.Equal(t, fmt.Sprintf("val-key-%d", res.keyIdx), res.val)
	}

	// Exactly 10 backend calls
	assert.Equal(t, numKeys, driver.BackendCalls(), "must make exactly %d backend calls for %d keys", numKeys, numKeys)
}

// TestAdversarial_M4_It2_ThunderingHerd_RapidFlushCycles verifies:
// 5 consecutive cycles of FlushCache() followed immediately by a stampede of 200 goroutines.
// Total backend calls across the entire test must be exactly 5.
func TestAdversarial_M4_It2_ThunderingHerd_RapidFlushCycles(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.SetLatency(20 * time.Millisecond)
	driver.PutSecret(context.Background(), "bifrost/keys/cycle", map[string]string{
		"token": "cycle-token-constant",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	const numCycles = 5
	const goroutinesPerCycle = 200

	for c := 0; c < numCycles; c++ {
		resolver.FlushCache()

		var wg sync.WaitGroup
		startCh := make(chan struct{})
		results := make([]string, goroutinesPerCycle)

		for i := 0; i < goroutinesPerCycle; i++ {
			wg.Add(1)
			idx := i
			go func() {
				defer wg.Done()
				<-startCh
				val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/cycle")
				if err == nil {
					results[idx] = val
				}
			}()
		}

		close(startCh)
		wg.Wait()

		for _, val := range results {
			assert.Equal(t, "cycle-token-constant", val)
		}
	}

	assert.Equal(t, numCycles, driver.BackendCalls(), "must have made exactly %d calls across %d flush cycles", numCycles, numCycles)
}

// ============================================================================
// CHALLENGE 3: CONCURRENT FLUSH & READ CONTENTION (HIGH INTENSITY)
// ============================================================================

// TestAdversarial_M4_It2_ConcurrentFlushAndReadContention_Extreme verifies:
// 1,000 reader goroutines continuously resolving 10 different keys while 100 flusher/mutator
// goroutines aggressively call FlushCache(), PutSecret(), and DeleteSecret() for 400ms.
// Verifies 0 data races, 0 deadlocks, 0 crashes.
func TestAdversarial_M4_It2_ConcurrentFlushAndReadContention_Extreme(t *testing.T) {
	driver := NewMockVaultDriver()
	for k := 0; k < 10; k++ {
		driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/contend-%d", k), map[string]string{
			"token": fmt.Sprintf("token-initial-%d", k),
		})
	}

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 500 * time.Millisecond,
	}, driver)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	var readSuccesses int64
	var flushesDone int64

	// 1,000 Reader goroutines
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		k := i % 10
		go func(keyIdx int) {
			defer wg.Done()
			ref := fmt.Sprintf("vault.bifrost/keys/contend-%d", keyIdx)
			for {
				select {
				case <-stopCh:
					return
				default:
					val, err := resolver.Resolve(context.Background(), ref)
					if err == nil && len(val) > 0 {
						atomic.AddInt64(&readSuccesses, 1)
					}
					time.Sleep(200 * time.Microsecond)
				}
			}
		}(k)
	}

	// 100 Flusher / Mutator goroutines
	for i := 0; i < 100; i++ {
		wg.Add(1)
		mod := i
		k := i % 10
		go func(m int, keyIdx int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					if m%2 == 0 {
						resolver.FlushCache()
						atomic.AddInt64(&flushesDone, 1)
					} else {
						driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/contend-%d", keyIdx), map[string]string{
							"token": fmt.Sprintf("token-updated-%d-%d", keyIdx, time.Now().UnixNano()),
						})
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}(mod, k)
	}

	// Run under severe contention for 400ms
	time.Sleep(400 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	assert.Greater(t, atomic.LoadInt64(&readSuccesses), int64(2000))
	assert.Greater(t, atomic.LoadInt64(&flushesDone), int64(100))
}

// TestAdversarial_M4_It2_FastHTTP_FlushCache_200ConcurrentRequests verifies:
// 200 concurrent HTTP requests to POST /api/vault/flush-cache concurrently with 500 readers.
func TestAdversarial_M4_It2_FastHTTP_FlushCache_200ConcurrentRequests(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/http_flush", map[string]string{"token": "test"})
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)

	broadcaster := &testBroadcaster{}
	handler := handlers.NewVaultHandler(resolver, broadcaster)

	r := router.New()
	handler.RegisterRoutes(r)

	const numHTTP = 200
	const numReaders = 500
	var wg sync.WaitGroup

	stopReaders := make(chan struct{})

	// Background readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_, _ = resolver.Resolve(context.Background(), "vault.bifrost/keys/http_flush")
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	var httpSuccessCount int64

	// 200 concurrent HTTP flush requests
	for i := 0; i < numHTTP; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var ctx fasthttp.RequestCtx
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/api/vault/flush-cache")
			r.Handler(&ctx)

			if ctx.Response.StatusCode() == fasthttp.StatusOK {
				body := ctx.Response.Body()
				if bytes.Contains(body, []byte("vault cache flushed")) {
					atomic.AddInt64(&httpSuccessCount, 1)
				}
			}
		}()
	}

	// Let flushes execute
	time.Sleep(100 * time.Millisecond)
	close(stopReaders)
	wg.Wait()

	assert.Equal(t, int64(numHTTP), atomic.LoadInt64(&httpSuccessCount), "all 200 flush requests must return 200 OK")
	assert.Equal(t, numHTTP, broadcaster.GetCount(), "broadcaster must be called 200 times")
}

// ============================================================================
// CHALLENGE 4: SECRETVAR PREFIX HANDLING & RESOLUTION MATRIX
// ============================================================================

// TestAdversarial_M4_It2_SecretVar_PrefixVariations_CanonicalAndURI verifies:
// Full matrix of "vault." and "vault://" prefixes with and without sub-key fragments.
func TestAdversarial_M4_It2_SecretVar_PrefixVariations_CanonicalAndURI(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/matrix_test", map[string]string{
		"token":     "matrix-token-val",
		"value":     "matrix-value-val",
		"api_key":   "matrix-api-key-val",
		"sub_field": "matrix-custom-sub-field",
	})
	driver.PutSecret(context.Background(), "deeply/nested/path/to/my/secret", map[string]string{
		"token": "deeply-nested-val",
	})

	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)
	resolver.WireHooks()
	defer resolver.UnwireHooks()

	matrixCases := []struct {
		name          string
		rawRef        string
		expectedPath  string
		expectedField string
		expectedVal   string
	}{
		{
			name:          "canonical dot without field",
			rawRef:        "vault.bifrost/keys/matrix_test",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "",
			expectedVal:   "matrix-token-val", // token has precedence
		},
		{
			name:          "URI scheme without field",
			rawRef:        "vault://bifrost/keys/matrix_test",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "",
			expectedVal:   "matrix-token-val",
		},
		{
			name:          "canonical dot with custom sub-field",
			rawRef:        "vault.bifrost/keys/matrix_test#sub_field",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "sub_field",
			expectedVal:   "matrix-custom-sub-field",
		},
		{
			name:          "URI scheme with custom sub-field",
			rawRef:        "vault://bifrost/keys/matrix_test#sub_field",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "sub_field",
			expectedVal:   "matrix-custom-sub-field",
		},
		{
			name:          "canonical dot with token field",
			rawRef:        "vault.bifrost/keys/matrix_test#token",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "token",
			expectedVal:   "matrix-token-val",
		},
		{
			name:          "URI scheme with token field",
			rawRef:        "vault://bifrost/keys/matrix_test#token",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "token",
			expectedVal:   "matrix-token-val",
		},
		{
			name:          "canonical dot with value field",
			rawRef:        "vault.bifrost/keys/matrix_test#value",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "value",
			expectedVal:   "matrix-value-val",
		},
		{
			name:          "URI scheme with value field",
			rawRef:        "vault://bifrost/keys/matrix_test#value",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "value",
			expectedVal:   "matrix-value-val",
		},
		{
			name:          "canonical dot with api_key field",
			rawRef:        "vault.bifrost/keys/matrix_test#api_key",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "api_key",
			expectedVal:   "matrix-api-key-val",
		},
		{
			name:          "URI scheme with api_key field",
			rawRef:        "vault://bifrost/keys/matrix_test#api_key",
			expectedPath:  "bifrost/keys/matrix_test",
			expectedField: "api_key",
			expectedVal:   "matrix-api-key-val",
		},
		{
			name:          "deeply nested path with canonical dot",
			rawRef:        "vault.deeply/nested/path/to/my/secret",
			expectedPath:  "deeply/nested/path/to/my/secret",
			expectedField: "",
			expectedVal:   "deeply-nested-val",
		},
		{
			name:          "deeply nested path with URI scheme",
			rawRef:        "vault://deeply/nested/path/to/my/secret",
			expectedPath:  "deeply/nested/path/to/my/secret",
			expectedField: "",
			expectedVal:   "deeply-nested-val",
		},
	}

	for _, tc := range matrixCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Test ParseReference
			p, f, isV := ParseReference(tc.rawRef)
			assert.True(t, isV, "isVault should be true")
			assert.Equal(t, tc.expectedPath, p, "path mismatch")
			assert.Equal(t, tc.expectedField, f, "field mismatch")

			// 2. Test Resolver.Resolve
			resolved, err := resolver.Resolve(context.Background(), tc.rawRef)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedVal, resolved)

			// 3. Test schemas.LookupVault
			lookedUp, ok := schemas.LookupVault(tc.rawRef)
			assert.True(t, ok, "LookupVault should return ok=true")
			assert.Equal(t, tc.expectedVal, lookedUp)

			// 4. Test NewSecretVar
			sVar := schemas.NewSecretVar(tc.rawRef)
			assert.True(t, sVar.IsFromVault())
			assert.True(t, sVar.IsFromSecret())
			assert.Equal(t, tc.expectedVal, sVar.GetValue())
			assert.Equal(t, tc.expectedPath, strings.Split(sVar.VaultPath(), "#")[0])
			assert.Equal(t, tc.expectedPath, strings.Split(sVar.GetRef(), "#")[0])
		})
	}
}

// TestAdversarial_M4_It2_SecretVar_JSONSerialization_BothSchemes verifies:
// JSON marshal/unmarshal, database driver Scan/Value, and Redaction methods
// behave consistently across both "vault." and "vault://" schemes.
func TestAdversarial_M4_It2_SecretVar_JSONSerialization_BothSchemes(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/serialize", map[string]string{
		"token": "secret-serialize-token",
	})
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)
	resolver.WireHooks()
	defer resolver.UnwireHooks()

	schemes := []string{
		"vault.bifrost/keys/serialize",
		"vault://bifrost/keys/serialize",
		"vault.bifrost/keys/serialize#token",
		"vault://bifrost/keys/serialize#token",
	}

	for _, ref := range schemes {
		t.Run(ref, func(t *testing.T) {
			sVar := schemas.NewSecretVar(ref)
			assert.True(t, sVar.IsFromVault())
			assert.Equal(t, "secret-serialize-token", sVar.GetValue())

			// 1. JSON Round-trip
			data, err := json.Marshal(sVar)
			require.NoError(t, err)

			var unmarshaled schemas.SecretVar
			err = json.Unmarshal(data, &unmarshaled)
			require.NoError(t, err)
			assert.True(t, unmarshaled.IsFromVault())
			assert.Equal(t, "secret-serialize-token", unmarshaled.GetValue())

			// 2. SQL driver Value & Scan
			dbVal, err := sVar.Value()
			require.NoError(t, err)
			assert.Equal(t, ref, dbVal)

			var scanned schemas.SecretVar
			err = scanned.Scan(dbVal)
			require.NoError(t, err)
			assert.True(t, scanned.IsFromVault())
			assert.Equal(t, "secret-serialize-token", scanned.GetValue())

			// 3. Redaction
			redacted := sVar.Redacted()
			assert.True(t, redacted.IsRedacted())
			assert.Equal(t, "secret-serialize-token", sVar.GetValue(), "original must not be mutated")

			fullyRedacted := sVar.FullyRedacted()
			assert.Equal(t, "<REDACTED>", fullyRedacted.GetValue())

			redactedIfSecret := sVar.RedactedIfSecret()
			assert.True(t, redactedIfSecret.IsRedacted())
		})
	}
}

// TestAdversarial_M4_It2_ProviderKeyBindings_MixedSchemes_Concurrency verifies:
// Concurrently binding keys using BindKeys with mixed "vault." and "vault://" schemes
// across 100 goroutines.
func TestAdversarial_M4_It2_ProviderKeyBindings_MixedSchemes_Concurrency(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/openai", map[string]string{"token": "sk-openai-key"})
	driver.PutSecret(context.Background(), "bifrost/keys/azure_sec", map[string]string{"token": "azure-secret-val"})
	driver.PutSecret(context.Background(), "bifrost/keys/azure_ep", map[string]string{"token": "https://azure.endpoint"})
	driver.PutSecret(context.Background(), "bifrost/keys/bedrock_sec", map[string]string{"token": "bedrock-sec-val"})
	driver.PutSecret(context.Background(), "bifrost/keys/bedrock_acc", map[string]string{"token": "bedrock-acc-val"})

	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)

	const numGoroutines = 100
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys := []schemas.Key{
				{
					ID:    "key-openai",
					Value: *schemas.NewSecretVar("vault://bifrost/keys/openai"),
				},
				{
					ID:    "key-azure",
					Value: *schemas.NewSecretVar("vault.bifrost/keys/openai"),
					AzureKeyConfig: &schemas.AzureKeyConfig{
						ClientSecret: schemas.NewSecretVar("vault://bifrost/keys/azure_sec"),
						Endpoint:     *schemas.NewSecretVar("vault.bifrost/keys/azure_ep"),
					},
				},
				{
					ID:    "key-bedrock",
					Value: *schemas.NewSecretVar("plain-val"),
					BedrockKeyConfig: &schemas.BedrockKeyConfig{
						SecretKey: *schemas.NewSecretVar("vault.bifrost/keys/bedrock_sec"),
						AccessKey: *schemas.NewSecretVar("vault://bifrost/keys/bedrock_acc"),
					},
				},
			}

			bound, err := BindKeys(context.Background(), resolver, keys)
			if err != nil {
				t.Errorf("BindKeys error: %v", err)
				return
			}

			if bound[0].Value.Val != "sk-openai-key" {
				t.Errorf("openai key mismatch: %s", bound[0].Value.Val)
			}
			if bound[1].AzureKeyConfig.ClientSecret.Val != "azure-secret-val" {
				t.Errorf("azure client secret mismatch: %s", bound[1].AzureKeyConfig.ClientSecret.Val)
			}
			if bound[1].AzureKeyConfig.Endpoint.Val != "https://azure.endpoint" {
				t.Errorf("azure endpoint mismatch: %s", bound[1].AzureKeyConfig.Endpoint.Val)
			}
			if bound[2].BedrockKeyConfig.SecretKey.Val != "bedrock-sec-val" {
				t.Errorf("bedrock secret key mismatch: %s", bound[2].BedrockKeyConfig.SecretKey.Val)
			}
			if bound[2].BedrockKeyConfig.AccessKey.Val != "bedrock-acc-val" {
				t.Errorf("bedrock access key mismatch: %s", bound[2].BedrockKeyConfig.AccessKey.Val)
			}
		}()
	}

	wg.Wait()
}

// TestAdversarial_M4_It2_Binding_SubKeyErrorPropagation_BothSchemes verifies:
// Missing subkey fragments or nonexistent secrets return appropriate wrapped errors
// for both "vault." and "vault://" schemes during BindKey.
func TestAdversarial_M4_It2_Binding_SubKeyErrorPropagation_BothSchemes(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/existing", map[string]string{
		"token": "valid-token",
	})
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)

	// Case 1: Dot notation with missing fragment
	k1 := &schemas.Key{
		ID: "k1",
		AzureKeyConfig: &schemas.AzureKeyConfig{
			ClientSecret: schemas.NewSecretVar("vault.bifrost/keys/existing#nonexistent"),
		},
	}
	err1 := BindKey(context.Background(), resolver, k1)
	require.Error(t, err1)
	assert.ErrorIs(t, err1, ErrFieldNotFound)

	// Case 2: URI notation with missing fragment
	k2 := &schemas.Key{
		ID: "k2",
		AzureKeyConfig: &schemas.AzureKeyConfig{
			ClientSecret: schemas.NewSecretVar("vault://bifrost/keys/existing#nonexistent"),
		},
	}
	err2 := BindKey(context.Background(), resolver, k2)
	require.Error(t, err2)
	assert.ErrorIs(t, err2, ErrFieldNotFound)

	// Case 3: Dot notation with nonexistent secret
	k3 := &schemas.Key{
		ID:    "k3",
		Value: *schemas.NewSecretVar("vault.bifrost/keys/does_not_exist"),
	}
	err3 := BindKey(context.Background(), resolver, k3)
	require.Error(t, err3)
	assert.ErrorIs(t, err3, ErrSecretNotFound)

	// Case 4: URI notation with nonexistent secret
	k4 := &schemas.Key{
		ID:    "k4",
		Value: *schemas.NewSecretVar("vault://bifrost/keys/does_not_exist"),
	}
	err4 := BindKey(context.Background(), resolver, k4)
	require.Error(t, err4)
	assert.ErrorIs(t, err4, ErrSecretNotFound)
}
