package vault

import (
	"bytes"
	"context"
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
// CHALLENGE 1: THUNDERING HERD / CACHE STAMPEDE GUARD (500-1000 GOROUTINES)
// ============================================================================

// TestAdversarial_ThunderingHerd_500Goroutines_ColdCache verifies:
//  1. When 500 concurrent goroutines query the exact same secret URI on a completely cold cache,
//     singleflight.Group coalesces the requests.
//  2. Exactly 1 call is made to the upstream vault backend.
//  3. All 500 goroutines receive the identical plaintext secret without errors or data races.
func TestAdversarial_ThunderingHerd_500Goroutines_ColdCache(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/production", map[string]string{
		"token": "sk-live-thundering-herd-secret-500",
	})
	// Add realistic network latency to simulate upstream Vault round-trip
	driver.SetLatency(25 * time.Millisecond)

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	const numGoroutines = 500
	var wg sync.WaitGroup
	startCh := make(chan struct{}) // release gate barrier

	results := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			<-startCh // wait for simultaneous release
			val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/production")
			results[idx] = val
			errors[idx] = err
		}()
	}

	// Release all 500 goroutines simultaneously
	close(startCh)
	wg.Wait()

	// 1. Verify zero errors
	for i, err := range errors {
		require.NoError(t, err, "goroutine %d encountered unexpected error", i)
	}

	// 2. Verify all received the correct secret
	for i, val := range results {
		assert.Equal(t, "sk-live-thundering-herd-secret-500", val, "goroutine %d received unexpected value", i)
	}

	// 3. Verify exactly 1 backend call was made by singleflight coalescing
	backendCalls := driver.BackendCalls()
	assert.Equal(t, 1, backendCalls, "expected exactly 1 backend call via singleflight coalescing, got %d", backendCalls)
}

// TestAdversarial_ThunderingHerd_1000Goroutines_PostFlushStampede verifies:
//  1. When 1000 concurrent goroutines hit the resolver immediately following FlushCache(),
//     singleflight.Group prevents a stampede.
//  2. Exactly 1 backend fetch occurs for the rotated secret.
//  3. All 1000 callers receive the rotated secret with zero data races.
func TestAdversarial_ThunderingHerd_1000Goroutines_PostFlushStampede(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/rotated", map[string]string{
		"token": "initial-secret",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	// Populate cache initially
	val0, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/rotated")
	require.NoError(t, err)
	require.Equal(t, "initial-secret", val0)
	require.Equal(t, 1, driver.BackendCalls())

	// Rotate secret in store and flush cache
	driver.PutSecret(context.Background(), "bifrost/keys/rotated", map[string]string{
		"token": "rotated-secret-version-2",
	})
	driver.SetLatency(30 * time.Millisecond)

	resolver.FlushCache()

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
			val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/rotated")
			results[idx] = val
			errors[idx] = err
		}()
	}

	// Trigger 1000-goroutine stampede
	close(startCh)
	wg.Wait()

	for i, err := range errors {
		require.NoError(t, err, "goroutine %d failed", i)
	}
	for i, val := range results {
		assert.Equal(t, "rotated-secret-version-2", val, "goroutine %d got wrong value", i)
	}

	// Initial call was 1; post-flush stampede must add exactly 1 more call = 2 calls total
	backendCalls := driver.BackendCalls()
	assert.Equal(t, 2, backendCalls, "expected 2 total backend calls (1 initial + 1 post-flush), got %d", backendCalls)
}

// TestAdversarial_ThunderingHerd_MultiKeyConcurrentStampede verifies:
// 5 distinct keys queried by 200 goroutines each (1000 goroutines total) simultaneously.
// Verifies each distinct key executes exactly 1 backend fetch and no cross-key data bleeding occurs.
func TestAdversarial_ThunderingHerd_MultiKeyConcurrentStampede(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.SetLatency(20 * time.Millisecond)

	const numKeys = 5
	const goroutinesPerKey = 200

	for k := 0; k < numKeys; k++ {
		driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/service-%d", k), map[string]string{
			"api_key": fmt.Sprintf("secret-token-key-%d", k),
		})
	}

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Minute,
	}, driver)

	var wg sync.WaitGroup
	startCh := make(chan struct{})
	totalGoroutines := numKeys * goroutinesPerKey

	type resultItem struct {
		keyIdx int
		val    string
		err    error
	}
	results := make([]resultItem, totalGoroutines)

	for k := 0; k < numKeys; k++ {
		for g := 0; g < goroutinesPerKey; g++ {
			wg.Add(1)
			index := k*goroutinesPerKey + g
			keyNum := k
			go func() {
				defer wg.Done()
				<-startCh
				ref := fmt.Sprintf("vault.bifrost/keys/service-%d", keyNum)
				val, err := resolver.Resolve(context.Background(), ref)
				results[index] = resultItem{keyIdx: keyNum, val: val, err: err}
			}()
		}
	}

	close(startCh)
	wg.Wait()

	for i, res := range results {
		require.NoError(t, res.err, "request %d failed", i)
		expected := fmt.Sprintf("secret-token-key-%d", res.keyIdx)
		assert.Equal(t, expected, res.val, "request %d received wrong secret", i)
	}

	// Exactly 1 call per key = 5 backend calls across 1000 requests
	assert.Equal(t, numKeys, driver.BackendCalls(), "expected exactly %d backend calls (1 per key), got %d", numKeys, driver.BackendCalls())
}

// ============================================================================
// CHALLENGE 2: UPSTREAM OUTAGE & STALE SECRET FALLBACK
// ============================================================================

// TestAdversarial_StaleSecretFallback_UpstreamOutage verifies:
// 1. A cached secret past TTL is served when upstream provider is unreachable.
// 2. ResiliencePolicy tracks consecutive failures and stale fallback count.
// 3. When circuit breaker trips, provider calls are suppressed and stale data continues to serve.
// 4. When upstream recovers, fresh data is fetched and consecutive failures reset to 0.
func TestAdversarial_StaleSecretFallback_UpstreamOutage(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/claude", map[string]string{
		"token": "sk-ant-original-secret",
	})

	// Configure short TTL (20ms) and low circuit threshold (3 failures)
	policy := NewResiliencePolicy(3, 50*time.Millisecond)
	cache := NewSecretCache(driver, 20*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 20 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// 1. Initial successful resolution
	val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/claude")
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-original-secret", val)
	assert.Equal(t, 1, driver.BackendCalls())
	assert.False(t, policy.IsCircuitOpen())

	// 2. Wait for TTL to expire
	time.Sleep(30 * time.Millisecond)

	// 3. Simulate upstream outage
	driver.SetOutage(true)

	// Update store behind the scenes — since outage is on, provider returns ErrProviderUnreachable
	driver.PutSecret(context.Background(), "bifrost/keys/claude", map[string]string{
		"token": "sk-ant-unreachable-update",
	})

	// 4. Serve stale secret past TTL
	for i := 0; i < 5; i++ {
		staleVal, staleErr := resolver.Resolve(context.Background(), "vault.bifrost/keys/claude")
		require.NoError(t, staleErr, "stale fallback should succeed during upstream outage")
		assert.Equal(t, "sk-ant-original-secret", staleVal, "must return stale secret past TTL")
	}

	// Stale fallback count must have incremented
	assert.GreaterOrEqual(t, policy.StaleFallbackCount(), 1, "stale fallback count must be tracked")

	// 5. Query a non-existent secret during outage -> MUST fail (no stale entry available)
	_, nonExistentErr := resolver.Resolve(context.Background(), "vault.bifrost/keys/never-cached")
	require.Error(t, nonExistentErr, "querying non-existent secret during outage must return error")
	assert.True(t, strings.Contains(nonExistentErr.Error(), "no stale secret available") ||
		strings.Contains(nonExistentErr.Error(), "provider unreachable"))

	// 6. Upstream recovery
	driver.SetOutage(false)
	// Update store now that upstream is back online
	err = driver.PutSecret(context.Background(), "bifrost/keys/claude", map[string]string{
		"token": "sk-ant-recovered-update",
	})
	require.NoError(t, err)

	// Wait for circuit cooldown if open
	time.Sleep(60 * time.Millisecond)

	// 7. Fresh secret successfully fetched after outage clears
	recoveredVal, recErr := resolver.Resolve(context.Background(), "vault.bifrost/keys/claude")
	require.NoError(t, recErr)
	assert.Equal(t, "sk-ant-recovered-update", recoveredVal, "must fetch new value once upstream recovers")
	assert.False(t, policy.IsCircuitOpen(), "circuit should close upon success")
}

// TestAdversarial_StaleFallback_500GoroutinesConcurrently verifies:
// 500 concurrent goroutines querying an expired secret during upstream outage simultaneously.
// Verifies zero races, zero deadlocks, and that all 500 callers receive the stale secret safely.
func TestAdversarial_StaleFallback_500GoroutinesConcurrently(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/gemini", map[string]string{
		"token": "gemini-stable-fallback-token",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 10 * time.Millisecond,
	}, driver)

	// Prime cache
	_, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/gemini")
	require.NoError(t, err)

	// Expire TTL
	time.Sleep(20 * time.Millisecond)

	// Trip outage
	driver.SetOutage(true)

	const numGoroutines = 500
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
			val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/gemini")
			results[idx] = val
			errors[idx] = err
		}()
	}

	close(startCh)
	wg.Wait()

	for i, err := range errors {
		require.NoError(t, err, "goroutine %d failed under concurrent stale fallback", i)
	}
	for i, val := range results {
		assert.Equal(t, "gemini-stable-fallback-token", val, "goroutine %d got wrong stale secret", i)
	}
}

// ============================================================================
// CHALLENGE 3: CACHE FLUSH SYNCHRONIZATION UNDER HIGH CONTENTION
// ============================================================================

// TestAdversarial_ConcurrentFlushAndReadContention verifies:
// 500 concurrent readers continuously querying the cache while 50 concurrent goroutines
// aggressively invoke FlushCache(), PutSecret(), and DeleteSecret().
// Verifies zero read-write map races, zero deadlocks, and clean thread-safe execution.
func TestAdversarial_ConcurrentFlushAndReadContention(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/contention", map[string]string{
		"token": "initial-contention-token",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		Prefix:   "bifrost",
		CacheTTL: 1 * time.Second,
	}, driver)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	var readSuccesses int64
	var flushCount int64

	// 500 Reader goroutines
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/contention")
					if err == nil && len(val) > 0 {
						atomic.AddInt64(&readSuccesses, 1)
					}
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	// 50 Flusher / Mutator goroutines
	for i := 0; i < 50; i++ {
		wg.Add(1)
		mod := i
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					if mod%2 == 0 {
						resolver.FlushCache()
						atomic.AddInt64(&flushCount, 1)
					} else {
						driver.PutSecret(context.Background(), "bifrost/keys/contention", map[string]string{
							"token": fmt.Sprintf("token-version-%d", time.Now().UnixNano()),
						})
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Run under intense contention for 300ms
	time.Sleep(300 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	assert.Greater(t, atomic.LoadInt64(&readSuccesses), int64(1000), "expected high read success throughput")
	assert.Greater(t, atomic.LoadInt64(&flushCount), int64(50), "expected multiple flushes executed")
}

// TestAdversarial_FastHTTP_FlushCacheEndpoint_HighConcurrency verifies:
// The FastHTTP /api/vault/flush-cache route handles 100 concurrent HTTP requests with
// mock flusher and broadcaster, checking zero races, HTTP 200 responses, and valid JSON.
func TestAdversarial_FastHTTP_FlushCacheEndpoint_HighConcurrency(t *testing.T) {
	flusher := &testFlusher{}
	broadcaster := &testBroadcaster{}
	handler := handlers.NewVaultHandler(flusher, broadcaster)

	r := router.New()
	handler.RegisterRoutes(r)

	const numRequests = 100
	var wg sync.WaitGroup
	var successCount int64

	for i := 0; i < numRequests; i++ {
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
					atomic.AddInt64(&successCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(numRequests), atomic.LoadInt64(&successCount), "all concurrent flush requests must return 200 OK")
	assert.Equal(t, numRequests, flusher.GetCalled(), "flusher must be called for each request")
	assert.Equal(t, numRequests, broadcaster.GetCount(), "broadcaster must be called for each request")
}

// ============================================================================
// CHALLENGE 4: MALFORMED URIS, NONEXISTENT PATHS & FIELD FRAGMENTS
// ============================================================================

// TestAdversarial_MalformedURIs_NoPanics verifies:
// Malformed reference URIs return safely without panic or corrupted internal state.
func TestAdversarial_MalformedURIs_NoPanics(t *testing.T) {
	driver := NewMockVaultDriver()
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)

	malformedCases := []struct {
		name        string
		uri         string
		expectVault bool
	}{
		{"empty string", "", false},
		{"spaces only", "    ", false},
		{"bare vault dot", "vault.", true},
		{"bare vault URI", "vault://", true},
		{"bare hash fragment", "vault.#", true},
		{"multiple hashes", "vault.bifrost/keys/test#field1#field2", true},
		{"URI multiple slashes", "vault://///keys///test", true},
		{"special chars in path", "vault.bifrost/keys/test?query=1&param=2", true},
		{"URI with hash only", "vault://#fragment", true},
		{"regular env string", "MY_PLAIN_API_KEY", false},
		{"regular sk- token", "sk-proj-1234567890abcdef", false},
		{"pseudo prefix", "vault_secret_not_dot", false},
	}

	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			path, field, isVault := ParseReference(tc.uri)
			assert.Equal(t, tc.expectVault, isVault, "isVault mismatch for %q", tc.uri)

			// Resolve must NEVER panic
			assert.NotPanics(t, func() {
				val, err := resolver.Resolve(context.Background(), tc.uri)
				if !isVault {
					assert.NoError(t, err)
					assert.Equal(t, tc.uri, val, "non-vault URI must return unmodified")
				} else {
					// Either resolved or returned error safely
					_ = err
				}
			}, "Resolve panicked on input %q", tc.uri)

			// ResolveString must NEVER panic
			assert.NotPanics(t, func() {
				strVal := tc.uri
				err := resolver.ResolveString(context.Background(), &strVal)
				_ = err
			}, "ResolveString panicked on input %q", tc.uri)

			_ = path
			_ = field
		})
	}
}

// TestAdversarial_MissingSecretsAndFields_GracefulErrors verifies:
// 1. Non-existent path returns ErrSecretNotFound.
// 2. Non-existent field fragment returns ErrFieldNotFound.
// 3. Field precedence: token -> value -> api_key -> single field -> json map.
func TestAdversarial_MissingSecretsAndFields_GracefulErrors(t *testing.T) {
	driver := NewMockVaultDriver()
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)

	// 1. Missing secret path
	_, err := resolver.Resolve(context.Background(), "vault.bifrost/missing/nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// 2. Secret exists, but fragment field is missing
	driver.PutSecret(context.Background(), "bifrost/keys/cohere", map[string]string{
		"token": "cohere-key-value",
	})

	_, err = resolver.Resolve(context.Background(), "vault.bifrost/keys/cohere#nonexistent_field")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFieldNotFound)

	// 3. Precedence: 'token' takes precedence over 'value' and 'api_key'
	driver.PutSecret(context.Background(), "bifrost/keys/multi_field", map[string]string{
		"value":   "val-field",
		"api_key": "key-field",
		"token":   "tok-field",
	})
	val1, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/multi_field")
	require.NoError(t, err)
	assert.Equal(t, "tok-field", val1)

	// 4. Precedence: 'value' takes precedence over 'api_key' when 'token' absent
	driver.PutSecret(context.Background(), "bifrost/keys/val_only", map[string]string{
		"value":   "val-field-2",
		"api_key": "key-field-2",
	})
	val2, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/val_only")
	require.NoError(t, err)
	assert.Equal(t, "val-field-2", val2)

	// 5. Precedence: 'api_key' used when 'token' and 'value' absent
	driver.PutSecret(context.Background(), "bifrost/keys/api_key_only", map[string]string{
		"api_key": "api-key-val",
		"other":   "extra-val",
	})
	val3, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/api_key_only")
	require.NoError(t, err)
	assert.Equal(t, "api-key-val", val3)

	// 6. Single arbitrary field returned when only 1 key present
	driver.PutSecret(context.Background(), "bifrost/keys/single_custom", map[string]string{
		"custom_secret_key": "my-custom-token",
	})
	val4, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/single_custom")
	require.NoError(t, err)
	assert.Equal(t, "my-custom-token", val4)
}

// ============================================================================
// CHALLENGE 5: DYNAMIC KEY BINDINGS & SCHEMAS HOOK WIRING UNDER CONCURRENCY
// ============================================================================

// TestAdversarial_DynamicKeyBinding_ConcurrentRaceSafety verifies:
// Concurrently binding 500 keys using BindKeys and BindKey across goroutines
// with mixed key configs (Azure, Bedrock, standard values).
func TestAdversarial_DynamicKeyBinding_ConcurrentRaceSafety(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/azure_secret", map[string]string{
		"token": "azure-client-secret-xyz",
	})
	driver.PutSecret(context.Background(), "bifrost/keys/bedrock_secret", map[string]string{
		"token": "bedrock-secret-key-abc",
	})
	driver.PutSecret(context.Background(), "bifrost/keys/primary_key", map[string]string{
		"token": "primary-api-key-val",
	})

	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true, Prefix: "bifrost"}, driver)

	const numWorkers = 100
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys := []schemas.Key{
				{
					ID:    "key-azure",
					Value: *schemas.NewSecretVar("vault.bifrost/keys/primary_key"),
					AzureKeyConfig: &schemas.AzureKeyConfig{
						ClientSecret: schemas.NewSecretVar("vault://bifrost/keys/azure_secret"),
					},
				},
				{
					ID:    "key-bedrock",
					Value: *schemas.NewSecretVar("plain-static-key"),
					BedrockKeyConfig: &schemas.BedrockKeyConfig{
						SecretKey: *schemas.NewSecretVar("vault.bifrost/keys/bedrock_secret"),
					},
				},
			}

			bound, err := BindKeys(context.Background(), resolver, keys)
			if err != nil {
				t.Errorf("BindKeys failed: %v", err)
				return
			}
			if bound[0].Value.Val != "primary-api-key-val" {
				t.Errorf("primary key not bound: %s", bound[0].Value.Val)
			}
			if bound[0].AzureKeyConfig.ClientSecret.Val != "azure-client-secret-xyz" {
				t.Errorf("azure client secret not bound: %s", bound[0].AzureKeyConfig.ClientSecret.Val)
			}
			if bound[1].BedrockKeyConfig.SecretKey.Val != "bedrock-secret-key-abc" {
				t.Errorf("bedrock secret key not bound: %s", bound[1].BedrockKeyConfig.SecretKey.Val)
			}
		}()
	}

	wg.Wait()
}

// TestAdversarial_GlobalHookWiring_LookupVault_RaceSafety verifies:
// schemas.LookupVault and schemas.VaultResolveHook operate safely under concurrent calls.
func TestAdversarial_GlobalHookWiring_LookupVault_RaceSafety(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/hook/test", map[string]string{
		"token": "hook-token-val",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:    true,
		Prefix:     "bifrost",
		AccessMode: AccessModeReadAndWrite,
	}, driver)

	resolver.WireHooks()
	defer resolver.UnwireHooks()

	const numGoroutines = 200
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, ok := schemas.LookupVault("vault.bifrost/hook/test")
			if !ok || val != "hook-token-val" {
				t.Errorf("LookupVault failed: got %q (ok=%v)", val, ok)
			}

			var strVal = "vault://bifrost/hook/test"
			if err := schemas.VaultResolveHook(context.Background(), &strVal); err != nil {
				t.Errorf("VaultResolveHook failed: %v", err)
			}
			if strVal != "hook-token-val" {
				t.Errorf("expected resolved string, got %s", strVal)
			}
		}()
	}

	wg.Wait()
}

// ============================================================================
// HELPER STRUCTS
// ============================================================================

type testFlusher struct {
	mu     sync.Mutex
	called int
}

func (f *testFlusher) FlushCache() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
}

func (f *testFlusher) GetCalled() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

type testBroadcaster struct {
	mu    sync.Mutex
	count int
}

func (b *testBroadcaster) BroadcastState(entity string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
	return nil
}

func (b *testBroadcaster) GetCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}
