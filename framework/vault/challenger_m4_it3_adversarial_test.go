package vault

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CHALLENGE 1: REPEATED FLAPPING UNDER CONTINUOUS TRAFFIC (10 CYCLES)
// ============================================================================

// TestAdversarial_M4_It3_CircuitBreaker_RepeatedFlapping_10Cycles stress-tests
// 10 consecutive cycles of upstream outage and recovery under continuous traffic.
// In each cycle:
// - Upstream is healthy and serving token-k
// - Upstream fails; cache expires; continuous traffic trips circuit breaker
// - While circuit is open, continuous traffic receives stale token-k without error
// - Upstream recovers with token-(k+1)
// - Cooldown elapses; continuous traffic probes upstream and updates cache to token-(k+1)
// - Circuit closes and all continuous traffic receives token-(k+1)
func TestAdversarial_M4_It3_CircuitBreaker_RepeatedFlapping_10Cycles(t *testing.T) {
	driver := NewMockVaultDriver()
	secretPath := "bifrost/keys/flapping_key"
	ref := "vault." + secretPath

	err := driver.PutSecret(context.Background(), secretPath, map[string]string{
		"token": "token-cycle-0",
	})
	require.NoError(t, err)

	// Threshold: 2 failures, Cooldown: 35ms, TTL: 10ms
	policy := NewResiliencePolicy(2, 35*time.Millisecond)
	cache := NewSecretCache(driver, 10*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 10 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// Prime initial secret
	val0, err := resolver.Resolve(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, "token-cycle-0", val0)

	stopTraffic := make(chan struct{})
	var wg sync.WaitGroup
	var totalReads int64
	var totalErrors int64

	const numWorkers = 15
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopTraffic:
					return
				default:
					val, rErr := resolver.Resolve(context.Background(), ref)
					if rErr != nil {
						atomic.AddInt64(&totalErrors, 1)
					} else if len(val) > 0 {
						atomic.AddInt64(&totalReads, 1)
					}
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}

	// Run 10 flapping cycles
	const numCycles = 10
	for cycle := 1; cycle <= numCycles; cycle++ {
		// 1. Expire TTL
		time.Sleep(15 * time.Millisecond)

		// 2. Upstream outage begins
		driver.SetOutage(true)

		// 3. Allow traffic to trip the circuit (needs >= 2 failures, each worker sleeps 2ms)
		time.Sleep(20 * time.Millisecond)
		require.True(t, policy.IsCircuitOpen(), "cycle %d: circuit breaker must be open during outage", cycle)

		// 4. Restore upstream and update upstream secret
		driver.SetOutage(false)
		expectedToken := fmt.Sprintf("token-cycle-%d", cycle)
		pErr := driver.PutSecret(context.Background(), secretPath, map[string]string{
			"token": expectedToken,
		})
		require.NoError(t, pErr)

		// 5. Wait for cooldown (35ms) to elapse under continuous traffic
		time.Sleep(45 * time.Millisecond)

		// 6. Verify circuit recovered under continuous traffic
		assert.False(t, policy.IsCircuitOpen(), "cycle %d: circuit breaker must recover once cooldown passes", cycle)

		// 7. Verify resolved value is the recovered token
		recoveredVal, recErr := resolver.Resolve(context.Background(), ref)
		require.NoError(t, recErr, "cycle %d: resolution should succeed post-recovery", cycle)
		assert.Equal(t, expectedToken, recoveredVal, "cycle %d: should receive updated token after recovery", cycle)
	}

	close(stopTraffic)
	wg.Wait()

	assert.Equal(t, int64(0), atomic.LoadInt64(&totalErrors), "zero errors expected during entire 10-cycle flapping test (stale fallback protects reads)")
	assert.Greater(t, atomic.LoadInt64(&totalReads), int64(300), "must have executed hundreds of reads during test")
}

// ============================================================================
// CHALLENGE 2: RAPID FLAPPING UNDER 50 HIGH-INTENSITY CONCURRENT WORKERS
// ============================================================================

// TestAdversarial_M4_It3_CircuitBreaker_RapidFlapping_50Workers verifies:
// 50 concurrent goroutines querying the cache while upstream flaps between online and offline
// rapidly every 25ms across 6 flapping transitions.
// Verifies 0 data races, 0 deadlocks, clean state transitions, and final convergence.
func TestAdversarial_M4_It3_CircuitBreaker_RapidFlapping_50Workers(t *testing.T) {
	driver := NewMockVaultDriver()
	secretPath := "bifrost/keys/rapid_flap"
	ref := "vault." + secretPath

	err := driver.PutSecret(context.Background(), secretPath, map[string]string{
		"token": "rapid-token-0",
	})
	require.NoError(t, err)

	policy := NewResiliencePolicy(2, 30*time.Millisecond)
	cache := NewSecretCache(driver, 10*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 10 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// Prime initial secret
	_, err = resolver.Resolve(context.Background(), ref)
	require.NoError(t, err)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	const numWorkers = 50

	var successReads int64
	var errorReads int64

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					val, rErr := resolver.Resolve(context.Background(), ref)
					if rErr != nil {
						atomic.AddInt64(&errorReads, 1)
					} else if len(val) > 0 {
						atomic.AddInt64(&successReads, 1)
					}
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	// Flap upstream 6 times
	for flap := 1; flap <= 6; flap++ {
		// Outage phase
		driver.SetOutage(true)
		time.Sleep(25 * time.Millisecond)

		// Recovery phase with new secret version
		driver.SetOutage(false)
		newToken := fmt.Sprintf("rapid-token-%d", flap)
		pErr := driver.PutSecret(context.Background(), secretPath, map[string]string{
			"token": newToken,
		})
		require.NoError(t, pErr)
		time.Sleep(40 * time.Millisecond) // wait for cooldown to pass and recovery to occur
	}

	close(stopCh)
	wg.Wait()

	assert.Equal(t, int64(0), atomic.LoadInt64(&errorReads), "all reads must succeed via stale fallback or fresh cache")
	assert.Greater(t, atomic.LoadInt64(&successReads), int64(1000))
	assert.False(t, policy.IsCircuitOpen(), "circuit breaker must be closed after final recovery")

	finalVal, finalErr := resolver.Resolve(context.Background(), ref)
	require.NoError(t, finalErr)
	assert.Equal(t, "rapid-token-6", finalVal, "final resolved value must be the latest token")
}

// ============================================================================
// CHALLENGE 3: COOLDOWN RE-ARMING ON FAILED PROBE (MULTIPLE OUTAGES)
// ============================================================================

// TestAdversarial_M4_It3_CircuitBreaker_CooldownReArmingOnFailedProbe verifies:
// 1. Upstream fails $\ge$ threshold $\to$ circuit opens.
// 2. Cooldown passes, but upstream is STILL failing.
// 3. First request sends a probe to upstream $\to$ probe fails.
// 4. Circuit breaker records failure, updates lastFailureTime, and re-arms cooldown.
// 5. During second cooldown, subsequent traffic is short-circuited without hitting provider.
// 6. After second cooldown, upstream is restored.
// 7. Probe succeeds, circuit closes, fresh secret is served.
func TestAdversarial_M4_It3_CircuitBreaker_CooldownReArmingOnFailedProbe(t *testing.T) {
	driver := NewMockVaultDriver()
	secretPath := "bifrost/keys/rearm_test"
	ref := "vault." + secretPath

	err := driver.PutSecret(context.Background(), secretPath, map[string]string{
		"token": "token-original",
	})
	require.NoError(t, err)

	policy := NewResiliencePolicy(2, 40*time.Millisecond)
	cache := NewSecretCache(driver, 10*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 10 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// 1. Prime cache
	_, err = resolver.Resolve(context.Background(), ref)
	require.NoError(t, err)

	// Expire TTL and trigger outage
	time.Sleep(15 * time.Millisecond)
	driver.SetOutage(true)

	// Trip circuit: 2 calls fail
	_, _ = resolver.Resolve(context.Background(), ref)
	_, _ = resolver.Resolve(context.Background(), ref)
	require.True(t, policy.IsCircuitOpen())

	callsAtTrip := driver.BackendCalls()

	// 2. Continuous traffic during first cooldown (30ms < 40ms cooldown)
	for i := 0; i < 6; i++ {
		time.Sleep(5 * time.Millisecond)
		val, _ := resolver.Resolve(context.Background(), ref)
		assert.Equal(t, "token-original", val)
	}
	// Verify no new backend calls occurred while circuit was open
	assert.Equal(t, callsAtTrip, driver.BackendCalls(), "no backend calls while circuit is open")

	// 3. Cooldown elapses (wait another 15ms, total > 40ms)
	time.Sleep(15 * time.Millisecond)

	// Upstream is STILL down! Next request will probe upstream and fail.
	valProbe, errProbe := resolver.Resolve(context.Background(), ref)
	require.NoError(t, errProbe) // stale fallback serves original token
	assert.Equal(t, "token-original", valProbe)

	// Upstream should have received exactly 1 probe call
	callsAfterProbe1 := driver.BackendCalls()
	assert.Equal(t, callsAtTrip+1, callsAfterProbe1, "exactly 1 probe call sent to failing upstream")

	// Verify circuit re-armed: IsCircuitOpen() is true again!
	assert.True(t, policy.IsCircuitOpen(), "circuit must re-arm after failed probe")

	// 4. Continuous traffic during second cooldown (30ms < 40ms cooldown)
	for i := 0; i < 6; i++ {
		time.Sleep(5 * time.Millisecond)
		val, _ := resolver.Resolve(context.Background(), ref)
		assert.Equal(t, "token-original", val)
	}
	// No new calls during second cooldown
	assert.Equal(t, callsAfterProbe1, driver.BackendCalls(), "no backend calls during second cooldown")

	// 5. Upstream finally recovers!
	driver.SetOutage(false)
	pErr := driver.PutSecret(context.Background(), secretPath, map[string]string{
		"token": "token-eventual-recovery",
	})
	require.NoError(t, pErr)

	// Wait for second cooldown (total > 40ms since probe failure)
	time.Sleep(20 * time.Millisecond)

	// 6. Next request probes upstream, succeeds, and closes circuit!
	valFinal, errFinal := resolver.Resolve(context.Background(), ref)
	require.NoError(t, errFinal)
	assert.Equal(t, "token-eventual-recovery", valFinal)
	assert.False(t, policy.IsCircuitOpen(), "circuit must be closed after successful recovery")
	assert.Equal(t, callsAfterProbe1+1, driver.BackendCalls(), "exactly 1 recovery probe call")
}

// ============================================================================
// CHALLENGE 4: MULTI-KEY FLAPPING UNDER CONTINUOUS LOAD
// ============================================================================

// TestAdversarial_M4_It3_CircuitBreaker_MultiKeyFlapping verifies:
// 5 distinct keys queried concurrently during repeated upstream outages and recoveries.
// Verifies all keys properly serve stale secrets during outage and recover fresh secrets
// without cross-key data leakage or race conditions.
func TestAdversarial_M4_It3_CircuitBreaker_MultiKeyFlapping(t *testing.T) {
	driver := NewMockVaultDriver()
	const numKeys = 5

	for k := 0; k < numKeys; k++ {
		err := driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/multi_flap_%d", k), map[string]string{
			"token": fmt.Sprintf("initial-val-%d", k),
		})
		require.NoError(t, err)
	}

	policy := NewResiliencePolicy(2, 35*time.Millisecond)
	cache := NewSecretCache(driver, 10*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 10 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// Prime all keys
	for k := 0; k < numKeys; k++ {
		ref := fmt.Sprintf("vault.bifrost/keys/multi_flap_%d", k)
		val, err := resolver.Resolve(context.Background(), ref)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("initial-val-%d", k), val)
	}

	// Run 3 flapping cycles across all 5 keys
	for cycle := 1; cycle <= 3; cycle++ {
		time.Sleep(15 * time.Millisecond) // expire TTL
		driver.SetOutage(true)

		// Concurrent reads during outage
		var wg sync.WaitGroup
		const callersPerKey = 20
		for k := 0; k < numKeys; k++ {
			keyIdx := k
			ref := fmt.Sprintf("vault.bifrost/keys/multi_flap_%d", keyIdx)
			for c := 0; c < callersPerKey; c++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					val, err := resolver.Resolve(context.Background(), ref)
					assert.NoError(t, err)
					assert.NotEmpty(t, val)
				}()
			}
		}
		wg.Wait()

		require.True(t, policy.IsCircuitOpen(), "circuit should open during multi-key outage")

		// Upstream recovers with updated tokens
		driver.SetOutage(false)
		for k := 0; k < numKeys; k++ {
			pErr := driver.PutSecret(context.Background(), fmt.Sprintf("bifrost/keys/multi_flap_%d", k), map[string]string{
				"token": fmt.Sprintf("recovered-val-%d-cycle-%d", k, cycle),
			})
			require.NoError(t, pErr)
		}

		// Wait for cooldown
		time.Sleep(45 * time.Millisecond)

		// Verify recovery on all keys
		for k := 0; k < numKeys; k++ {
			ref := fmt.Sprintf("vault.bifrost/keys/multi_flap_%d", k)
			val, err := resolver.Resolve(context.Background(), ref)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("recovered-val-%d-cycle-%d", k, cycle), val)
		}
		assert.False(t, policy.IsCircuitOpen(), "circuit must close after all keys recover")
	}
}

// ============================================================================
// CHALLENGE 5: UNCACHED KEY OUTAGE AND RECOVERY
// ============================================================================

// TestAdversarial_M4_It3_CircuitBreaker_UncachedKeyFlapping verifies:
// When an uncached key fails repeatedly during an outage:
// 1. Callers receive errors (since no stale secret exists).
// 2. Circuit breaker trips.
// 3. Upstream recovers and populates the key.
// 4. Cooldown passes.
// 5. Subsequent caller successfully fetches the secret and closes the circuit.
func TestAdversarial_M4_It3_CircuitBreaker_UncachedKeyFlapping(t *testing.T) {
	driver := NewMockVaultDriver()
	secretPath := "bifrost/keys/never_cached"
	ref := "vault." + secretPath

	policy := NewResiliencePolicy(2, 35*time.Millisecond)
	cache := NewSecretCache(driver, 10*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 10 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	// Trigger outage before key is ever cached
	driver.SetOutage(true)

	// 2 calls fail $\to$ trip circuit
	_, err1 := resolver.Resolve(context.Background(), ref)
	require.Error(t, err1)
	_, err2 := resolver.Resolve(context.Background(), ref)
	require.Error(t, err2)
	require.True(t, policy.IsCircuitOpen())

	// Calls while circuit open also return error (no stale data)
	for i := 0; i < 5; i++ {
		time.Sleep(3 * time.Millisecond)
		_, cErr := resolver.Resolve(context.Background(), ref)
		require.Error(t, cErr)
	}

	// Upstream comes online and secret is created
	driver.SetOutage(false)
	pErr := driver.PutSecret(context.Background(), secretPath, map[string]string{
		"token": "brand-new-secret",
	})
	require.NoError(t, pErr)

	// Wait for cooldown
	time.Sleep(45 * time.Millisecond)

	// Caller probes upstream and recovers
	val, err := resolver.Resolve(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "brand-new-secret", val)
	assert.False(t, policy.IsCircuitOpen(), "circuit should close on successful fetch")
}

// ============================================================================
// CHALLENGE 6: GOROUTINE LEAK CHECK ACROSS 15 REPEATED FLAPPING CYCLES
// ============================================================================

// TestAdversarial_M4_It3_CircuitBreaker_NoGoroutineLeak verifies:
// Running 15 rapid flapping cycles with concurrent goroutines does not leak any goroutines.
func TestAdversarial_M4_It3_CircuitBreaker_NoGoroutineLeak(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	driver := NewMockVaultDriver()
	secretPath := "bifrost/keys/leak_check"
	ref := "vault." + secretPath

	err := driver.PutSecret(context.Background(), secretPath, map[string]string{
		"token": "leak-test-token-0",
	})
	require.NoError(t, err)

	policy := NewResiliencePolicy(2, 20*time.Millisecond)
	cache := NewSecretCache(driver, 5*time.Millisecond, policy)
	resolver := &VaultResolver{
		config:   VaultStoreConfig{Enabled: true, Prefix: "bifrost", CacheTTL: 5 * time.Millisecond},
		provider: driver,
		cache:    cache,
	}

	_, _ = resolver.Resolve(context.Background(), ref)

	for cycle := 1; cycle <= 15; cycle++ {
		time.Sleep(10 * time.Millisecond)
		driver.SetOutage(true)

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = resolver.Resolve(context.Background(), ref)
			}()
		}
		wg.Wait()

		driver.SetOutage(false)
		pErr := driver.PutSecret(context.Background(), secretPath, map[string]string{
			"token": fmt.Sprintf("leak-test-token-%d", cycle),
		})
		require.NoError(t, pErr)

		time.Sleep(30 * time.Millisecond)
		_, _ = resolver.Resolve(context.Background(), ref)
	}

	cache.Close()

	// Wait and GC to let transient goroutines terminate
	time.Sleep(50 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	// Allow a small margin (up to 4 goroutines) for background testing or runtime pools
	diff := finalGoroutines - initialGoroutines
	assert.LessOrEqual(t, diff, 4, "goroutine count should return to baseline (initial=%d, final=%d)", initialGoroutines, finalGoroutines)
}
