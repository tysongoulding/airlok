package governance

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ADVERSARIAL CHALLENGE: MILESTONE 5 (TOKEN EXCHANGE & VIRTUAL MCP CONCURRENCY)
// ============================================================================

// 1. DEADLOCK REPRODUCTION: Recursive RLock in AuthorizeTool
// AuthorizeTool acquires r.mu.RLock() and then internally calls CheckToolAccess,
// which also acquires r.mu.RLock(). In Go's sync.RWMutex, if a writer calls Lock()
// (e.g., SetUserPermissions or RegisterVirtualMCP) between these two calls,
// the inner RLock() will block waiting for the writer, while the writer waits
// for the outer RLock() to release. This causes an immediate, permanent DEADLOCK.
func TestAdversarial_AuthorizeTool_RecursiveRLockDeadlock(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)
	registry.RegisterVirtualMCP("prod-suite", "tenant-123", []string{"tool-alpha", "tool-beta"})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	doneCh := make(chan struct{})

	go func() {
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					default:
						if id%2 == 0 {
							// Writer: acquires r.mu.Lock()
							_ = registry.SetUserPermissions("prod-suite", fmt.Sprintf("user-%d", id), []string{"tool-alpha"})
						} else {
							// Reader: acquires r.mu.RLock(), and inside calls CheckToolAccess which acquires r.mu.RLock()
							_, _ = registry.AuthorizeTool(ctx, fmt.Sprintf("user-%d", id), "tenant-123", "tool-alpha")
						}
					}
				}
			}(i)
		}
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		t.Log("No deadlock observed")
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK DETECTED: AuthorizeTool causes recursive RLock deadlock under concurrent SetUserPermissions writers!")
	}
}

// 2. THUNDERING HERD DEDUPLICATION: 1000 Concurrent Goroutines on Same Key
// Verifies single-flight deduplication: upstream token minting MUST execute only once
// for 1000 concurrent callers arriving at the exact same instant on an empty cache.
func TestAdversarial_TokenExchanger_ThunderingHerd_1000Goroutines(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	const numGoroutines = 1000
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	tokens := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	subjectToken := "thundering-herd-token"
	audience := "https://api.github.com"

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-startGate // Synchronized thundering herd release
			tok, err := exchanger.ExchangeToken(ctx, subjectToken, audience)
			tokens[idx] = tok
			errors[idx] = err
		}(i)
	}

	close(startGate)
	wg.Wait()

	// Verify all returned without error
	firstToken := tokens[0]
	require.NotEmpty(t, firstToken)

	for i := 0; i < numGoroutines; i++ {
		require.NoError(t, errors[i], "goroutine %d failed", i)
		assert.Equal(t, firstToken, tokens[i], "goroutine %d got divergent token", i)
	}

	// Verify upstream mint counter: did performExchange run only once?
	mintCount := exchanger.tokenCounter.Load()
	t.Logf("Thundering herd: 1000 goroutines completed. Upstream mint count = %d", mintCount)
	assert.Equal(t, uint64(1), mintCount, "Upstream exchange MUST execute only once for 1000 concurrent callers on same key")
}

// 3. CACHE INVALIDATION & FLUSH UNDER HIGH CONCURRENCY (1000 Goroutines)
// Subject FederatedTokenExchanger to heavy concurrent reads, invalidations, and cache flushes.
func TestAdversarial_TokenExchanger_ConcurrentInvalidateAndFlush_1000Goroutines(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	const numGoroutines = 1000
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-startGate

			sub := fmt.Sprintf("user-%d", id%10)
			aud := fmt.Sprintf("https://api.svc-%d.com", id%5)

			switch id % 10 {
			case 0:
				// Flush cache
				exchanger.FlushCache()
			case 1:
				// Invalidate specific token
				exchanger.InvalidateToken(sub, aud)
			default:
				// Token exchange
				tok, err := exchanger.ExchangeToken(ctx, sub, aud)
				if err != nil {
					t.Errorf("unexpected error for %s:%s: %v", sub, aud, err)
					return
				}
				if !strings.HasPrefix(tok, "downstream-token-for-") {
					t.Errorf("corrupted token format: %s", tok)
				}
			}
		}(i)
	}

	close(startGate)
	wg.Wait()
}

// 4. VIRTUAL MCP CONCURRENCY: Register, SetPermissions, and CheckToolAccess under 1000 Goroutines
func TestAdversarial_VirtualMCP_ConcurrentMutationsAndQueries_1000Goroutines(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	// Pre-seed some slugs
	registry.RegisterVirtualMCP("core-slug", "tenant-base", []string{"tool-a", "tool-b"})

	const numGoroutines = 1000
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-startGate

			slug := fmt.Sprintf("slug-%d", id%20)
			user := fmt.Sprintf("user-%d", id%50)

			switch id % 5 {
			case 0:
				// Register
				registry.RegisterVirtualMCP(slug, fmt.Sprintf("tenant-%d", id%10), []string{"tool-1", "tool-2", "*"})
			case 1:
				// SetUserPermissions
				_ = registry.SetUserPermissions("core-slug", user, []string{"tool-a", "*"})
			case 2:
				// Check access on allowed connector
				allowed, action, _ := registry.CheckToolAccess("core-slug", user, "google_workspace", "tool-a")
				if allowed {
					assert.Equal(t, PolicyActionAllow, action)
				}
			case 3:
				// Check access on blocked connector: office365 MUST ALWAYS be denied
				allowed, action, _ := registry.CheckToolAccess("core-slug", user, "office365", "tool-a")
				assert.False(t, allowed, "office365 must never be allowed")
				assert.Equal(t, PolicyActionDeny, action)
			case 4:
				// Non-existent slug check
				allowed, action, _ := registry.CheckToolAccess("definitely-nonexistent-slug", user, "google_workspace", "tool-a")
				assert.False(t, allowed)
				assert.Equal(t, PolicyActionDeny, action)
			}
		}(i)
	}

	close(startGate)
	wg.Wait()
}

// 5. WILDCARD PERMISSIONS & STRICT CONNECTOR DENIAL ENFORCEMENT
// Verifies that wildcard '*' permissions at both tenant and user levels NEVER bypass
// a denied connector (office365).
func TestAdversarial_VirtualMCP_DeniedConnector_StrictOverrideOverWildcards(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	// Tenant has wildcard, user has wildcard
	registry.RegisterVirtualMCP("super-root", "tenant-root", []string{"*"})
	err := registry.SetUserPermissions("super-root", "root-admin", []string{"*"})
	require.NoError(t, err)

	// Case 1: google_workspace (allowed by policy) -> allowed with PolicyActionAllow
	allowed, action, reason := registry.CheckToolAccess("super-root", "root-admin", "google_workspace", "danger_nuke_everything")
	assert.True(t, allowed)
	assert.Equal(t, PolicyActionAllow, action)
	assert.Empty(t, reason)

	// Case 2: office365 (denied by policy) -> MUST be strictly DENIED despite double wildcards
	allowedDeny, actionDeny, reasonDeny := registry.CheckToolAccess("super-root", "root-admin", "office365", "danger_nuke_everything")
	assert.False(t, allowedDeny, "office365 must be blocked even when user and tenant have wildcard '*'")
	assert.Equal(t, PolicyActionDeny, actionDeny)
	assert.True(t, strings.Contains(strings.ToLower(reasonDeny), "policy"), "reason should cite policy: %s", reasonDeny)

	// Case 3: catalog_3000 (require approval by policy) -> allowed but PolicyActionRequireApproval
	allowedReq, actionReq, _ := registry.CheckToolAccess("super-root", "root-admin", "catalog_3000", "any_tool")
	assert.True(t, allowedReq)
	assert.Equal(t, PolicyActionRequireApproval, actionReq)
}

// 6. NON-EXISTENT / UNCONFIGURED SLUGS: 500 Goroutines Concurrent Probe
func TestAdversarial_VirtualMCP_NonExistentSlugs_UniformDenial_500Goroutines(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	const numGoroutines = 500
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-startGate
			slug := fmt.Sprintf("random-missing-slug-%d", id)
			allowed, action, reason := registry.CheckToolAccess(slug, "any-user", "google_workspace", "any-tool")
			assert.False(t, allowed)
			assert.Equal(t, PolicyActionDeny, action)
			assert.Contains(t, reason, "not found")
		}(i)
	}

	close(startGate)
	wg.Wait()
}
