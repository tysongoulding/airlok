package enterprise

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ADVERSARIAL CHALLENGE: FEDERATED MCP & VIRTUAL MCP CONCURRENCY (FEATURE 32 & 33)
// ============================================================================

// 1. Concurrency: 1000 Goroutines Token Exchange Deduplication Stress
func TestAdversarial_Enterprise_MCP_ConcurrentTokenExchange_1000Goroutines(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	subjectToken := "user-jwt-bearer-swarm-token"
	audience := "https://api.github.com"

	const numGoroutines = 1000
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	tokens := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-startGate
			tokens[idx], errors[idx] = mcp.ExchangeToken(context.Background(), subjectToken, audience)
		}(i)
	}

	close(startGate)
	wg.Wait()

	firstToken := tokens[0]
	require.NotEmpty(t, firstToken)

	for i := 0; i < numGoroutines; i++ {
		require.NoError(t, errors[i])
		assert.Equal(t, firstToken, tokens[i], "goroutine %d got divergent token", i)
	}

	// Verify only 1 cached entry in map
	assert.Equal(t, 1, len(mcp.ExchangedTokens), "expected exactly 1 cached entry for single audience")
}

// 2. Concurrency: 500 Goroutines Probing Non-Existent Slugs uniformly receive HTTP 403
func TestAdversarial_Enterprise_MCP_ConcurrentNonExistentSlugs_500Goroutines(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	require.NoError(t, err)
	defer gw.Close()

	const numGoroutines = 500
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var forbiddenCount atomic.Int64
	var otherCount atomic.Int64

	client := &http.Client{}

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-startGate
			url := fmt.Sprintf("%s/mcp/missing-slug-%d?connector=google_workspace&tool=read", gw.URL(), id)
			resp, err := client.Get(url)
			if err != nil {
				otherCount.Add(1)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusForbidden {
				forbiddenCount.Add(1)
			} else {
				otherCount.Add(1)
			}
		}(i)
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int64(numGoroutines), forbiddenCount.Load(), "all 500 unconfigured slugs must receive HTTP 403 Forbidden")
	assert.Equal(t, int64(0), otherCount.Load())
}

// 3. Concurrency & ACL: Denied Connector Blocked Under Wildcards for 500 Goroutines
func TestAdversarial_Enterprise_MCP_DeniedConnector_BlockedUnderWildcard_500Goroutines(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	mcp.RegisterVirtualMCP("root-slug", "tenant-root", []string{"*"})
	mcp.SetUserPermissions("root-slug", "admin-user", []string{"*"})

	const numGoroutines = 500
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var blockedCount atomic.Int64
	var leakCount atomic.Int64

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-startGate
			allowed, action, _ := mcp.CheckToolAccess("root-slug", "admin-user", "office365", "delete_all")
			if !allowed && action == mock.MCPActionDeny {
				blockedCount.Add(1)
			} else {
				leakCount.Add(1)
			}
		}()
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int64(numGoroutines), blockedCount.Load(), "office365 must be blocked 100% of the time")
	assert.Equal(t, int64(0), leakCount.Load())
}

// 4. Concurrency: 500 Goroutines Checking Cross-Plane Data Boundary
func TestAdversarial_Enterprise_MCP_CrossPlaneBoundary_Concurrent_500Goroutines(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()

	const numGoroutines = 500
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var violationCount atomic.Int64
	var allowedCount atomic.Int64

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-startGate
			if id%2 == 0 {
				// Violation case: google_workspace -> openai
				err := mcp.CheckCrossPlaneDataBoundary("google_workspace", "openai")
				if err != nil {
					violationCount.Add(1)
				}
			} else {
				// Allowed case: google_workspace -> anthropic
				err := mcp.CheckCrossPlaneDataBoundary("google_workspace", "anthropic")
				if err == nil {
					allowedCount.Add(1)
				}
			}
		}(i)
	}

	close(startGate)
	wg.Wait()

	assert.Equal(t, int64(250), violationCount.Load())
	assert.Equal(t, int64(250), allowedCount.Load())
}
