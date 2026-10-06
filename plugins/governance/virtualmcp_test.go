package governance

import (
	"context"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVirtualMCP_MultiTenancyAndRegistration(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	regEng := registry.RegisterVirtualMCP("engineering", "tenant-alpha", []string{"git_commit", "deploy_service"})
	regFin := registry.RegisterVirtualMCP("finance", "tenant-beta", []string{"generate_invoice", "view_ledger"})

	assert.Equal(t, "engineering", regEng.Slug)
	assert.Equal(t, "tenant-alpha", regEng.TenantID)
	assert.Equal(t, "finance", regFin.Slug)
	assert.Equal(t, "tenant-beta", regFin.TenantID)

	vmcpEng, ok := registry.GetVirtualMCP("engineering")
	require.True(t, ok)
	assert.Equal(t, "tenant-alpha", vmcpEng.TenantID)
	assert.ElementsMatch(t, []string{"git_commit", "deploy_service"}, vmcpEng.Tools)

	vmcpFin, ok := registry.GetVirtualMCP("finance")
	require.True(t, ok)
	assert.Equal(t, "tenant-beta", vmcpFin.TenantID)
	assert.ElementsMatch(t, []string{"generate_invoice", "view_ledger"}, vmcpFin.Tools)

	_, ok = registry.GetVirtualMCP("nonexistent")
	assert.False(t, ok)
}

func TestVirtualMCP_ToolAccessPrecedence(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	registry.RegisterVirtualMCP("prod", "tenant-corp", []string{"read_metrics", "delete_cluster"})
	err := registry.SetUserPermissions("prod", "junior-dev", []string{"read_metrics"})
	require.NoError(t, err)

	// 1. junior-dev calling read_metrics on allowed connector -> allowed
	allowed, action, reason := registry.CheckToolAccess("prod", "junior-dev", "google_workspace", "read_metrics")
	assert.True(t, allowed)
	assert.Equal(t, PolicyActionAllow, action)
	assert.Empty(t, reason)

	// 2. junior-dev calling delete_cluster -> denied because junior-dev permissions restrict it
	allowed, action, reason = registry.CheckToolAccess("prod", "junior-dev", "google_workspace", "delete_cluster")
	assert.False(t, allowed)
	assert.Equal(t, PolicyActionDeny, action)
	assert.Contains(t, reason, "lacks permission")

	// 3. Denied connector (office365) -> blocked even for allowed tools
	allowed, action, reason = registry.CheckToolAccess("prod", "junior-dev", "office365", "read_metrics")
	assert.False(t, allowed)
	assert.Equal(t, PolicyActionDeny, action)
	assert.NotEmpty(t, reason)

	// 4. RequireApproval connector (catalog_3000) -> allowed with PolicyActionRequireApproval
	allowed, action, reason = registry.CheckToolAccess("prod", "junior-dev", "catalog_3000", "read_metrics")
	assert.True(t, allowed)
	assert.Equal(t, PolicyActionRequireApproval, action)
	assert.Empty(t, reason)

	// 5. User without specific permissions -> falls back to tenant tools
	allowed, action, reason = registry.CheckToolAccess("prod", "senior-dev", "google_workspace", "delete_cluster")
	assert.True(t, allowed)
	assert.Equal(t, PolicyActionAllow, action)

	// Tool not in tenant tools -> denied
	allowed, action, reason = registry.CheckToolAccess("prod", "senior-dev", "google_workspace", "unregistered_tool")
	assert.False(t, allowed)
	assert.Equal(t, PolicyActionDeny, action)
	assert.Contains(t, reason, "not permitted")

	// 6. Non-existent slug -> denied
	allowed, action, reason = registry.CheckToolAccess("nonexistent-slug", "user-1", "google_workspace", "read")
	assert.False(t, allowed)
	assert.Equal(t, PolicyActionDeny, action)
	assert.Contains(t, reason, "not found")
}

func TestVirtualMCP_WildcardPermissions(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	// Tenant has wildcard, user has wildcard
	registry.RegisterVirtualMCP("admin-suite", "tenant-root", []string{"*"})
	err := registry.SetUserPermissions("admin-suite", "super-admin", []string{"*"})
	require.NoError(t, err)

	allowed, action, _ := registry.CheckToolAccess("admin-suite", "super-admin", "google_workspace", "any_arbitrary_tool")
	assert.True(t, allowed)
	assert.Equal(t, PolicyActionAllow, action)

	// Blocked connector still blocked even under wildcard
	allowedBlocked, actionBlocked, _ := registry.CheckToolAccess("admin-suite", "super-admin", "office365", "any_arbitrary_tool")
	assert.False(t, allowedBlocked)
	assert.Equal(t, PolicyActionDeny, actionBlocked)
}

func TestVirtualMCP_AuthorizeTool(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	registry.RegisterVirtualMCP("analytics", "tenant-finance", []string{"query_database", "export_csv"})
	err := registry.SetUserPermissions("analytics", "alice", []string{"query_database"})
	require.NoError(t, err)

	ctx := context.Background()

	// Alice calling query_database -> authorized
	ok, err := registry.AuthorizeTool(ctx, "alice", "tenant-finance", "query_database")
	require.NoError(t, err)
	assert.True(t, ok)

	// Alice calling export_csv -> unauthorized
	ok, err = registry.AuthorizeTool(ctx, "alice", "tenant-finance", "export_csv")
	require.Error(t, err)
	assert.False(t, ok)

	// Unknown tenant
	ok, err = registry.AuthorizeTool(ctx, "alice", "tenant-unknown", "query_database")
	require.Error(t, err)
	assert.False(t, ok)
}

func TestVirtualMCP_StampContext(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)

	registry.RegisterVirtualMCP("ops", "tenant-ops", []string{"restart", "logs"})
	_ = registry.SetUserPermissions("ops", "bob", []string{"logs"})

	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)

	// Stamp for bob
	stamped := registry.StampContext(ctx, "ops", "bob")
	assert.True(t, stamped)
	tools, ok := ctx.Value(schemas.MCPContextKeyIncludeTools).([]string)
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"logs"}, tools)

	// Stamp for unknown user falls back to tenant tools
	ctx2 := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	stamped2 := registry.StampContext(ctx2, "ops", "other-user")
	assert.True(t, stamped2)
	tools2, ok := ctx2.Value(schemas.MCPContextKeyIncludeTools).([]string)
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"restart", "logs"}, tools2)
}

func TestVirtualMCP_ConcurrentAccess(t *testing.T) {
	acl := DefaultAirlokPolicy()
	registry := NewVirtualMCPRegistry(acl)
	registry.RegisterVirtualMCP("concurrency-test", "tenant-test", []string{"tool-1", "tool-2"})

	concurrency := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			if idx%3 == 0 {
				_ = registry.SetUserPermissions("concurrency-test", "user", []string{"tool-1"})
			} else {
				allowed, _, _ := registry.CheckToolAccess("concurrency-test", "user", "google_workspace", "tool-1")
				assert.True(t, allowed)
			}
		}(i)
	}

	wg.Wait()
}
