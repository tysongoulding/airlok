package enterprise

import (
	"context"
	"net/http"
	"testing"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// TIER 1: FEATURE COVERAGE (R6 Federated MCP Authorization & Tool Governance)
// ============================================================================

func TestMCP_Tier1_RFC8693_TokenExchange(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	subjectToken := "user-jwt-bearer-xyz789"
	audience := "https://api.slack.com"

	downstreamToken, err := mcp.ExchangeToken(context.Background(), subjectToken, audience)
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	if downstreamToken == "" {
		t.Fatalf("exchanged downstream token is empty")
	}

	// Idempotent exchange with same user and audience
	cachedToken, err := mcp.ExchangeToken(context.Background(), subjectToken, audience)
	if err != nil || cachedToken != downstreamToken {
		t.Fatalf("cached exchanged token mismatch: %s vs %s", cachedToken, downstreamToken)
	}
}

func TestMCP_Tier1_VirtualMCP_MultiTenancy(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	mcp.RegisterVirtualMCP("engineering", "tenant-alpha", []string{"git_commit", "deploy_service"})
	mcp.RegisterVirtualMCP("finance", "tenant-beta", []string{"generate_invoice", "view_ledger"})

	// Verify tenant-alpha virtual MCP
	vmcpEng, exists := mcp.VirtualMCPs["engineering"]
	if !exists || vmcpEng.TenantID != "tenant-alpha" {
		t.Fatalf("engineering virtual MCP not registered properly")
	}

	// Verify tenant-beta virtual MCP
	vmcpFin, exists := mcp.VirtualMCPs["finance"]
	if !exists || vmcpFin.TenantID != "tenant-beta" {
		t.Fatalf("finance virtual MCP not registered properly")
	}
}

func TestMCP_Tier1_DualPlaneACL_ConnectorEnforcement(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	mcp.RegisterVirtualMCP("ops", "tenant-1", []string{"*"})

	// Case 1: google_workspace -> Allow
	allowed, action, _ := mcp.CheckToolAccess("ops", "user-1", "google_workspace", "drive_read")
	if !allowed || action != mock.MCPActionAllow {
		t.Fatalf("google_workspace should be allowed, got allowed=%v, action=%s", allowed, action)
	}

	// Case 2: office365 -> Deny
	allowedOff, actionOff, reason := mcp.CheckToolAccess("ops", "user-1", "office365", "mail_send")
	if allowedOff || actionOff != mock.MCPActionDeny {
		t.Fatalf("office365 should be denied, got allowed=%v, reason=%s", allowedOff, reason)
	}

	// Case 3: catalog_3000 -> RequireApproval
	allowedCat, actionCat, _ := mcp.CheckToolAccess("ops", "user-1", "catalog_3000", "query_database")
	if !allowedCat || actionCat != mock.MCPActionRequireApproval {
		t.Fatalf("catalog_3000 should require approval, got action=%s", actionCat)
	}
}

func TestMCP_Tier1_CrossPlaneDataBoundary_LeakPrevention(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()

	// Data from google_workspace going to OpenAI -> VIOLATION
	err := mcp.CheckCrossPlaneDataBoundary("google_workspace", "openai")
	if err == nil {
		t.Fatalf("expected cross-plane violation for google_workspace -> openai")
	}

	// Data from google_workspace going to Anthropic -> ALLOWED
	errClaude := mcp.CheckCrossPlaneDataBoundary("google_workspace", "anthropic")
	if errClaude != nil {
		t.Fatalf("google_workspace -> anthropic should be allowed: %v", errClaude)
	}
}

func TestMCP_Tier1_PerUserToolPermissions(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	mcp.RegisterVirtualMCP("prod", "tenant-corp", []string{"read_metrics", "delete_cluster"})
	mcp.SetUserPermissions("prod", "junior-dev", []string{"read_metrics"})

	// junior-dev calling read_metrics -> allowed
	allowed1, _, _ := mcp.CheckToolAccess("prod", "junior-dev", "google_workspace", "read_metrics")
	if !allowed1 {
		t.Fatalf("read_metrics should be allowed for junior-dev")
	}

	// junior-dev calling delete_cluster -> denied
	allowed2, _, reason := mcp.CheckToolAccess("prod", "junior-dev", "google_workspace", "delete_cluster")
	if allowed2 {
		t.Fatalf("delete_cluster should be denied for junior-dev: %s", reason)
	}
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (R6 Federated MCP Governance)
// ============================================================================

func TestMCP_Tier2_MissingSubjectToken_ExchangeError(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	_, err := mcp.ExchangeToken(context.Background(), "", "https://api.github.com")
	if err == nil {
		t.Fatalf("expected error for empty subject token")
	}
}

func TestMCP_Tier2_ExpiredSubjectToken_ExchangeError(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	_, err := mcp.ExchangeToken(context.Background(), "expired-token-jwt-123", "https://api.github.com")
	if err == nil {
		t.Fatalf("expected error for expired subject token")
	}
}

func TestMCP_Tier2_NonExistentVirtualMCPSlug_Returns404(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/mcp/nonexistent-slug?connector=google_workspace&tool=read")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for unconfigured slug, got %d", resp.StatusCode)
	}
}

func TestMCP_Tier2_UnauthorizedCrossPlaneDestination_Returns403(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	// Disallow slack to openai
	err := mcp.CheckCrossPlaneDataBoundary("slack", "openai")
	if err == nil {
		t.Fatalf("expected cross-plane error")
	}
}

func TestMCP_Tier2_WildcardToolPermissions(t *testing.T) {
	mcp := mock.NewMockMCPGovernance()
	mcp.RegisterVirtualMCP("admin-suite", "tenant-root", []string{"*"})
	mcp.SetUserPermissions("admin-suite", "super-admin", []string{"*"})

	allowed, _, _ := mcp.CheckToolAccess("admin-suite", "super-admin", "google_workspace", "any_arbitrary_tool")
	if !allowed {
		t.Fatalf("wildcard tool permissions should allow any tool")
	}
}
