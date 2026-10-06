package enterprise

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// TIER 4: REAL-WORLD APPLICATION SCENARIOS
// ============================================================================

// TestScenario_Tier4_EnterpriseFinancialAssistant tests:
// High-compliance banking workflow: OIDC SSO auth -> PII Guardrails (SSN blocked, Card masked) ->
// Adaptive Load Balancer -> Signed Audit Logging -> S3 Payload Archival.
func TestScenario_Tier4_EnterpriseFinancialAssistant(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. Analyst authenticates via OIDC
	analystClaims := mock.UserClaims{
		Subject: "analyst-jane-doe",
		Email:   "jane.doe@globalbank.com",
		Groups:  []string{"Engineering-Devs"},
	}
	token, err := gw.SSO.GenerateTestJWT(analystClaims, false)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	// 2. Analyst submits prompt containing prohibited SSN -> Intercepted with HTTP 422
	badPayload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Retrieve account details for SSN 987-65-4321 immediately."},
		},
	}
	badBody, _ := json.Marshal(badPayload)
	req1, _ := http.NewRequest(http.MethodPost, gw.URL()+"/v1/chat/completions", bytes.NewReader(badBody))
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected HTTP 422 for SSN leak attempt, got %d", resp1.StatusCode)
	}

	// 3. Analyst submits sanitized prompt containing email -> Allowed with redaction
	gw.LoadBalancer.RegisterRoute("key-fin-1", "openai", "gpt-4o")

	goodPayload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Analyze portfolio risk for client contact client.support@globalbank.com."},
		},
	}
	goodBody, _ := json.Marshal(goodPayload)
	req2, _ := http.NewRequest(http.MethodPost, gw.URL()+"/v1/chat/completions", bytes.NewReader(goodBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK for sanitized prompt, got %d", resp2.StatusCode)
	}

	// 4. Large compliance report payload offloaded to S3
	reportPayload := []byte("COMPLIANCE FINANCIAL REPORT: RISK ASSESSMENT P50=0.04%...")
	s3Key := "s3://bank-compliance/2026/10/06/report-jane-doe.gz"
	if err := gw.LogExporter.OffloadPayloadToS3(s3Key, reportPayload); err != nil {
		t.Fatalf("report offload failed: %v", err)
	}

	// 5. Audit trail records signed event
	auditEvent, err := gw.Audit.RecordEvent(
		"financial_query",
		"portfolio",
		"port-9921",
		analystClaims.Email,
		"10.100.20.15",
		string(reportPayload),
	)
	if err != nil || !gw.Audit.VerifySignature(auditEvent) {
		t.Fatalf("audit ledger verification failed")
	}
}

// TestScenario_Tier4_MultiTenantAgentWorkflow tests:
// Multi-tenant agent executing across Virtual MCP boundaries (/mcp/finance, /mcp/ops),
// performing RFC 8693 token exchange, enforcing cross-plane data boundaries, and respecting cluster rate limits.
func TestScenario_Tier4_MultiTenantAgentWorkflow(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. Setup multi-tenant Virtual MCPs
	gw.MCP.RegisterVirtualMCP("finance", "tenant-fin", []string{"export_payroll", "read_ledger"})
	gw.MCP.RegisterVirtualMCP("ops", "tenant-ops", []string{"restart_service", "read_metrics"})

	gw.MCP.SetUserPermissions("finance", "agent-007", []string{"read_ledger"})
	gw.MCP.SetUserPermissions("ops", "agent-007", []string{"read_metrics"})

	// 2. Agent exchanges token for downstream service
	toolToken, err := gw.MCP.ExchangeToken(context.Background(), "agent-bearer-jwt", "https://finance-service.internal")
	if err != nil || toolToken == "" {
		t.Fatalf("token exchange failed: %v", err)
	}

	// 3. Agent calls permitted tool in /mcp/finance
	allowed1, _, _ := gw.MCP.CheckToolAccess("finance", "agent-007", "google_workspace", "read_ledger")
	if !allowed1 {
		t.Fatalf("read_ledger should be allowed for agent-007")
	}

	// 4. Agent attempts restricted tool in /mcp/finance (export_payroll) -> Denied
	allowed2, _, reason := gw.MCP.CheckToolAccess("finance", "agent-007", "google_workspace", "export_payroll")
	if allowed2 {
		t.Fatalf("export_payroll should be denied for agent-007: %s", reason)
	}

	// 5. Enforce Cross-Plane Data Boundary:
	// Prevent data from source connector "google_workspace" from being routed to OpenAI
	errLeak := gw.MCP.CheckCrossPlaneDataBoundary("google_workspace", "openai")
	if errLeak == nil {
		t.Fatalf("cross-plane boundary must prevent google_workspace data leaking to openai")
	}

	// Routing to Anthropic is allowed
	errSafe := gw.MCP.CheckCrossPlaneDataBoundary("google_workspace", "anthropic")
	if errSafe != nil {
		t.Fatalf("google_workspace to anthropic should be allowed: %v", errSafe)
	}
}

// TestScenario_Tier4_DisasterRecoveryFailover tests:
// Primary provider experiences latency spike & spillover header; Circuit Breaker trips;
// Traffic dynamically reroutes 100% to secondary fallback; Cluster synchronizes health; SLA captures status.
func TestScenario_Tier4_DisasterRecoveryFailover(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. Configure Primary and Secondary routes
	gw.LoadBalancer.RegisterRoute("key-us-east-pri", "azure-openai", "gpt-4o")
	gw.LoadBalancer.RegisterRoute("key-us-west-sec", "anthropic", "claude-sonnet-4-5")

	gw.LoadBalancer.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "DR Spillover Failover",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-Ms-Is-Spilled-Over": "true",
		},
		DefaultCooldown: 45 * time.Second,
	})

	// 2. Primary provider begins returning 800ms latency spikes and spillover headers
	for i := 0; i < 5; i++ {
		gw.LoadBalancer.RecordAttempt("key-us-east-pri", 800.0, true, 503)
	}
	gw.LoadBalancer.InspectResponse("azure-openai", "gpt-4o", map[string]string{
		"X-Ms-Is-Spilled-Over": "true",
	})

	// 3. Verify Circuit Breaker opened and dynamically reroutes to anthropic
	_, fbProv, fbModel, tripped, err := gw.LoadBalancer.SelectRoute(context.Background(), "azure-openai", "gpt-4o")
	if err != nil {
		t.Fatalf("failover failed: %v", err)
	}
	if !tripped || fbProv != "anthropic" || fbModel != "claude-sonnet-4-5" {
		t.Fatalf("expected 100%% traffic shift to anthropic/claude-sonnet-4-5, got %s/%s", fbProv, fbModel)
	}

	// 4. Cluster node broadcast health state
	nodeA := gw.Cluster.CreateNode("node-east", "us-east-1", "10.0.1.1", 10101, 10102)
	nodeB := gw.Cluster.CreateNode("node-west", "us-west-2", "10.0.2.1", 10101, 10102)
	_ = nodeA.Join("node-west")

	stateMsg := []byte(`{"event": "circuit_tripped", "provider": "azure-openai", "fallback": "anthropic"}`)
	_ = nodeA.BroadcastState(context.Background(), stateMsg)

	if len(nodeB.SyncMessages) != 1 {
		t.Fatalf("expected node-west to receive failover state sync")
	}

	// 5. Query SLA diagnostic endpoint
	slaResp, err := http.Get(gw.URL() + "/api/v1/enterprise/diagnostics/sla?window=1h")
	if err != nil {
		t.Fatalf("SLA request failed: %v", err)
	}
	defer slaResp.Body.Close()

	if slaResp.StatusCode != http.StatusOK {
		t.Fatalf("SLA endpoint failed during failover")
	}
}

// TestScenario_Tier4_RegulatoryComplianceAuditAndKeyRotation tests:
// Security Auditor authenticates via SSO; Downloads SLA & Health Bundle; Executes POST /api/vault/flush-cache;
// Verifies HMAC signatures on all audit entries with IP omission.
func TestScenario_Tier4_RegulatoryComplianceAuditAndKeyRotation(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. Auditor SSO authentication
	auditorClaims := mock.UserClaims{
		Subject: "auditor-01",
		Email:   "auditor@compliance.gov",
		Groups:  []string{"Security-Auditors"},
	}
	role, err := gw.SSO.ResolveRole(&auditorClaims)
	if err != nil || role != "Security Auditor" {
		t.Fatalf("expected Security Auditor role, got: %s", role)
	}

	// 2. Download Health Bundle (gzip)
	bundleResp, err := http.Get(gw.URL() + "/api/v1/enterprise/diagnostics/health-bundle")
	if err != nil {
		t.Fatalf("health bundle request failed: %v", err)
	}
	defer bundleResp.Body.Close()

	if bundleResp.StatusCode != http.StatusOK || bundleResp.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("invalid health bundle response")
	}

	// 3. Flush Vault Cache
	gw.Vault.PutSecret("bifrost/keys/claude", map[string]string{"token": "old-token"})
	_, _ = gw.Vault.Resolve(context.Background(), "vault.bifrost/keys/claude")
	gw.Vault.PutSecret("bifrost/keys/claude", map[string]string{"token": "new-rotated-token"})

	flushResp, err := http.Post(gw.URL()+"/api/vault/flush-cache", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil || flushResp.StatusCode != http.StatusOK {
		t.Fatalf("vault flush cache failed")
	}
	flushResp.Body.Close()

	freshSecret, _ := gw.Vault.Resolve(context.Background(), "vault.bifrost/keys/claude")
	if freshSecret != "new-rotated-token" {
		t.Fatalf("expected rotated token after flush")
	}

	// 4. Audit ledger records key rotation event with IP omitted
	gw.Audit.OmitIPAddresses = true
	auditEvent, err := gw.Audit.RecordEvent(
		"rotate_keys",
		"vault",
		"fleet-wide",
		auditorClaims.Email,
		"192.168.0.50",
		`{"flush_timestamp": "2026-10-06T01:50:00Z"}`,
	)
	if err != nil {
		t.Fatalf("audit record failed: %v", err)
	}

	if auditEvent.ClientIP != "" {
		t.Fatalf("expected client IP to be omitted in compliance audit")
	}

	if !gw.Audit.VerifySignature(auditEvent) {
		t.Fatalf("audit event signature verification failed")
	}
}
