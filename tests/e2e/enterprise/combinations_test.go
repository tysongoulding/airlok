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
// TIER 3: CROSS-FEATURE COMBINATIONS (Pairwise Interactions)
// ============================================================================

// TestCombinations_Tier3_SSO_Guardrails_LoadBalancer_Audit tests:
// SSO Authenticated User (R4) invoking Guardrailed LLM (R1) through Adaptive Load Balancer (R3) with Audit Trail logging (R7).
func TestCombinations_Tier3_SSO_Guardrails_LoadBalancer_Audit(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway server: %v", err)
	}
	defer gw.Close()

	// 1. Authenticate via OIDC JWT
	userClaims := mock.UserClaims{
		Subject: "fin-analyst-101",
		Email:   "analyst@enterprise-bank.com",
		Groups:  []string{"Engineering-Devs"},
	}
	jwtToken, err := gw.SSO.GenerateTestJWT(userClaims, false)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}
	claims, err := gw.SSO.ValidateToken(context.Background(), jwtToken)
	if err != nil || claims.Subject != "fin-analyst-101" {
		t.Fatalf("SSO token validation failed: %v", err)
	}

	// 2. Register routes in Adaptive Load Balancer
	gw.LoadBalancer.RegisterRoute("key-openai-1", "openai", "gpt-4o")
	gw.LoadBalancer.RegisterRoute("key-anthropic-1", "anthropic", "claude-sonnet-4-5")

	// 3. Send prompt containing email (should be redacted)
	reqPayload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Please analyze transactions for customer email client@bank.com"},
		},
	}
	body, _ := json.Marshal(reqPayload)

	httpReq, _ := http.NewRequest(http.MethodPost, gw.URL()+"/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+jwtToken)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d", resp.StatusCode)
	}

	var respBody map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&respBody)
	choices := respBody["choices"].([]interface{})
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	content := msg["content"].(string)

	if !bytes.Contains([]byte(content), []byte("[EMAIL]")) {
		t.Fatalf("expected email to be redacted before upstream processing: %s", content)
	}

	// 4. Record and verify signed audit event
	auditEvent, err := gw.Audit.RecordEvent(
		"inference",
		"model",
		"gpt-4o",
		claims.Email,
		"10.0.5.21",
		`{"prompt_redacted": true, "entities": ["EMAIL"]}`,
	)
	if err != nil || !gw.Audit.VerifySignature(auditEvent) {
		t.Fatalf("audit event signing/verification failed: %v", err)
	}
}

// TestCombinations_Tier3_VirtualMCP_TokenExchange_Vault_RBAC tests:
// Virtual MCP execution (R6) with RFC 8693 token exchange resolving credentials from Vault (R5) under RBAC control (R8).
func TestCombinations_Tier3_VirtualMCP_TokenExchange_Vault_RBAC(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. RBAC check: Developer role is authorized for VirtualMCP inference
	allowMCP, err := gw.RBAC.Authorize("Developer", mock.ResourceVirtualMCPs, mock.OpInference)
	if err != nil || !allowMCP {
		t.Fatalf("Developer should be authorized for VirtualMCP inference")
	}

	// 2. Register Virtual MCP
	gw.MCP.RegisterVirtualMCP("analytics", "tenant-finance", []string{"query_database", "export_csv"})
	gw.MCP.SetUserPermissions("analytics", "dev-alice", []string{"query_database"})

	// 3. User exchanges subject token for downstream tool token
	downstreamToken, err := gw.MCP.ExchangeToken(context.Background(), "user-bearer-dev-alice", "https://db.internal.analytics")
	if err != nil || downstreamToken == "" {
		t.Fatalf("RFC 8693 token exchange failed: %v", err)
	}

	// 4. Tool credentials resolved from Vault
	gw.Vault.PutSecret("bifrost/mcp/analytics/db", map[string]string{
		"db_password": "super-secret-vault-password",
	})
	pwd, err := gw.Vault.Resolve(context.Background(), "vault.bifrost/mcp/analytics/db#db_password")
	if err != nil || pwd != "super-secret-vault-password" {
		t.Fatalf("vault resolution failed: %v", err)
	}

	// 5. Check tool access on Virtual MCP
	allowed, action, _ := gw.MCP.CheckToolAccess("analytics", "dev-alice", "google_workspace", "query_database")
	if !allowed || action != mock.MCPActionAllow {
		t.Fatalf("expected tool access allowed")
	}
}

// TestCombinations_Tier3_Cluster_DistributedRateLimit_LoadBalancerFailover tests:
// Cluster Mode (R2) distributed rate limiting while Adaptive Load Balancer (R3) reroutes degraded routes.
func TestCombinations_Tier3_Cluster_DistributedRateLimit_LoadBalancerFailover(t *testing.T) {
	mesh := mock.NewMockClusterMesh()
	nodeA := mesh.CreateNode("node-A", "us-east-1", "10.0.0.1", 10101, 10102)
	nodeB := mesh.CreateNode("node-B", "us-east-1", "10.0.0.2", 10101, 10102)
	_ = nodeA.Join("node-B")

	lb := mock.NewMockAdaptiveLoadBalancer()
	lb.RegisterRoute("key-primary", "openai", "gpt-4o")
	lb.RegisterRoute("key-secondary", "openai", "gpt-4o")

	// 1. Shared rate limit capacity
	rateLimitKey := "vk-cluster-shared:tpm"
	var totalTokens int64 = 500

	// Node A charges 200 tokens
	allowedA, remA, _ := nodeA.CheckAndChargeDistributedRateLimit(rateLimitKey, 200, totalTokens, 1*time.Minute)
	if !allowedA || remA != 300 {
		t.Fatalf("node A charge failed: rem=%d", remA)
	}

	// 2. Primary key on Node A experiences latency spike (500ms)
	for i := 0; i < 5; i++ {
		lb.RecordAttempt("key-primary", 500.0, false, 0)
	}
	// Secondary key stays fast (15ms)
	for i := 0; i < 5; i++ {
		lb.RecordAttempt("key-secondary", 15.0, false, 0)
	}

	// Load balancer should now favor key-secondary
	selectedKey, _, _, _, err := lb.SelectRoute(context.Background(), "openai", "gpt-4o")
	if err != nil || selectedKey != "key-secondary" {
		t.Fatalf("expected failover to key-secondary, got: %s", selectedKey)
	}

	// 3. Node B charges remaining tokens (300 tokens) -> aggregate bucket exhausted
	allowedB, remB, _ := nodeB.CheckAndChargeDistributedRateLimit(rateLimitKey, 300, totalTokens, 1*time.Minute)
	if !allowedB || remB != 0 {
		t.Fatalf("node B charge failed: rem=%d", remB)
	}

	// 4. Any further charge on Node A or Node B is rejected
	allowedOverflow, _, _ := nodeA.CheckAndChargeDistributedRateLimit(rateLimitKey, 10, totalTokens, 1*time.Minute)
	if allowedOverflow {
		t.Fatalf("distributed rate limit overflow allowed on Node A")
	}
}

// TestCombinations_Tier3_GuardrailRedaction_S3PayloadOffload_AuditIPOmission tests:
// Guardrail PII Redaction (R1) + S3 Payload Offloader (R7) + Audit Log IP Omission (R7).
func TestCombinations_Tier3_GuardrailRedaction_S3PayloadOffload_AuditIPOmission(t *testing.T) {
	engine := mock.NewMockGuardrailsEngine()
	exporter := mock.NewMockLogExporter(10, 1*time.Second)
	ledger, _ := mock.NewMockAuditLedger("hmac-secret-key-that-is-at-least-32-bytes-long", true) // omitIP=true

	rawPrompt := "Process customer email alice.smith@bank.org for account reconciliation."
	grResult := engine.EvaluateText(rawPrompt, "llm", "input", nil)

	if !grResult.Allowed || !bytes.Contains([]byte(grResult.TransformedText), []byte("[EMAIL]")) {
		t.Fatalf("guardrail redaction failed: %s", grResult.TransformedText)
	}

	// Large payload offloaded to S3
	payload := []byte("Redacted Content: " + grResult.TransformedText)
	s3Key := "s3://compliance-vault/audit/2026-10-06/req-001.gz"
	if err := exporter.OffloadPayloadToS3(s3Key, payload); err != nil {
		t.Fatalf("s3 offload failed: %v", err)
	}

	// Audit log records action with IP omitted
	auditEvent, err := ledger.RecordEvent("anonymize", "prompt", "req-001", "service-agent", "203.0.113.195", string(payload))
	if err != nil {
		t.Fatalf("audit logging failed: %v", err)
	}
	if auditEvent.ClientIP != "" {
		t.Fatalf("expected client IP to be omitted")
	}
	if !ledger.VerifySignature(auditEvent) {
		t.Fatalf("audit signature verification failed")
	}
}

// TestCombinations_Tier3_CircuitBreaker_VaultRotation_AuditSecurityEvent tests:
// Circuit breaker header trip (R3) triggers Vault cache flush (R5) and Audit Trail logging (R7).
func TestCombinations_Tier3_CircuitBreaker_VaultRotation_AuditSecurityEvent(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. Circuit Breaker policy
	gw.LoadBalancer.RegisterCircuitPolicy(mock.CircuitPolicy{
		Name:             "Azure Spillover Breaker",
		PrimaryProvider:  "azure-openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-sonnet-4-5",
		TriggerHeaders: map[string]string{
			"X-Ms-Is-Spilled-Over": "true",
		},
		DefaultCooldown: 30 * time.Second,
	})

	// 2. Upstream returns spillover header -> trips breaker
	gw.LoadBalancer.InspectResponse("azure-openai", "gpt-4o", map[string]string{
		"X-Ms-Is-Spilled-Over": "true",
	})

	// 3. Verify failover to anthropic
	_, fbProv, fbModel, tripped, _ := gw.LoadBalancer.SelectRoute(context.Background(), "azure-openai", "gpt-4o")
	if !tripped || fbProv != "anthropic" || fbModel != "claude-sonnet-4-5" {
		t.Fatalf("circuit breaker dynamic failover failed: %s/%s", fbProv, fbModel)
	}

	// 4. Operator triggers vault cache flush
	gw.Vault.FlushCache()

	// 5. Audit log records security failover event
	event, err := gw.Audit.RecordEvent("failover", "provider", "azure-openai", "system-monitor", "127.0.0.1", `{"reason": "X-Ms-Is-Spilled-Over triggered"}`)
	if err != nil || !gw.Audit.VerifySignature(event) {
		t.Fatalf("audit event recording failed")
	}
}

// TestCombinations_Tier3_SCIMProvisioning_RBACPermissionBoundary_AuditVerification tests:
// SCIM provisioning (R4) creates Developer user; RBAC (R8) rejects Admin mutation; Audit (R7) logs event.
func TestCombinations_Tier3_SCIMProvisioning_RBACPermissionBoundary_AuditVerification(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	// 1. SCIM provisioning
	scimUser := mock.SCIMUser{
		ID:       "usr-bob-dev",
		UserName: "bob@developer.internal",
		Groups:   []string{"Engineering-Devs"},
	}
	if err := gw.SSO.ProvisionSCIMUser(scimUser); err != nil {
		t.Fatalf("SCIM provisioning failed: %v", err)
	}

	// 2. Map role -> Developer
	role, err := gw.SSO.ResolveRole(gw.SSO.Users["bob@developer.internal"])
	if err != nil || role != "Developer" {
		t.Fatalf("expected Developer role for Bob: %s", role)
	}

	// 3. Bob attempts Admin operation (create role) -> RBAC denies
	allowed, _ := gw.RBAC.Authorize(role, mock.ResourceRoles, mock.OpCreate)
	if allowed {
		t.Fatalf("Developer Bob must NOT be allowed to create roles")
	}

	// 4. Audit ledger logs access violation
	auditEvent, err := gw.Audit.RecordEvent("access_denied", "role", "admin", "bob@developer.internal", "192.168.1.50", `{"action": "create_role", "status": "forbidden"}`)
	if err != nil || !gw.Audit.VerifySignature(auditEvent) {
		t.Fatalf("audit verification failed: %v", err)
	}
}
