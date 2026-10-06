package enterprise

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// TIER 1: FEATURE COVERAGE (R7 Audit Trail & Log Export & R8 RBAC & Diagnostics)
// ============================================================================

func TestAudit_Tier1_HMAC_SHA256_SignatureSigning(t *testing.T) {
	key := "a-very-secret-hmac-key-that-is-at-least-32-bytes!"
	ledger, err := mock.NewMockAuditLedger(key, false)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}

	event, err := ledger.RecordEvent(
		"create",
		"virtual_key",
		"vk-corp-01",
		"admin@enterprise.com",
		"192.168.1.100",
		`{"name": "finance-vk", "tpm": 100000}`,
	)
	if err != nil {
		t.Fatalf("failed to record audit event: %v", err)
	}

	if event.HMACSignature == "" {
		t.Fatalf("audit event missing HMAC signature")
	}

	if !ledger.VerifySignature(event) {
		t.Fatalf("audit signature verification failed on untampered event")
	}
}

func TestAudit_Tier1_IPAddressOmission_GDPRCompliance(t *testing.T) {
	key := "a-very-secret-hmac-key-that-is-at-least-32-bytes!"
	ledger, err := mock.NewMockAuditLedger(key, true) // omitIP = true
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}

	event, err := ledger.RecordEvent(
		"delete",
		"policy",
		"pol-99",
		"operator@corp.com",
		"10.20.30.40", // Provided client IP
		`{"reason": "deprecating old policy"}`,
	)
	if err != nil {
		t.Fatalf("failed to record audit event: %v", err)
	}

	if event.ClientIP != "" {
		t.Fatalf("expected client IP to be omitted for privacy, got: %s", event.ClientIP)
	}

	if !ledger.VerifySignature(event) {
		t.Fatalf("signature verification failed on IP-omitted audit event")
	}
}

func TestLogExport_Tier1_BatchedLogQueue_Flushing(t *testing.T) {
	batchSize := 5
	exporter := mock.NewMockLogExporter(batchSize, 1*time.Second)

	// Enqueue 4 items -> no flush yet
	for i := 0; i < 4; i++ {
		exporter.Enqueue(map[string]interface{}{"index": i})
	}
	if len(exporter.FlushedBatches) != 0 {
		t.Fatalf("expected 0 flushed batches before reaching threshold, got %d", len(exporter.FlushedBatches))
	}

	// Enqueue 5th item -> immediate flush trigger
	exporter.Enqueue(map[string]interface{}{"index": 4})
	if len(exporter.FlushedBatches) != 1 {
		t.Fatalf("expected 1 flushed batch upon reaching batch size, got %d", len(exporter.FlushedBatches))
	}
	if len(exporter.FlushedBatches[0]) != 5 {
		t.Fatalf("expected batch size 5, got %d", len(exporter.FlushedBatches[0]))
	}
}

func TestLogExport_Tier1_S3PayloadOffloader(t *testing.T) {
	exporter := mock.NewMockLogExporter(10, 1*time.Second)
	payload := []byte(stringsRepeat("Payload line for LLM completion request...\n", 100))

	key := "s3://bifrost-logs/2026/10/06/chatcmpl-large.json.gz"
	if err := exporter.OffloadPayloadToS3(key, payload); err != nil {
		t.Fatalf("s3 offload failed: %v", err)
	}

	offloaded, exists := exporter.OffloadedS3[key]
	if !exists || len(offloaded) != len(payload) {
		t.Fatalf("offloaded payload missing or size mismatch in mock S3")
	}
}

func TestAudit_Tier1_TamperDetection(t *testing.T) {
	key := "a-very-secret-hmac-key-that-is-at-least-32-bytes!"
	ledger, _ := mock.NewMockAuditLedger(key, false)

	event, _ := ledger.RecordEvent(
		"update",
		"role",
		"role-dev",
		"admin@corp.com",
		"127.0.0.1",
		`{"permissions": ["read"]}`,
	)

	// Tamper payload directly in storage
	event.Payload = `{"permissions": ["admin", "root_access"]}`

	if ledger.VerifySignature(event) {
		t.Fatalf("expected signature verification failure on tampered audit record")
	}
}

func TestRBAC_Tier1_GranularRoles_AdminAllowed(t *testing.T) {
	rbac := mock.NewMockRBACAuthorizer()

	// Admin should have access to create roles, view logs, delete virtual keys
	allowRole, err := rbac.Authorize("Admin", mock.ResourceRoles, mock.OpCreate)
	if err != nil || !allowRole {
		t.Fatalf("Admin must be permitted to create roles")
	}

	allowLogs, _ := rbac.Authorize("Admin", mock.ResourceLogs, mock.OpView)
	if !allowLogs {
		t.Fatalf("Admin must be permitted to view logs")
	}
}

func TestRBAC_Tier1_UnauthorizedOperations_RejectedWithHTTP403(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	// Request with Developer role attempting to create role -> HTTP 403
	req, _ := http.NewRequest(http.MethodPost, gw.URL()+"/api/governance/roles", bytes.NewReader([]byte("{}")))
	req.Header.Set("X-User-Role", "Developer")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for unauthorized developer operation, got %d", resp.StatusCode)
	}
}

func TestDiagnostics_Tier1_SLAReportingEndpoint(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/enterprise/diagnostics/sla?window=24h")
	if err != nil {
		t.Fatalf("SLA request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from SLA endpoint, got %d", resp.StatusCode)
	}

	var sla map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&sla); err != nil {
		t.Fatalf("failed to parse SLA response: %v", err)
	}

	if sla["window"] != "24h" || sla["status"] != "HEALTHY" {
		t.Fatalf("unexpected SLA content: %+v", sla)
	}
}

func TestDiagnostics_Tier1_HealthBundleExport_ValidGzip(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/enterprise/diagnostics/health-bundle")
	if err != nil {
		t.Fatalf("health bundle request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from health bundle export, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("expected Content-Type application/gzip, got %s", resp.Header.Get("Content-Type"))
	}

	bundleBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read health bundle body: %v", err)
	}

	// Decompress gzip and verify tar archive
	gr, err := gzip.NewReader(bytes.NewReader(bundleBytes))
	if err != nil {
		t.Fatalf("failed to initialize gzip reader on health bundle: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	foundDiagnostics := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar decompression error: %v", err)
		}
		if hdr.Name == "diagnostics.json" {
			foundDiagnostics = true
			var content map[string]interface{}
			if err := json.NewDecoder(tr).Decode(&content); err != nil {
				t.Fatalf("failed to decode diagnostics.json from bundle: %v", err)
			}
			if content["version"] != "1.0-enterprise" {
				t.Fatalf("diagnostics version mismatch: %v", content["version"])
			}
		}
	}

	if !foundDiagnostics {
		t.Fatalf("diagnostics.json not found in exported health bundle archive")
	}
}

func TestRBAC_Tier1_SecurityAuditorRolePermissions(t *testing.T) {
	rbac := mock.NewMockRBACAuthorizer()

	// Can view audit logs
	allowViewAudit, _ := rbac.Authorize("Security Auditor", mock.ResourceAuditLogs, mock.OpView)
	if !allowViewAudit {
		t.Fatalf("Security Auditor must be allowed to view audit logs")
	}

	// Cannot perform model inference
	allowInference, _ := rbac.Authorize("Security Auditor", mock.ResourceVirtualMCPs, mock.OpInference)
	if allowInference {
		t.Fatalf("Security Auditor must NOT be allowed to perform inference")
	}
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (R7 Audit & Log Export & R8 RBAC & Diagnostics)
// ============================================================================

func TestAudit_Tier2_HMACKeyLengthRejection(t *testing.T) {
	shortKey := "short-key-16-bytes"
	_, err := mock.NewMockAuditLedger(shortKey, false)
	if err == nil {
		t.Fatalf("expected error when HMAC key is shorter than 32 bytes")
	}
}

func TestLogExport_Tier2_EmptyQueueFlush_NoOp(t *testing.T) {
	exporter := mock.NewMockLogExporter(10, 1*time.Second)
	exporter.Flush()

	if len(exporter.FlushedBatches) != 0 {
		t.Fatalf("flushing empty queue should not generate batches, got %d", len(exporter.FlushedBatches))
	}
}

func TestRBAC_Tier2_UndefinedRole_DeniesAll(t *testing.T) {
	rbac := mock.NewMockRBACAuthorizer()
	allowed, err := rbac.Authorize("GhostRole", mock.ResourceLogs, mock.OpView)
	if err == nil || allowed {
		t.Fatalf("undefined role must return error and be denied")
	}
}

func TestRBAC_Tier2_UndefinedResource_Denied(t *testing.T) {
	rbac := mock.NewMockRBACAuthorizer()
	allowed, err := rbac.Authorize("Developer", mock.Resource("UnknownResource"), mock.OpView)
	if err != nil || allowed {
		t.Fatalf("undefined resource should be denied")
	}
}

func TestDiagnostics_Tier2_DefaultWindowQueryParam(t *testing.T) {
	diag := mock.NewMockDiagnosticsReporter()
	report, err := diag.GenerateSLAReport(context.Background(), "")
	if err != nil {
		t.Fatalf("report generation failed: %v", err)
	}

	if report["window"] != "24h" {
		t.Fatalf("expected default window 24h, got: %v", report["window"])
	}
}

func stringsRepeat(s string, count int) string {
	var b bytes.Buffer
	for i := 0; i < count; i++ {
		b.WriteString(s)
	}
	return b.String()
}
