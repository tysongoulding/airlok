package diagnostics_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/diagnostics"
)

func TestDiagnostics_SLAReport_DefaultWindowAndBaseline(t *testing.T) {
	tracker := diagnostics.NewSLATracker()

	report, err := tracker.GenerateSLAReport(context.Background(), "")
	if err != nil {
		t.Fatalf("failed to generate SLA report: %v", err)
	}

	if report.Window != "24h" {
		t.Fatalf("expected default window 24h, got %s", report.Window)
	}
	if report.Status != "HEALTHY" {
		t.Fatalf("expected baseline status HEALTHY, got %s", report.Status)
	}
	if report.UptimePct < 99.9 {
		t.Fatalf("expected high baseline uptime, got %f", report.UptimePct)
	}
	if report.P50LatencyMs != 14.2 || report.P95LatencyMs != 48.5 || report.P99LatencyMs != 112.0 {
		t.Fatalf("unexpected baseline latency metrics: p50=%f, p95=%f, p99=%f",
			report.P50LatencyMs, report.P95LatencyMs, report.P99LatencyMs)
	}
}

func TestDiagnostics_SLAReport_TrafficCalculations(t *testing.T) {
	tracker := diagnostics.NewSLATracker()

	// Record 90 successful requests (latency 10ms-50ms)
	for i := 0; i < 90; i++ {
		tracker.RecordRequest("openai", "gpt-4o", time.Duration(10+i)*time.Millisecond, true)
	}
	// Record 10 failed requests
	for i := 0; i < 10; i++ {
		tracker.RecordRequest("openai", "gpt-4o", 500*time.Millisecond, false)
	}

	report, err := tracker.GenerateSLAReport(context.Background(), "1h")
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	if report.TotalRequests != 100 {
		t.Fatalf("expected 100 total requests, got %d", report.TotalRequests)
	}
	if report.SuccessfulRequests != 90 {
		t.Fatalf("expected 90 successful requests, got %d", report.SuccessfulRequests)
	}
	if report.FailedRequests != 10 {
		t.Fatalf("expected 10 failed requests, got %d", report.FailedRequests)
	}
	if report.UptimePct != 90.0 {
		t.Fatalf("expected 90%% uptime, got %f", report.UptimePct)
	}
	// Under 95% uptime -> status should be CRITICAL
	if report.Status != "CRITICAL" {
		t.Fatalf("expected CRITICAL status for 90%% uptime, got %s", report.Status)
	}

	if report.P50LatencyMs <= 0 || report.P95LatencyMs <= 0 || report.P99LatencyMs <= 0 {
		t.Fatalf("expected positive percentile latencies")
	}

	if prov, ok := report.ProviderMetrics["openai"]; !ok || prov.TotalCount != 100 {
		t.Fatalf("expected provider metrics for openai with 100 total count")
	}
}

func TestDiagnostics_HealthBundleExport_ArchiveStructure(t *testing.T) {
	cfg := map[string]interface{}{
		"provider_key":   "sk-live-secret-key-12345",
		"database_dsn":   "postgres://user:password@localhost/bifrost",
		"public_host":    "api.enterprise.com",
		"cluster_mesh":   true,
		"debug_mode":     false,
		"sync_port":      10102,
		"gossip_port":    10101,
		"rate_limit_tpm": int64(50000),
		"uptime_sla":     99.95,
		"allowed_nodes":  []int{1, 2, 3},
		"optional_field": nil,
		"nested_settings": map[string]interface{}{
			"auth_token": "Bearer sensitive-token-xyz",
			"max_conns":  1000,
			"enabled":    true,
		},
	}

	gen := diagnostics.NewHealthBundleGenerator(cfg, func() map[string]interface{} {
		return map[string]interface{}{
			"nodes": []string{"node-1", "node-2"},
		}
	})

	bundle, err := gen.ExportHealthBundle(context.Background())
	if err != nil {
		t.Fatalf("export health bundle failed: %v", err)
	}

	// Decompress gzip and inspect tar
	gr, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	foundFiles := make(map[string]bool)
	var foundDiagnosticsVersion string
	var sanitizedConfigData map[string]interface{}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read error: %v", err)
		}
		foundFiles[hdr.Name] = true

		if hdr.Name == "diagnostics.json" {
			var diag map[string]interface{}
			if err := json.NewDecoder(tr).Decode(&diag); err != nil {
				t.Fatalf("failed to decode diagnostics.json: %v", err)
			}
			if v, ok := diag["version"].(string); ok {
				foundDiagnosticsVersion = v
			}
		}

		if hdr.Name == "sanitized_config.json" {
			_ = json.NewDecoder(tr).Decode(&sanitizedConfigData)
		}
	}

	expectedFiles := []string{
		"diagnostics.json",
		"system_info.json",
		"runtime_memory.json",
		"goroutines.txt",
		"cluster_topology.json",
		"sanitized_config.json",
	}
	for _, f := range expectedFiles {
		if !foundFiles[f] {
			t.Fatalf("expected file %s missing from health bundle", f)
		}
	}

	if foundDiagnosticsVersion != "1.0-enterprise" {
		t.Fatalf("expected verbatim version '1.0-enterprise', got '%s'", foundDiagnosticsVersion)
	}

	// Verify secrets were scrubbed
	if sanitizedConfigData["provider_key"] != "[REDACTED]" {
		t.Fatalf("expected provider_key to be [REDACTED], got: %v", sanitizedConfigData["provider_key"])
	}
	if sanitizedConfigData["database_dsn"] != "[REDACTED]" {
		t.Fatalf("expected database_dsn to be [REDACTED], got: %v", sanitizedConfigData["database_dsn"])
	}
	if sanitizedConfigData["public_host"] != "api.enterprise.com" {
		t.Fatalf("expected non-sensitive public_host preserved, got: %v", sanitizedConfigData["public_host"])
	}

	// Verify non-string primitives preserved intact
	if sanitizedConfigData["cluster_mesh"] != true {
		t.Fatalf("expected cluster_mesh true, got: %v", sanitizedConfigData["cluster_mesh"])
	}
	if sanitizedConfigData["debug_mode"] != false {
		t.Fatalf("expected debug_mode false, got: %v", sanitizedConfigData["debug_mode"])
	}
	if sanitizedConfigData["sync_port"] != float64(10102) {
		t.Fatalf("expected sync_port 10102, got: %v", sanitizedConfigData["sync_port"])
	}
	if sanitizedConfigData["rate_limit_tpm"] != float64(50000) {
		t.Fatalf("expected rate_limit_tpm 50000, got: %v", sanitizedConfigData["rate_limit_tpm"])
	}
	if sanitizedConfigData["uptime_sla"] != 99.95 {
		t.Fatalf("expected uptime_sla 99.95, got: %v", sanitizedConfigData["uptime_sla"])
	}

	// Verify nested structure redaction & primitive preservation
	nested, ok := sanitizedConfigData["nested_settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested_settings map, got: %T", sanitizedConfigData["nested_settings"])
	}
	if nested["auth_token"] != "[REDACTED]" {
		t.Fatalf("expected nested auth_token to be [REDACTED], got: %v", nested["auth_token"])
	}
	if nested["max_conns"] != float64(1000) {
		t.Fatalf("expected nested max_conns 1000, got: %v", nested["max_conns"])
	}
	if nested["enabled"] != true {
		t.Fatalf("expected nested enabled true, got: %v", nested["enabled"])
	}
}

func TestDiagnostics_SanitizeSecretFields_PrimitivesAndEdgeCases(t *testing.T) {
	// 1. Primitive Booleans & Numbers
	if res := diagnostics.SanitizeSecretFields(true); res != true {
		t.Fatalf("expected true, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(false); res != false {
		t.Fatalf("expected false, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(10102); res != 10102 {
		t.Fatalf("expected 10102, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(int64(999999)); res != int64(999999) {
		t.Fatalf("expected int64(999999), got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(3.14159); res != 3.14159 {
		t.Fatalf("expected 3.14159, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(nil); res != nil {
		t.Fatalf("expected nil, got %v", res)
	}

	// 2. Sensitive vs Non-Sensitive Strings
	if res := diagnostics.SanitizeSecretFields("public_api"); res != "public_api" {
		t.Fatalf("expected public_api preserved, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields("sk-live-secret-999"); res != "[REDACTED]" {
		t.Fatalf("expected sk-live secret redacted, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields("Bearer eyJhbGciOi..."); res != "[REDACTED]" {
		t.Fatalf("expected Bearer token redacted, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields("AKIAIOSFODNN7EXAMPLE"); res != "[REDACTED]" {
		t.Fatalf("expected AKIA key redacted, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields("vault.bifrost/keys/prod"); res != "[REDACTED]" {
		t.Fatalf("expected vault path redacted, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields("ghp_github_pat_123"); res != "[REDACTED]" {
		t.Fatalf("expected ghp token redacted, got %v", res)
	}

	// 3. Typed Struct with Mixed Primitives and Secrets
	type TypedGatewayConfig struct {
		ClusterMesh bool    `json:"cluster_mesh"`
		SyncPort    int     `json:"sync_port"`
		Threshold   float64 `json:"threshold"`
		APIKey      string  `json:"api_key"`
		Password    string  `json:"password"`
		Host        string  `json:"host"`
	}

	cfg := TypedGatewayConfig{
		ClusterMesh: true,
		SyncPort:    10102,
		Threshold:   0.99,
		APIKey:      "sk-live-test",
		Password:    "super-secret-pwd",
		Host:        "gateway.internal",
	}

	sanitized := diagnostics.SanitizeSecretFields(cfg)
	m, ok := sanitized.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got: %T", sanitized)
	}
	if m["api_key"] != "[REDACTED]" {
		t.Fatalf("expected api_key redacted, got %v", m["api_key"])
	}
	if m["password"] != "[REDACTED]" {
		t.Fatalf("expected password redacted, got %v", m["password"])
	}
	if m["cluster_mesh"] != true {
		t.Fatalf("expected cluster_mesh true, got %v", m["cluster_mesh"])
	}
	if m["sync_port"] != float64(10102) {
		t.Fatalf("expected sync_port 10102, got %v", m["sync_port"])
	}
	if m["threshold"] != 0.99 {
		t.Fatalf("expected threshold 0.99, got %v", m["threshold"])
	}
	if m["host"] != "gateway.internal" {
		t.Fatalf("expected host gateway.internal, got %v", m["host"])
	}

	// 4. Custom Types
	type CustomPort int
	type CustomFlag bool
	type CustomToken string

	if res := diagnostics.SanitizeSecretFields(CustomPort(8080)); res != CustomPort(8080) {
		t.Fatalf("expected CustomPort(8080), got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(CustomFlag(true)); res != CustomFlag(true) {
		t.Fatalf("expected CustomFlag(true), got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(CustomToken("sk-live-custom")); res != "[REDACTED]" {
		t.Fatalf("expected CustomToken redacted, got %v", res)
	}
}

func TestDiagnostics_ConcurrentRecording_RaceDetector(t *testing.T) {
	tracker := diagnostics.NewSLATracker()

	workers := 20
	iterations := 100
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tracker.RecordRequest("anthropic", "claude-sonnet-4-5", 25*time.Millisecond, i%10 != 0)
				if i%20 == 0 {
					_, _ = tracker.GenerateSLAReport(context.Background(), "1h")
				}
			}
		}(w)
	}

	wg.Wait()

	report, err := tracker.GenerateSLAReport(context.Background(), "24h")
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}
	if report.TotalRequests != int64(workers*iterations) {
		t.Fatalf("expected %d requests, got %d", workers*iterations, report.TotalRequests)
	}
}
