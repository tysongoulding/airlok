package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// CHALLENGE 1: HEALTH BUNDLE ARCHIVE INTEGRITY & VERBATIM VERSION CHECK
// ============================================================================

func TestAdversarial_HealthBundleExport_ArchiveIntegrity_And_VerbatimVersion(t *testing.T) {
	cfg := map[string]interface{}{
		"api_key":      "sk-proj-test-key-12345",
		"environment":  "production",
		"cluster_mesh": true,
		"sync_port":    10102,
	}

	mockClusterProvider := func() map[string]interface{} {
		return map[string]interface{}{
			"cluster_enabled": true,
			"node_id":         "node-alpha-1",
			"peers":           []string{"10.0.0.1:10101", "10.0.0.2:10101"},
			"sync_port":       10102,
			"gossip_port":     10101,
		}
	}

	gen := NewHealthBundleGenerator(cfg, mockClusterProvider)
	bundleBytes, err := gen.ExportHealthBundle(context.Background())
	if err != nil {
		t.Fatalf("failed to export health bundle: %v", err)
	}

	if len(bundleBytes) == 0 {
		t.Fatalf("exported health bundle archive is empty")
	}

	// Decompress gzip stream
	gzReader, err := gzip.NewReader(bytes.NewReader(bundleBytes))
	if err != nil {
		t.Fatalf("failed to create gzip reader on bundle: %v", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	archiveFiles := make(map[string][]byte)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar decompression error: %v", err)
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("failed to read tar entry %s: %v", header.Name, err)
		}
		archiveFiles[header.Name] = content
	}

	// 1. Verify all 6 mandatory files exist in archive
	requiredFiles := []string{
		"diagnostics.json",
		"system_info.json",
		"runtime_memory.json",
		"goroutines.txt",
		"cluster_topology.json",
		"sanitized_config.json",
	}

	for _, reqFile := range requiredFiles {
		data, exists := archiveFiles[reqFile]
		if !exists {
			t.Fatalf("archive integrity failure: missing required file %q in health bundle", reqFile)
		}
		if len(data) == 0 {
			t.Fatalf("archive integrity failure: file %q is empty in health bundle", reqFile)
		}
	}

	// 2. Verbatim version check in diagnostics.json
	var diagJSON map[string]interface{}
	if err := json.Unmarshal(archiveFiles["diagnostics.json"], &diagJSON); err != nil {
		t.Fatalf("failed to parse diagnostics.json: %v", err)
	}

	versionVal, ok := diagJSON["version"].(string)
	if !ok || versionVal != "1.0-enterprise" {
		t.Fatalf("diagnostics.json version mismatch: expected verbatim '1.0-enterprise', got %q", versionVal)
	}

	if diagJSON["status"] != "HEALTHY" {
		t.Fatalf("expected status 'HEALTHY', got %v", diagJSON["status"])
	}

	// 3. Inspect system_info.json
	var sysInfo map[string]interface{}
	if err := json.Unmarshal(archiveFiles["system_info.json"], &sysInfo); err != nil {
		t.Fatalf("failed to parse system_info.json: %v", err)
	}
	if sysInfo["os"] == "" || sysInfo["arch"] == "" || sysInfo["go_version"] == "" {
		t.Fatalf("system_info.json missing core runtime telemetry")
	}

	// 4. Inspect runtime_memory.json
	var memStats map[string]interface{}
	if err := json.Unmarshal(archiveFiles["runtime_memory.json"], &memStats); err != nil {
		t.Fatalf("failed to parse runtime_memory.json: %v", err)
	}
	if alloc, ok := memStats["alloc_bytes"].(float64); !ok || alloc == 0 {
		t.Fatalf("runtime_memory.json invalid alloc_bytes: %v", memStats["alloc_bytes"])
	}

	// 5. Inspect goroutines.txt
	goroutinesDump := string(archiveFiles["goroutines.txt"])
	if !strings.Contains(goroutinesDump, "goroutine ") {
		t.Fatalf("goroutines.txt does not contain valid pprof stack dump")
	}

	// 6. Inspect cluster_topology.json
	var clusterJSON map[string]interface{}
	if err := json.Unmarshal(archiveFiles["cluster_topology.json"], &clusterJSON); err != nil {
		t.Fatalf("failed to parse cluster_topology.json: %v", err)
	}
	if clusterJSON["node_id"] != "node-alpha-1" {
		t.Fatalf("expected node_id 'node-alpha-1', got %v", clusterJSON["node_id"])
	}
}

// ============================================================================
// CHALLENGE 2: RECURSIVE SECRET SCRUBBING ON COMPLEX NESTED STRUCTURES
// ============================================================================

type testUserCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	HMACKey  string `json:"hmac_key"`
}

type testDatabaseConfig struct {
	ConnString string `json:"conn_str"`
	DBPassword string `json:"db_password"`
	Host       string `json:"host"`
	Port       string `json:"port"`
}

type testNestedConfig struct {
	APIKey         string                 `json:"api_key"`
	SecretToken    string                 `json:"secret_token"`
	Password       string                 `json:"password"`
	Bearer         string                 `json:"auth_bearer"`
	PrivateKey     string                 `json:"private_key"`
	ClientSecret   string                 `json:"client_secret"`
	Database       testDatabaseConfig     `json:"database"`
	Users          []testUserCredential   `json:"users"`
	AuthTokens     []interface{}          `json:"auth_tokens"`
	ArbitraryMap   map[string]interface{} `json:"arbitrary_map"`
	PreservedHost  string                 `json:"public_hostname"`
	PreservedDebug string                 `json:"debug_mode"`
}

func TestAdversarial_SecretScrubbing_DeepNestedStructures(t *testing.T) {
	plainSecrets := []string{
		"sk-live-deep-key-1234567890",
		"ghp_github_personal_access_token_999",
		"AKIAIOSFODNN7EXAMPLE_AWS_KEY",
		"vault.bifrost/keys/production#secret_token",
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature",
		"super_secret_db_password_xyz!",
		"user_plaintext_password_456!",
		"hmac_secret_sha256_key_9999",
		"my_oauth_client_secret_xyz",
		"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
	}

	nestedPayload := testNestedConfig{
		APIKey:       plainSecrets[0],
		SecretToken:  plainSecrets[1],
		Password:     "my_top_secret_password_111",
		Bearer:       plainSecrets[4],
		PrivateKey:   plainSecrets[9],
		ClientSecret: plainSecrets[8],
		Database: testDatabaseConfig{
			ConnString: "postgres://user:super_secret_db_password_xyz!@db:5432/airlok",
			DBPassword: plainSecrets[5],
			Host:       "database.internal",
			Port:       "5432",
		},
		Users: []testUserCredential{
			{Username: "operator_alice", Password: plainSecrets[6], HMACKey: plainSecrets[7]},
		},
		AuthTokens: []interface{}{
			plainSecrets[4], // Bearer
			plainSecrets[0], // sk-
			plainSecrets[2], // AKIA
			plainSecrets[3], // vault.
			map[string]interface{}{
				"deep_secret_key": "nested-token-value-999",
				"public_field":    "visible-data",
			},
		},
		ArbitraryMap: map[string]interface{}{
			"secret_token": "sensitive_val",
			"private_key":  "sensitive_rsa",
			"sub_tree": map[string]interface{}{
				"token":     "deep_token_val",
				"safe_name": "gateway_mesh",
			},
		},
		PreservedHost:  "api.enterprise.airlok.com",
		PreservedDebug: "disabled",
	}

	// 1. Direct SanitizeSecretFields call
	sanitized := SanitizeSecretFields(nestedPayload)
	if sanitized == nil {
		t.Fatalf("sanitized result is nil")
	}

	sanitizedBytes, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal sanitized output: %v", err)
	}
	sanitizedStr := string(sanitizedBytes)

	// 2. Audit zero plaintext leakage across all secret strings
	for _, secret := range plainSecrets {
		if strings.Contains(sanitizedStr, secret) {
			t.Fatalf("CRITICAL SECURITY LEAK: plaintext secret %q found in sanitized output:\n%s", secret, sanitizedStr)
		}
	}

	// Check sensitive substrings are absent
	forbiddenSubstrings := []string{
		"my_top_secret_password_111",
		"nested-token-value-999",
		"sensitive_val",
		"sensitive_rsa",
		"deep_token_val",
	}
	for _, forbidden := range forbiddenSubstrings {
		if strings.Contains(sanitizedStr, forbidden) {
			t.Fatalf("CRITICAL SECURITY LEAK: sensitive field value %q was not redacted:\n%s", forbidden, sanitizedStr)
		}
	}

	// 3. Verify public non-sensitive fields are preserved
	if !strings.Contains(sanitizedStr, "api.enterprise.airlok.com") {
		t.Fatalf("expected preserved public_hostname 'api.enterprise.airlok.com' missing")
	}
	if !strings.Contains(sanitizedStr, "operator_alice") {
		t.Fatalf("expected preserved username 'operator_alice' missing")
	}
	if !strings.Contains(sanitizedStr, "gateway_mesh") {
		t.Fatalf("expected preserved safe_name 'gateway_mesh' missing")
	}

	// 4. Test within HealthBundleGenerator export
	gen := NewHealthBundleGenerator(nestedPayload, nil)
	bundle, err := gen.ExportHealthBundle(context.Background())
	if err != nil {
		t.Fatalf("export health bundle failed with nested config: %v", err)
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var sanitizedConfigBytes []byte
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar error: %v", err)
		}
		if hdr.Name == "sanitized_config.json" {
			sanitizedConfigBytes, _ = io.ReadAll(tarReader)
			break
		}
	}

	if len(sanitizedConfigBytes) == 0 {
		t.Fatalf("sanitized_config.json missing from health bundle")
	}

	bundleSanitizedStr := string(sanitizedConfigBytes)
	for _, secret := range plainSecrets {
		if strings.Contains(bundleSanitizedStr, secret) {
			t.Fatalf("CRITICAL SECURITY LEAK: plaintext secret %q found in health bundle sanitized_config.json:\n%s", secret, bundleSanitizedStr)
		}
	}
}

// ============================================================================
// CHALLENGE 2B: EMPIRICAL REPRODUCTION OF SANITIZER FATAL STACK OVERFLOW
// ============================================================================

func TestAdversarial_SanitizeSecretFields_NonStringPrimitive_FatalStackOverflow(t *testing.T) {
	if os.Getenv("TEST_CRASH_CHILD") == "1" {
		// When called with a boolean (e.g. true) or integer, SanitizeSecretFields must
		// return without stack overflow.
		_ = SanitizeSecretFields(true)
		_ = SanitizeSecretFields(10102)
		return
	}

	// 1. Direct in-process verification
	if res := SanitizeSecretFields(true); res != true {
		t.Fatalf("expected true, got %v", res)
	}
	if res := SanitizeSecretFields(10102); res != 10102 {
		t.Fatalf("expected 10102, got %v", res)
	}

	// 2. Child process verification: verify process exits cleanly with exit code 0 (no stack overflow)
	cmd := exec.Command(os.Args[0], "-test.run=TestAdversarial_SanitizeSecretFields_NonStringPrimitive_FatalStackOverflow")
	cmd.Env = append(os.Environ(), "TEST_CRASH_CHILD=1")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("expected child process to exit cleanly, but failed with: %v\nOutput: %s", err, string(out))
	}

	outputStr := string(out)
	if strings.Contains(outputStr, "stack overflow") || strings.Contains(outputStr, "goroutine stack exceeds") {
		t.Fatalf("fatal stack overflow detected in output: %s", outputStr)
	}
}

// ============================================================================
// CHALLENGE 3: SLA HIGH CONCURRENCY (100,000 REQUESTS / 500 GOROUTINES)
// ============================================================================

func TestAdversarial_SLAReporting_100kRequests_500Goroutines_MathCorrectness(t *testing.T) {
	tracker := NewSLATracker()

	const numWorkers = 500
	const requestsPerWorker = 200 // 500 * 200 = 100,000 requests

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	startBarrier := make(chan struct{})

	// Concurrently run 5 reader goroutines polling SLA reports under high write load
	var readWg sync.WaitGroup
	readStop := make(chan struct{})
	for r := 0; r < 5; r++ {
		readWg.Add(1)
		go func() {
			defer readWg.Done()
			<-startBarrier
			for {
				select {
				case <-readStop:
					return
				default:
					_, _ = tracker.GenerateSLAReport(context.Background(), "24h")
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			<-startBarrier

			// Each worker runs 200 requests with identical 25-request deterministic distribution:
			// - 15 requests (60%): 20ms latency, success true
			// - 9 requests  (36%): 60ms latency, success true
			// - 1 request   (4%):  120ms latency, success false
			for req := 0; req < requestsPerWorker; req++ {
				cycleIdx := req % 25
				var latMs float64
				var success bool
				var provider string

				if workerID%2 == 0 {
					provider = "openai"
				} else {
					provider = "anthropic"
				}

				if cycleIdx < 15 {
					latMs = 20.0
					success = true
				} else if cycleIdx < 24 {
					latMs = 60.0
					success = true
				} else {
					latMs = 120.0
					success = false
				}

				tracker.RecordRequest(provider, "claude-or-gpt", time.Duration(latMs*1000)*time.Microsecond, success)
			}
		}()
	}

	close(startBarrier)
	wg.Wait()
	close(readStop)
	readWg.Wait()

	// Verify mathematically exact totals across the 100,000 requests
	report, err := tracker.GenerateSLAReport(context.Background(), "24h")
	if err != nil {
		t.Fatalf("failed to generate 24h SLA report: %v", err)
	}

	const expectedTotal = int64(100000)
	const expectedSuccessful = int64(96000) // 96%
	const expectedFailed = int64(4000)      // 4%

	if report.TotalRequests != expectedTotal {
		t.Fatalf("expected total %d requests, got %d", expectedTotal, report.TotalRequests)
	}
	if report.SuccessfulRequests != expectedSuccessful {
		t.Fatalf("expected %d successful requests, got %d", expectedSuccessful, report.SuccessfulRequests)
	}
	if report.FailedRequests != expectedFailed {
		t.Fatalf("expected %d failed requests, got %d", expectedFailed, report.FailedRequests)
	}

	expectedUptime := 96.0
	if report.UptimePct < expectedUptime-0.001 || report.UptimePct > expectedUptime+0.001 {
		t.Fatalf("expected uptime %f%%, got %f%%", expectedUptime, report.UptimePct)
	}

	// In sla.go:187-193, uptime < 99.5% maps to "DEGRADED"
	if report.Status != "DEGRADED" {
		t.Fatalf("expected DEGRADED status for 96%% uptime (<99.5%% threshold), got %s", report.Status)
	}

	// Verify mathematical percentiles:
	// Distribution: 60% @ 20ms, 36% @ 60ms, 4% @ 120ms
	// p50 must be 20.0 ms (index 0.50 falls in the 60% range)
	// p95 must be 60.0 ms (index 0.95 falls in the 36% range: 60% + 36% = 96%)
	// p99 must be 120.0 ms (index 0.99 falls in the top 4% range: 96% to 100%)
	if report.P50LatencyMs != 20.0 {
		t.Fatalf("expected p50 latency 20.0ms, got %f", report.P50LatencyMs)
	}
	if report.P95LatencyMs != 60.0 {
		t.Fatalf("expected p95 latency 60.0ms, got %f", report.P95LatencyMs)
	}
	if report.P99LatencyMs != 120.0 {
		t.Fatalf("expected p99 latency 120.0ms, got %f", report.P99LatencyMs)
	}

	// Verify provider breakdowns
	for _, prov := range []string{"openai", "anthropic"} {
		m, ok := report.ProviderMetrics[prov]
		if !ok {
			t.Fatalf("expected provider metrics for %q", prov)
		}
		if m.TotalCount != expectedTotal/2 {
			t.Fatalf("expected provider %q total %d, got %d", prov, expectedTotal/2, m.TotalCount)
		}
		if m.UptimePct < 95.9 || m.UptimePct > 96.1 {
			t.Fatalf("expected provider %q uptime ~96%%, got %f", prov, m.UptimePct)
		}
	}
}

// ============================================================================
// CHALLENGE 4: SLIDING WINDOW EVICTION MATHEMATICAL ACCURACY
// ============================================================================

func TestAdversarial_SLAReporting_SlidingWindowEviction(t *testing.T) {
	tracker := NewSLATracker()

	now := time.Now().UTC()

	// Inject 3 distinct time buckets into tracker directly:
	// Bucket 1: 25 hours ago (must be evicted from 24h window, retained in 7d window)
	// Bucket 2: 2 hours ago  (must be evicted from 1h window, included in 24h window)
	// Bucket 3: 10 minutes ago (included in 1h, 24h, and 7d windows)
	tracker.mu.Lock()
	tracker.buckets = []*timeBucket{
		{
			Timestamp:          now.Add(-25 * time.Hour).Truncate(time.Minute),
			TotalRequests:      50,
			SuccessfulRequests: 50,
			FailedRequests:     0,
			LatencySamples:     []float64{10.0, 10.0},
			ProviderSamples:    map[string][]float64{"openai": {10.0}},
			ProviderSuccess:    map[string]int64{"openai": 50},
			ProviderTotal:      map[string]int64{"openai": 50},
		},
		{
			Timestamp:          now.Add(-2 * time.Hour).Truncate(time.Minute),
			TotalRequests:      30,
			SuccessfulRequests: 28,
			FailedRequests:     2,
			LatencySamples:     []float64{25.0, 25.0},
			ProviderSamples:    map[string][]float64{"openai": {25.0}},
			ProviderSuccess:    map[string]int64{"openai": 28},
			ProviderTotal:      map[string]int64{"openai": 30},
		},
		{
			Timestamp:          now.Add(-10 * time.Minute).Truncate(time.Minute),
			TotalRequests:      20,
			SuccessfulRequests: 18,
			FailedRequests:     2,
			LatencySamples:     []float64{40.0, 40.0},
			ProviderSamples:    map[string][]float64{"openai": {40.0}},
			ProviderSuccess:    map[string]int64{"openai": 18},
			ProviderTotal:      map[string]int64{"openai": 20},
		},
	}
	tracker.mu.Unlock()

	// 1. Window: "1h" -> MUST only include Bucket 3 (10m ago)
	report1h, err := tracker.GenerateSLAReport(context.Background(), "1h")
	if err != nil {
		t.Fatalf("failed to generate 1h report: %v", err)
	}
	if report1h.TotalRequests != 20 {
		t.Fatalf("expected 1h report to only count Bucket 3 (20 requests), got %d (eviction failed)", report1h.TotalRequests)
	}
	if report1h.SuccessfulRequests != 18 || report1h.FailedRequests != 2 {
		t.Fatalf("unexpected counts in 1h report: %+v", report1h)
	}
	if report1h.P50LatencyMs != 40.0 {
		t.Fatalf("expected 1h report p50 40.0ms, got %f", report1h.P50LatencyMs)
	}

	// 2. Window: "24h" -> MUST include Bucket 2 and Bucket 3 (30 + 20 = 50 requests), evict Bucket 1 (25h ago)
	report24h, err := tracker.GenerateSLAReport(context.Background(), "24h")
	if err != nil {
		t.Fatalf("failed to generate 24h report: %v", err)
	}
	if report24h.TotalRequests != 50 {
		t.Fatalf("expected 24h report to count Buckets 2 & 3 (50 requests), got %d (25h eviction failed)", report24h.TotalRequests)
	}
	if report24h.SuccessfulRequests != 46 || report24h.FailedRequests != 4 {
		t.Fatalf("unexpected counts in 24h report: %+v", report24h)
	}

	// 3. Window: "7d" -> MUST include all 3 buckets (50 + 30 + 20 = 100 requests)
	report7d, err := tracker.GenerateSLAReport(context.Background(), "7d")
	if err != nil {
		t.Fatalf("failed to generate 7d report: %v", err)
	}
	if report7d.TotalRequests != 100 {
		t.Fatalf("expected 7d report to count all buckets (100 requests), got %d", report7d.TotalRequests)
	}
	if report7d.SuccessfulRequests != 96 || report7d.FailedRequests != 4 {
		t.Fatalf("unexpected counts in 7d report: %+v", report7d)
	}

	// 4. Test physical memory eviction via pruneOldBucketsLocked
	tracker.mu.Lock()
	// Add an ancient bucket 8 days ago (beyond 7d maxRetention)
	ancientBucket := &timeBucket{
		Timestamp:     now.Add(-8 * 24 * time.Hour),
		TotalRequests: 10,
	}
	tracker.buckets = append([]*timeBucket{ancientBucket}, tracker.buckets...)
	if len(tracker.buckets) != 4 {
		t.Fatalf("expected 4 buckets before prune")
	}
	tracker.pruneOldBucketsLocked(now)
	if len(tracker.buckets) != 3 {
		t.Fatalf("expected 3 buckets after pruneOldBucketsLocked, ancient bucket was not pruned")
	}
	if tracker.buckets[0].Timestamp.Equal(ancientBucket.Timestamp) {
		t.Fatalf("ancient bucket still present in slice after prune")
	}
	tracker.mu.Unlock()
}
