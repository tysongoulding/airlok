package diagnostics_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/diagnostics"
)

type CustomPort int
type CustomFlag bool
type CustomRate uint64
type CustomMetric float64
type CustomSecret string

type ComplexStruct struct {
	Port       CustomPort   `json:"port"`
	Flag       CustomFlag   `json:"flag"`
	Rate       CustomRate   `json:"rate"`
	Metric     CustomMetric `json:"metric"`
	SecretKey  CustomSecret `json:"secret_key"`
	APIKey     string       `json:"api_key"`
	SafeString string       `json:"safe_string"`
}

// ============================================================================
// EMPIRICAL CHALLENGE 1: EXTENSIVE PRIMITIVE & CUSTOM TYPE STACK SAFETY
// ============================================================================

func TestAdversarial_Challenger2_AllGoPrimitivesAndCustomTypes(t *testing.T) {
	// 1. Primitive scalars must return exactly identical values in O(1)
	primitives := []interface{}{
		true,
		false,
		int(42),
		int8(-8),
		int16(-16),
		int32(-32),
		int64(-64),
		uint(42),
		uint8(8),
		uint16(16),
		uint32(32),
		uint64(64),
		uintptr(12345),
		float32(3.14),
		float64(2.718281828459),
		complex64(complex(1, 2)),
		complex128(complex(3, 4)),
		nil,
	}

	for _, p := range primitives {
		res := diagnostics.SanitizeSecretFields(p)
		if res != p {
			t.Fatalf("expected primitive %v (%T) returned identical, got %v (%T)", p, p, res, res)
		}
	}

	// 2. Custom defined types based on primitives
	if res := diagnostics.SanitizeSecretFields(CustomPort(8080)); res != CustomPort(8080) {
		t.Fatalf("expected CustomPort(8080) preserved, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(CustomFlag(true)); res != CustomFlag(true) {
		t.Fatalf("expected CustomFlag(true) preserved, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(CustomRate(100000)); res != CustomRate(100000) {
		t.Fatalf("expected CustomRate(100000) preserved, got %v", res)
	}
	if res := diagnostics.SanitizeSecretFields(CustomMetric(99.95)); res != CustomMetric(99.95) {
		t.Fatalf("expected CustomMetric(99.95) preserved, got %v", res)
	}
	// Custom string with sensitive value must be redacted
	if res := diagnostics.SanitizeSecretFields(CustomSecret("sk-proj-custom-secret")); res != "[REDACTED]" {
		t.Fatalf("expected sensitive CustomSecret redacted, got %v", res)
	}

	// 3. Nested slices of numbers and mixed types
	nestedSlices := []interface{}{
		[]int{1, 2, 3, 4, 5},
		[][]int{{10, 20}, {30, 40}},
		[]interface{}{
			[]float64{1.1, 2.2},
			[]string{"safe_val", "sk-nested-key"},
			CustomPort(9090),
			true,
		},
	}
	sanitizedSlices := diagnostics.SanitizeSecretFields(nestedSlices)
	raw, err := json.Marshal(sanitizedSlices)
	if err != nil {
		t.Fatalf("failed to marshal sanitized nested slices: %v", err)
	}
	rawStr := string(raw)
	if strings.Contains(rawStr, "sk-nested-key") {
		t.Fatalf("nested secret leaked in slice: %s", rawStr)
	}
	if !strings.Contains(rawStr, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in nested slice, got: %s", rawStr)
	}

	// 4. Complex typed struct with mixed fields
	cs := ComplexStruct{
		Port:       CustomPort(10101),
		Flag:       CustomFlag(true),
		Rate:       CustomRate(50000),
		Metric:     CustomMetric(99.99),
		SecretKey:  CustomSecret("Bearer custom-secret-token"),
		APIKey:     "sk-top-secret-openai-key",
		SafeString: "bifrost-mesh-node",
	}
	sanitizedStruct := diagnostics.SanitizeSecretFields(cs)
	csBytes, err := json.Marshal(sanitizedStruct)
	if err != nil {
		t.Fatalf("failed to marshal sanitized struct: %v", err)
	}
	csStr := string(csBytes)
	if strings.Contains(csStr, "custom-secret-token") || strings.Contains(csStr, "sk-top-secret-openai-key") {
		t.Fatalf("sensitive struct fields leaked: %s", csStr)
	}
	if !strings.Contains(csStr, "bifrost-mesh-node") {
		t.Fatalf("safe string missing from sanitized struct: %s", csStr)
	}

	// 5. Deep recursion stack safety (bounded within maxSanitizerDepth)
	deepMap := make(map[string]interface{})
	curr := deepMap
	for i := 0; i < 25; i++ {
		next := make(map[string]interface{})
		curr[fmt.Sprintf("level_%d", i)] = next
		curr["bool_val"] = (i%2 == 0)
		curr["int_val"] = i
		if i == 24 {
			next["deep_secret_token"] = "sk-deep-nested-12345"
			next["deep_safe_value"] = "safe_at_level_25"
		}
		curr = next
	}
	sanitizedDeep := diagnostics.SanitizeSecretFields(deepMap)
	deepBytes, err := json.Marshal(sanitizedDeep)
	if err != nil {
		t.Fatalf("failed to marshal deep map: %v", err)
	}
	deepStr := string(deepBytes)
	if strings.Contains(deepStr, "sk-deep-nested-12345") {
		t.Fatalf("deep secret leaked: %s", deepStr)
	}
	if !strings.Contains(deepStr, "safe_at_level_25") {
		t.Fatalf("deep safe value missing: %s", deepStr)
	}

	// Beyond maxSanitizerDepth (40 levels) must be safely bounded with [MAX_DEPTH_EXCEEDED]
	veryDeepMap := make(map[string]interface{})
	vCurr := veryDeepMap
	for i := 0; i < 40; i++ {
		vNext := make(map[string]interface{})
		vCurr[fmt.Sprintf("level_%d", i)] = vNext
		vCurr = vNext
	}
	sanitizedVeryDeep := diagnostics.SanitizeSecretFields(veryDeepMap)
	veryDeepBytes, err := json.Marshal(sanitizedVeryDeep)
	if err != nil {
		t.Fatalf("failed to marshal very deep map: %v", err)
	}
	if !strings.Contains(string(veryDeepBytes), "[MAX_DEPTH_EXCEEDED]") {
		t.Fatalf("expected [MAX_DEPTH_EXCEEDED] in deep map output: %s", string(veryDeepBytes))
	}
}

// ============================================================================
// EMPIRICAL CHALLENGE 2: HEALTH BUNDLE ENDPOINT INTEGRITY & ARCHIVE TARBALL
// ============================================================================

func TestAdversarial_Challenger2_HealthBundle_FullArchiveIntegrity(t *testing.T) {
	testConfig := map[string]interface{}{
		"api_key":      "sk-live-full-archive-secret-123",
		"vault_token":  "s.abcdef9876543210",
		"db_password":  "super_secret_database_pwd",
		"conn_str":     "postgres://user:super_secret_database_pwd@db:5432/airlok",
		"sync_port":    10102,
		"gossip_port":  10101,
		"cluster_mesh": true,
		"debug_mode":   false,
		"sla_target":   99.95,
		"custom_port":  CustomPort(8080),
		"allowed_ips":  []string{"10.0.0.1", "10.0.0.2"},
		"nested_governance": map[string]interface{}{
			"auth_token": "Bearer token_secret_12345",
			"max_burst":  500,
			"enabled":    true,
		},
	}

	clusterFn := func() map[string]interface{} {
		return map[string]interface{}{
			"node_id":   "airlok-primary-01",
			"is_leader": true,
			"peers":     []string{"airlok-replica-02:10101"},
		}
	}

	gen := diagnostics.NewHealthBundleGenerator(testConfig, clusterFn)
	archiveBytes, err := gen.ExportHealthBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportHealthBundle failed: %v", err)
	}

	if len(archiveBytes) < 100 {
		t.Fatalf("archive unexpectedly small (%d bytes)", len(archiveBytes))
	}

	// Decompress gzip
	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		t.Fatalf("gzip reader creation failed: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	filesFound := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read error: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("failed to read tar entry %s: %v", hdr.Name, err)
		}
		filesFound[hdr.Name] = content
	}

	// Verify all 6 mandatory files are present
	requiredFiles := []string{
		"diagnostics.json",
		"system_info.json",
		"runtime_memory.json",
		"goroutines.txt",
		"cluster_topology.json",
		"sanitized_config.json",
	}
	for _, req := range requiredFiles {
		if _, ok := filesFound[req]; !ok {
			t.Fatalf("missing required file in health bundle: %s", req)
		}
	}

	// 1. diagnostics.json: version MUST be verbatim "1.0-enterprise"
	var diagMap map[string]interface{}
	if err := json.Unmarshal(filesFound["diagnostics.json"], &diagMap); err != nil {
		t.Fatalf("invalid diagnostics.json: %v", err)
	}
	if v, ok := diagMap["version"].(string); !ok || v != "1.0-enterprise" {
		t.Fatalf("diagnostics.json version is not verbatim '1.0-enterprise', got: %v", diagMap["version"])
	}

	// 2. sanitized_config.json: NO plaintext secrets leaked, primitives preserved
	var sanConfig map[string]interface{}
	if err := json.Unmarshal(filesFound["sanitized_config.json"], &sanConfig); err != nil {
		t.Fatalf("invalid sanitized_config.json: %v", err)
	}

	rawSanitized := string(filesFound["sanitized_config.json"])
	secrets := []string{
		"sk-live-full-archive-secret-123",
		"s.abcdef9876543210",
		"super_secret_database_pwd",
		"token_secret_12345",
	}
	for _, s := range secrets {
		if strings.Contains(rawSanitized, s) {
			t.Fatalf("CRITICAL SECURITY DEFECT: plaintext secret %q leaked in sanitized_config.json:\n%s", s, rawSanitized)
		}
	}

	// Primitives verification
	if sanConfig["cluster_mesh"] != true {
		t.Fatalf("expected cluster_mesh true, got: %v", sanConfig["cluster_mesh"])
	}
	if sanConfig["debug_mode"] != false {
		t.Fatalf("expected debug_mode false, got: %v", sanConfig["debug_mode"])
	}
	if sanConfig["sync_port"] != float64(10102) {
		t.Fatalf("expected sync_port 10102, got: %v", sanConfig["sync_port"])
	}
	if sanConfig["gossip_port"] != float64(10101) {
		t.Fatalf("expected gossip_port 10101, got: %v", sanConfig["gossip_port"])
	}
	if sanConfig["sla_target"] != 99.95 {
		t.Fatalf("expected sla_target 99.95, got: %v", sanConfig["sla_target"])
	}
}

// ============================================================================
// EMPIRICAL CHALLENGE 3: HIGH CONCURRENCY GENERATION & RECORDING STRESS
// ============================================================================

func TestAdversarial_Challenger2_ConcurrentSLAAndHealthBundleStress(t *testing.T) {
	tracker := diagnostics.NewSLATracker()

	testCfg := map[string]interface{}{
		"api_key":   "sk-stress-key-999",
		"sync_port": 10102,
		"enabled":   true,
	}
	gen := diagnostics.NewHealthBundleGenerator(testCfg, nil)
	tracker.SetHealthBundleGenerator(gen)

	const numWriters = 200
	const numReaders = 50
	const operationsPerWorker = 50

	var wg sync.WaitGroup
	wg.Add(numWriters + numReaders)

	startBarrier := make(chan struct{})

	// 200 writer goroutines recording requests
	for w := 0; w < numWriters; w++ {
		go func(workerID int) {
			defer wg.Done()
			<-startBarrier

			r := rand.New(rand.NewSource(int64(workerID)))
			for i := 0; i < operationsPerWorker; i++ {
				dur := time.Duration(10+r.Intn(100)) * time.Millisecond
				success := (r.Intn(100) < 95)
				tracker.RecordRequest("openai", "gpt-4o", dur, success)
			}
		}(w)
	}

	// 50 reader goroutines concurrently generating SLA reports and health bundles
	for r := 0; r < numReaders; r++ {
		go func(readerID int) {
			defer wg.Done()
			<-startBarrier

			for i := 0; i < operationsPerWorker; i++ {
				if i%2 == 0 {
					report, err := tracker.GenerateSLAReport(context.Background(), "24h")
					if err != nil {
						t.Errorf("GenerateSLAReport failed under concurrency: %v", err)
					}
					if report == nil || report.Status == "" {
						t.Errorf("nil or invalid report received under concurrency")
					}
				} else {
					bundle, err := tracker.ExportHealthBundle(context.Background())
					if err != nil {
						t.Errorf("ExportHealthBundle failed under concurrency: %v", err)
					}
					if len(bundle) == 0 {
						t.Errorf("empty bundle received under concurrency")
					}
				}
			}
		}(r)
	}

	close(startBarrier)
	wg.Wait()

	// Final verification
	finalReport, err := tracker.GenerateSLAReport(context.Background(), "24h")
	if err != nil {
		t.Fatalf("final SLA report failed: %v", err)
	}
	if finalReport.TotalRequests != int64(numWriters*operationsPerWorker) {
		t.Fatalf("expected total requests %d, got %d", numWriters*operationsPerWorker, finalReport.TotalRequests)
	}
}
