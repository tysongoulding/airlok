package handlers_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"sync"
	"testing"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/maximhq/bifrost/framework/rbac"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// EMPIRICAL CHALLENGE: HTTP HEALTH BUNDLE ENDPOINT INTEGRITY WITH PRIMITIVES
// ============================================================================

func TestAdversarial_Challenger2_HTTPHealthBundle_VerbatimVersionAndPrimitives(t *testing.T) {
	fullConfig := map[string]interface{}{
		"provider_token": "sk-proj-super-secret-key-999",
		"vault_address":  "vault.corp.internal/v1/secret",
		"cluster_mesh":   true,
		"debug_mode":     false,
		"sync_port":      10102,
		"gossip_port":    10101,
		"sla_target_pct": 99.95,
		"nested_info": map[string]interface{}{
			"auth_header": "Bearer secret_bearer_token",
			"concurrency": 250,
			"is_active":   true,
		},
	}

	clusterMock := func() map[string]interface{} {
		return map[string]interface{}{
			"nodes": []string{"node-01:10101", "node-02:10101"},
		}
	}

	tracker := diagnostics.NewSLATracker()
	gen := diagnostics.NewHealthBundleGenerator(fullConfig, clusterMock)
	tracker.SetHealthBundleGenerator(gen)

	diagHandler := handlers.NewDiagnosticsHandler(tracker)
	r := router.New()
	diagHandler.RegisterRoutes(r)

	// Make HTTP request to /api/v1/enterprise/diagnostics/health-bundle
	reqCtx := &fasthttp.RequestCtx{}
	reqCtx.Request.Header.SetMethod("GET")
	reqCtx.Request.SetRequestURI("/api/v1/enterprise/diagnostics/health-bundle")

	r.Handler(reqCtx)

	// Verify HTTP 200 and Content-Type header
	if reqCtx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", reqCtx.Response.StatusCode())
	}
	if string(reqCtx.Response.Header.ContentType()) != "application/gzip" {
		t.Fatalf("expected application/gzip, got %s", string(reqCtx.Response.Header.ContentType()))
	}
	if string(reqCtx.Response.Header.Peek("Content-Disposition")) != "attachment; filename=\"bifrost-health-bundle.tar.gz\"" {
		t.Fatalf("expected Content-Disposition attachment, got %s", string(reqCtx.Response.Header.Peek("Content-Disposition")))
	}

	// Decompress gzip response
	bodyBytes := reqCtx.Response.Body()
	gr, err := gzip.NewReader(bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("failed to open gzip reader on response body: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	archiveEntries := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar decompression error: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("failed to read tar entry %s: %v", hdr.Name, err)
		}
		archiveEntries[hdr.Name] = data
	}

	// Verify all 6 mandatory files are present
	for _, expectedFile := range []string{
		"diagnostics.json", "system_info.json", "runtime_memory.json",
		"goroutines.txt", "cluster_topology.json", "sanitized_config.json",
	} {
		if _, ok := archiveEntries[expectedFile]; !ok {
			t.Fatalf("required archive file %q missing from HTTP health bundle response", expectedFile)
		}
	}

	// 1. diagnostics.json version check (MUST be verbatim "1.0-enterprise")
	var diagJSON map[string]interface{}
	if err := json.Unmarshal(archiveEntries["diagnostics.json"], &diagJSON); err != nil {
		t.Fatalf("failed to parse diagnostics.json: %v", err)
	}
	if diagJSON["version"] != "1.0-enterprise" {
		t.Fatalf("expected verbatim version '1.0-enterprise', got %v", diagJSON["version"])
	}

	// 2. sanitized_config.json: verify secret scrubbing and primitive preservation
	var sanConfig map[string]interface{}
	if err := json.Unmarshal(archiveEntries["sanitized_config.json"], &sanConfig); err != nil {
		t.Fatalf("failed to parse sanitized_config.json: %v", err)
	}

	rawSan := string(archiveEntries["sanitized_config.json"])
	if bytes.Contains(archiveEntries["sanitized_config.json"], []byte("sk-proj-super-secret-key-999")) {
		t.Fatalf("provider_token leaked in sanitized_config.json: %s", rawSan)
	}
	if bytes.Contains(archiveEntries["sanitized_config.json"], []byte("secret_bearer_token")) {
		t.Fatalf("nested auth_header leaked in sanitized_config.json: %s", rawSan)
	}

	if sanConfig["provider_token"] != "[REDACTED]" {
		t.Fatalf("expected provider_token [REDACTED], got %v", sanConfig["provider_token"])
	}
	if sanConfig["cluster_mesh"] != true {
		t.Fatalf("expected cluster_mesh true, got %v", sanConfig["cluster_mesh"])
	}
	if sanConfig["debug_mode"] != false {
		t.Fatalf("expected debug_mode false, got %v", sanConfig["debug_mode"])
	}
	if sanConfig["sync_port"] != float64(10102) {
		t.Fatalf("expected sync_port 10102, got %v", sanConfig["sync_port"])
	}
	if sanConfig["gossip_port"] != float64(10101) {
		t.Fatalf("expected gossip_port 10101, got %v", sanConfig["gossip_port"])
	}
	if sanConfig["sla_target_pct"] != 99.95 {
		t.Fatalf("expected sla_target_pct 99.95, got %v", sanConfig["sla_target_pct"])
	}
}

// ============================================================================
// EMPIRICAL CHALLENGE: CONCURRENT HTTP 403 / 200 WITH UNUSUAL ROLES & CASE DRIFT
// ============================================================================

func TestAdversarial_Challenger2_HTTP_AdversarialRolePermutations(t *testing.T) {
	authorizer := rbac.NewRBACAuthorizer()
	mw := handlers.NewRBACMiddleware(authorizer)

	targetHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString(`{"success":true}`)
	}

	handler := mw.Require(rbac.ResourceVirtualKeys, rbac.OpCreate)(targetHandler)

	const numWorkers = 200
	const iters = 20
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				// 1. Developer and Admin can create virtual keys -> HTTP 200
				ctxDev := &fasthttp.RequestCtx{}
				ctxDev.Request.Header.Set("X-User-Role", "Developer")
				handler(ctxDev)
				if ctxDev.Response.StatusCode() != fasthttp.StatusOK {
					t.Errorf("expected 200 for Developer creating virtual keys, got %d", ctxDev.Response.StatusCode())
				}

				// 2. Operator cannot create virtual keys -> HTTP 403
				ctxOp := &fasthttp.RequestCtx{}
				ctxOp.Request.Header.Set("X-User-Role", "Operator")
				handler(ctxOp)
				if ctxOp.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for Operator creating virtual keys, got %d", ctxOp.Response.StatusCode())
				}

				// 3. Security Auditor cannot create virtual keys -> HTTP 403
				ctxAudit := &fasthttp.RequestCtx{}
				ctxAudit.Request.Header.Set("X-User-Role", "Security Auditor")
				handler(ctxAudit)
				if ctxAudit.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for Security Auditor creating virtual keys, got %d", ctxAudit.Response.StatusCode())
				}

				// 4. Case sensitivity: "developer" != "Developer" -> HTTP 403
				ctxBadCase := &fasthttp.RequestCtx{}
				ctxBadCase.Request.Header.Set("X-User-Role", "developer")
				handler(ctxBadCase)
				if ctxBadCase.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for lower-case 'developer', got %d", ctxBadCase.Response.StatusCode())
				}

				// 5. Injected header: "Developer\r\nAdmin" -> HTTP 403
				ctxInject := &fasthttp.RequestCtx{}
				ctxInject.Request.Header.Set("X-User-Role", "Developer\nAdmin")
				handler(ctxInject)
				if ctxInject.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for header injection, got %d", ctxInject.Response.StatusCode())
				}
			}
		}(w)
	}

	wg.Wait()
}
