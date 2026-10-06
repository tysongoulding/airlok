package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/valyala/fasthttp"
)

func TestDiagnosticsHandler_Routes(t *testing.T) {
	tracker := diagnostics.NewSLATracker()
	h := NewDiagnosticsHandler(tracker)

	r := router.New()
	h.RegisterRoutes(r)

	// 1. Test SLA endpoint
	ctxSLA := &fasthttp.RequestCtx{}
	ctxSLA.Request.Header.SetMethod("GET")
	ctxSLA.Request.SetRequestURI("/api/v1/enterprise/diagnostics/sla?window=24h")
	r.Handler(ctxSLA)

	if ctxSLA.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200 from SLA endpoint, got %d", ctxSLA.Response.StatusCode())
	}

	var slaResp map[string]interface{}
	if err := json.Unmarshal(ctxSLA.Response.Body(), &slaResp); err != nil {
		t.Fatalf("failed to decode SLA JSON response: %v", err)
	}
	if slaResp["window"] != "24h" || slaResp["status"] != "HEALTHY" {
		t.Fatalf("unexpected SLA response: %+v", slaResp)
	}

	// 2. Test Health Bundle endpoint
	ctxBundle := &fasthttp.RequestCtx{}
	ctxBundle.Request.Header.SetMethod("GET")
	ctxBundle.Request.SetRequestURI("/api/v1/enterprise/diagnostics/health-bundle")
	r.Handler(ctxBundle)

	if ctxBundle.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200 from health bundle endpoint, got %d", ctxBundle.Response.StatusCode())
	}
	if string(ctxBundle.Response.Header.ContentType()) != "application/gzip" {
		t.Fatalf("expected application/gzip content type, got %s", string(ctxBundle.Response.Header.ContentType()))
	}

	// Decompress and verify diagnostics.json version
	gr, err := gzip.NewReader(bytes.NewReader(ctxBundle.Response.Body()))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
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
			t.Fatalf("tar error: %v", err)
		}
		if hdr.Name == "diagnostics.json" {
			foundDiagnostics = true
			var d map[string]interface{}
			if err := json.NewDecoder(tr).Decode(&d); err != nil {
				t.Fatalf("failed to parse diagnostics.json: %v", err)
			}
			if d["version"] != "1.0-enterprise" {
				t.Fatalf("expected version 1.0-enterprise, got %v", d["version"])
			}
		}
	}

	if !foundDiagnostics {
		t.Fatalf("diagnostics.json missing from health bundle")
	}
}
