package handlers

import (
	"encoding/json"
	"testing"

	"github.com/fasthttp/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestAirlokHarnessHandlerPresets(t *testing.T) {
	tmpDir := t.TempDir()
	handler := NewAirlokHarnessHandler(tmpDir)

	r := router.New()
	handler.RegisterRoutes(r)

	// Test Cursor config preset
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/v1/airlok/harness/config?client=cursor")
	ctx.Request.Header.SetHost("localhost:8080")

	r.Handler(ctx)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var cursorResp HarnessConfigResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &cursorResp))
	assert.Equal(t, "cursor", cursorResp.Harness)
	assert.Contains(t, cursorResp.EnvVars["OPENAI_BASE_URL"], "localhost:8080")

	// Test Claude config preset
	ctx = &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/v1/airlok/harness/config?client=claude")
	ctx.Request.Header.SetHost("localhost:8080")

	r.Handler(ctx)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var claudeResp HarnessConfigResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &claudeResp))
	assert.Equal(t, "claude", claudeResp.Harness)
	assert.Contains(t, claudeResp.EnvVars["ANTHROPIC_BASE_URL"], "localhost:8080/anthropic")
}

func TestAirlokHarnessHandlerAclStatus(t *testing.T) {
	tmpDir := t.TempDir()
	handler := NewAirlokHarnessHandler(tmpDir)

	r := router.New()
	handler.RegisterRoutes(r)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/v1/airlok/acl/status")

	r.Handler(ctx)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.Equal(t, "1.0", body["version"])
	assert.Equal(t, "active", body["status"])
}
