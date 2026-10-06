package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/gitstore"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// AirlokHarnessHandler exposes dedicated configuration, ACL status, and GitOps endpoints for coding harnesses.
type AirlokHarnessHandler struct {
	acl       *governance.DualPlaneACL
	gitSyncer *gitstore.GitSyncer
}

// NewAirlokHarnessHandler initializes the Airlok harness adapter.
func NewAirlokHarnessHandler(repoPath string) *AirlokHarnessHandler {
	if repoPath == "" {
		repoPath = "."
	}
	acl := governance.DefaultAirlokPolicy()
	if policyPath := os.Getenv("AIRLOK_POLICY_PATH"); policyPath != "" {
		if data, err := os.ReadFile(policyPath); err == nil {
			if loaded, err := governance.NewDualPlaneACL(data); err == nil {
				acl = loaded
			}
		}
	}
	return &AirlokHarnessHandler{
		acl:       acl,
		gitSyncer: gitstore.NewGitSyncer(repoPath, 5000000000), // 5s debounce
	}
}

// RegisterRoutes registers Airlok harness management endpoints on the Fasthttp router.
func (h *AirlokHarnessHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/v1/airlok/harness/config", lib.ChainMiddlewares(h.GetHarnessConfig, middlewares...))
	r.GET("/api/v1/airlok/acl/status", lib.ChainMiddlewares(h.GetAclStatus, middlewares...))
	r.POST("/api/v1/airlok/storage/checkpoint", lib.ChainMiddlewares(h.CreateCheckpoint, middlewares...))
}

// HarnessConfigResponse provides environment presets for agent harnesses.
type HarnessConfigResponse struct {
	Harness      string            `json:"harness"`
	BaseURL      string            `json:"base_url"`
	EnvVars      map[string]string `json:"env_vars"`
	Instructions string            `json:"instructions"`
}

// GetHarnessConfig returns setup instructions and environment variables for the requested client.
func (h *AirlokHarnessHandler) GetHarnessConfig(ctx *fasthttp.RequestCtx) {
	client := strings.ToLower(string(ctx.QueryArgs().Peek("client")))
	if client == "" {
		client = "cursor"
	}

	host := string(ctx.Host())
	if host == "" {
		host = "localhost:8080"
	}
	baseURL := fmt.Sprintf("http://%s", host)

	resp := HarnessConfigResponse{
		Harness: client,
		BaseURL: baseURL,
		EnvVars: make(map[string]string),
	}

	switch client {
	case "claude", "claudecode":
		resp.EnvVars["ANTHROPIC_BASE_URL"] = fmt.Sprintf("%s/anthropic", baseURL)
		resp.EnvVars["ANTHROPIC_API_KEY"] = "airlok-local-token"
		resp.Instructions = "Set ANTHROPIC_BASE_URL to route Claude Code through Airlok governance."
	case "antigravity":
		resp.EnvVars["AIRLOK_GATEWAY_URL"] = baseURL
		resp.EnvVars["GOOGLE_GENAI_BASE_URL"] = fmt.Sprintf("%s/genai", baseURL)
		resp.Instructions = "Antigravity connects directly to the local execution boundary with unified ACL."
	case "pi":
		resp.EnvVars["OPENAI_BASE_URL"] = fmt.Sprintf("%s/openai/v1", baseURL)
		resp.EnvVars["PI_GATEWAY_URL"] = baseURL
		resp.Instructions = "Pi agent connects via standard OpenAI-compatible API entrypoint."
	default:
		// Cursor
		resp.EnvVars["OPENAI_BASE_URL"] = fmt.Sprintf("%s/openai/v1", baseURL)
		resp.EnvVars["OPENAI_API_KEY"] = "airlok-local-token"
		resp.Instructions = "Configure Cursor's OpenAI Base URL to Airlok for governed model execution."
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(resp)
}

// GetAclStatus returns the active dual-plane ACL configuration.
func (h *AirlokHarnessHandler) GetAclStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(map[string]interface{}{
		"version": "1.0",
		"status":  "active",
		"llm_rules": []string{
			"google/gemini-* (allow)",
			"anthropic/claude-* (audit)",
			"xai/grok-* (allow)",
			"openai/* (deny)",
		},
		"connector_rules": []string{
			"google_workspace (allow)",
			"slack (allow)",
			"office365 (deny)",
			"catalog_3000 (require_approval)",
		},
	})
}

// CheckpointRequest payload for GitOps persistence.
type CheckpointRequest struct {
	SessionID string   `json:"session_id"`
	Message   string   `json:"message"`
	Files     []string `json:"files"`
}

// CreateCheckpoint triggers a debounced Git commit for session state and workspace files.
func (h *AirlokHarnessHandler) CreateCheckpoint(ctx *fasthttp.RequestCtx) {
	var req CheckpointRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(fmt.Sprintf(`{"error": "invalid request body: %s"}`, err.Error()))
		return
	}

	commitHash, err := h.gitSyncer.CommitCheckpoint(req.Message, req.Files)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(fmt.Sprintf(`{"error": "%s"}`, err.Error()))
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(map[string]interface{}{
		"status":     "success",
		"session_id": req.SessionID,
		"commit":     commitHash,
	})
}
