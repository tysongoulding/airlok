package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// EnterpriseGatewayServer provides a fully functional, self-contained mock gateway for E2E testing.
type EnterpriseGatewayServer struct {
	Server        *httptest.Server
	Guardrails    *MockGuardrailsEngine
	Cluster       *MockClusterMesh
	LoadBalancer  *MockAdaptiveLoadBalancer
	SSO           *MockSSOAdapter
	Vault         *MockVaultRegistry
	MCP           *MockMCPGovernance
	Audit         *MockAuditLedger
	LogExporter   *MockLogExporter
	RBAC          *MockRBACAuthorizer
	Diagnostics   *MockDiagnosticsReporter
	UpstreamCalls int
	mu            sync.Mutex
}

func NewEnterpriseGatewayServer() (*EnterpriseGatewayServer, error) {
	sso, err := NewMockSSOAdapter()
	if err != nil {
		return nil, err
	}

	audit, err := NewMockAuditLedger("test-audit-hmac-key-minimum-32-chars-long", false)
	if err != nil {
		return nil, err
	}

	gw := &EnterpriseGatewayServer{
		Guardrails:   NewMockGuardrailsEngine(),
		Cluster:      NewMockClusterMesh(),
		LoadBalancer: NewMockAdaptiveLoadBalancer(),
		SSO:          sso,
		Vault:        NewMockVaultRegistry(1 * time.Hour),
		MCP:          NewMockMCPGovernance(),
		Audit:        audit,
		LogExporter:  NewMockLogExporter(10, 50*time.Millisecond),
		RBAC:         NewMockRBACAuthorizer(),
		Diagnostics:  NewMockDiagnosticsReporter(),
	}

	gw.LoadBalancer.RegisterRoute("key-default-openai", "openai", "gpt-4o")
	gw.LoadBalancer.RegisterRoute("key-default-anthropic", "anthropic", "claude-sonnet-4-5")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", gw.handleChatCompletions)
	mux.HandleFunc("/api/vault/flush-cache", gw.handleVaultFlush)
	mux.HandleFunc("/api/v1/enterprise/diagnostics/sla", gw.handleDiagnosticsSLA)
	mux.HandleFunc("/api/v1/enterprise/diagnostics/health-bundle", gw.handleHealthBundle)
	mux.HandleFunc("/api/v1/airlok/harness/config", gw.handleHarnessConfig)
	mux.HandleFunc("/api/v1/airlok/acl/status", gw.handleAclStatus)
	mux.HandleFunc("/mcp/", gw.handleVirtualMCP)
	mux.HandleFunc("/api/governance/roles", gw.handleProtectedRoles)
	mux.HandleFunc("/api/governance/virtual-keys", gw.handleProtectedVirtualKeys)

	gw.Server = httptest.NewServer(mux)
	return gw, nil
}

func (gw *EnterpriseGatewayServer) Close() {
	if gw.Server != nil {
		gw.Server.Close()
	}
}

func (gw *EnterpriseGatewayServer) URL() string {
	return gw.Server.URL
}

func (gw *EnterpriseGatewayServer) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. Extract prompt content
	prompt := ""
	if msgs, ok := req["messages"].([]interface{}); ok && len(msgs) > 0 {
		if firstMsg, ok := msgs[0].(map[string]interface{}); ok {
			if content, ok := firstMsg["content"].(string); ok {
				prompt = content
			}
		}
	}

	model, _ := req["model"].(string)

	// 2. Guardrails evaluation on input
	grResult := gw.Guardrails.EvaluateText(prompt, "llm", "input", map[string]string{
		"model": model,
	})

	if !grResult.Allowed {
		// Emit HTTP 422 Unprocessable Entity
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": grResult.InterventionReason,
				"type":    "guardrail_violation",
				"code":    "guardrail_intervention",
				"details": grResult.Findings,
			},
		})
		return
	}

	// 3. Adaptive Load Balancer & Circuit Breaker
	provider := "openai"
	if strings.HasPrefix(model, "claude-") {
		provider = "anthropic"
	}
	keyID, fbProv, fbModel, circuitTripped, err := gw.LoadBalancer.SelectRoute(r.Context(), provider, model)
	if err != nil && !circuitTripped {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	gw.mu.Lock()
	gw.UpstreamCalls++
	gw.mu.Unlock()

	// 4. Log Exporter & Audit Logging
	gw.LogExporter.Enqueue(map[string]interface{}{
		"model":      model,
		"prompt_len": len(prompt),
		"status":     200,
		"timestamp":  time.Now(),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     "chatcmpl-mock",
		"object": "chat.completion",
		"model":  model,
		"key_id": keyID,
		"fallback": map[string]interface{}{
			"tripped":  circuitTripped,
			"provider": fbProv,
			"model":    fbModel,
		},
		"choices": []map[string]interface{}{
			{
				"message": map[string]string{
					"role":    "assistant",
					"content": "Mock response to: " + grResult.TransformedText,
				},
				"finish_reason": "stop",
			},
		},
	})
}

func (gw *EnterpriseGatewayServer) handleVaultFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	gw.Vault.FlushCache()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "vault cache flushed"})
}

func (gw *EnterpriseGatewayServer) handleDiagnosticsSLA(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	sla, err := gw.Diagnostics.GenerateSLAReport(r.Context(), window)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(sla)
}

func (gw *EnterpriseGatewayServer) handleHealthBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := gw.Diagnostics.ExportHealthBundle(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

func (gw *EnterpriseGatewayServer) handleHarnessConfig(w http.ResponseWriter, r *http.Request) {
	client := strings.ToLower(r.URL.Query().Get("client"))
	if client == "" {
		client = "cursor"
	}
	baseURL := gw.URL()

	resp := map[string]interface{}{
		"harness":  client,
		"base_url": baseURL,
		"env_vars": map[string]string{
			"OPENAI_BASE_URL":    fmt.Sprintf("%s/v1", baseURL),
			"AIRLOK_GATEWAY_URL": baseURL,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (gw *EnterpriseGatewayServer) handleAclStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"version": "1.0",
		"status":  "active",
		"llm_rules": []string{
			"google/gemini-* (allow)",
			"anthropic/claude-* (audit)",
			"xai/grok-* (allow)",
			"openai/* (deny)",
		},
	})
}

func (gw *EnterpriseGatewayServer) handleVirtualMCP(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/mcp/")
	user := r.Header.Get("X-User-ID")
	tool := r.URL.Query().Get("tool")
	connector := r.URL.Query().Get("connector")

	allowed, action, reason := gw.MCP.CheckToolAccess(slug, user, connector, tool)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "allowed",
		"action": action,
		"tool":   tool,
	})
}

func (gw *EnterpriseGatewayServer) handleProtectedRoles(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-User-Role")
	allowed, err := gw.RBAC.Authorize(role, ResourceRoles, OpCreate)
	if err != nil || !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized: permission denied"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "role created"})
}

func (gw *EnterpriseGatewayServer) handleProtectedVirtualKeys(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-User-Role")
	allowed, err := gw.RBAC.Authorize(role, ResourceVirtualKeys, OpCreate)
	if err != nil || !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized: permission denied"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "virtual key created"})
}
