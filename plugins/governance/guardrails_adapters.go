package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// CloudSafetyRequest represents the normalized payload sent to cloud safety providers.
type CloudSafetyRequest struct {
	Phase    string            `json:"phase"` // "input" or "output"
	Text     string            `json:"text"`
	Model    string            `json:"model,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CloudSafetyResponse represents the evaluation result returned by the cloud provider.
type CloudSafetyResponse struct {
	Allowed            bool               `json:"allowed"`
	ActionTaken        string             `json:"action_taken"` // "allow", "block", "redact"
	InterventionReason string             `json:"intervention_reason,omitempty"`
	TransformedText    string             `json:"transformed_text,omitempty"`
	Assessments        []string           `json:"assessments,omitempty"`
	UsageUnits         map[string]int     `json:"usage_units,omitempty"`
	Detections         []GuardrailFinding `json:"detections,omitempty"`
}

// CloudGuardrailAdapter defines the standard interface for external cloud safety services.
type CloudGuardrailAdapter interface {
	Name() string
	InspectContent(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error)
	Close() error
}

// ============================================================================
// AWS Bedrock Guardrails Adapter
// ============================================================================

// BedrockConfig contains configuration for AWS Bedrock Guardrail.
type BedrockConfig struct {
	AuthType         string `json:"auth_type"` // "keys", "api_key", "iam_role"
	AccessKey        string `json:"access_key,omitempty"`
	SecretKey        string `json:"secret_key,omitempty"`
	SessionToken     string `json:"session_token,omitempty"`
	BedrockAPIKey    string `json:"bedrock_api_key,omitempty"`
	GuardrailARN     string `json:"guardrail_arn"`
	GuardrailVersion string `json:"guardrail_version"`
	Region           string `json:"region"`
	BaseURL          string `json:"base_url,omitempty"`  // Used for offline test mocks
	SkipAuth         bool   `json:"skip_auth,omitempty"` // Used for offline test mocks
	Timeout          int    `json:"timeout,omitempty"`
}

// BedrockAdapter implements CloudGuardrailAdapter for AWS Bedrock ApplyGuardrail.
type BedrockAdapter struct {
	cfg        BedrockConfig
	httpClient *http.Client
	guardID    string
}

// NewBedrockAdapter creates a new AWS Bedrock Guardrail adapter.
func NewBedrockAdapter(cfg BedrockConfig, client *http.Client) (*BedrockAdapter, error) {
	if client == nil {
		timeout := 10 * time.Second
		if cfg.Timeout > 0 {
			timeout = time.Duration(cfg.Timeout) * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	guardID := extractGuardrailID(cfg.GuardrailARN)
	return &BedrockAdapter{
		cfg:        cfg,
		httpClient: client,
		guardID:    guardID,
	}, nil
}

func (a *BedrockAdapter) Name() string { return "bedrock" }

func (a *BedrockAdapter) InspectContent(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error) {
	source := "INPUT"
	if req.Phase == "output" {
		source = "OUTPUT"
	}

	payload := map[string]interface{}{
		"source": source,
		"content": []map[string]interface{}{
			{
				"text": map[string]string{
					"text": req.Text,
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bedrock request: %w", err)
	}

	endpoint := a.cfg.BaseURL
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", a.cfg.Region)
	}
	targetURL := fmt.Sprintf("%s/guardrail/%s/version/%s/apply", endpoint, a.guardID, a.cfg.GuardrailVersion)

	var reqCtx context.Context = context.Background()
	if ctx != nil {
		reqCtx = ctx
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if !a.cfg.SkipAuth {
		if a.cfg.BedrockAPIKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+a.cfg.BedrockAPIKey)
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("bedrock request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read bedrock response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bedrock returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var bResp struct {
		Action       string `json:"action"` // "NONE" or "GUARDRAIL_INTERVENED"
		ActionReason string `json:"actionReason,omitempty"`
		Outputs      []struct {
			Text string `json:"text"`
		} `json:"outputs,omitempty"`
		Assessments []struct {
			ContentPolicy *struct {
				Filters []struct {
					Type   string `json:"type"`
					Action string `json:"action"`
				} `json:"filters"`
			} `json:"contentPolicy,omitempty"`
			TopicPolicy *struct {
				Topics []struct {
					Name   string `json:"name"`
					Action string `json:"action"`
				} `json:"topics"`
			} `json:"topicPolicy,omitempty"`
		} `json:"assessments,omitempty"`
		Usage map[string]int `json:"usage,omitempty"`
	}

	if err := json.Unmarshal(respBytes, &bResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bedrock response: %w", err)
	}

	res := &CloudSafetyResponse{
		Allowed:     true,
		ActionTaken: "allow",
		UsageUnits:  bResp.Usage,
	}

	for _, assess := range bResp.Assessments {
		if assess.ContentPolicy != nil {
			for _, f := range assess.ContentPolicy.Filters {
				if f.Action == "BLOCKED" {
					res.Assessments = append(res.Assessments, f.Type)
				}
			}
		}
		if assess.TopicPolicy != nil {
			for _, t := range assess.TopicPolicy.Topics {
				if t.Action == "BLOCKED" {
					res.Assessments = append(res.Assessments, t.Name)
				}
			}
		}
	}

	if bResp.Action == "GUARDRAIL_INTERVENED" {
		if len(bResp.Outputs) > 0 && bResp.Outputs[0].Text != "" && bResp.Outputs[0].Text != req.Text {
			res.ActionTaken = "redact"
			res.TransformedText = bResp.Outputs[0].Text
		} else {
			res.Allowed = false
			res.ActionTaken = "block"
			res.InterventionReason = fmt.Sprintf("Blocked by AWS Bedrock Guardrail: %s", bResp.ActionReason)
		}
	}

	return res, nil
}

func (a *BedrockAdapter) Close() error { return nil }

func extractGuardrailID(arnOrID string) string {
	if strings.Contains(arnOrID, "guardrail/") {
		parts := strings.Split(arnOrID, "guardrail/")
		return parts[len(parts)-1]
	}
	return arnOrID
}

// ============================================================================
// Azure AI Content Safety Adapter
// ============================================================================

// AzureContentSafetyConfig contains configuration for Azure AI Content Safety.
type AzureContentSafetyConfig struct {
	Endpoint                 string   `json:"endpoint"`
	AuthType                 string   `json:"auth_type"` // "api_key", "entra_id"
	APIKey                   string   `json:"api_key"`
	AnalyzeSeverityThreshold string   `json:"analyze_severity_threshold"` // "low", "medium", "high"
	JailbreakShieldEnabled   bool     `json:"jailbreak_shield_enabled"`
	CopyrightEnabled         bool     `json:"copyright_enabled"`
	TextBlocklistEnabled     bool     `json:"text_blocklist_enabled"`
	BlocklistNames           []string `json:"blocklist_names"`
	SkipAuth                 bool     `json:"skip_auth,omitempty"` // For test mocks
	Timeout                  int      `json:"timeout,omitempty"`
}

// AzureAdapter implements CloudGuardrailAdapter for Azure AI Content Safety.
type AzureAdapter struct {
	cfg        AzureContentSafetyConfig
	httpClient *http.Client
	threshold  int // 2 (low), 4 (medium), 6 (high)
}

// NewAzureAdapter creates a new Azure Content Safety adapter.
func NewAzureAdapter(cfg AzureContentSafetyConfig, client *http.Client) (*AzureAdapter, error) {
	if client == nil {
		timeout := 10 * time.Second
		if cfg.Timeout > 0 {
			timeout = time.Duration(cfg.Timeout) * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	threshold := 4
	switch strings.ToLower(cfg.AnalyzeSeverityThreshold) {
	case "low":
		threshold = 2
	case "high":
		threshold = 6
	}
	return &AzureAdapter{
		cfg:        cfg,
		httpClient: client,
		threshold:  threshold,
	}, nil
}

func (a *AzureAdapter) Name() string { return "azure" }

func (a *AzureAdapter) InspectContent(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error) {
	baseURL := strings.TrimRight(a.cfg.Endpoint, "/")

	// 1. Jailbreak prompt shield (input only)
	if req.Phase == "input" && a.cfg.JailbreakShieldEnabled {
		shieldPayload, _ := json.Marshal(map[string]string{"userPrompt": req.Text})
		shieldURL := fmt.Sprintf("%s/contentsafety/text:shieldPrompt?api-version=2024-09-01", baseURL)
		var reqCtx context.Context = context.Background()
		if ctx != nil {
			reqCtx = ctx
		}
		sReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, shieldURL, bytes.NewReader(shieldPayload))
		if err != nil {
			return nil, err
		}
		a.applyHeaders(sReq)

		sResp, err := a.httpClient.Do(sReq)
		if err == nil {
			defer sResp.Body.Close()
			sBytes, _ := io.ReadAll(sResp.Body)
			if sResp.StatusCode == http.StatusOK {
				var parsed struct {
					UserPromptAnalysis struct {
						AttackDetected bool `json:"attackDetected"`
					} `json:"userPromptAnalysis"`
				}
				if err := json.Unmarshal(sBytes, &parsed); err == nil && parsed.UserPromptAnalysis.AttackDetected {
					return &CloudSafetyResponse{
						Allowed:            false,
						ActionTaken:        "block",
						InterventionReason: "Azure Content Safety prompt shield: jailbreak detected",
						Assessments:        []string{"Jailbreak"},
					}, nil
				}
			}
		}
	}

	// 2. Text Content Analyze
	categories := []string{"Hate", "Sexual", "Violence", "SelfHarm"}
	analyzeReq := map[string]interface{}{
		"text":               req.Text,
		"categories":         categories,
		"blocklistNames":     a.cfg.BlocklistNames,
		"haltOnBlocklistHit": true,
		"outputType":         "FourSeverityLevels",
	}
	bodyBytes, err := json.Marshal(analyzeReq)
	if err != nil {
		return nil, err
	}

	analyzeURL := fmt.Sprintf("%s/contentsafety/text:analyze?api-version=2024-09-01", baseURL)
	var reqCtx context.Context = context.Background()
	if ctx != nil {
		reqCtx = ctx
	}
	hReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, analyzeURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	a.applyHeaders(hReq)

	hResp, err := a.httpClient.Do(hReq)
	if err != nil {
		return nil, fmt.Errorf("azure analyze request failed: %w", err)
	}
	defer hResp.Body.Close()

	respBytes, err := io.ReadAll(hResp.Body)
	if err != nil {
		return nil, err
	}
	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure returned HTTP %d: %s", hResp.StatusCode, string(respBytes))
	}

	var parsed struct {
		CategoriesAnalysis []struct {
			Category string `json:"category"`
			Severity int    `json:"severity"`
		} `json:"categoriesAnalysis"`
		BlocklistsMatch []struct {
			BlocklistName string `json:"blocklistName"`
		} `json:"blocklistsMatch,omitempty"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal azure response: %w", err)
	}

	if len(parsed.BlocklistsMatch) > 0 {
		return &CloudSafetyResponse{
			Allowed:            false,
			ActionTaken:        "block",
			InterventionReason: fmt.Sprintf("Azure Content Safety: matched custom blocklist %s", parsed.BlocklistsMatch[0].BlocklistName),
			Assessments:        []string{"Blocklist:" + parsed.BlocklistsMatch[0].BlocklistName},
		}, nil
	}

	for _, cat := range parsed.CategoriesAnalysis {
		if cat.Severity >= a.threshold {
			return &CloudSafetyResponse{
				Allowed:            false,
				ActionTaken:        "block",
				InterventionReason: fmt.Sprintf("Azure Content Safety: %s exceeded severity threshold (got %d, max %d)", cat.Category, cat.Severity, a.threshold),
				Assessments:        []string{fmt.Sprintf("%s:%d", cat.Category, cat.Severity)},
			}, nil
		}
	}

	return &CloudSafetyResponse{
		Allowed:     true,
		ActionTaken: "allow",
	}, nil
}

func (a *AzureAdapter) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if !a.cfg.SkipAuth && a.cfg.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", a.cfg.APIKey)
	}
}

func (a *AzureAdapter) Close() error { return nil }

// ============================================================================
// Google Model Armor Adapter
// ============================================================================

// ModelArmorConfig contains configuration for Google Model Armor.
type ModelArmorConfig struct {
	ProjectID  string `json:"project_id"`
	Location   string `json:"location"`
	TemplateID string `json:"template_id"`
	AuthType   string `json:"auth_type"`           // "default_credential", "service_account_json"
	BaseURL    string `json:"base_url,omitempty"`  // Used for offline test mocks
	SkipAuth   bool   `json:"skip_auth,omitempty"` // Used for offline test mocks
	Timeout    int    `json:"timeout,omitempty"`
}

// ModelArmorAdapter implements CloudGuardrailAdapter for Google Model Armor.
type ModelArmorAdapter struct {
	cfg        ModelArmorConfig
	httpClient *http.Client
}

// NewModelArmorAdapter creates a new Google Model Armor adapter.
func NewModelArmorAdapter(cfg ModelArmorConfig, client *http.Client) (*ModelArmorAdapter, error) {
	if client == nil {
		timeout := 30 * time.Second
		if cfg.Timeout > 0 {
			timeout = time.Duration(cfg.Timeout) * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &ModelArmorAdapter{
		cfg:        cfg,
		httpClient: client,
	}, nil
}

func (a *ModelArmorAdapter) Name() string { return "model-armor" }

func (a *ModelArmorAdapter) InspectContent(ctx *schemas.BifrostContext, req *CloudSafetyRequest) (*CloudSafetyResponse, error) {
	var bodyBytes []byte
	var actionMethod string

	if req.Phase == "input" {
		actionMethod = "sanitizeUserPrompt"
		payload := map[string]interface{}{
			"userPromptData": map[string]string{
				"text": req.Text,
			},
		}
		bodyBytes, _ = json.Marshal(payload)
	} else {
		actionMethod = "sanitizeModelResponse"
		payload := map[string]interface{}{
			"modelResponseData": map[string]string{
				"text": req.Text,
			},
		}
		bodyBytes, _ = json.Marshal(payload)
	}

	endpoint := a.cfg.BaseURL
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://modelarmor.%s.rep.googleapis.com", a.cfg.Location)
	}
	targetURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/templates/%s:%s",
		endpoint, a.cfg.ProjectID, a.cfg.Location, a.cfg.TemplateID, actionMethod)

	var reqCtx context.Context = context.Background()
	if ctx != nil {
		reqCtx = ctx
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("model armor request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model armor returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		SanitizationResult struct {
			FilterMatchState string `json:"filterMatchState"` // "NO_MATCH_FOUND" | "MATCH_FOUND"
			FilterResults    struct {
				PIAndJailbreakFilterResult *struct {
					MatchState string `json:"matchState"`
				} `json:"piAndJailbreakFilterResult,omitempty"`
				RAIFilterResult *struct {
					MatchState string `json:"matchState"`
				} `json:"raiFilterResult,omitempty"`
				SDPFilterResult *struct {
					DeidentifyResult *struct {
						TransformedText string `json:"transformedText"`
					} `json:"deidentifyResult,omitempty"`
				} `json:"sdpFilterResult,omitempty"`
			} `json:"filterResults"`
		} `json:"sanitizationResult"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal model armor response: %w", err)
	}

	matchState := parsed.SanitizationResult.FilterMatchState
	if matchState == "NO_MATCH_FOUND" || matchState == "" {
		return &CloudSafetyResponse{
			Allowed:     true,
			ActionTaken: "allow",
		}, nil
	}

	// Check if SDP de-identification produced transformed text
	fr := parsed.SanitizationResult.FilterResults
	if fr.SDPFilterResult != nil && fr.SDPFilterResult.DeidentifyResult != nil && fr.SDPFilterResult.DeidentifyResult.TransformedText != "" {
		return &CloudSafetyResponse{
			Allowed:         true,
			ActionTaken:     "redact",
			TransformedText: fr.SDPFilterResult.DeidentifyResult.TransformedText,
			Assessments:     []string{"SDP_Deidentified"},
		}, nil
	}

	matchedFilters := []string{}
	if fr.PIAndJailbreakFilterResult != nil && fr.PIAndJailbreakFilterResult.MatchState == "MATCH_FOUND" {
		matchedFilters = append(matchedFilters, "pi_and_jailbreak")
	}
	if fr.RAIFilterResult != nil && fr.RAIFilterResult.MatchState == "MATCH_FOUND" {
		matchedFilters = append(matchedFilters, "rai")
	}
	if len(matchedFilters) == 0 {
		matchedFilters = append(matchedFilters, "model_armor_policy")
	}

	return &CloudSafetyResponse{
		Allowed:            false,
		ActionTaken:        "block",
		InterventionReason: fmt.Sprintf("Blocked by Google Model Armor policy: matched %s", strings.Join(matchedFilters, ", ")),
		Assessments:        matchedFilters,
	}, nil
}

func (a *ModelArmorAdapter) Close() error { return nil }

// ============================================================================
// 100% Offline Test Mocks
// ============================================================================

// MockBedrockServer simulates AWS Bedrock ApplyGuardrail completely offline.
type MockBedrockServer struct {
	Server        *httptest.Server
	Calls         int64
	mu            sync.Mutex
	Action        string // "NONE" or "GUARDRAIL_INTERVENED"
	Reason        string
	MaskedText    string
	BlockKeywords []string
	Usage         map[string]int
}

// NewMockBedrockServer creates an in-process mock server for AWS Bedrock Guardrails.
func NewMockBedrockServer() *MockBedrockServer {
	m := &MockBedrockServer{
		Action:        "NONE",
		BlockKeywords: []string{"ignore previous instructions", "prompt attack"},
		Usage:         map[string]int{"contentPolicyUnits": 1},
	}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&m.Calls, 1)

		bodyBytes, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(bodyBytes, &req)

		// Extract text
		text := ""
		if content, ok := req["content"].([]interface{}); ok && len(content) > 0 {
			if block, ok := content[0].(map[string]interface{}); ok {
				if tObj, ok := block["text"].(map[string]interface{}); ok {
					if tStr, ok := tObj["text"].(string); ok {
						text = tStr
					}
				}
			}
		}

		m.mu.Lock()
		action := m.Action
		reason := m.Reason
		masked := m.MaskedText
		for _, kw := range m.BlockKeywords {
			if strings.Contains(strings.ToLower(text), strings.ToLower(kw)) {
				action = "GUARDRAIL_INTERVENED"
				reason = "Bedrock Guardrail: Prompt attack detected"
				break
			}
		}
		m.mu.Unlock()

		respPayload := map[string]interface{}{
			"action":       action,
			"actionReason": reason,
			"usage":        m.Usage,
		}

		if action == "GUARDRAIL_INTERVENED" && masked != "" {
			respPayload["outputs"] = []map[string]string{
				{"text": masked},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(respPayload)
	}))

	return m
}

func (m *MockBedrockServer) URL() string {
	return m.Server.URL
}

func (m *MockBedrockServer) Close() {
	m.Server.Close()
}

// MockAzureServer simulates Azure Content Safety AnalyzeText & ShieldPrompt completely offline.
type MockAzureServer struct {
	Server             *httptest.Server
	Calls              int64
	mu                 sync.Mutex
	HateKeywords       []string
	BlocklistMatches   []string
	DetectJailbreak    bool
	SeverityByCategory map[string]int
}

// NewMockAzureServer creates an in-process mock server for Azure Content Safety.
func NewMockAzureServer() *MockAzureServer {
	m := &MockAzureServer{
		HateKeywords:       []string{"hate speech content", "violent attack"},
		SeverityByCategory: map[string]int{"Hate": 0, "Sexual": 0, "Violence": 0, "SelfHarm": 0},
	}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&m.Calls, 1)

		bodyBytes, _ := io.ReadAll(r.Body)

		if strings.Contains(r.URL.Path, "shieldPrompt") {
			// Prompt shield endpoint
			var req struct {
				UserPrompt string `json:"userPrompt"`
			}
			_ = json.Unmarshal(bodyBytes, &req)

			isAttack := m.DetectJailbreak || strings.Contains(strings.ToLower(req.UserPrompt), "jailbreak")
			resp := map[string]interface{}{
				"userPromptAnalysis": map[string]bool{
					"attackDetected": isAttack,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Text analyze endpoint
		var req struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(bodyBytes, &req)

		m.mu.Lock()
		severities := make(map[string]int)
		for k, v := range m.SeverityByCategory {
			severities[k] = v
		}
		for _, kw := range m.HateKeywords {
			if strings.Contains(strings.ToLower(req.Text), strings.ToLower(kw)) {
				severities["Hate"] = 6
				break
			}
		}
		blocklists := m.BlocklistMatches
		m.mu.Unlock()

		var catAnalysis []map[string]interface{}
		for cat, sev := range severities {
			catAnalysis = append(catAnalysis, map[string]interface{}{
				"category": cat,
				"severity": sev,
			})
		}

		resp := map[string]interface{}{
			"categoriesAnalysis": catAnalysis,
		}
		if len(blocklists) > 0 {
			var bMatches []map[string]string
			for _, b := range blocklists {
				bMatches = append(bMatches, map[string]string{"blocklistName": b})
			}
			resp["blocklistsMatch"] = bMatches
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	return m
}

func (m *MockAzureServer) URL() string {
	return m.Server.URL
}

func (m *MockAzureServer) Close() {
	m.Server.Close()
}

// MockModelArmorServer simulates Google Model Armor sanitize endpoints completely offline.
type MockModelArmorServer struct {
	Server           *httptest.Server
	Calls            int64
	mu               sync.Mutex
	FilterMatchState string // "NO_MATCH_FOUND" or "MATCH_FOUND"
	DeidentifyText   string
	BlockKeywords    []string
}

// NewMockModelArmorServer creates an in-process mock server for Google Model Armor.
func NewMockModelArmorServer() *MockModelArmorServer {
	m := &MockModelArmorServer{
		FilterMatchState: "NO_MATCH_FOUND",
		BlockKeywords:    []string{"model armor attack", "jailbreak attempt"},
	}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&m.Calls, 1)

		bodyBytes, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(bodyBytes, &req)

		text := ""
		if promptData, ok := req["userPromptData"].(map[string]interface{}); ok {
			if t, ok := promptData["text"].(string); ok {
				text = t
			}
		} else if respData, ok := req["modelResponseData"].(map[string]interface{}); ok {
			if t, ok := respData["text"].(string); ok {
				text = t
			}
		}

		m.mu.Lock()
		matchState := m.FilterMatchState
		deidentify := m.DeidentifyText
		for _, kw := range m.BlockKeywords {
			if strings.Contains(strings.ToLower(text), strings.ToLower(kw)) {
				matchState = "MATCH_FOUND"
				break
			}
		}
		m.mu.Unlock()

		resp := map[string]interface{}{
			"sanitizationResult": map[string]interface{}{
				"filterMatchState": matchState,
			},
		}

		if matchState == "MATCH_FOUND" {
			filterResults := map[string]interface{}{}
			if deidentify != "" {
				filterResults["sdpFilterResult"] = map[string]interface{}{
					"deidentifyResult": map[string]string{
						"transformedText": deidentify,
					},
				}
			} else {
				filterResults["piAndJailbreakFilterResult"] = map[string]string{
					"matchState": "MATCH_FOUND",
				}
			}
			resp["sanitizationResult"].(map[string]interface{})["filterResults"] = filterResults
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	return m
}

func (m *MockModelArmorServer) URL() string {
	return m.Server.URL
}

func (m *MockModelArmorServer) Close() {
	m.Server.Close()
}
