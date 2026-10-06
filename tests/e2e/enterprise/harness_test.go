package enterprise

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

func TestHarness_Preset_Cursor(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/airlok/harness/config?client=cursor")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if config["harness"] != "cursor" {
		t.Fatalf("expected harness=cursor, got %v", config["harness"])
	}
	envVars, ok := config["env_vars"].(map[string]interface{})
	if !ok || envVars["OPENAI_BASE_URL"] == nil {
		t.Fatalf("missing OPENAI_BASE_URL in env_vars")
	}
}

func TestHarness_Preset_ClaudeCode(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/airlok/harness/config?client=claude")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&config)
	if config["harness"] != "claude" {
		t.Fatalf("expected harness=claude, got %v", config["harness"])
	}
}

func TestHarness_Preset_Antigravity(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/airlok/harness/config?client=antigravity")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&config)
	if config["harness"] != "antigravity" {
		t.Fatalf("expected harness=antigravity, got %v", config["harness"])
	}
}

func TestHarness_Preset_Pi(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/airlok/harness/config?client=pi")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&config)
	if config["harness"] != "pi" {
		t.Fatalf("expected harness=pi, got %v", config["harness"])
	}
}

func TestHarness_AclStatus_Inspection(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init gateway: %v", err)
	}
	defer gw.Close()

	resp, err := http.Get(gw.URL() + "/api/v1/airlok/acl/status")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var status map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&status)
	if status["version"] != "1.0" || status["status"] != "active" {
		t.Fatalf("unexpected ACL status: %+v", status)
	}

	rules := status["llm_rules"].([]interface{})
	hasOpenAIDeny := false
	for _, r := range rules {
		if strings.Contains(r.(string), "openai/* (deny)") {
			hasOpenAIDeny = true
			break
		}
	}
	if !hasOpenAIDeny {
		t.Fatalf("expected default ACL to contain openai/* (deny)")
	}
}
