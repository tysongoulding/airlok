package governance

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// PolicyAction defines the enforcement outcome of an ACL check.
type PolicyAction string

const (
	PolicyActionAllow           PolicyAction = "allow"
	PolicyActionAudit           PolicyAction = "audit"
	PolicyActionRequireApproval PolicyAction = "require_approval"
	PolicyActionDeny            PolicyAction = "deny"
)

// LLMRule specifies a model-level governance constraint.
type LLMRule struct {
	Provider        string       `json:"provider"`
	ModelPattern    string       `json:"model_pattern"`
	Action          PolicyAction `json:"action"`
	Audit           bool         `json:"audit,omitempty"`
	AuditTag        string       `json:"audit_tag,omitempty"`
	RejectionReason string       `json:"rejection_reason,omitempty"`
}

// ConnectorRule specifies a tool/connector-level governance constraint.
type ConnectorRule struct {
	Name            string       `json:"name"`
	Action          PolicyAction `json:"action"`
	Scopes          []string     `json:"scopes,omitempty"`
	Sandbox         bool         `json:"sandbox,omitempty"`
	RejectionReason string       `json:"rejection_reason,omitempty"`
}

// CrossPlaneRule enforces data boundary isolation between connectors and LLMs.
type CrossPlaneRule struct {
	RuleID                 string   `json:"rule_id"`
	WhenSourceConnector    []string `json:"when_source_connector"`
	DisallowDestinationLLM []string `json:"disallow_destination_llm"`
}

// DualPlanePolicy contains the complete ACL rule matrix for Airlok.
type DualPlanePolicy struct {
	Version string `json:"version"`
	LLM     struct {
		Defaults struct {
			Action PolicyAction `json:"action"`
		} `json:"defaults"`
		Rules []LLMRule `json:"rules"`
	} `json:"llm"`
	Connectors struct {
		Defaults struct {
			Action PolicyAction `json:"action"`
		} `json:"defaults"`
		Rules []ConnectorRule `json:"rules"`
	} `json:"connectors"`
	CrossPlaneConstraints []CrossPlaneRule `json:"cross_plane_constraints,omitempty"`
}

// DualPlaneACL evaluates inbound requests against the dual-plane matrix.
type DualPlaneACL struct {
	policy DualPlanePolicy
}

// NewDualPlaneACL initializes an evaluator from JSON configuration.
func NewDualPlaneACL(data []byte) (*DualPlaneACL, error) {
	var policy DualPlanePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse dual-plane ACL policy: %w", err)
	}
	return &DualPlaneACL{policy: policy}, nil
}

// DefaultAirlokPolicy returns the default recommended policy matching the target architecture.
func DefaultAirlokPolicy() *DualPlaneACL {
	var policy DualPlanePolicy
	policy.Version = "1.0"
	policy.LLM.Defaults.Action = PolicyActionDeny
	policy.LLM.Rules = []LLMRule{
		{Provider: "google", ModelPattern: "gemini-*", Action: PolicyActionAllow},
		{Provider: "anthropic", ModelPattern: "claude-*", Action: PolicyActionAllow, Audit: true, AuditTag: "monitored-claude"},
		{Provider: "xai", ModelPattern: "grok-*", Action: PolicyActionAllow},
		{Provider: "openai", ModelPattern: "*", Action: PolicyActionDeny, RejectionReason: "OpenAI ChatGPT models blocked by security governance policy"},
	}

	policy.Connectors.Defaults.Action = PolicyActionDeny
	policy.Connectors.Rules = []ConnectorRule{
		{Name: "google_workspace", Action: PolicyActionAllow, Scopes: []string{"drive.readonly", "docs", "sheets", "gmail.send"}},
		{Name: "slack", Action: PolicyActionAllow, Scopes: []string{"chat:write", "channels:read"}},
		{Name: "office365", Action: PolicyActionDeny, RejectionReason: "Office365 integrations disabled by policy"},
		{Name: "catalog_3000", Action: PolicyActionRequireApproval, Sandbox: true},
	}

	policy.CrossPlaneConstraints = []CrossPlaneRule{
		{
			RuleID:                 "prevent_data_leak",
			WhenSourceConnector:    []string{"google_workspace", "slack"},
			DisallowDestinationLLM: []string{"openai/*"},
		},
	}

	return &DualPlaneACL{policy: policy}
}

// CheckLLM checks whether the requested provider and model are permitted.
func (acl *DualPlaneACL) CheckLLM(provider schemas.ModelProvider, model string) (PolicyAction, string) {
	provStr := strings.ToLower(string(provider))
	for _, rule := range acl.policy.LLM.Rules {
		if ruleMatches(rule.Provider, provStr) && modelMatches(rule.ModelPattern, model) {
			if rule.Action == PolicyActionDeny {
				reason := rule.RejectionReason
				if reason == "" {
					reason = fmt.Sprintf("Model '%s/%s' is blocked by organization ACL", provStr, model)
				}
				return PolicyActionDeny, reason
			}
			if rule.Audit || rule.Action == PolicyActionAudit {
				return PolicyActionAudit, rule.AuditTag
			}
			return rule.Action, ""
		}
	}

	if acl.policy.LLM.Defaults.Action == PolicyActionDeny {
		return PolicyActionDeny, fmt.Sprintf("Model '%s/%s' denied by default ACL policy", provStr, model)
	}
	return acl.policy.LLM.Defaults.Action, ""
}

// CheckConnector checks whether a connector or tool is permitted.
func (acl *DualPlaneACL) CheckConnector(connectorName, requestedScope string) (PolicyAction, string) {
	nameLower := strings.ToLower(connectorName)
	for _, rule := range acl.policy.Connectors.Rules {
		if ruleMatches(rule.Name, nameLower) {
			if rule.Action == PolicyActionDeny {
				reason := rule.RejectionReason
				if reason == "" {
					reason = fmt.Sprintf("Connector '%s' is blocked by organization ACL", connectorName)
				}
				return PolicyActionDeny, reason
			}
			if requestedScope != "" && len(rule.Scopes) > 0 {
				scopeAllowed := false
				for _, s := range rule.Scopes {
					if s == requestedScope {
						scopeAllowed = true
						break
					}
				}
				if !scopeAllowed {
					return PolicyActionDeny, fmt.Sprintf("Scope '%s' not granted for connector '%s'", requestedScope, connectorName)
				}
			}
			return rule.Action, ""
		}
	}

	if acl.policy.Connectors.Defaults.Action == PolicyActionDeny {
		return PolicyActionDeny, fmt.Sprintf("Connector '%s' denied by default ACL policy", connectorName)
	}
	return acl.policy.Connectors.Defaults.Action, ""
}

// CheckCrossPlane validates that active connector outputs cannot reach blocked destination LLMs.
func (acl *DualPlaneACL) CheckCrossPlane(activeConnectors []string, destProvider schemas.ModelProvider, destModel string) error {
	destTarget := fmt.Sprintf("%s/%s", strings.ToLower(string(destProvider)), destModel)

	for _, rule := range acl.policy.CrossPlaneConstraints {
		hasSensitive := false
		for _, conn := range activeConnectors {
			for _, sensitive := range rule.WhenSourceConnector {
				if strings.EqualFold(conn, sensitive) {
					hasSensitive = true
					break
				}
			}
			if hasSensitive {
				break
			}
		}

		if hasSensitive {
			for _, pattern := range rule.DisallowDestinationLLM {
				if strings.HasSuffix(pattern, "/*") {
					prefix := strings.TrimSuffix(pattern, "/*")
					if strings.EqualFold(prefix, strings.ToLower(string(destProvider))) {
						return fmt.Errorf("cross-plane security violation [rule: %s]: sensitive data from %v cannot be passed to provider '%s'",
							rule.RuleID, rule.WhenSourceConnector, destProvider)
					}
				} else if pattern == "*" || strings.EqualFold(pattern, destTarget) {
					return fmt.Errorf("cross-plane security violation [rule: %s]: sensitive data from %v cannot be passed to '%s'",
						rule.RuleID, rule.WhenSourceConnector, destTarget)
				}
			}
		}
	}

	return nil
}

func ruleMatches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	return strings.EqualFold(pattern, value)
}

func modelMatches(pattern, model string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(strings.ToLower(model), strings.ToLower(prefix))
	}
	return strings.EqualFold(pattern, model)
}
