package governance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

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
	mu              sync.RWMutex
	policy          DualPlanePolicy
	registry        *VirtualMCPRegistry
	knownConnectors []string
}

var defaultStandardConnectors = []string{
	"google_workspace",
	"catalog_3000",
	"salesforce",
	"azure_blob",
	"office365",
	"zendesk",
	"aws_s3",
	"github",
	"trello",
	"notion",
	"slack",
	"jira",
	"gcs",
}

func (acl *DualPlaneACL) initKnownConnectors() {
	candidates := append([]string(nil), defaultStandardConnectors...)
	for _, r := range acl.policy.Connectors.Rules {
		if r.Name != "" && r.Name != "*" {
			candidates = append(candidates, r.Name)
		}
	}
	for _, cp := range acl.policy.CrossPlaneConstraints {
		for _, src := range cp.WhenSourceConnector {
			if src != "" && src != "*" {
				candidates = append(candidates, src)
			}
		}
	}
	seen := make(map[string]bool, len(candidates))
	var unique []string
	for _, c := range candidates {
		lower := strings.ToLower(c)
		if !seen[lower] && lower != "" {
			seen[lower] = true
			unique = append(unique, c)
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		if len(unique[i]) != len(unique[j]) {
			return len(unique[i]) > len(unique[j])
		}
		return unique[i] < unique[j]
	})
	acl.knownConnectors = unique
}

func (acl *DualPlaneACL) getRegistry() *VirtualMCPRegistry {
	acl.mu.RLock()
	if acl.registry != nil {
		reg := acl.registry
		acl.mu.RUnlock()
		return reg
	}
	acl.mu.RUnlock()

	acl.mu.Lock()
	defer acl.mu.Unlock()
	if acl.registry == nil {
		acl.registry = NewVirtualMCPRegistry(acl)
	}
	return acl.registry
}

// RegisterVirtualMCP registers a virtual MCP slug for tenant scoping and ACL.
func (acl *DualPlaneACL) RegisterVirtualMCP(slug, tenantID string, tools []string) *VirtualMCP {
	return acl.getRegistry().RegisterVirtualMCP(slug, tenantID, tools)
}

// SetUserPermissions configures user-level tool allowlists within a Virtual MCP.
func (acl *DualPlaneACL) SetUserPermissions(slug, user string, allowedTools []string) error {
	return acl.getRegistry().SetUserPermissions(slug, user, allowedTools)
}

// CheckToolAccess verifies Virtual MCP existence, Connector ACL action, and User tool permissions.
func (acl *DualPlaneACL) CheckToolAccess(slug string, user string, connector string, tool string) (allowed bool, action PolicyAction, reason string) {
	return acl.getRegistry().CheckToolAccess(slug, user, connector, tool)
}

// NewDualPlaneACL initializes an evaluator from JSON configuration.
func NewDualPlaneACL(data []byte) (*DualPlaneACL, error) {
	var policy DualPlanePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse dual-plane ACL policy: %w", err)
	}
	acl := &DualPlaneACL{policy: policy}
	acl.initKnownConnectors()
	return acl, nil
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

	acl := &DualPlaneACL{policy: policy}
	acl.initKnownConnectors()
	return acl
}

// CheckLLM checks whether the requested provider and model are permitted.
func (acl *DualPlaneACL) CheckLLM(provider schemas.ModelProvider, model string) (PolicyAction, string) {
	if acl == nil {
		return PolicyActionAllow, ""
	}
	acl.mu.RLock()
	defer acl.mu.RUnlock()

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

// ExtractConnectorName extracts the canonical connector name from a tool name.
// Safe to invoke with a nil DualPlaneACL receiver.
func (acl *DualPlaneACL) ExtractConnectorName(toolName string) string {
	if toolName == "" {
		return ""
	}
	var candidates []string
	if acl != nil {
		acl.mu.RLock()
		candidates = acl.knownConnectors
		acl.mu.RUnlock()
	}
	if len(candidates) == 0 {
		candidates = defaultStandardConnectors
	}
	toolLower := strings.ToLower(toolName)
	for _, cand := range candidates {
		candLower := strings.ToLower(cand)
		if toolLower == candLower {
			return cand
		}
		candLen := len(candLower)
		if strings.HasPrefix(toolLower, candLower) && len(toolLower) > candLen {
			sep := toolLower[candLen]
			if sep == '_' || sep == '-' || sep == ':' || sep == '/' || sep == '.' {
				return cand
			}
		}
	}
	if idx := strings.IndexAny(toolName, "-:/"); idx > 0 {
		return toolName[:idx]
	}
	return toolName
}

// CheckConnector checks whether a connector or tool is permitted.
func (acl *DualPlaneACL) CheckConnector(connectorName, requestedScope string) (PolicyAction, string) {
	if acl == nil {
		return PolicyActionAllow, ""
	}
	acl.mu.RLock()
	defer acl.mu.RUnlock()

	nameLower := strings.ToLower(connectorName)
	canonicalLower := strings.ToLower(acl.ExtractConnectorName(connectorName))
	for _, rule := range acl.policy.Connectors.Rules {
		if ruleMatches(rule.Name, nameLower) || ruleMatches(rule.Name, canonicalLower) {
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
	if acl == nil {
		return nil
	}
	acl.mu.RLock()
	defer acl.mu.RUnlock()

	destTarget := fmt.Sprintf("%s/%s", strings.ToLower(string(destProvider)), destModel)

	for _, rule := range acl.policy.CrossPlaneConstraints {
		hasSensitive := false
		for _, conn := range activeConnectors {
			canonicalConn := acl.ExtractConnectorName(conn)
			for _, sensitive := range rule.WhenSourceConnector {
				if strings.EqualFold(conn, sensitive) || strings.EqualFold(canonicalConn, sensitive) {
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

// CheckCrossPlaneDataBoundary validates that connector data cannot flow to unauthorized destination LLMs.
// Returns nil if allowed, or formatted error if violated:
// "cross-plane violation: data from %s cannot be forwarded to %s models"
func (acl *DualPlaneACL) CheckCrossPlaneDataBoundary(sourceConnector string, destinationLLMProvider string) error {
	if acl == nil {
		return nil
	}
	acl.mu.RLock()
	defer acl.mu.RUnlock()

	sourceLower := strings.ToLower(sourceConnector)
	canonicalSource := strings.ToLower(acl.ExtractConnectorName(sourceConnector))
	destLower := strings.ToLower(destinationLLMProvider)

	for _, rule := range acl.policy.CrossPlaneConstraints {
		matchedSource := false
		for _, src := range rule.WhenSourceConnector {
			if src == "*" || strings.EqualFold(src, sourceLower) || strings.EqualFold(src, canonicalSource) {
				matchedSource = true
				break
			}
		}
		if matchedSource {
			for _, pattern := range rule.DisallowDestinationLLM {
				patLower := strings.ToLower(pattern)
				targetPrefix := strings.TrimSuffix(patLower, "/*")
				if patLower == "*" || patLower == destLower || patLower == destLower+"/*" || strings.EqualFold(targetPrefix, destLower) || strings.HasPrefix(destLower, targetPrefix) {
					return fmt.Errorf("cross-plane violation: data from %s cannot be forwarded to %s models", sourceConnector, destinationLLMProvider)
				}
			}
		}
	}
	return nil
}

// Enterprise context keys for Airlok MCP governance and provenance.
const (
	BifrostContextKeyActiveConnectors schemas.BifrostContextKey = "airlok_active_connectors"
	BifrostContextKeyMCPPolicyAction  schemas.BifrostContextKey = "airlok_mcp_policy_action"
	BifrostContextKeyAuditMonitored   schemas.BifrostContextKey = "airlok_audit_monitored"
)

// AddActiveConnector adds a source connector to request context provenance using copy-on-write semantics.
func AddActiveConnector(ctx *schemas.BifrostContext, connector string) {
	if ctx == nil || connector == "" {
		return
	}
	existing := GetActiveConnectors(ctx)
	for _, c := range existing {
		if strings.EqualFold(c, connector) {
			return
		}
	}
	next := make([]string, len(existing)+1)
	copy(next, existing)
	next[len(existing)] = connector
	ctx.SetValue(BifrostContextKeyActiveConnectors, next)
}

// GetActiveConnectors retrieves active source connectors from context, returning a copy.
func GetActiveConnectors(ctx *schemas.BifrostContext) []string {
	if ctx == nil {
		return nil
	}
	if v, ok := ctx.Value(BifrostContextKeyActiveConnectors).([]string); ok && len(v) > 0 {
		result := make([]string, len(v))
		copy(result, v)
		return result
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
