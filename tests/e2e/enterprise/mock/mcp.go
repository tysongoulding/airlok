package mock

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type MCPPolicyAction string

const (
	MCPActionAllow           MCPPolicyAction = "allow"
	MCPActionAudit           MCPPolicyAction = "audit"
	MCPActionRequireApproval MCPPolicyAction = "require_approval"
	MCPActionDeny            MCPPolicyAction = "deny"
)

type VirtualMCP struct {
	Slug        string
	TenantID    string
	Tools       []string
	Permissions map[string][]string // user -> allowed tools
}

type CrossPlaneConstraint struct {
	SourceConnector string
	DisallowedLLMs  []string
}

// MockMCPGovernance coordinates multi-tenant virtual MCPs, RFC 8693 token exchange, and ACL.
type MockMCPGovernance struct {
	mu                    sync.RWMutex
	VirtualMCPs           map[string]*VirtualMCP
	ExchangedTokens       map[string]string // userToken:audience -> exchangedToken
	ConnectorRules        map[string]MCPPolicyAction
	CrossPlaneConstraints []CrossPlaneConstraint
}

func NewMockMCPGovernance() *MockMCPGovernance {
	return &MockMCPGovernance{
		VirtualMCPs:     make(map[string]*VirtualMCP),
		ExchangedTokens: make(map[string]string),
		ConnectorRules: map[string]MCPPolicyAction{
			"google_workspace": MCPActionAllow,
			"slack":            MCPActionAllow,
			"office365":        MCPActionDeny,
			"catalog_3000":     MCPActionRequireApproval,
		},
		CrossPlaneConstraints: []CrossPlaneConstraint{
			{
				SourceConnector: "google_workspace",
				DisallowedLLMs:  []string{"openai"},
			},
			{
				SourceConnector: "slack",
				DisallowedLLMs:  []string{"openai"},
			},
		},
	}
}

func (m *MockMCPGovernance) RegisterVirtualMCP(slug, tenantID string, tools []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VirtualMCPs[slug] = &VirtualMCP{
		Slug:        slug,
		TenantID:    tenantID,
		Tools:       tools,
		Permissions: make(map[string][]string),
	}
}

func (m *MockMCPGovernance) SetUserPermissions(slug, user string, allowedTools []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if vmcp, ok := m.VirtualMCPs[slug]; ok {
		vmcp.Permissions[user] = allowedTools
	}
}

// ExchangeToken implements RFC 8693 OAuth 2.0 Token Exchange.
func (m *MockMCPGovernance) ExchangeToken(ctx context.Context, subjectToken string, audience string) (string, error) {
	if subjectToken == "" {
		return "", fmt.Errorf("missing subject token")
	}
	if strings.HasPrefix(subjectToken, "expired-") {
		return "", fmt.Errorf("subject token expired")
	}

	key := fmt.Sprintf("%s:%s", subjectToken, audience)
	m.mu.Lock()
	defer m.mu.Unlock()

	if cached, ok := m.ExchangedTokens[key]; ok {
		return cached, nil
	}

	exchanged := fmt.Sprintf("downstream-token-for-%s-%d", audience, len(m.ExchangedTokens)+1)
	m.ExchangedTokens[key] = exchanged
	return exchanged, nil
}

// CheckToolAccess verifies Virtual MCP tenant scope and user permissions.
func (m *MockMCPGovernance) CheckToolAccess(slug string, user string, connector string, tool string) (allowed bool, action MCPPolicyAction, reason string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Virtual MCP existence
	vmcp, exists := m.VirtualMCPs[slug]
	if !exists {
		return false, MCPActionDeny, fmt.Sprintf("virtual mcp %s not found", slug)
	}

	// 2. Connector ACL rule
	action, ok := m.ConnectorRules[connector]
	if !ok || action == MCPActionDeny {
		return false, MCPActionDeny, fmt.Sprintf("connector %s is blocked by security governance policy", connector)
	}

	// 3. User tool permissions
	if allowedTools, userExists := vmcp.Permissions[user]; userExists {
		toolAllowed := false
		for _, at := range allowedTools {
			if at == tool || at == "*" {
				toolAllowed = true
				break
			}
		}
		if !toolAllowed {
			return false, MCPActionDeny, fmt.Sprintf("user %s lacks permission for tool %s", user, tool)
		}
	}

	return true, action, ""
}

// CheckCrossPlaneDataBoundary checks if connector data is permitted to flow to destination LLM.
func (m *MockMCPGovernance) CheckCrossPlaneDataBoundary(sourceConnector string, destinationLLMProvider string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, constraint := range m.CrossPlaneConstraints {
		if constraint.SourceConnector == sourceConnector {
			for _, disallowed := range constraint.DisallowedLLMs {
				if disallowed == destinationLLMProvider || disallowed == "*" {
					return fmt.Errorf("cross-plane violation: data from %s cannot be forwarded to %s models", sourceConnector, destinationLLMProvider)
				}
			}
		}
	}
	return nil
}
