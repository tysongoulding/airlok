package governance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/maximhq/bifrost/core/schemas"
)

var (
	// ErrVirtualMCPNotFound indicates a requested virtual MCP slug does not exist.
	ErrVirtualMCPNotFound = errors.New("virtual mcp not found")
	// ErrUnauthorizedToolAccess indicates a requested tool is not permitted for the user/tenant.
	ErrUnauthorizedToolAccess = errors.New("unauthorized tool access")
	// ErrConnectorBlockedByACL indicates an underlying connector is blocked by policy.
	ErrConnectorBlockedByACL = errors.New("connector is blocked by security governance policy")
)

// VirtualMCP represents an enterprise tenant-scoped virtual tool container.
type VirtualMCP struct {
	Slug        string              `json:"slug"`
	TenantID    string              `json:"tenant_id"`
	Tools       []string            `json:"tools"`       // Tenant-level allowed tools, or ["*"]
	Permissions map[string][]string `json:"permissions"` // user -> allowed tools, or ["*"]
}

// ToolAuthorizer defines the contract for validating tool access across tenant and user scopes.
type ToolAuthorizer interface {
	AuthorizeTool(ctx context.Context, user string, tenant string, tool string) (bool, error)
	CheckToolAccess(slug string, user string, connector string, tool string) (allowed bool, action PolicyAction, reason string)
}

// VirtualMCPRegistry coordinates multi-tenant Virtual MCP registrations and authorizations.
type VirtualMCPRegistry struct {
	mu          sync.RWMutex
	virtualMCPs map[string]*VirtualMCP // slug -> VirtualMCP
	acl         *DualPlaneACL          // Connector & LLM ACL evaluator
}

// NewVirtualMCPRegistry initializes a thread-safe registry.
func NewVirtualMCPRegistry(acl *DualPlaneACL) *VirtualMCPRegistry {
	if acl == nil {
		acl = DefaultAirlokPolicy()
	}
	return &VirtualMCPRegistry{
		virtualMCPs: make(map[string]*VirtualMCP),
		acl:         acl,
	}
}

// RegisterVirtualMCP registers a new Virtual MCP for a tenant.
func (r *VirtualMCPRegistry) RegisterVirtualMCP(slug, tenantID string, tools []string) *VirtualMCP {
	r.mu.Lock()
	defer r.mu.Unlock()

	toolsCopy := make([]string, len(tools))
	copy(toolsCopy, tools)

	vmcp := &VirtualMCP{
		Slug:        slug,
		TenantID:    tenantID,
		Tools:       toolsCopy,
		Permissions: make(map[string][]string),
	}
	r.virtualMCPs[slug] = vmcp
	return vmcp
}

// SetUserPermissions configures per-user allowed tools for a specific Virtual MCP.
func (r *VirtualMCPRegistry) SetUserPermissions(slug, user string, allowedTools []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	vmcp, ok := r.virtualMCPs[slug]
	if !ok {
		return fmt.Errorf("%w: %s", ErrVirtualMCPNotFound, slug)
	}

	toolsCopy := make([]string, len(allowedTools))
	copy(toolsCopy, allowedTools)
	vmcp.Permissions[user] = toolsCopy
	return nil
}

// GetVirtualMCP retrieves a Virtual MCP by its slug.
func (r *VirtualMCPRegistry) GetVirtualMCP(slug string) (*VirtualMCP, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	vmcp, ok := r.virtualMCPs[slug]
	if !ok {
		return nil, false
	}
	// Return shallow copy
	permissionsCopy := make(map[string][]string, len(vmcp.Permissions))
	for k, v := range vmcp.Permissions {
		vCopy := make([]string, len(v))
		copy(vCopy, v)
		permissionsCopy[k] = vCopy
	}
	return &VirtualMCP{
		Slug:        vmcp.Slug,
		TenantID:    vmcp.TenantID,
		Tools:       append([]string(nil), vmcp.Tools...),
		Permissions: permissionsCopy,
	}, true
}

// checkToolAccessLocked verifies Virtual MCP existence, connector ACL, and user-level tool permissions.
// Caller MUST hold r.mu (at least for reading).
func (r *VirtualMCPRegistry) checkToolAccessLocked(slug string, user string, connector string, tool string) (allowed bool, action PolicyAction, reason string) {
	// 1. Virtual MCP existence check
	vmcp, exists := r.virtualMCPs[slug]
	if !exists {
		return false, PolicyActionDeny, fmt.Sprintf("virtual mcp %s not found", slug)
	}

	// 2. Connector ACL rule check via Dual-Plane ACL
	if r.acl != nil && connector != "" {
		act, rsn := r.acl.CheckConnector(connector, "")
		if act == PolicyActionDeny {
			if rsn == "" {
				rsn = fmt.Sprintf("connector %s is blocked by security governance policy", connector)
			}
			return false, PolicyActionDeny, rsn
		}
		action = act
	} else {
		action = PolicyActionAllow
	}

	// 3. User tool permission check
	if len(vmcp.Permissions) > 0 && user != "" {
		if allowedTools, userExists := vmcp.Permissions[user]; userExists {
			toolAllowed := false
			for _, at := range allowedTools {
				if at == tool || at == "*" {
					toolAllowed = true
					break
				}
			}
			if !toolAllowed {
				return false, PolicyActionDeny, fmt.Sprintf("user %s lacks permission for tool %s", user, tool)
			}
			return true, action, ""
		}
	}

	// 4. Fallback to Virtual MCP declared tool list
	if tool != "" {
		toolAllowed := false
		for _, t := range vmcp.Tools {
			if t == tool || t == "*" {
				toolAllowed = true
				break
			}
		}
		if !toolAllowed {
			return false, PolicyActionDeny, fmt.Sprintf("tool %s is not permitted on virtual mcp %s", tool, slug)
		}
	}

	return true, action, ""
}

// CheckToolAccess verifies Virtual MCP existence, connector ACL, and user-level tool permissions.
func (r *VirtualMCPRegistry) CheckToolAccess(slug string, user string, connector string, tool string) (allowed bool, action PolicyAction, reason string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.checkToolAccessLocked(slug, user, connector, tool)
}

// AuthorizeTool implements the ToolAuthorizer interface specified in PROJECT.md.
func (r *VirtualMCPRegistry) AuthorizeTool(ctx context.Context, user string, tenant string, tool string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	foundTenant := false
	for _, vmcp := range r.virtualMCPs {
		if vmcp.TenantID == tenant {
			foundTenant = true
			allowed, _, reason := r.checkToolAccessLocked(vmcp.Slug, user, "", tool)
			if allowed {
				return true, nil
			}
			if reason != "" && strings.Contains(reason, "lacks permission") {
				return false, fmt.Errorf("%w: %s", ErrUnauthorizedToolAccess, reason)
			}
		}
	}

	if !foundTenant {
		return false, fmt.Errorf("%w: tenant '%s' has no virtual mcps", ErrUnauthorizedToolAccess, tenant)
	}
	return false, fmt.Errorf("%w: tool '%s' unauthorized for user '%s' in tenant '%s'", ErrUnauthorizedToolAccess, tool, user, tenant)
}

// StampContext stamps schemas.MCPContextKeyIncludeTools on a BifrostContext with allowed tools for the given slug and user.
func (r *VirtualMCPRegistry) StampContext(ctx *schemas.BifrostContext, slug, user string) bool {
	if ctx == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	vmcp, exists := r.virtualMCPs[slug]
	if !exists {
		return false
	}

	var allowed []string
	if user != "" && len(vmcp.Permissions) > 0 {
		if userTools, ok := vmcp.Permissions[user]; ok {
			allowed = userTools
		}
	}
	if len(allowed) == 0 {
		allowed = vmcp.Tools
	}

	ctx.SetValue(schemas.MCPContextKeyIncludeTools, allowed)
	return true
}
