package rbac

import (
	"fmt"
	"sync"
)

// RBACAuthorizer provides a thread-safe implementation of Authorizer.
type RBACAuthorizer struct {
	mu    sync.RWMutex
	roles map[string]*Role
}

// NewRBACAuthorizer initializes built-in system roles and permissions.
func NewRBACAuthorizer() *RBACAuthorizer {
	auth := &RBACAuthorizer{
		roles: make(map[string]*Role),
	}
	auth.initSystemRoles()
	return auth
}

func (a *RBACAuthorizer) initSystemRoles() {
	allResources := []Resource{
		ResourceLogs, ResourceModelProvider, ResourceVirtualKeys,
		ResourceAuditLogs, ResourceGuardrailsConfig, ResourceGuardrailsProviders,
		ResourceCluster, ResourceVirtualMCPs, ResourceAdaptiveRouter,
		ResourceRoles, ResourceDiagnostics, ResourceUsers,
		ResourceObservability, ResourceSettings, ResourcePlugins,
		ResourceMCPGateway, ResourceMCPLogs, ResourceWarp, ResourceWarpSession,
	}
	allOperations := []Operation{
		OpView, OpCreate, OpUpdate, OpDelete, OpDownload, OpInference, OpReveal,
	}

	// 1. Admin: Full system access
	adminPerms := make(map[string]bool)
	for _, res := range allResources {
		for _, op := range allOperations {
			adminPerms[fmt.Sprintf("%s:%s", res, op)] = true
		}
	}
	a.roles[RoleAdmin] = &Role{
		Name:        RoleAdmin,
		Description: "Full access to all gateway resources and administrative mutations",
		IsSystem:    true,
		Permissions: adminPerms,
	}

	// 2. Developer: CRUD on virtual keys, logs, model providers, and model/MCP inference
	devPerms := map[string]bool{
		"VirtualKeys:View":        true,
		"VirtualKeys:Create":      true,
		"VirtualKeys:Update":      true,
		"Logs:View":               true,
		"ModelProvider:View":      true,
		"ModelProvider:Inference": true,
		"VirtualMCPs:View":        true,
		"VirtualMCPs:Inference":   true,
		"Cluster:View":            true,
		"Observability:View":      true,
		"Diagnostics:View":        true,
	}
	a.roles[RoleDeveloper] = &Role{
		Name:        RoleDeveloper,
		Description: "CRUD access to keys, technical resources, logs, and model inference",
		IsSystem:    true,
		Permissions: devPerms,
	}

	// 3. Security Auditor: Read-only access to audit logs, guardrails, roles, and download capabilities
	auditorPerms := map[string]bool{
		"AuditLogs:View":           true,
		"AuditLogs:Download":       true,
		"GuardrailsConfig:View":    true,
		"GuardrailsProviders:View": true,
		"Roles:View":               true,
		"Users:View":               true,
		"Logs:View":                true,
		"MCPLogs:View":             true,
		"Diagnostics:View":         true,
	}
	a.roles[RoleSecurityAuditor] = &Role{
		Name:        RoleSecurityAuditor,
		Description: "Read-only access to audit trails, compliance logs, and security guardrail configurations",
		IsSystem:    true,
		Permissions: auditorPerms,
	}

	// 4. Operator: Cluster management, adaptive router tuning, health diagnostics
	opPerms := map[string]bool{
		"Cluster:View":          true,
		"Cluster:Update":        true,
		"AdaptiveRouter:View":   true,
		"AdaptiveRouter:Update": true,
		"Logs:View":             true,
		"Observability:View":    true,
		"VirtualKeys:View":      true,
		"Diagnostics:View":      true,
	}
	a.roles[RoleOperator] = &Role{
		Name:        RoleOperator,
		Description: "Operational health, cluster node management, routing, and telemetry inspection",
		IsSystem:    true,
		Permissions: opPerms,
	}
}

func (a *RBACAuthorizer) Authorize(role string, res Resource, op Operation) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	r, ok := a.roles[role]
	if !ok {
		return false, fmt.Errorf("role %s not defined", role)
	}

	key := fmt.Sprintf("%s:%s", res, op)
	return r.Permissions[key], nil
}

func (a *RBACAuthorizer) GetRole(name string) (*Role, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	r, ok := a.roles[name]
	if !ok {
		return nil, ErrRoleNotFound
	}

	// Return deep copy to prevent external mutation races
	copiedPerms := make(map[string]bool, len(r.Permissions))
	for k, v := range r.Permissions {
		copiedPerms[k] = v
	}

	return &Role{
		Name:        r.Name,
		Description: r.Description,
		IsSystem:    r.IsSystem,
		Permissions: copiedPerms,
	}, nil
}

func (a *RBACAuthorizer) ListRoles() []*Role {
	a.mu.RLock()
	defer a.mu.RUnlock()

	list := make([]*Role, 0, len(a.roles))
	for _, r := range a.roles {
		copiedPerms := make(map[string]bool, len(r.Permissions))
		for k, v := range r.Permissions {
			copiedPerms[k] = v
		}
		list = append(list, &Role{
			Name:        r.Name,
			Description: r.Description,
			IsSystem:    r.IsSystem,
			Permissions: copiedPerms,
		})
	}
	return list
}

func (a *RBACAuthorizer) CreateRole(name, description string, perms []Permission) (*Role, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.roles[name]; exists {
		return nil, ErrRoleAlreadyExists
	}

	permMap := make(map[string]bool, len(perms))
	for _, p := range perms {
		permMap[p.String()] = true
	}

	role := &Role{
		Name:        name,
		Description: description,
		IsSystem:    false,
		Permissions: permMap,
	}
	a.roles[name] = role

	return &Role{
		Name:        role.Name,
		Description: role.Description,
		IsSystem:    role.IsSystem,
		Permissions: permMap,
	}, nil
}

func (a *RBACAuthorizer) UpdateRolePermissions(name string, perms []Permission) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	role, exists := a.roles[name]
	if !exists {
		return ErrRoleNotFound
	}
	if role.IsSystem {
		return ErrCannotModifySystemRole
	}

	permMap := make(map[string]bool, len(perms))
	for _, p := range perms {
		permMap[p.String()] = true
	}
	role.Permissions = permMap
	return nil
}

func (a *RBACAuthorizer) DeleteRole(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	role, exists := a.roles[name]
	if !exists {
		return ErrRoleNotFound
	}
	if role.IsSystem {
		return ErrCannotDeleteSystemRole
	}

	delete(a.roles, name)
	return nil
}
