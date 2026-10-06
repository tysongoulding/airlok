package rbac

import (
	"errors"
	"fmt"
)

var (
	ErrRoleNotFound           = errors.New("role not found")
	ErrRoleAlreadyExists       = errors.New("role already exists")
	ErrCannotDeleteSystemRole  = errors.New("cannot delete system role")
	ErrCannotModifySystemRole  = errors.New("cannot modify system role")
)

// Standard System Roles
const (
	RoleAdmin           = "Admin"
	RoleDeveloper       = "Developer"
	RoleSecurityAuditor = "Security Auditor"
	RoleOperator        = "Operator"
)

// Resource represents a protected gateway entity.
type Resource string

const (
	ResourceLogs                Resource = "Logs"
	ResourceModelProvider       Resource = "ModelProvider"
	ResourceVirtualKeys         Resource = "VirtualKeys"
	ResourceAuditLogs           Resource = "AuditLogs"
	ResourceGuardrailsConfig    Resource = "GuardrailsConfig"
	ResourceGuardrailsProviders Resource = "GuardrailsProviders"
	ResourceCluster             Resource = "Cluster"
	ResourceVirtualMCPs         Resource = "VirtualMCPs"
	ResourceAdaptiveRouter      Resource = "AdaptiveRouter"
	ResourceRoles               Resource = "Roles"
	ResourceDiagnostics         Resource = "Diagnostics"
	ResourceUsers               Resource = "Users"
	ResourceObservability       Resource = "Observability"
	ResourceSettings            Resource = "Settings"
	ResourcePlugins             Resource = "Plugins"
	ResourceMCPGateway          Resource = "MCPGateway"
	ResourceMCPLogs             Resource = "MCPLogs"
	ResourceWarp                Resource = "Warp"
	ResourceWarpSession         Resource = "WarpSession"
)

// Operation represents an action performed on a resource.
type Operation string

const (
	OpView      Operation = "View"
	OpCreate    Operation = "Create"
	OpUpdate    Operation = "Update"
	OpDelete    Operation = "Delete"
	OpDownload  Operation = "Download"
	OpInference Operation = "Inference"
	OpReveal    Operation = "Reveal"
)

// Permission models a specific resource:operation entitlement.
type Permission struct {
	Resource  Resource  `json:"resource"`
	Operation Operation `json:"operation"`
}

func (p Permission) String() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Operation)
}

// Role defines a collection of permissions.
type Role struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	IsSystem    bool            `json:"is_system"`
	Permissions map[string]bool `json:"permissions"` // "Resource:Operation" -> true
}

// Authorizer specifies RBAC validation and role lifecycle operations.
type Authorizer interface {
	Authorize(role string, res Resource, op Operation) (bool, error)
	GetRole(name string) (*Role, error)
	ListRoles() []*Role
	CreateRole(name, description string, perms []Permission) (*Role, error)
	UpdateRolePermissions(name string, perms []Permission) error
	DeleteRole(name string) error
}
