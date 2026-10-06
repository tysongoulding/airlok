package rbac_test

import (
	"sync"
	"testing"

	"github.com/maximhq/bifrost/framework/rbac"
)

func TestRBAC_Admin_FullAccess(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	allow, err := auth.Authorize(rbac.RoleAdmin, rbac.ResourceRoles, rbac.OpCreate)
	if err != nil || !allow {
		t.Fatalf("Admin must be allowed to create roles")
	}

	allowLogs, err := auth.Authorize(rbac.RoleAdmin, rbac.ResourceLogs, rbac.OpView)
	if err != nil || !allowLogs {
		t.Fatalf("Admin must be allowed to view logs")
	}

	allowInference, err := auth.Authorize(rbac.RoleAdmin, rbac.ResourceVirtualMCPs, rbac.OpInference)
	if err != nil || !allowInference {
		t.Fatalf("Admin must be allowed to perform inference")
	}
}

func TestRBAC_Developer_PermissionsAndBoundaries(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	// Developer can view/create keys and do inference
	allowKeyCreate, err := auth.Authorize(rbac.RoleDeveloper, rbac.ResourceVirtualKeys, rbac.OpCreate)
	if err != nil || !allowKeyCreate {
		t.Fatalf("Developer must be allowed to create virtual keys")
	}

	allowInference, err := auth.Authorize(rbac.RoleDeveloper, rbac.ResourceVirtualMCPs, rbac.OpInference)
	if err != nil || !allowInference {
		t.Fatalf("Developer must be allowed to perform inference")
	}

	// Developer cannot create roles or modify audit logs
	allowRoleCreate, err := auth.Authorize(rbac.RoleDeveloper, rbac.ResourceRoles, rbac.OpCreate)
	if err != nil || allowRoleCreate {
		t.Fatalf("Developer must NOT be allowed to create roles")
	}

	allowAuditView, err := auth.Authorize(rbac.RoleDeveloper, rbac.ResourceAuditLogs, rbac.OpView)
	if err != nil || allowAuditView {
		t.Fatalf("Developer must NOT be allowed to view audit logs")
	}
}

func TestRBAC_SecurityAuditor_PermissionsAndBoundaries(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	// Security Auditor can view and download audit logs
	allowViewAudit, err := auth.Authorize(rbac.RoleSecurityAuditor, rbac.ResourceAuditLogs, rbac.OpView)
	if err != nil || !allowViewAudit {
		t.Fatalf("Security Auditor must be allowed to view audit logs")
	}

	allowDownloadAudit, err := auth.Authorize(rbac.RoleSecurityAuditor, rbac.ResourceAuditLogs, rbac.OpDownload)
	if err != nil || !allowDownloadAudit {
		t.Fatalf("Security Auditor must be allowed to download audit logs")
	}

	// Security Auditor CANNOT perform inference
	allowInference, err := auth.Authorize(rbac.RoleSecurityAuditor, rbac.ResourceVirtualMCPs, rbac.OpInference)
	if err != nil || allowInference {
		t.Fatalf("Security Auditor must NOT be allowed to perform inference")
	}
}

func TestRBAC_Operator_Permissions(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	allowClusterUpdate, err := auth.Authorize(rbac.RoleOperator, rbac.ResourceCluster, rbac.OpUpdate)
	if err != nil || !allowClusterUpdate {
		t.Fatalf("Operator must be allowed to update cluster")
	}

	allowRouterUpdate, err := auth.Authorize(rbac.RoleOperator, rbac.ResourceAdaptiveRouter, rbac.OpUpdate)
	if err != nil || !allowRouterUpdate {
		t.Fatalf("Operator must be allowed to update adaptive router")
	}

	allowRoleCreate, err := auth.Authorize(rbac.RoleOperator, rbac.ResourceRoles, rbac.OpCreate)
	if err != nil || allowRoleCreate {
		t.Fatalf("Operator must NOT be allowed to create roles")
	}
}

func TestRBAC_UndefinedRole_And_UndefinedResource(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	allow, err := auth.Authorize("GhostRole", rbac.ResourceLogs, rbac.OpView)
	if err == nil || allow {
		t.Fatalf("undefined role must return error and false")
	}

	allowRes, err := auth.Authorize(rbac.RoleDeveloper, rbac.Resource("NonExistentResource"), rbac.OpView)
	if err != nil || allowRes {
		t.Fatalf("undefined resource must be denied without error")
	}
}

func TestRBAC_CustomRole_LifecycleAndSystemProtection(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	// Cannot delete or modify system roles
	if err := auth.DeleteRole(rbac.RoleAdmin); err != rbac.ErrCannotDeleteSystemRole {
		t.Fatalf("deleting system role must fail with ErrCannotDeleteSystemRole, got %v", err)
	}
	if err := auth.UpdateRolePermissions(rbac.RoleDeveloper, []rbac.Permission{}); err != rbac.ErrCannotModifySystemRole {
		t.Fatalf("modifying system role must fail with ErrCannotModifySystemRole, got %v", err)
	}

	// Create custom role
	customRoleName := "ComplianceOfficer"
	perms := []rbac.Permission{
		{Resource: rbac.ResourceAuditLogs, Operation: rbac.OpView},
		{Resource: rbac.ResourceDiagnostics, Operation: rbac.OpView},
	}
	role, err := auth.CreateRole(customRoleName, "Custom compliance officer role", perms)
	if err != nil || role == nil {
		t.Fatalf("failed to create custom role: %v", err)
	}

	allowAudit, err := auth.Authorize(customRoleName, rbac.ResourceAuditLogs, rbac.OpView)
	if err != nil || !allowAudit {
		t.Fatalf("custom role must have permitted access")
	}

	allowInference, err := auth.Authorize(customRoleName, rbac.ResourceVirtualMCPs, rbac.OpInference)
	if err != nil || allowInference {
		t.Fatalf("custom role must not have ungranted access")
	}

	// Update custom role
	updatedPerms := []rbac.Permission{
		{Resource: rbac.ResourceAuditLogs, Operation: rbac.OpView},
		{Resource: rbac.ResourceVirtualMCPs, Operation: rbac.OpInference},
	}
	if err := auth.UpdateRolePermissions(customRoleName, updatedPerms); err != nil {
		t.Fatalf("failed to update custom role: %v", err)
	}

	allowInferenceNow, _ := auth.Authorize(customRoleName, rbac.ResourceVirtualMCPs, rbac.OpInference)
	if !allowInferenceNow {
		t.Fatalf("custom role should now have inference access")
	}

	// Delete custom role
	if err := auth.DeleteRole(customRoleName); err != nil {
		t.Fatalf("failed to delete custom role: %v", err)
	}

	_, err = auth.Authorize(customRoleName, rbac.ResourceAuditLogs, rbac.OpView)
	if err == nil {
		t.Fatalf("authorizing deleted role must return error")
	}
}

func TestRBAC_ConcurrentAuthorizations_RaceDetector(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	workers := 25
	iterations := 100
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, _ = auth.Authorize(rbac.RoleAdmin, rbac.ResourceRoles, rbac.OpCreate)
				_, _ = auth.Authorize(rbac.RoleDeveloper, rbac.ResourceVirtualKeys, rbac.OpCreate)
				_, _ = auth.Authorize(rbac.RoleSecurityAuditor, rbac.ResourceAuditLogs, rbac.OpView)
				_, _ = auth.Authorize(rbac.RoleOperator, rbac.ResourceCluster, rbac.OpUpdate)
				_ = auth.ListRoles()
			}
		}(w)
	}

	wg.Wait()
}
