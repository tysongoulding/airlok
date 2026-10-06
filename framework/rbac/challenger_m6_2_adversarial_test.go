package rbac_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/framework/rbac"
)

// ============================================================================
// CHALLENGE 1: PRIVILEGE ESCALATION ATTACKS (SYSTEM ROLE TAMPERING & MUTATION)
// ============================================================================

func TestAdversarial_PrivilegeEscalation_SystemRoleTampering(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	systemRoles := []string{
		rbac.RoleAdmin,
		rbac.RoleDeveloper,
		rbac.RoleSecurityAuditor,
		rbac.RoleOperator,
	}

	for _, roleName := range systemRoles {
		// 1. Attempt to delete system role -> MUST fail with ErrCannotDeleteSystemRole
		if err := auth.DeleteRole(roleName); err != rbac.ErrCannotDeleteSystemRole {
			t.Fatalf("privilege escalation vulnerability: DeleteRole(%q) returned %v, expected ErrCannotDeleteSystemRole", roleName, err)
		}

		// 2. Attempt to strip permissions from system role -> MUST fail with ErrCannotModifySystemRole
		if err := auth.UpdateRolePermissions(roleName, []rbac.Permission{}); err != rbac.ErrCannotModifySystemRole {
			t.Fatalf("privilege escalation vulnerability: UpdateRolePermissions(%q, empty) returned %v, expected ErrCannotModifySystemRole", roleName, err)
		}

		// 3. Attempt to escalate permissions on system role -> MUST fail with ErrCannotModifySystemRole
		escalatePerms := []rbac.Permission{
			{Resource: rbac.ResourceRoles, Operation: rbac.OpCreate},
			{Resource: rbac.ResourceRoles, Operation: rbac.OpDelete},
		}
		if err := auth.UpdateRolePermissions(roleName, escalatePerms); err != rbac.ErrCannotModifySystemRole {
			t.Fatalf("privilege escalation vulnerability: UpdateRolePermissions(%q, escalate) returned %v, expected ErrCannotModifySystemRole", roleName, err)
		}

		// 4. Attempt to overwrite system role via CreateRole -> MUST fail with ErrRoleAlreadyExists
		if _, err := auth.CreateRole(roleName, "Attacker overwrite", escalatePerms); err != rbac.ErrRoleAlreadyExists {
			t.Fatalf("privilege escalation vulnerability: CreateRole(%q) returned %v, expected ErrRoleAlreadyExists", roleName, err)
		}

		// 5. Verify system role remains valid and intact
		role, err := auth.GetRole(roleName)
		if err != nil {
			t.Fatalf("system role %q unexpectedly corrupted: %v", roleName, err)
		}
		if !role.IsSystem {
			t.Fatalf("system role %q IsSystem flag was cleared", roleName)
		}
		if len(role.Permissions) == 0 {
			t.Fatalf("system role %q permissions were emptied", roleName)
		}
	}

	// 6. Test unauthorized lowercase / alias roles
	invalidRoles := []string{"admin", "developer", "security_auditor", "operator", "root", "superuser", ""}
	for _, badRole := range invalidRoles {
		allowed, err := auth.Authorize(badRole, rbac.ResourceRoles, rbac.OpCreate)
		if err == nil && allowed {
			t.Fatalf("privilege escalation vulnerability: unauthorized role %q was granted Roles:Create", badRole)
		}
		allowed, err = auth.Authorize(badRole, rbac.ResourceVirtualKeys, rbac.OpView)
		if err == nil && allowed {
			t.Fatalf("privilege escalation vulnerability: unauthorized role %q was granted VirtualKeys:View", badRole)
		}
	}
}

// ============================================================================
// CHALLENGE 2: UNAUTHORIZED RESOURCE ACTIONS BOUNDARY MATRIX
// ============================================================================

func TestAdversarial_UnauthorizedResourceActions_BoundaryMatrix(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	type boundaryCheck struct {
		role string
		res  rbac.Resource
		op   rbac.Operation
	}

	unauthorizedMatrix := []boundaryCheck{
		// Developer must NOT have administrative mutations, audit logs, cluster mutations, or key deletion
		{rbac.RoleDeveloper, rbac.ResourceRoles, rbac.OpCreate},
		{rbac.RoleDeveloper, rbac.ResourceRoles, rbac.OpUpdate},
		{rbac.RoleDeveloper, rbac.ResourceRoles, rbac.OpDelete},
		{rbac.RoleDeveloper, rbac.ResourceAuditLogs, rbac.OpView},
		{rbac.RoleDeveloper, rbac.ResourceAuditLogs, rbac.OpDownload},
		{rbac.RoleDeveloper, rbac.ResourceCluster, rbac.OpUpdate},
		{rbac.RoleDeveloper, rbac.ResourceAdaptiveRouter, rbac.OpUpdate},
		{rbac.RoleDeveloper, rbac.ResourceSettings, rbac.OpView},
		{rbac.RoleDeveloper, rbac.ResourceSettings, rbac.OpUpdate},
		{rbac.RoleDeveloper, rbac.ResourcePlugins, rbac.OpUpdate},
		{rbac.RoleDeveloper, rbac.ResourceVirtualKeys, rbac.OpDelete}, // Dev has View/Create/Update only

		// Security Auditor must NOT have inference or mutation capabilities
		{rbac.RoleSecurityAuditor, rbac.ResourceVirtualMCPs, rbac.OpInference},
		{rbac.RoleSecurityAuditor, rbac.ResourceModelProvider, rbac.OpInference},
		{rbac.RoleSecurityAuditor, rbac.ResourceVirtualKeys, rbac.OpCreate},
		{rbac.RoleSecurityAuditor, rbac.ResourceVirtualKeys, rbac.OpUpdate},
		{rbac.RoleSecurityAuditor, rbac.ResourceVirtualKeys, rbac.OpDelete},
		{rbac.RoleSecurityAuditor, rbac.ResourceRoles, rbac.OpCreate},
		{rbac.RoleSecurityAuditor, rbac.ResourceRoles, rbac.OpUpdate},
		{rbac.RoleSecurityAuditor, rbac.ResourceRoles, rbac.OpDelete},
		{rbac.RoleSecurityAuditor, rbac.ResourceCluster, rbac.OpUpdate},
		{rbac.RoleSecurityAuditor, rbac.ResourceAdaptiveRouter, rbac.OpUpdate},

		// Operator must NOT have role administration, audit trails, or inference
		{rbac.RoleOperator, rbac.ResourceRoles, rbac.OpCreate},
		{rbac.RoleOperator, rbac.ResourceRoles, rbac.OpUpdate},
		{rbac.RoleOperator, rbac.ResourceRoles, rbac.OpDelete},
		{rbac.RoleOperator, rbac.ResourceAuditLogs, rbac.OpView},
		{rbac.RoleOperator, rbac.ResourceAuditLogs, rbac.OpDownload},
		{rbac.RoleOperator, rbac.ResourceVirtualKeys, rbac.OpCreate},
		{rbac.RoleOperator, rbac.ResourceVirtualKeys, rbac.OpUpdate},
		{rbac.RoleOperator, rbac.ResourceVirtualKeys, rbac.OpDelete},
		{rbac.RoleOperator, rbac.ResourceVirtualMCPs, rbac.OpInference},
		{rbac.RoleOperator, rbac.ResourceModelProvider, rbac.OpInference},
	}

	for _, tc := range unauthorizedMatrix {
		allowed, err := auth.Authorize(tc.role, tc.res, tc.op)
		if err != nil {
			t.Fatalf("unexpected error authorizing %s on %s:%s: %v", tc.role, tc.res, tc.op, err)
		}
		if allowed {
			t.Fatalf("RBAC boundary breach: role %q was permitted unauthorized action %s:%s", tc.role, tc.res, tc.op)
		}
	}
}

// ============================================================================
// CHALLENGE 3: 500 CONCURRENT GOROUTINES AUTHORIZATION & MUTATION STRESS
// ============================================================================

func TestAdversarial_ConcurrentAuthorizationStress_500Goroutines(t *testing.T) {
	auth := rbac.NewRBACAuthorizer()

	const numWorkers = 500
	const iterationsPerWorker = 20

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	startBarrier := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			<-startBarrier

			for i := 0; i < iterationsPerWorker; i++ {
				// 1. Authorize standard operations
				adminAllowed, err := auth.Authorize(rbac.RoleAdmin, rbac.ResourceRoles, rbac.OpCreate)
				if err != nil || !adminAllowed {
					t.Errorf("Admin authorization failed under concurrency: %v", err)
				}

				devAllowed, err := auth.Authorize(rbac.RoleDeveloper, rbac.ResourceVirtualKeys, rbac.OpCreate)
				if err != nil || !devAllowed {
					t.Errorf("Developer authorization failed under concurrency: %v", err)
				}

				devBreach, _ := auth.Authorize(rbac.RoleDeveloper, rbac.ResourceRoles, rbac.OpCreate)
				if devBreach {
					t.Errorf("Developer breached boundary under concurrency")
				}

				// 2. Query and inspect roles
				_ = auth.ListRoles()
				_, _ = auth.GetRole(rbac.RoleSecurityAuditor)

				// 3. Attempt illegal system role mutations concurrently
				_ = auth.DeleteRole(rbac.RoleAdmin)
				_ = auth.UpdateRolePermissions(rbac.RoleDeveloper, []rbac.Permission{})
				_, _ = auth.CreateRole(rbac.RoleOperator, "Overwritten", nil)

				// 4. Create, update, and delete ephemeral custom roles per worker
				if i%5 == 0 {
					customName := fmt.Sprintf("EphemeralRole_%d_%d", workerID, i)
					perms := []rbac.Permission{
						{Resource: rbac.ResourceLogs, Operation: rbac.OpView},
					}
					createdRole, cErr := auth.CreateRole(customName, "Temporary stress role", perms)
					if cErr == nil && createdRole != nil {
						canLog, _ := auth.Authorize(customName, rbac.ResourceLogs, rbac.OpView)
						if !canLog {
							t.Errorf("Ephemeral role failed to authorize view logs")
						}
						_ = auth.UpdateRolePermissions(customName, append(perms, rbac.Permission{
							Resource:  rbac.ResourceDiagnostics,
							Operation: rbac.OpView,
						}))
						_ = auth.DeleteRole(customName)
					}
				}
			}
		}()
	}

	close(startBarrier)
	wg.Wait()

	// Final verification: all 4 system roles must still exist completely unmodified
	for _, roleName := range []string{rbac.RoleAdmin, rbac.RoleDeveloper, rbac.RoleSecurityAuditor, rbac.RoleOperator} {
		role, err := auth.GetRole(roleName)
		if err != nil || role == nil {
			t.Fatalf("system role %q missing after concurrent stress test: %v", roleName, err)
		}
		if !role.IsSystem {
			t.Fatalf("system role %q IsSystem flag corrupted", roleName)
		}
	}
}
