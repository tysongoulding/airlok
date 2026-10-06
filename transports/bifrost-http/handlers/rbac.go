package handlers

import (
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/rbac"
	"github.com/valyala/fasthttp"
)

// RBACMiddleware enforces role-based access control across FastHTTP routes.
type RBACMiddleware struct {
	authorizer rbac.Authorizer
}

// NewRBACMiddleware constructs a new RBACMiddleware.
func NewRBACMiddleware(authorizer rbac.Authorizer) *RBACMiddleware {
	return &RBACMiddleware{
		authorizer: authorizer,
	}
}

// ExtractRole derives the caller's role from context or request headers.
func (m *RBACMiddleware) ExtractRole(ctx *fasthttp.RequestCtx) string {
	// 1. Local admin session bypass
	if isAdmin, ok := ctx.UserValue(schemas.IsLocalAdminContextKey).(bool); ok && isAdmin {
		return rbac.RoleAdmin
	}
	// 2. Test harness & reverse proxy header
	if headerRole := string(ctx.Request.Header.Peek("X-User-Role")); headerRole != "" {
		return headerRole
	}
	// 3. SSO enterprise role
	if role, ok := ctx.UserValue("enterprise_role").(string); ok && role != "" {
		return role
	}
	if role, ok := ctx.UserValue(schemas.BifrostContextKeyUserRole).(string); ok && role != "" {
		return role
	}
	return ""
}

// Require returns a route-level middleware enforcing specific permissions.
func (m *RBACMiddleware) Require(res rbac.Resource, op rbac.Operation) schemas.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			role := m.ExtractRole(ctx)
			if role == "" {
				SendJSONWithStatus(ctx, map[string]string{
					"error": "unauthorized: permission denied",
				}, fasthttp.StatusForbidden)
				return
			}

			allowed, err := m.authorizer.Authorize(role, res, op)
			if err != nil || !allowed {
				SendJSONWithStatus(ctx, map[string]string{
					"error": "unauthorized: permission denied",
				}, fasthttp.StatusForbidden)
				return
			}

			ctx.SetUserValue("rbac_authorized", true)
			next(ctx)
		}
	}
}

// PathInspectorMiddleware intercepts path patterns and enforces automatic RBAC.
func (m *RBACMiddleware) PathInspectorMiddleware() schemas.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			path := string(ctx.Request.URI().PathOriginal())
			method := string(ctx.Method())

			// Skip public routes
			if strings.HasPrefix(path, "/health") || strings.HasPrefix(path, "/.well-known") {
				next(ctx)
				return
			}

			res, op, matched := matchRoutePermission(method, path)
			if matched {
				role := m.ExtractRole(ctx)
				if role == "" {
					SendJSONWithStatus(ctx, map[string]string{
						"error": "unauthorized: permission denied",
					}, fasthttp.StatusForbidden)
					return
				}

				allowed, err := m.authorizer.Authorize(role, res, op)
				if err != nil || !allowed {
					SendJSONWithStatus(ctx, map[string]string{
						"error": "unauthorized: permission denied",
					}, fasthttp.StatusForbidden)
					return
				}
			}

			next(ctx)
		}
	}
}

func matchRoutePermission(method, path string) (rbac.Resource, rbac.Operation, bool) {
	switch {
	case strings.HasPrefix(path, "/api/governance/roles"):
		switch method {
		case "GET":
			return rbac.ResourceRoles, rbac.OpView, true
		case "POST":
			return rbac.ResourceRoles, rbac.OpCreate, true
		case "PUT":
			return rbac.ResourceRoles, rbac.OpUpdate, true
		case "DELETE":
			return rbac.ResourceRoles, rbac.OpDelete, true
		}
	case strings.HasPrefix(path, "/api/governance/virtual-keys"):
		switch method {
		case "GET":
			return rbac.ResourceVirtualKeys, rbac.OpView, true
		case "POST":
			return rbac.ResourceVirtualKeys, rbac.OpCreate, true
		case "PUT":
			return rbac.ResourceVirtualKeys, rbac.OpUpdate, true
		case "DELETE":
			return rbac.ResourceVirtualKeys, rbac.OpDelete, true
		}
	case strings.HasPrefix(path, "/api/audit-logs"):
		if strings.Contains(path, "download") || strings.Contains(path, "export") {
			return rbac.ResourceAuditLogs, rbac.OpDownload, true
		}
		return rbac.ResourceAuditLogs, rbac.OpView, true
	case strings.HasPrefix(path, "/mcp/"):
		return rbac.ResourceVirtualMCPs, rbac.OpInference, true
	}
	return "", "", false
}
