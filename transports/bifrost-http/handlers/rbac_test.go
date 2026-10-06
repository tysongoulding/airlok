package handlers

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/rbac"
	"github.com/valyala/fasthttp"
)

func TestRBACMiddleware_RequirePermission(t *testing.T) {
	authorizer := rbac.NewRBACAuthorizer()
	mw := NewRBACMiddleware(authorizer)

	// Handler that sets status 200 OK
	targetHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("authorized")
	}

	roleReqMiddleware := mw.Require(rbac.ResourceRoles, rbac.OpCreate)(targetHandler)

	// 1. Admin allowed
	ctxAdmin := &fasthttp.RequestCtx{}
	ctxAdmin.Request.Header.Set("X-User-Role", "Admin")
	roleReqMiddleware(ctxAdmin)
	if ctxAdmin.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200 for Admin, got %d", ctxAdmin.Response.StatusCode())
	}

	// 2. Developer rejected with HTTP 403
	ctxDev := &fasthttp.RequestCtx{}
	ctxDev.Request.Header.Set("X-User-Role", "Developer")
	roleReqMiddleware(ctxDev)
	if ctxDev.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected HTTP 403 for Developer creating roles, got %d", ctxDev.Response.StatusCode())
	}

	// 3. Local Admin bypass
	ctxLocalAdmin := &fasthttp.RequestCtx{}
	ctxLocalAdmin.SetUserValue(schemas.IsLocalAdminContextKey, true)
	roleReqMiddleware(ctxLocalAdmin)
	if ctxLocalAdmin.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200 for local admin, got %d", ctxLocalAdmin.Response.StatusCode())
	}

	// 4. Missing role rejected with HTTP 403
	ctxNoRole := &fasthttp.RequestCtx{}
	roleReqMiddleware(ctxNoRole)
	if ctxNoRole.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected HTTP 403 for unauthenticated caller, got %d", ctxNoRole.Response.StatusCode())
	}
}

func TestRBACMiddleware_PathInspector(t *testing.T) {
	authorizer := rbac.NewRBACAuthorizer()
	mw := NewRBACMiddleware(authorizer)

	targetHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	inspector := mw.PathInspectorMiddleware()(targetHandler)

	// Developer POST /api/governance/roles -> Forbidden
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/api/governance/roles")
	ctx.Request.Header.Set("X-User-Role", "Developer")
	inspector(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected HTTP 403 for developer posting roles, got %d", ctx.Response.StatusCode())
	}

	// Developer POST /api/governance/virtual-keys -> Allowed
	ctx2 := &fasthttp.RequestCtx{}
	ctx2.Request.Header.SetMethod("POST")
	ctx2.Request.SetRequestURI("/api/governance/virtual-keys")
	ctx2.Request.Header.Set("X-User-Role", "Developer")
	inspector(ctx2)
	if ctx2.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200 for developer creating virtual key, got %d", ctx2.Response.StatusCode())
	}
}
