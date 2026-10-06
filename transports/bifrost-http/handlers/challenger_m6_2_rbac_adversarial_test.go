package handlers

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/rbac"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// CHALLENGE: HTTP 403 FORBIDDEN ENFORCEMENT UNDER 500-GOROUTINE CONCURRENCY
// ============================================================================

func TestAdversarial_RBAC_HTTP403Enforcement_UnderConcurrency(t *testing.T) {
	authorizer := rbac.NewRBACAuthorizer()
	mw := NewRBACMiddleware(authorizer)

	targetOKHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString(`{"status":"ok"}`)
	}

	roleMiddleware := mw.Require(rbac.ResourceRoles, rbac.OpCreate)(targetOKHandler)
	inspectorMiddleware := mw.PathInspectorMiddleware()(targetOKHandler)

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
				// Case A: Missing role / empty header -> MUST return HTTP 403
				ctxNoRole := &fasthttp.RequestCtx{}
				ctxNoRole.Request.SetRequestURI("/api/governance/roles")
				ctxNoRole.Request.Header.SetMethod("POST")
				roleMiddleware(ctxNoRole)
				if ctxNoRole.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for missing role, got %d", ctxNoRole.Response.StatusCode())
				}
				verifyForbiddenBody(t, ctxNoRole.Response.Body())

				// Case B: Unauthorized Developer requesting Roles:Create -> MUST return HTTP 403
				ctxDev := &fasthttp.RequestCtx{}
				ctxDev.Request.Header.Set("X-User-Role", "Developer")
				roleMiddleware(ctxDev)
				if ctxDev.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for Developer creating roles, got %d", ctxDev.Response.StatusCode())
				}
				verifyForbiddenBody(t, ctxDev.Response.Body())

				// Case C: Spoofed / unknown role name -> MUST return HTTP 403
				ctxSpoofed := &fasthttp.RequestCtx{}
				ctxSpoofed.Request.Header.Set("X-User-Role", fmt.Sprintf("MaliciousAttackerRole_%d", workerID))
				roleMiddleware(ctxSpoofed)
				if ctxSpoofed.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for spoofed role, got %d", ctxSpoofed.Response.StatusCode())
				}
				verifyForbiddenBody(t, ctxSpoofed.Response.Body())

				// Case D: Lowercase 'admin' (strict case-sensitive role check) -> MUST return HTTP 403
				ctxLowerAdmin := &fasthttp.RequestCtx{}
				ctxLowerAdmin.Request.Header.Set("X-User-Role", "admin")
				roleMiddleware(ctxLowerAdmin)
				if ctxLowerAdmin.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 for lowercase 'admin', got %d", ctxLowerAdmin.Response.StatusCode())
				}
				verifyForbiddenBody(t, ctxLowerAdmin.Response.Body())

				// Case E: PathInspector intercepting unauthorized POST to /api/governance/roles
				ctxInspectDev := &fasthttp.RequestCtx{}
				ctxInspectDev.Request.Header.SetMethod("POST")
				ctxInspectDev.Request.SetRequestURI("/api/governance/roles")
				ctxInspectDev.Request.Header.Set("X-User-Role", "Developer")
				inspectorMiddleware(ctxInspectDev)
				if ctxInspectDev.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 from path inspector for Developer POST roles, got %d", ctxInspectDev.Response.StatusCode())
				}
				verifyForbiddenBody(t, ctxInspectDev.Response.Body())

				// Case F: PathInspector intercepting Operator attempting /api/audit-logs
				ctxInspectOp := &fasthttp.RequestCtx{}
				ctxInspectOp.Request.Header.SetMethod("GET")
				ctxInspectOp.Request.SetRequestURI("/api/audit-logs")
				ctxInspectOp.Request.Header.Set("X-User-Role", "Operator")
				inspectorMiddleware(ctxInspectOp)
				if ctxInspectOp.Response.StatusCode() != fasthttp.StatusForbidden {
					t.Errorf("expected 403 from path inspector for Operator GET audit-logs, got %d", ctxInspectOp.Response.StatusCode())
				}
				verifyForbiddenBody(t, ctxInspectOp.Response.Body())

				// Case G: Legitimate Admin -> MUST return HTTP 200
				ctxAdmin := &fasthttp.RequestCtx{}
				ctxAdmin.Request.Header.Set("X-User-Role", "Admin")
				roleMiddleware(ctxAdmin)
				if ctxAdmin.Response.StatusCode() != fasthttp.StatusOK {
					t.Errorf("expected 200 for Admin, got %d", ctxAdmin.Response.StatusCode())
				}

				// Case H: Local admin session bypass -> MUST return HTTP 200
				ctxLocalAdmin := &fasthttp.RequestCtx{}
				ctxLocalAdmin.SetUserValue(schemas.IsLocalAdminContextKey, true)
				roleMiddleware(ctxLocalAdmin)
				if ctxLocalAdmin.Response.StatusCode() != fasthttp.StatusOK {
					t.Errorf("expected 200 for local admin bypass, got %d", ctxLocalAdmin.Response.StatusCode())
				}

				// Case I: Legitimate Developer creating virtual keys via PathInspector -> MUST return HTTP 200
				ctxDevVK := &fasthttp.RequestCtx{}
				ctxDevVK.Request.Header.SetMethod("POST")
				ctxDevVK.Request.SetRequestURI("/api/governance/virtual-keys")
				ctxDevVK.Request.Header.Set("X-User-Role", "Developer")
				inspectorMiddleware(ctxDevVK)
				if ctxDevVK.Response.StatusCode() != fasthttp.StatusOK {
					t.Errorf("expected 200 for Developer creating virtual keys, got %d", ctxDevVK.Response.StatusCode())
				}
			}
		}()
	}

	close(startBarrier)
	wg.Wait()
}

func verifyForbiddenBody(t *testing.T, body []byte) {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Errorf("failed to parse 403 JSON error response: %v", err)
		return
	}
	if resp["error"] != "unauthorized: permission denied" {
		t.Errorf("expected error 'unauthorized: permission denied', got %q", resp["error"])
	}
}
