package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// CHALLENGER 1 FASTHTTP SSO ROUTE MATCHING ADVERSARIAL TEST (M4 ITERATION 2)
// ============================================================================

func TestChallenger_SSOMiddleware_DiscreteRouteExactMatching(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	cache := sso.NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-route-chal", &privKey.PublicKey)

	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{}, cache)
	mapper := sso.NewRoleMapper([]sso.AttributeRoleMapping{
		{Attribute: "groups", Value: "Org-Admins", Role: sso.RoleAdmin},
	}, sso.StrategyHighestPermissionCount)
	jit := sso.NewJITEngine(sso.NewMemoryUserStore(), "both")
	enforcer := sso.NewSSOEnforcer(validator, mapper, jit)
	middleware := NewSSOMiddleware(enforcer)

	// Create a test handler wrapped with SSOMiddleware
	r := router.New()

	passHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
		ctx.SetBodyString("authorized_access")
	}

	// Register test routes
	testRoutes := []string{
		// Discrete legitimate routes
		"/health",
		"/login",
		"/favicon.ico",
		"/api/session/is-auth-enabled",
		"/api/session/login",

		// Sibling routes that MUST NOT bypass
		"/healthcheck",
		"/healthcare",
		"/health-check",
		"/health_admin",
		"/login_admin",
		"/login-debug",
		"/login_bypass",
		"/login/admin",
		"/favicon.ico.png",
		"/favicon.ico/evil",
		"/api/session/is-auth-enabled-bypass",
		"/api/session/login-admin",

		// Directory legitimate routes
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
		"/assets/bundle.js",
		"/assets/style.css",

		// Directory sibling routes that MUST NOT bypass
		"/.well-known-bypass",
		"/assets-admin",
		"/assets-secret",
	}

	for _, rt := range testRoutes {
		r.GET(rt, lib.ChainMiddlewares(passHandler, middleware.Middleware()))
	}

	// 1. Legitimate discrete routes must pass without authentication (HTTP 200 OK)
	legitimateAllowed := []string{
		"/health",
		"/login",
		"/favicon.ico",
		"/api/session/is-auth-enabled",
		"/api/session/login",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
		"/assets/bundle.js",
		"/assets/style.css",
	}

	for _, path := range legitimateAllowed {
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI(path)

		r.Handler(&ctx)

		if ctx.Response.StatusCode() != http.StatusOK {
			t.Errorf("expected 200 OK for legitimate whitelisted route %s, got: %d", path, ctx.Response.StatusCode())
		}
	}

	// 2. Sibling endpoints MUST be rejected with HTTP 401 Unauthorized
	adversarialBypasses := []string{
		"/healthcheck",
		"/healthcare",
		"/health-check",
		"/health_admin",
		"/login_admin",
		"/login-debug",
		"/login_bypass",
		"/login/admin",
		"/favicon.ico.png",
		"/favicon.ico/evil",
		"/api/session/is-auth-enabled-bypass",
		"/api/session/login-admin",
		"/.well-known-bypass",
		"/assets-admin",
		"/assets-secret",
	}

	for _, bypassPath := range adversarialBypasses {
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI(bypassPath)

		r.Handler(&ctx)

		if ctx.Response.StatusCode() != http.StatusUnauthorized {
			t.Errorf("SECURITY VULNERABILITY: Sibling bypass route %s bypassed auth with status %d (expected 401)",
				bypassPath, ctx.Response.StatusCode())
		}
	}
}
