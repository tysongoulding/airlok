package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

func generateTestJWT(t *testing.T, privKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	payloadJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, payloadB64)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, 0, h[:])
	if err != nil {
		t.Fatalf("sign rsa: %v", err)
	}
	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(sig))
}

func setupTestSSOEnforcer(t *testing.T) (*sso.SSOEnforcer, *rsa.PrivateKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cache := sso.NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k1", &privKey.PublicKey)

	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{}, cache)
	mapper := sso.NewRoleMapper([]sso.AttributeRoleMapping{
		{Attribute: "groups", Value: "Org-Admins", Role: sso.RoleAdmin},
		{Attribute: "groups", Value: "Engineering-Devs", Role: sso.RoleDeveloper},
	}, sso.StrategyHighestPermissionCount)
	jit := sso.NewJITEngine(sso.NewMemoryUserStore(), "both")

	return sso.NewSSOEnforcer(validator, mapper, jit), privKey
}

func TestSSOMiddleware_PublicRouteBypass(t *testing.T) {
	enforcer, _ := setupTestSSOEnforcer(t)
	middleware := NewSSOMiddleware(enforcer)

	r := router.New()
	r.GET("/health", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
		ctx.SetBodyString("ok")
	}, middleware.Middleware()))
	r.GET("/login", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
		ctx.SetBodyString("ok")
	}, middleware.Middleware()))

	for _, p := range []string{"/health", "/login"} {
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI(p)
		r.Handler(&ctx)
		if ctx.Response.StatusCode() != http.StatusOK {
			t.Fatalf("expected 200 OK for public route %s, got %d", p, ctx.Response.StatusCode())
		}
	}
}

func TestSSOMiddleware_DiscreteRoutePrefix_DoesNotBypass(t *testing.T) {
	enforcer, _ := setupTestSSOEnforcer(t)
	middleware := NewSSOMiddleware(enforcer)

	r := router.New()
	handler := lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
		ctx.SetBodyString("ok")
	}, middleware.Middleware())

	r.GET("/healthcheck", handler)
	r.GET("/login_admin", handler)
	r.GET("/login-debug", handler)
	r.GET("/healthcare", handler)

	siblingRoutes := []string{"/healthcheck", "/login_admin", "/login-debug", "/healthcare"}
	for _, route := range siblingRoutes {
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI(route)

		r.Handler(&ctx)

		if ctx.Response.StatusCode() != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for sibling route %s, got %d", route, ctx.Response.StatusCode())
		}
	}
}


func TestSSOMiddleware_MissingOrInvalidToken(t *testing.T) {
	enforcer, _ := setupTestSSOEnforcer(t)
	middleware := NewSSOMiddleware(enforcer)

	r := router.New()
	r.GET("/api/protected", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
	}, middleware.Middleware()))

	// 1. Missing header
	var ctx1 fasthttp.RequestCtx
	ctx1.Request.Header.SetMethod(http.MethodGet)
	ctx1.Request.SetRequestURI("/api/protected")
	r.Handler(&ctx1)
	if ctx1.Response.StatusCode() != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing token, got %d", ctx1.Response.StatusCode())
	}

	// 2. Invalid scheme
	var ctx2 fasthttp.RequestCtx
	ctx2.Request.Header.SetMethod(http.MethodGet)
	ctx2.Request.SetRequestURI("/api/protected")
	ctx2.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	r.Handler(&ctx2)
	if ctx2.Response.StatusCode() != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid scheme, got %d", ctx2.Response.StatusCode())
	}
}

func TestSSOMiddleware_ValidMappedRole_Passes(t *testing.T) {
	enforcer, privKey := setupTestSSOEnforcer(t)
	middleware := NewSSOMiddleware(enforcer)

	token := generateTestJWT(t, privKey, map[string]interface{}{
		"sub":    "developer-1",
		"email":  "dev@enterprise.corp",
		"groups": []string{"Engineering-Devs"},
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	})

	var recordedUser *sso.User
	var recordedRole string

	r := router.New()
	r.GET("/api/protected", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		if u, ok := ctx.UserValue("enterprise_user").(*sso.User); ok {
			recordedUser = u
		}
		if role, ok := ctx.UserValue("enterprise_role").(string); ok {
			recordedRole = role
		}
		ctx.SetStatusCode(http.StatusOK)
	}, middleware.Middleware()))

	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/api/protected")
	ctx.Request.Header.Set("Authorization", "Bearer "+token)

	r.Handler(&ctx)

	if ctx.Response.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
	if recordedUser == nil || recordedUser.ID != "developer-1" {
		t.Errorf("expected user developer-1 in context, got %+v", recordedUser)
	}
	if recordedRole != sso.RoleDeveloper {
		t.Errorf("expected role Developer, got %s", recordedRole)
	}
}

func TestSSOMiddleware_UnmappedRole_Returns403(t *testing.T) {
	enforcer, privKey := setupTestSSOEnforcer(t)
	middleware := NewSSOMiddleware(enforcer)

	unmappedToken := generateTestJWT(t, privKey, map[string]interface{}{
		"sub":    "guest-1",
		"email":  "guest@external.corp",
		"groups": []string{"External-Guests"}, // Not mapped in RoleMapper
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	})

	r := router.New()
	r.GET("/api/protected", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
	}, middleware.Middleware()))

	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/api/protected")
	ctx.Request.Header.Set("Authorization", "Bearer "+unmappedToken)

	r.Handler(&ctx)

	if ctx.Response.StatusCode() != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for unmapped group, got %d", ctx.Response.StatusCode())
	}

	var resp map[string]map[string]interface{}
	_ = json.Unmarshal(ctx.Response.Body(), &resp)
	if resp["error"]["code"] != "sso_unmapped_group" {
		t.Errorf("expected code sso_unmapped_group, got %v", resp["error"]["code"])
	}
}

func TestSSOHandler_MetadataAndStatus(t *testing.T) {
	enforcer, _ := setupTestSSOEnforcer(t)
	handler := NewSSOHandler(enforcer, "https://gateway.example.com/sp")

	r := router.New()
	handler.RegisterRoutes(r)

	// Test metadata
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/api/sso/saml/metadata")
	r.Handler(&ctx)

	if ctx.Response.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 for metadata, got %d", ctx.Response.StatusCode())
	}
	if string(ctx.Response.Header.ContentType()) != "application/xml" {
		t.Errorf("expected application/xml, got %s", string(ctx.Response.Header.ContentType()))
	}
}
