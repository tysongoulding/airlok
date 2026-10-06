package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// ADVERSARIAL CHALLENGE: FASTHTTP SSO MIDDLEWARE & HANDLER CONCURRENCY & RBAC
// ============================================================================

func TestAdversarial_SSOMiddleware_StrictUnmappedGroup403_ConcurrentSwarm(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := sso.NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-adv", &privKey.PublicKey)

	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{}, cache)
	mapper := sso.NewRoleMapper([]sso.AttributeRoleMapping{
		{Attribute: "groups", Value: "Org-Admins", Role: sso.RoleAdmin},
		{Attribute: "groups", Value: "Engineering-Devs", Role: sso.RoleDeveloper},
	}, sso.StrategyHighestPermissionCount)
	store := sso.NewMemoryUserStore()
	jit := sso.NewJITEngine(store, "both")
	enforcer := sso.NewSSOEnforcer(validator, mapper, jit)
	middleware := NewSSOMiddleware(enforcer)

	var downstreamExecuted atomic.Int64
	r := router.New()
	r.GET("/api/v1/protected/resource", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		downstreamExecuted.Add(1)
		ctx.SetStatusCode(http.StatusOK)
		ctx.SetBodyString("authorized")
	}, middleware.Middleware()))

	const numGoroutines = 500
	var wg sync.WaitGroup
	var forbiddenCount atomic.Int64
	var unauthorizedCount atomic.Int64
	var otherCount atomic.Int64

	unmappedScenarios := [][]string{
		{"External-Contractors"},
		{"Guests", "Anonymous"},
		{"Hacker-Role"},
		{},
		{"admin"},      // lowercase
		{"Developers"}, // case mismatch
		{"*.*"},
	}

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(iter int) {
			defer wg.Done()
			groups := unmappedScenarios[iter%len(unmappedScenarios)]
			token := generateTestJWTWithKey(t, privKey, "k-adv", map[string]interface{}{
				"sub":    fmt.Sprintf("unmapped-%d", iter),
				"email":  fmt.Sprintf("unmapped-%d@evil.corp", iter),
				"groups": groups,
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
			})

			var ctx fasthttp.RequestCtx
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.SetRequestURI("/api/v1/protected/resource")
			ctx.Request.Header.Set("Authorization", "Bearer "+token)

			r.Handler(&ctx)

			status := ctx.Response.StatusCode()
			switch status {
			case http.StatusForbidden:
				// Verify JSON response payload specifies sso_unmapped_group
				var body map[string]map[string]interface{}
				if err := json.Unmarshal(ctx.Response.Body(), &body); err == nil {
					if body["error"]["code"] == "sso_unmapped_group" {
						forbiddenCount.Add(1)
						return
					}
				}
				otherCount.Add(1)
			case http.StatusUnauthorized:
				unauthorizedCount.Add(1)
			default:
				otherCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if downstreamExecuted.Load() > 0 {
		t.Fatalf("SECURITY VIOLATION: downstream handler was executed %d times for unmapped users!", downstreamExecuted.Load())
	}
	if forbiddenCount.Load() != numGoroutines {
		t.Fatalf("expected exactly %d HTTP 403 Forbidden responses, got: forbidden=%d, unauthorized=%d, other=%d",
			numGoroutines, forbiddenCount.Load(), unauthorizedCount.Load(), otherCount.Load())
	}

	// Verify user store has 0 users created
	users, err := store.ListUsers(ctxBackground())
	if err != nil || len(users) != 0 {
		t.Fatalf("SECURITY VIOLATION: %d unauthorized users were provisioned into store!", len(users))
	}
}

func TestAdversarial_SSOMiddleware_MalformedAndExpiredTokens_Concurrent401(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := sso.NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-mal", &privKey.PublicKey)

	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{}, cache)
	mapper := sso.NewRoleMapper([]sso.AttributeRoleMapping{
		{Attribute: "groups", Value: "Org-Admins", Role: sso.RoleAdmin},
	}, sso.StrategyHighestPermissionCount)
	jit := sso.NewJITEngine(sso.NewMemoryUserStore(), "both")
	enforcer := sso.NewSSOEnforcer(validator, mapper, jit)
	middleware := NewSSOMiddleware(enforcer)

	var downstreamExecuted atomic.Int64
	r := router.New()
	r.GET("/api/v1/secure", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		downstreamExecuted.Add(1)
		ctx.SetStatusCode(http.StatusOK)
	}, middleware.Middleware()))

	const numGoroutines = 400
	var wg sync.WaitGroup
	var unauthorizedCount atomic.Int64

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(iter int) {
			defer wg.Done()
			var authHeader string

			switch iter % 4 {
			case 0:
				// Expired token
				tok := generateTestJWTWithKey(t, privKey, "k-mal", map[string]interface{}{
					"sub": "expired-user",
					"exp": time.Now().Add(-1 * time.Hour).Unix(),
				})
				authHeader = "Bearer " + tok
			case 1:
				// Malformed segment count
				authHeader = "Bearer malformed.single.segment"
			case 2:
				// Tampered payload
				validTok := generateTestJWTWithKey(t, privKey, "k-mal", map[string]interface{}{
					"sub": "tampered-user",
					"exp": time.Now().Add(10 * time.Minute).Unix(),
				})
				authHeader = "Bearer " + validTok + "-tampered"
			case 3:
				// Invalid auth scheme
				authHeader = "Token 123456789"
			}

			var ctx fasthttp.RequestCtx
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.SetRequestURI("/api/v1/secure")
			ctx.Request.Header.Set("Authorization", authHeader)

			r.Handler(&ctx)

			if ctx.Response.StatusCode() == http.StatusUnauthorized {
				unauthorizedCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if downstreamExecuted.Load() > 0 {
		t.Fatalf("downstream executed for invalid tokens: %d", downstreamExecuted.Load())
	}
	if unauthorizedCount.Load() != numGoroutines {
		t.Fatalf("expected %d HTTP 401 responses, got %d", numGoroutines, unauthorizedCount.Load())
	}
}

func TestAdversarial_SSOMiddleware_ConcurrentJITProvisioning_1000Requests(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := sso.NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-jit", &privKey.PublicKey)

	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{}, cache)
	mapper := sso.NewRoleMapper([]sso.AttributeRoleMapping{
		{Attribute: "groups", Value: "Org-Admins", Role: sso.RoleAdmin},
		{Attribute: "groups", Value: "Engineering-Devs", Role: sso.RoleDeveloper},
	}, sso.StrategyHighestPermissionCount)
	store := sso.NewMemoryUserStore()
	jit := sso.NewJITEngine(store, "both")
	enforcer := sso.NewSSOEnforcer(validator, mapper, jit)
	middleware := NewSSOMiddleware(enforcer)

	r := router.New()
	r.GET("/api/v1/endpoint", lib.ChainMiddlewares(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(http.StatusOK)
		ctx.SetBodyString("ok")
	}, middleware.Middleware()))

	const totalRequests = 1000
	var wg sync.WaitGroup
	var successCount atomic.Int64

	// 500 requests for SAME user + 500 requests for 500 DISTINCT users
	wg.Add(totalRequests)
	for i := 0; i < totalRequests; i++ {
		go func(iter int) {
			defer wg.Done()
			var sub, email, group string
			if iter < 500 {
				sub = "http-swarm-user"
				email = "swarm@enterprise.corp"
				group = "Org-Admins"
			} else {
				sub = fmt.Sprintf("http-distinct-%04d", iter-500)
				email = fmt.Sprintf("distinct-%04d@enterprise.corp", iter-500)
				group = "Engineering-Devs"
			}

			tok := generateTestJWTWithKey(t, privKey, "k-jit", map[string]interface{}{
				"sub":    sub,
				"email":  email,
				"groups": []string{group},
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
			})

			var ctx fasthttp.RequestCtx
			ctx.Request.Header.SetMethod(http.MethodGet)
			ctx.Request.SetRequestURI("/api/v1/endpoint")
			ctx.Request.Header.Set("Authorization", "Bearer "+tok)

			r.Handler(&ctx)

			if ctx.Response.StatusCode() == http.StatusOK {
				successCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if successCount.Load() != totalRequests {
		t.Fatalf("expected %d 200 OK responses, got %d", totalRequests, successCount.Load())
	}

	// Verify store count: Exactly 1 swarm user + 500 distinct users = 501 users total
	users, err := store.ListUsers(ctxBackground())
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if len(users) != 501 {
		t.Fatalf("CONCURRENCY INVARIANT VIOLATED: expected exactly 501 users in store, got %d", len(users))
	}
}

// Helper functions for handler adversarial tests
func generateTestJWTWithKey(t *testing.T, privKey *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
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

func ctxBackground() *fasthttp.RequestCtx {
	return &fasthttp.RequestCtx{}
}
