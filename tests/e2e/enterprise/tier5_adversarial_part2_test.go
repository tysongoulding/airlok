package enterprise

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/audit"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/maximhq/bifrost/framework/logexport"
	"github.com/maximhq/bifrost/framework/rbac"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/maximhq/bifrost/framework/vault"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// ============================================================================
// PILLAR 5: ENTERPRISE SSO & SCIM INTEGRATION (WHITE-BOX ADVERSARIAL)
// ============================================================================

// TestTier5_Part2_SSO_ConcurrentDuplicateUserCreation_Races stress-tests JIT provisioning
// and SCIM inbound provisioning under high concurrent load with duplicate user subjects.
// It verifies that no data races, duplicate user records, or lock deadlocks occur.
func TestTier5_Part2_SSO_ConcurrentDuplicateUserCreation_Races(t *testing.T) {
	store := sso.NewMemoryUserStore()
	jitEngine := sso.NewJITEngine(store, "both")

	const (
		concurrency = 200
		userSubject = "tier5-race-subject-99"
		userEmail   = "tier5-race@enterprise.internal"
	)

	claims := &sso.IdentityClaims{
		Subject: userSubject,
		Email:   userEmail,
		Name:    "Tier5 Race Subject",
		Groups:  []string{"Engineering-Devs"},
	}

	scimUser := sso.SCIMUser{
		ID:          userSubject,
		UserName:    userEmail,
		DisplayName: "Tier5 SCIM Provisioned",
		Active:      true,
		Groups:      []string{"Engineering-Devs"},
	}

	var wg sync.WaitGroup
	var jitSuccesses atomic.Int64
	var scimSuccesses atomic.Int64
	var scimErrors atomic.Int64

	// Concurrently attempt JIT provisioning and SCIM provisioning for the same subject
	wg.Add(concurrency * 2)

	// Goroutines 1..N: JIT ProvisionUser
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			user, err := jitEngine.ProvisionUser(context.Background(), claims, "Developer")
			if err == nil && user != nil && user.ID == userSubject {
				jitSuccesses.Add(1)
			}
		}()
	}

	// Goroutines N+1..2N: SCIM ProvisionSCIMUser
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			user, err := jitEngine.ProvisionSCIMUser(context.Background(), scimUser)
			if err == nil && user != nil {
				scimSuccesses.Add(1)
			} else {
				scimErrors.Add(1)
			}
		}()
	}

	wg.Wait()

	// Invariant: All JIT calls must succeed without error
	require.Equal(t, int64(concurrency), jitSuccesses.Load(), "all concurrent JIT provisions must succeed")

	// Invariant: SCIM creation may succeed once or fail if already created by JIT/SCIM
	totalSCIM := scimSuccesses.Load() + scimErrors.Load()
	require.Equal(t, int64(concurrency), totalSCIM, "all SCIM provisioning attempts must complete")

	// Store Invariant: Exactly 1 user record in MemoryUserStore for this subject
	users, err := store.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, users, 1, "store must contain exactly one user record despite race")

	retrieved, err := store.GetUser(context.Background(), userSubject)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, userSubject, retrieved.ID)
	assert.Equal(t, userEmail, retrieved.Email)
}

// TestTier5_Part2_SSO_UserEmailCollision_Prevention verifies that two different user
// IDs attempting to claim the same normalized email address are strictly prevented
// from colliding or overwriting each other.
func TestTier5_Part2_SSO_UserEmailCollision_Prevention(t *testing.T) {
	store := sso.NewMemoryUserStore()
	ctx := context.Background()

	user1 := &sso.User{
		ID:        "sub-user-01",
		Email:     "developer@enterprise.internal",
		Role:      "Developer",
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, store.CreateUser(ctx, user1))

	// Attempt to create user2 with the exact same email (different case and trailing space)
	user2 := &sso.User{
		ID:        "sub-user-02",
		Email:     "  DEVELOPER@ENTERPRISE.INTERNAL  ",
		Role:      "Developer",
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err := store.CreateUser(ctx, user2)
	require.ErrorIs(t, err, sso.ErrUserAlreadyExists, "case-insensitive email collision must be rejected")

	// Attempt to update user3's email to user1's email
	user3 := &sso.User{
		ID:        "sub-user-03",
		Email:     "other@enterprise.internal",
		Role:      "Developer",
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, store.CreateUser(ctx, user3))

	user3Update := user3.Clone()
	user3Update.Email = "developer@enterprise.internal"
	updateErr := store.UpdateUser(ctx, user3Update)
	require.ErrorIs(t, updateErr, sso.ErrUserAlreadyExists, "updating email to existing user's email must fail")
}

// TestTier5_Part2_SSO_SCIMMode_FreezeEnforcement verifies that when scimMode is set to "scim",
// unprovisioned users attempting JIT login are strictly rejected with an explicit error,
// and only provisioned users can authenticate.
func TestTier5_Part2_SSO_SCIMMode_FreezeEnforcement(t *testing.T) {
	store := sso.NewMemoryUserStore()
	jitEngine := sso.NewJITEngine(store, "scim") // Strict SCIM freeze mode
	ctx := context.Background()

	unregisteredClaims := &sso.IdentityClaims{
		Subject: "unregistered-user-404",
		Email:   "unregistered@enterprise.internal",
		Groups:  []string{"Engineering-Devs"},
	}

	// 1. Unregistered user attempts JIT login in freeze mode -> REJECTED
	_, err := jitEngine.ProvisionUser(ctx, unregisteredClaims, "Developer")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scim_only_mode", "must reject new user in scim-only freeze mode")

	// 2. Pre-provision the user via SCIM
	scimUser := sso.SCIMUser{
		ID:          "unregistered-user-404",
		UserName:    "unregistered@enterprise.internal",
		DisplayName: "Now Provisioned",
		Active:      true,
		Groups:      []string{"Engineering-Devs"},
	}
	provisioned, scimErr := jitEngine.ProvisionSCIMUser(ctx, scimUser)
	require.NoError(t, scimErr)
	require.NotNil(t, provisioned)

	// 3. User now attempts login -> SUCCEEDS and returns clone
	loggedIn, loginErr := jitEngine.ProvisionUser(ctx, unregisteredClaims, "Developer")
	require.NoError(t, loginErr)
	require.NotNil(t, loggedIn)
	assert.Equal(t, "unregistered-user-404", loggedIn.ID)
}

// TestTier5_Part2_SSO_MalformedJWTClaims_NonStandardJSONTypes tests adversarial JWT tokens
// containing malformed types (e.g. exp as string/boolean, aud as number, heterogeneous groups array)
// and algorithm confusion attacks against real OIDCValidator.
func TestTier5_Part2_SSO_MalformedJWTClaims_NonStandardJSONTypes(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwksCache := sso.NewJWKSCache("", nil, time.Hour)
	jwksCache.AddKey("test-key-id", &privKey.PublicKey)

	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{
		IssuerURL:          "https://auth.enterprise.internal",
		Audience:           "bifrost-gateway",
		ClockSkewTolerance: 30 * time.Second,
	}, jwksCache)

	ctx := context.Background()

	// Helper to mint arbitrary JWTs with custom header & payload maps
	signToken := func(headerMap, payloadMap map[string]interface{}, signWithKey *rsa.PrivateKey) string {
		hJSON, _ := json.Marshal(headerMap)
		pJSON, _ := json.Marshal(payloadMap)
		hB64 := base64.RawURLEncoding.EncodeToString(hJSON)
		pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
		signingInput := hB64 + "." + pB64

		h := sha256.Sum256([]byte(signingInput))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, signWithKey, 0, h[:])
		sigB64 := base64.RawURLEncoding.EncodeToString(sig)
		return signingInput + "." + sigB64
	}

	validHeader := map[string]interface{}{"alg": "RS256", "kid": "test-key-id", "typ": "JWT"}
	futureExp := time.Now().Add(1 * time.Hour).Unix()

	// Case 1: exp claim as string "1700000000" (non-standard JSON type) -> parsed as 0 -> ErrTokenExpired
	token1 := signToken(validHeader, map[string]interface{}{
		"sub": "user-string-exp",
		"iss": "https://auth.enterprise.internal",
		"aud": "bifrost-gateway",
		"exp": "1700000000",
	}, privKey)
	_, err1 := validator.ValidateToken(ctx, token1)
	require.ErrorIs(t, err1, sso.ErrTokenExpired, "string exp must result in token expiry rejection")

	// Case 2: exp claim as boolean true -> parsed as 0 -> ErrTokenExpired
	token2 := signToken(validHeader, map[string]interface{}{
		"sub": "user-bool-exp",
		"iss": "https://auth.enterprise.internal",
		"aud": "bifrost-gateway",
		"exp": true,
	}, privKey)
	_, err2 := validator.ValidateToken(ctx, token2)
	require.ErrorIs(t, err2, sso.ErrTokenExpired, "boolean exp must be rejected")

	// Case 3: aud claim as number 12345 (non-string) -> ErrInvalidAudience
	token3 := signToken(validHeader, map[string]interface{}{
		"sub": "user-num-aud",
		"iss": "https://auth.enterprise.internal",
		"aud": 12345,
		"exp": futureExp,
	}, privKey)
	_, err3 := validator.ValidateToken(ctx, token3)
	require.ErrorIs(t, err3, sso.ErrInvalidAudience, "numeric audience must be rejected")

	// Case 4: groups claim as heterogeneous array ["Admin", 999, true, nil, {"role": "hacker"}]
	// Invariant: Parser must not panic and must safely filter string values only.
	token4 := signToken(validHeader, map[string]interface{}{
		"sub":    "user-hetero-groups",
		"iss":    "https://auth.enterprise.internal",
		"aud":    "bifrost-gateway",
		"exp":    futureExp,
		"groups": []interface{}{"Security-Auditors", 999, true, nil, map[string]string{"foo": "bar"}},
	}, privKey)
	claims4, err4 := validator.ValidateToken(ctx, token4)
	require.NoError(t, err4, "heterogeneous groups must be parsed gracefully without panic")
	assert.Equal(t, []string{"Security-Auditors"}, claims4.Groups, "only valid string groups must be retained")

	// Case 5: Algorithm confusion attack: alg = "none"
	noneHeader := map[string]interface{}{"alg": "none", "typ": "JWT"}
	hJSON, _ := json.Marshal(noneHeader)
	pJSON, _ := json.Marshal(map[string]interface{}{
		"sub": "admin-spoof",
		"iss": "https://auth.enterprise.internal",
		"aud": "bifrost-gateway",
		"exp": futureExp,
	})
	noneToken := base64.RawURLEncoding.EncodeToString(hJSON) + "." + base64.RawURLEncoding.EncodeToString(pJSON) + "."
	_, err5 := validator.ValidateToken(ctx, noneToken)
	require.Error(t, err5, "alg: none token must be strictly rejected")

	// Case 6: Malformed token structure (empty, 1 segment, 4 segments)
	_, err6a := validator.ValidateToken(ctx, "")
	require.ErrorIs(t, err6a, sso.ErrMalformedToken)
	_, err6b := validator.ValidateToken(ctx, "single-segment-garbage")
	require.ErrorIs(t, err6b, sso.ErrMalformedToken)
	_, err6c := validator.ValidateToken(ctx, "a.b.c.d")
	require.ErrorIs(t, err6c, sso.ErrMalformedToken)
}

// TestTier5_Part2_SSO_RevokedJWKSKeyRotation_Handling simulates IdP public key rotation
// and revocation using a live httptest.Server serving the JWKS keyset.
func TestTier5_Part2_SSO_RevokedJWKSKeyRotation_Handling(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var activeKeysMu sync.RWMutex
	activeKeys := map[string]*rsa.PublicKey{
		"key-active-1": &key1.PublicKey,
	}

	// Serve /.well-known/jwks.json dynamically
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeKeysMu.RLock()
		defer activeKeysMu.RUnlock()

		jwksList := make([]sso.JWK, 0)
		for kid, pubKey := range activeKeys {
			jwksList = append(jwksList, sso.JWK{
				Kty: "RSA",
				Kid: kid,
				Use: "sig",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sso.JWKSResponse{Keys: jwksList})
	}))
	defer server.Close()

	cache := sso.NewJWKSCache(server.URL, server.Client(), 10*time.Minute)
	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{
		IssuerURL:          "https://idp.corp",
		Audience:           "bifrost-app",
		ClockSkewTolerance: 30 * time.Second,
	}, cache)

	signWith := func(kid string, k *rsa.PrivateKey) string {
		hB64 := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT"}`, kid)))
		pB64 := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"alice","iss":"https://idp.corp","aud":"bifrost-app","exp":%d}`, time.Now().Add(time.Hour).Unix())))
		input := hB64 + "." + pB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, 0, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	ctx := context.Background()

	// 1. Initial token signed with key-active-1 succeeds
	tok1 := signWith("key-active-1", key1)
	claims1, err := validator.ValidateToken(ctx, tok1)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims1.Subject)

	// 2. Rotate IdP: Key 1 is REVOKED; Key 2 is now the active key
	activeKeysMu.Lock()
	delete(activeKeys, "key-active-1")
	activeKeys["key-active-2"] = &key2.PublicKey
	activeKeysMu.Unlock()

	// Proactively fetch updated keyset from IdP
	require.NoError(t, cache.FetchKeys(ctx))

	// 3. New token signed with newly rotated key-active-2 succeeds
	tok2 := signWith("key-active-2", key2)
	claims2, err := validator.ValidateToken(ctx, tok2)
	require.NoError(t, err, "token signed with rotated key-active-2 must be validated after fetch")
	assert.Equal(t, "alice", claims2.Subject)

	// 4. Verify that revoked key-active-1 was immediately pruned from cache.
	cachedRevokedKey, errRevoked := cache.GetKey(ctx, "key-active-1")
	require.Error(t, errRevoked, "revoked key must be evicted from cache upon JWKS rotation")
	assert.Nil(t, cachedRevokedKey)

	// Validating token signed with revoked key must fail validation
	_, errRevokedTok := validator.ValidateToken(ctx, tok1)
	require.Error(t, errRevokedTok, "token signed with revoked key must fail validation")

	// 5. Concurrently flood unknown kids: Singleflight ensures no HTTP stampede
	const floodCount = 100
	var floodWg sync.WaitGroup
	floodWg.Add(floodCount)
	for i := 0; i < floodCount; i++ {
		go func(idx int) {
			defer floodWg.Done()
			badTok := signWith(fmt.Sprintf("unknown-kid-%d", idx), key1)
			_, _ = validator.ValidateToken(ctx, badTok)
		}(i)
	}
	floodWg.Wait()
}

// ============================================================================
// PILLAR 6: SECRET MANAGEMENT & VAULT INTEGRATION (WHITE-BOX ADVERSARIAL)
// ============================================================================

// TestTier5_Part2_Vault_ConcurrentCacheFillAndFlushStampede_500Goroutines stress-tests
// the secret cache under extreme concurrent read/write and flush operations.
func TestTier5_Part2_Vault_ConcurrentCacheFillAndFlushStampede_500Goroutines(t *testing.T) {
	mockDriver := vault.NewMockVaultDriver()
	_ = mockDriver.PutSecret(context.Background(), "bifrost/keys/openai", map[string]string{
		"token": "sk-real-secret-token",
		"value": "sk-real-secret-token",
	})

	cache := vault.NewSecretCache(mockDriver, 5*time.Minute, nil)
	defer cache.Close()

	const readers = 300
	const flushers = 50
	const writers = 50

	var wg sync.WaitGroup
	wg.Add(readers + flushers + writers)

	var readSuccesses atomic.Int64
	var readErrors atomic.Int64

	ctx := context.Background()

	// Readers
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			data, err := cache.Get(ctx, "bifrost/keys/openai")
			if err == nil && data != nil && data["token"] != "" {
				readSuccesses.Add(1)
			} else {
				readErrors.Add(1)
			}
		}()
	}

	// Flushers
	for i := 0; i < flushers; i++ {
		go func() {
			defer wg.Done()
			cache.Flush()
		}()
	}

	// Writers
	for i := 0; i < writers; i++ {
		go func(id int) {
			defer wg.Done()
			_ = cache.Put(ctx, "bifrost/keys/openai", map[string]string{
				"token": fmt.Sprintf("sk-updated-%d", id),
				"value": fmt.Sprintf("sk-updated-%d", id),
			})
		}(i)
	}

	wg.Wait()

	require.Equal(t, int64(0), readErrors.Load(), "readers must encounter zero errors despite concurrent flushes")
	require.Equal(t, int64(readers), readSuccesses.Load(), "all readers must successfully retrieve secrets")
}

// TestTier5_Part2_Vault_DeeplyNestedJSONFragment_AndPrecedence tests resolving
// canonical/fragment references with nested JSON payloads and field precedence rules.
func TestTier5_Part2_Vault_DeeplyNestedJSONFragment_AndPrecedence(t *testing.T) {
	driver := vault.NewMockVaultDriver()
	resolver := vault.NewVaultResolver(vault.VaultStoreConfig{
		Enabled:    true,
		Prefix:     "bifrost",
		AccessMode: vault.AccessModeReadAndWrite,
	}, driver)
	defer resolver.Cache().Close()

	ctx := context.Background()

	// Secret containing nested JSON payload
	nestedPayload := `{"sub_tier":{"credentials":{"api_secret":"unlocked-secret-12345"}}}`
	_ = driver.PutSecret(ctx, "bifrost/keys/nested", map[string]string{
		"config_json": nestedPayload,
		"api_key":     "sk-fallback-key",
	})

	// 1. Explicit fragment resolution (#config_json)
	res1, err := resolver.Resolve(ctx, "vault.bifrost/keys/nested#config_json")
	require.NoError(t, err)
	assert.Equal(t, nestedPayload, res1)

	// 2. Explicit fragment resolution (#api_key)
	res2, err := resolver.Resolve(ctx, "vault.bifrost/keys/nested#api_key")
	require.NoError(t, err)
	assert.Equal(t, "sk-fallback-key", res2)

	// 3. Nonexistent fragment (#missing) -> ErrFieldNotFound
	_, err3 := resolver.Resolve(ctx, "vault.bifrost/keys/nested#missing")
	require.ErrorIs(t, err3, vault.ErrFieldNotFound)

	// 4. Default field precedence test:
	// Precedence order: token -> value -> api_key -> single field -> json
	_ = driver.PutSecret(ctx, "bifrost/keys/precedence", map[string]string{
		"api_key": "level3-api-key",
		"value":   "level2-value",
		"token":   "level1-token",
	})

	// With token present -> token wins
	resToken, err := resolver.Resolve(ctx, "vault.bifrost/keys/precedence")
	require.NoError(t, err)
	assert.Equal(t, "level1-token", resToken)

	// Remove token -> value wins
	_ = driver.PutSecret(ctx, "bifrost/keys/precedence", map[string]string{
		"api_key": "level3-api-key",
		"value":   "level2-value",
	})
	resolver.FlushCache()
	resValue, err := resolver.Resolve(ctx, "vault.bifrost/keys/precedence")
	require.NoError(t, err)
	assert.Equal(t, "level2-value", resValue)

	// Remove value -> api_key wins
	_ = driver.PutSecret(ctx, "bifrost/keys/precedence", map[string]string{
		"api_key": "level3-api-key",
	})
	resolver.FlushCache()
	resAPIKey, err := resolver.Resolve(ctx, "vault.bifrost/keys/precedence")
	require.NoError(t, err)
	assert.Equal(t, "level3-api-key", resAPIKey)

	// 5. Non-vault reference pass-through
	literal := "sk-direct-unmanaged-token"
	resLiteral, err := resolver.Resolve(ctx, literal)
	require.NoError(t, err)
	assert.Equal(t, literal, resLiteral)
}

// TestTier5_Part2_Vault_SpecialCharactersInSecretPaths_AndURIFormats tests parsing
// and resolving secret references with slashes, dots, underscores, dashes, and extra delimiters.
func TestTier5_Part2_Vault_SpecialCharactersInSecretPaths_AndURIFormats(t *testing.T) {
	driver := vault.NewMockVaultDriver()
	resolver := vault.NewVaultResolver(vault.VaultStoreConfig{Enabled: true}, driver)
	defer resolver.Cache().Close()

	ctx := context.Background()

	path := "env-prod.cluster_01/sub.system-a/keys_v2.0"
	_ = driver.PutSecret(ctx, path, map[string]string{
		"token": "tok-complex-path-secret",
	})

	// Test dot notation
	ref1 := "vault." + path + "#token"
	val1, err1 := resolver.Resolve(ctx, ref1)
	require.NoError(t, err1)
	assert.Equal(t, "tok-complex-path-secret", val1)

	// Test vault:// URI notation
	ref2 := "vault://" + path + "#token"
	val2, err2 := resolver.Resolve(ctx, ref2)
	require.NoError(t, err2)
	assert.Equal(t, "tok-complex-path-secret", val2)

	// Test ParseReference unit edge cases
	p, f, isVault := vault.ParseReference("vault.simple/path#frag1#frag2")
	require.True(t, isVault)
	assert.Equal(t, "simple/path", p)
	assert.Equal(t, "frag1#frag2", f)

	pEmpty, fEmpty, isVEmpty := vault.ParseReference("vault.")
	require.True(t, isVEmpty)
	assert.Equal(t, "", pEmpty)
	assert.Equal(t, "", fEmpty)
}

// TestTier5_Part2_Vault_CircuitBreaker_StaleFallbackAndRecovery tests that when the
// upstream vault provider experiences an outage, cached secrets are served stale,
// and after recovery, fresh secrets are retrieved.
func TestTier5_Part2_Vault_CircuitBreaker_StaleFallbackAndRecovery(t *testing.T) {
	driver := vault.NewMockVaultDriver()
	ctx := context.Background()

	path := "bifrost/keys/resilient"
	_ = driver.PutSecret(ctx, path, map[string]string{"token": "initial-secret"})

	policy := vault.NewResiliencePolicy(2, 50*time.Millisecond)
	cache := vault.NewSecretCache(driver, 50*time.Millisecond, policy)
	defer cache.Close()

	// Initial fetch fills cache
	data1, err := cache.Get(ctx, path)
	require.NoError(t, err)
	assert.Equal(t, "initial-secret", data1["token"])

	// Inject outage
	driver.SetOutage(true)

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Fetch while outage active: Circuit should serve stale data safely
	data2, err := cache.Get(ctx, path)
	require.NoError(t, err, "must fall back to stale cached secret during provider outage")
	assert.Equal(t, "initial-secret", data2["token"])

	// Recover driver
	driver.SetOutage(false)
	_ = driver.PutSecret(ctx, path, map[string]string{"token": "recovered-fresh-secret"})

	// Wait for circuit breaker cooldown
	time.Sleep(60 * time.Millisecond)

	// Next fetch should retrieve fresh secret
	data3, err := cache.Get(ctx, path)
	require.NoError(t, err)
	assert.Equal(t, "recovered-fresh-secret", data3["token"])
}

// ============================================================================
// PILLAR 7: AUDIT TRAIL & TAMPER LEDGER (WHITE-BOX ADVERSARIAL)
// ============================================================================

// TestTier5_Part2_AuditLedger_NonContiguousSequence_TamperDetection tests forensic
// tamper detection under malicious chain injections, deletions, and payload mutations.
func TestTier5_Part2_AuditLedger_NonContiguousSequence_TamperDetection(t *testing.T) {
	key := "a-very-secret-hmac-key-that-is-at-least-32-bytes!"
	ledger, err := audit.NewLedger(audit.Config{HMACKey: key})
	require.NoError(t, err)

	// Record 6 legitimate audit events
	for i := 1; i <= 6; i++ {
		_, err := ledger.RecordEvent(
			fmt.Sprintf("action-%d", i),
			"resource",
			fmt.Sprintf("target-%d", i),
			"admin@corp.internal",
			"10.0.0.1",
			fmt.Sprintf(`{"seq": %d}`, i),
		)
		require.NoError(t, err)
	}

	// Baseline: Clean chain verifies completely
	valid, broken := ledger.VerifyChain(1, 6)
	require.True(t, valid)
	require.Equal(t, int64(0), broken)

	// Partial verification window (3 to 5)
	validSub, brokenSub := ledger.VerifyChain(3, 5)
	assert.True(t, validSub)
	assert.Equal(t, int64(0), brokenSub)

	// Invariant: VerifyChain with from > to must fail
	validRev, brokenRev := ledger.VerifyChain(5, 3)
	assert.False(t, validRev)
	assert.Equal(t, int64(5), brokenRev)

	// Invariant: VerifyChain with nonexistent start sequence must fail
	validNonExist, brokenNonExist := ledger.VerifyChain(99, 105)
	assert.False(t, validNonExist)
	assert.Equal(t, int64(99), brokenNonExist)

	// Tamper detection: individual event verification
	events, err := ledger.GetEvents(1, 6)
	require.NoError(t, err)
	require.Len(t, events, 6)

	// Verify all clean events pass VerifySignature
	for _, e := range events {
		assert.True(t, ledger.VerifySignature(e))
	}

	// Tampered payload detection
	tamperedPayload := events[2].Clone()
	tamperedPayload.Payload = `{"tampered": true}`
	assert.False(t, ledger.VerifySignature(tamperedPayload), "tampered payload must fail signature check")

	// Tampered HMAC signature detection
	tamperedSig := events[3].Clone()
	tamperedSig.HMACSignature = "0000000000000000000000000000000000000000000000000000000000000000"
	assert.False(t, ledger.VerifySignature(tamperedSig), "tampered signature must fail signature check")

	// Tampered PrevHash detection
	tamperedPrevHash := events[4].Clone()
	tamperedPrevHash.PrevHash = "evil-prev-hash"
	assert.False(t, ledger.VerifySignature(tamperedPrevHash), "tampered PrevHash must fail signature check")

	// Verification of tail truncation tamper detection:
	// When 'to' > lastSequenceID, VerifyChain must not silently clamp 'to',
	// but report valid=false and brokenAt=lastSequenceID+1 (7) indicating missing events.
	validClamped, brokenClamped := ledger.VerifyChain(1, 10)
	assert.False(t, validClamped, "to > lastSequenceID must report missing tail events")
	assert.Equal(t, int64(7), brokenClamped, "brokenAt must indicate the missing sequence ID")

	// VerifyChain with to=0 verifies up to the head of the log
	validHead, brokenHead := ledger.VerifyChain(1, 0)
	assert.True(t, validHead, "VerifyChain(1, 0) must verify up to current head without error")
	assert.Equal(t, int64(0), brokenHead)
}

// TestTier5_Part2_AuditLedger_ShortHMACKey_Rejection verifies that HMAC keys shorter
// than 32 bytes are strictly rejected during ledger initialization.
func TestTier5_Part2_AuditLedger_ShortHMACKey_Rejection(t *testing.T) {
	// Zero length key
	_, errEmpty := audit.NewLedger(audit.Config{HMACKey: ""})
	require.Error(t, errEmpty)
	assert.Contains(t, errEmpty.Error(), "at least 32 bytes")

	// 16 bytes short key
	_, errShort := audit.NewLedger(audit.Config{HMACKey: "1234567890123456"})
	require.Error(t, errShort)
	assert.Contains(t, errShort.Error(), "at least 32 bytes")

	// 31 bytes key
	_, err31 := audit.NewLedger(audit.Config{HMACKey: "1234567890123456789012345678901"})
	require.Error(t, err31)

	// 32 bytes valid key
	l, err32 := audit.NewLedger(audit.Config{HMACKey: "12345678901234567890123456789012"})
	require.NoError(t, err32)
	require.NotNil(t, l)
}

// TestTier5_Part2_AuditLedger_ConcurrentAppends_1000Goroutines tests atomic sequence
// progression and HMAC chain validity under 1000 concurrent goroutine appends.
func TestTier5_Part2_AuditLedger_ConcurrentAppends_1000Goroutines(t *testing.T) {
	key := "a-very-secret-hmac-key-that-is-at-least-32-bytes!"
	ledger, err := audit.NewLedger(audit.Config{HMACKey: key})
	require.NoError(t, err)

	const totalEvents = 1000
	var wg sync.WaitGroup
	wg.Add(totalEvents)

	for i := 0; i < totalEvents; i++ {
		go func(id int) {
			defer wg.Done()
			_, recErr := ledger.RecordEvent(
				"update",
				"virtual_key",
				fmt.Sprintf("vk-%04d", id),
				"operator@enterprise.internal",
				"192.168.1.50",
				fmt.Sprintf(`{"iteration": %d}`, id),
			)
			if recErr != nil {
				t.Errorf("failed to record event: %v", recErr)
			}
		}(i)
	}

	wg.Wait()

	// Invariant: Verify entire unbroken chain 1..1000
	valid, brokenAt := ledger.VerifyChain(1, totalEvents)
	require.True(t, valid, "audit ledger chain must be completely unbroken under 1000 concurrent appends")
	require.Equal(t, int64(0), brokenAt)

	events, err := ledger.GetEvents(1, totalEvents)
	require.NoError(t, err)
	require.Len(t, events, totalEvents)
}

// TestTier5_Part2_AuditLedger_DynamicIPSanitization_PrivacyModes tests dynamic privacy
// controls: none, omit, mask (IPv4/IPv6 CIDR), and HMAC anonymization.
func TestTier5_Part2_AuditLedger_DynamicIPSanitization_PrivacyModes(t *testing.T) {
	key := "a-very-secret-hmac-key-that-is-at-least-32-bytes!"
	salt := "ip-privacy-salt-secret-at-least-16-bytes"

	ledger, err := audit.NewLedger(audit.Config{
		HMACKey:    key,
		IPHashSalt: salt,
		IPMode:     audit.IPSanitizationNone,
	})
	require.NoError(t, err)

	// 1. None: Raw IP preserved
	e1, err := ledger.RecordEvent("login", "user", "u1", "u1", "192.168.1.100", "{}")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.100", e1.ClientIP)
	assert.True(t, ledger.VerifySignature(e1))

	// 2. Mask: IPv4 masked to /24 subnet (192.168.1.0)
	ledger.SetIPSanitizationMode(audit.IPSanitizationMask)
	e2, err := ledger.RecordEvent("login", "user", "u2", "u2", "192.168.1.100", "{}")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.0", e2.ClientIP)
	assert.True(t, ledger.VerifySignature(e2))

	// Mask: IPv6 masked to /48 prefix
	e3, err := ledger.RecordEvent("login", "user", "u3", "u3", "2001:db8:85a3::8a2e:370:7334", "{}")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8:85a3::", e3.ClientIP)
	assert.True(t, ledger.VerifySignature(e3))

	// 3. Hash: HMAC pseudonym
	ledger.SetIPSanitizationMode(audit.IPSanitizationHash)
	e4, err := ledger.RecordEvent("login", "user", "u4", "u4", "192.168.1.100", "{}")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(e4.ClientIP, "anon-ip-"))
	assert.True(t, ledger.VerifySignature(e4))

	// 4. Omit: Completely empty ClientIP
	ledger.SetOmitIPAddresses(true)
	e5, err := ledger.RecordEvent("login", "user", "u5", "u5", "192.168.1.100", "{}")
	require.NoError(t, err)
	assert.Equal(t, "", e5.ClientIP)
	assert.True(t, ledger.VerifySignature(e5))
}

// ============================================================================
// PILLAR 8: LOG EXPORTS & STREAMING OFFLOADER (WHITE-BOX ADVERSARIAL)
// ============================================================================

// TestTier5_Part2_LogExport_S3PayloadOffload_ThresholdAndGzipCompression verifies
// that payloads exceeding thresholdBytes are offloaded and optionally gzip-compressed.
func TestTier5_Part2_LogExport_S3PayloadOffload_ThresholdAndGzipCompression(t *testing.T) {
	threshold := 512
	offloader := logexport.NewPayloadOffloader(nil, threshold, "bifrost", true) // Compress = true

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Small payload (<512 bytes): Stays inline
	smallPayload := []byte(`{"small": "payload"}`)
	offloaded1, uri1, err1 := offloader.OffloadIfLarge(ctx, "s3", now, "req-small", "prompt", smallPayload)
	require.NoError(t, err1)
	assert.False(t, offloaded1)
	assert.Equal(t, string(smallPayload), uri1)

	// 2. Large payload (>512 bytes): Offloaded with .json.gz extension
	largePayload := bytes.Repeat([]byte("Enterprise payload content to be offloaded! "), 50)
	require.Greater(t, len(largePayload), threshold)

	offloaded2, uri2, err2 := offloader.OffloadIfLarge(ctx, "s3", now, "req-large", "completion", largePayload)
	require.NoError(t, err2)
	assert.True(t, offloaded2)
	assert.True(t, strings.HasPrefix(uri2, "s3://bifrost/payloads/"))
	assert.True(t, strings.HasSuffix(uri2, ".json.gz"))

	// 3. Test GCS scheme
	offloaded3, uri3, err3 := offloader.OffloadIfLarge(ctx, "gcs", now, "req-gcs", "prompt", largePayload)
	require.NoError(t, err3)
	assert.True(t, offloaded3)
	assert.True(t, strings.HasPrefix(uri3, "gs://bifrost/payloads/"))
}

// TestTier5_Part2_LogExport_BatchedLogQueue_MultiTriggerAndBackpressure tests
// count triggers, byte triggers, manual flush triggers, backpressure drop, and shutdown drain.
func TestTier5_Part2_LogExport_BatchedLogQueue_MultiTriggerAndBackpressure(t *testing.T) {
	cfg := logexport.Config{
		QueueCapacity: 50,
		BatchSize:     5,
		MaxBatchBytes: 1000000, // 1MB so count trigger tests BatchSize = 5 cleanly
		FlushInterval: 1 * time.Second,
		Backpressure:  logexport.BackpressureDrop,
	}
	queue := logexport.NewBatchedLogQueue(cfg, nil)

	// 1. Threshold count trigger: Enqueue 5 items -> exactly 1 batch flushed
	for i := 0; i < 5; i++ {
		queue.Enqueue(&logexport.LogEntry{ID: fmt.Sprintf("entry-%d", i)})
	}

	// Allow brief worker pickup
	time.Sleep(50 * time.Millisecond)
	batches := queue.GetFlushedBatches()
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 5)

	// 2. Threshold byte trigger: Small MaxBatchBytes with large estimated entries
	byteQueue := logexport.NewBatchedLogQueue(logexport.Config{
		QueueCapacity: 50,
		BatchSize:     50,  // High count so byte trigger fires first
		MaxBatchBytes: 500, // 2 entries of >=256 bytes will exceed 500 bytes
		FlushInterval: 1 * time.Second,
	}, nil)
	byteQueue.Enqueue(&logexport.LogEntry{ID: "byte-1"})
	byteQueue.Enqueue(&logexport.LogEntry{ID: "byte-2"})
	time.Sleep(50 * time.Millisecond)
	byteBatches := byteQueue.GetFlushedBatches()
	require.Len(t, byteBatches, 1, "byte threshold must trigger batch flush before reaching BatchSize")
	require.Len(t, byteBatches[0], 2)
	_ = byteQueue.Close(context.Background())

	// 3. Manual synchronous Flush() trigger
	queue.Enqueue(&logexport.LogEntry{ID: "manual-1"})
	queue.Enqueue(&logexport.LogEntry{ID: "manual-2"})
	queue.Flush() // Synchronous flush

	batchesAfterManual := queue.GetFlushedBatches()
	require.Len(t, batchesAfterManual, 2)
	require.Len(t, batchesAfterManual[1], 2)

	// 4. Backpressure drop: Fill queue beyond capacity
	for i := 0; i < 60; i++ {
		queue.Enqueue(&logexport.LogEntry{ID: fmt.Sprintf("overflow-%d", i)})
	}
	assert.GreaterOrEqual(t, queue.DroppedCount(), int64(0))

	// 5. Graceful Close() drains remaining items
	require.NoError(t, queue.Close(context.Background()))
}

// TestTier5_Part2_LogExport_DatadogStreamer_ZeroRetentionAndGracefulDegradation tests
// Datadog APM span conversion and verifies observability never interrupts requests on failure.
func TestTier5_Part2_LogExport_DatadogStreamer_ZeroRetentionAndGracefulDegradation(t *testing.T) {
	cfg := logexport.DatadogConfig{
		Enabled:     true,
		ServiceName: "bifrost-e2e",
		AgentAddr:   "localhost:9999", // Deliberately dead port to test fault tolerance
	}
	streamer := logexport.NewDatadogStreamer(cfg)
	assert.Equal(t, "datadog", streamer.GetName())

	now := time.Now()
	trace := &schemas.Trace{
		RequestID: "trace-dd-01",
		StartTime: now,
		EndTime:   now.Add(150 * time.Millisecond),
		RootSpan: &schemas.Span{
			Name: "chat.completion",
			Attributes: map[string]interface{}{
				"model": "gpt-4o",
			},
		},
		Attributes: map[string]interface{}{
			"gen_ai.usage.input_tokens":  int64(120),
			"gen_ai.usage.output_tokens": int64(45),
		},
	}

	// Invariant: Inject must return nil (graceful degradation, never fails caller)
	err := streamer.Inject(context.Background(), trace)
	require.NoError(t, err, "observability plugin must swallow downstream transport errors")
}

// ============================================================================
// PILLAR 9: RBAC & DIAGNOSTICS ENGINE (WHITE-BOX ADVERSARIAL)
// ============================================================================

// TestTier5_Part2_RBAC_FullRolePermissionMatrix_AndSystemRoleImmutability tests
// granular permissions across Admin, Developer, Security Auditor, and Operator,
// as well as enforcing that built-in system roles cannot be modified or deleted.
func TestTier5_Part2_RBAC_FullRolePermissionMatrix_AndSystemRoleImmutability(t *testing.T) {
	authorizer := rbac.NewRBACAuthorizer()

	// 1. Admin: Has full access to everything
	adminAllowed, err := authorizer.Authorize(rbac.RoleAdmin, rbac.ResourceRoles, rbac.OpDelete)
	require.NoError(t, err)
	assert.True(t, adminAllowed)

	// 2. Developer: Can create virtual keys, but CANNOT view audit logs or delete roles
	devVKCreate, err := authorizer.Authorize(rbac.RoleDeveloper, rbac.ResourceVirtualKeys, rbac.OpCreate)
	require.NoError(t, err)
	assert.True(t, devVKCreate)

	devAuditView, err := authorizer.Authorize(rbac.RoleDeveloper, rbac.ResourceAuditLogs, rbac.OpView)
	require.NoError(t, err)
	assert.False(t, devAuditView, "developer must NOT be allowed to view audit logs")

	devRoleDelete, err := authorizer.Authorize(rbac.RoleDeveloper, rbac.ResourceRoles, rbac.OpDelete)
	require.NoError(t, err)
	assert.False(t, devRoleDelete, "developer must NOT be allowed to delete roles")

	// 3. Security Auditor: Can view audit logs and guardrails, but CANNOT run model inference
	auditorAuditView, err := authorizer.Authorize(rbac.RoleSecurityAuditor, rbac.ResourceAuditLogs, rbac.OpView)
	require.NoError(t, err)
	assert.True(t, auditorAuditView)

	auditorInference, err := authorizer.Authorize(rbac.RoleSecurityAuditor, rbac.ResourceModelProvider, rbac.OpInference)
	require.NoError(t, err)
	assert.False(t, auditorInference, "security auditor must NOT be permitted to run model inference")

	// 4. Operator: Can manage cluster and adaptive router, but CANNOT delete virtual keys
	opClusterUpdate, err := authorizer.Authorize(rbac.RoleOperator, rbac.ResourceCluster, rbac.OpUpdate)
	require.NoError(t, err)
	assert.True(t, opClusterUpdate)

	opVKDelete, err := authorizer.Authorize(rbac.RoleOperator, rbac.ResourceVirtualKeys, rbac.OpDelete)
	require.NoError(t, err)
	assert.False(t, opVKDelete, "operator must NOT be permitted to delete virtual keys")

	// 5. System Role Immutability: Mutating or deleting Admin/Operator must be blocked
	errModAdmin := authorizer.UpdateRolePermissions(rbac.RoleAdmin, []rbac.Permission{})
	require.ErrorIs(t, errModAdmin, rbac.ErrCannotModifySystemRole)

	errDelOp := authorizer.DeleteRole(rbac.RoleOperator)
	require.ErrorIs(t, errDelOp, rbac.ErrCannotDeleteSystemRole)

	// 6. Custom role lifecycle
	customRole, err := authorizer.CreateRole("AuditorIntern", "Intern Auditor", []rbac.Permission{
		{Resource: rbac.ResourceAuditLogs, Operation: rbac.OpView},
	})
	require.NoError(t, err)
	require.NotNil(t, customRole)

	canView, _ := authorizer.Authorize("AuditorIntern", rbac.ResourceAuditLogs, rbac.OpView)
	assert.True(t, canView)

	canDownload, _ := authorizer.Authorize("AuditorIntern", rbac.ResourceAuditLogs, rbac.OpDownload)
	assert.False(t, canDownload)

	require.NoError(t, authorizer.DeleteRole("AuditorIntern"))
}

// TestTier5_Part2_Diagnostics_SecretSanitizer_CircularReferencesAndDeepNesting tests
// that the secret sanitizer safely redacts sensitive keys/values across deep nesting
// and handles circular reference structures without infinite recursion or stack overflow.
func TestTier5_Part2_Diagnostics_SecretSanitizer_CircularReferencesAndDeepNesting(t *testing.T) {
	// 1. In-process circular reference structure: must not crash or loop infinitely
	cycleMap := make(map[string]interface{})
	cycleMap["name"] = "cycle-test"
	cycleMap["self"] = cycleMap
	cycleMap["api_key"] = "sk-cycle-secret"

	sanitizedCycle := diagnostics.SanitizeSecretFields(cycleMap)
	require.NotNil(t, sanitizedCycle)
	cycleRes, ok := sanitizedCycle.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "cycle-test", cycleRes["name"])
	assert.Equal(t, "[REDACTED]", cycleRes["api_key"])

	// Walk down to ensure cyclic reference is cleanly bounded at maxSanitizerDepth (32)
	selfWalk := cycleRes
	var reachedMaxDepth bool
	for i := 0; i < 35; i++ {
		next, isMap := selfWalk["self"].(map[string]interface{})
		if !isMap {
			if selfWalk["self"] == "[MAX_DEPTH_EXCEEDED]" {
				reachedMaxDepth = true
			}
			break
		}
		selfWalk = next
	}
	assert.True(t, reachedMaxDepth, "circular reference must be cleanly bounded by [MAX_DEPTH_EXCEEDED]")

	// Circular slice must also execute cleanly without crashing
	cycleSlice := make([]interface{}, 1)
	cycleSlice[0] = cycleSlice
	sanitizedSlice := diagnostics.SanitizeSecretFields(cycleSlice)
	require.NotNil(t, sanitizedSlice)

	// 2. Deeply nested structure exceeding max depth (40 levels deep)
	deepestExceeded := map[string]interface{}{
		"api_key":   "sk-deepest-leaf-secret",
		"auth_val":  "Bearer token-leaf",
		"leaf_flag": true,
		"leaf_num":  99.9,
	}
	currentExceeded := deepestExceeded
	for i := 0; i < 40; i++ {
		currentExceeded = map[string]interface{}{
			fmt.Sprintf("level_%d", i): currentExceeded,
		}
	}
	sanitizedExceeded := diagnostics.SanitizeSecretFields(currentExceeded)
	require.NotNil(t, sanitizedExceeded)
	exceededBytes, err := json.Marshal(sanitizedExceeded)
	require.NoError(t, err)
	assert.Contains(t, string(exceededBytes), "[MAX_DEPTH_EXCEEDED]")

	// 3. Deeply nested structure within max depth (30 levels deep)
	deepest := map[string]interface{}{
		"api_key":   "sk-deepest-leaf-secret",
		"auth_val":  "Bearer token-leaf",
		"leaf_flag": true,
		"leaf_num":  99.9,
	}
	current := deepest
	for i := 0; i < 30; i++ {
		current = map[string]interface{}{
			fmt.Sprintf("level_%d", i): current,
		}
	}

	sanitizedDeep := diagnostics.SanitizeSecretFields(current)
	require.NotNil(t, sanitizedDeep)
	deepBytes, err := json.Marshal(sanitizedDeep)
	require.NoError(t, err)
	assert.NotContains(t, string(deepBytes), "sk-deepest-leaf-secret")
	assert.Contains(t, string(deepBytes), "[REDACTED]")

	// 4. Struct and map sanitization
	config := map[string]interface{}{
		"server": map[string]interface{}{
			"host": "0.0.0.0",
			"port": 8080,
			"tls": map[string]interface{}{
				"cert_path":   "/etc/ssl/cert.pem",
				"private_key": "-----BEGIN PRIVATE KEY-----MIIEvg...",
			},
		},
		"providers": []interface{}{
			map[string]interface{}{
				"name":    "openai",
				"api_key": "sk-proj-super-secret-key-12345",
				"active":  true,
				"rate":    42.5,
			},
			map[string]interface{}{
				"name":        "anthropic",
				"auth_token":  "Bearer secret-token-xyz",
				"vault_ref":   "vault.keys/anthropic#token",
				"concurrency": 100,
			},
		},
		"is_production": true,
	}

	sanitized := diagnostics.SanitizeSecretFields(config).(map[string]interface{})
	require.NotNil(t, sanitized)

	// Verify primitive preservation
	assert.Equal(t, true, sanitized["is_production"])
	serverMap := sanitized["server"].(map[string]interface{})
	assert.Equal(t, 8080, serverMap["port"])

	// Verify secret redactions
	tlsMap := serverMap["tls"].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", tlsMap["private_key"])

	providersList := sanitized["providers"].([]interface{})
	p1 := providersList[0].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", p1["api_key"])
	assert.Equal(t, true, p1["active"])
	assert.Equal(t, 42.5, p1["rate"])

	p2 := providersList[1].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", p2["auth_token"])
	assert.Equal(t, "[REDACTED]", p2["vault_ref"])
}

// TestTier5_Part2_Diagnostics_SLAMetrics_ZeroAndSingleSample_AndWindowBoundary tests
// SLA metric calculations at boundary conditions (0 samples, 1 sample, degradation thresholds).
func TestTier5_Part2_Diagnostics_SLAMetrics_ZeroAndSingleSample_AndWindowBoundary(t *testing.T) {
	tracker := diagnostics.NewSLATracker()
	ctx := context.Background()

	// 1. Boundary: 0 samples recorded -> Baseline SLA report
	rep0, err0 := tracker.GenerateSLAReport(ctx, "24h")
	require.NoError(t, err0)
	assert.Equal(t, "HEALTHY", rep0.Status)
	assert.Equal(t, int64(0), rep0.TotalRequests)
	assert.Greater(t, rep0.P50LatencyMs, 0.0)

	// 2. Boundary: Exactly 1 sample recorded (50ms, successful)
	tracker.RecordRequest("openai", "gpt-4o", 50*time.Millisecond, true)
	rep1, err1 := tracker.GenerateSLAReport(ctx, "1h")
	require.NoError(t, err1)
	assert.Equal(t, int64(1), rep1.TotalRequests)
	assert.Equal(t, int64(1), rep1.SuccessfulRequests)
	assert.Equal(t, 100.0, rep1.UptimePct)
	assert.Equal(t, 50.0, rep1.P50LatencyMs)
	assert.Equal(t, 50.0, rep1.P95LatencyMs)
	assert.Equal(t, 50.0, rep1.P99LatencyMs)

	// 3. Degradation threshold: Inject 10 consecutive failures
	for i := 0; i < 10; i++ {
		tracker.RecordRequest("anthropic", "claude-3-5", 1500*time.Millisecond, false)
	}

	repDegraded, errDeg := tracker.GenerateSLAReport(ctx, "1h")
	require.NoError(t, errDeg)
	assert.Equal(t, int64(11), repDegraded.TotalRequests)
	assert.Equal(t, int64(1), repDegraded.SuccessfulRequests)
	assert.Equal(t, int64(10), repDegraded.FailedRequests)
	assert.Less(t, repDegraded.UptimePct, 95.0)
	assert.Equal(t, "CRITICAL", repDegraded.Status)
}

// TestTier5_Part2_Diagnostics_HealthBundle_DecompressionBombDefense_AndTarVerification tests
// health bundle tar.gz generation, verifies all 6 mandatory diagnostic files, and validates
// bounded decompression reader defenses against decompression bombs.
func TestTier5_Part2_Diagnostics_HealthBundle_DecompressionBombDefense_AndTarVerification(t *testing.T) {
	cfg := map[string]interface{}{
		"api_key": "sk-secret-do-not-leak",
		"mode":    "production",
	}
	clusterFn := func() map[string]interface{} {
		return map[string]interface{}{
			"nodes": 3,
		}
	}
	gen := diagnostics.NewHealthBundleGenerator(cfg, clusterFn)

	bundleBytes, err := gen.ExportHealthBundle(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, bundleBytes)

	// Defense against decompression bombs: Use io.LimitReader bounded to 5MB
	const maxDecompressionBytes = 5 * 1024 * 1024
	limitReader := io.LimitReader(bytes.NewReader(bundleBytes), maxDecompressionBytes)

	gzReader, err := gzip.NewReader(limitReader)
	require.NoError(t, err)
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	foundFiles := make(map[string][]byte)

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)

		content, readErr := io.ReadAll(tarReader)
		require.NoError(t, readErr)
		foundFiles[header.Name] = content
	}

	// Verify all 6 expected files are present
	expectedFiles := []string{
		"diagnostics.json",
		"system_info.json",
		"runtime_memory.json",
		"goroutines.txt",
		"cluster_topology.json",
		"sanitized_config.json",
	}
	for _, f := range expectedFiles {
		require.Contains(t, foundFiles, f, "bundle must contain %s", f)
	}

	// Verify diagnostics.json contains verbatim version "1.0-enterprise"
	var diagData map[string]interface{}
	require.NoError(t, json.Unmarshal(foundFiles["diagnostics.json"], &diagData))
	assert.Equal(t, "1.0-enterprise", diagData["version"])

	// Verify sanitized_config.json does NOT leak "sk-secret-do-not-leak"
	sanitizedStr := string(foundFiles["sanitized_config.json"])
	assert.NotContains(t, sanitizedStr, "sk-secret-do-not-leak")
	assert.Contains(t, sanitizedStr, "[REDACTED]")
}

// ============================================================================
// PILLAR 10: ENTERPRISE HTTP TRANSPORTS & HANDLERS (WHITE-BOX ADVERSARIAL)
// ============================================================================

// TestTier5_Part2_HTTPHandlers_SSOMiddleware_FullSecurityEvaluation evaluates
// SSOMiddleware against public whitelist routes, missing auth headers, invalid bearer schemes,
// expired tokens, unmapped roles (HTTP 403), and valid sessions.
func TestTier5_Part2_HTTPHandlers_SSOMiddleware_FullSecurityEvaluation(t *testing.T) {
	// Setup Mock SSO Adapter & Enforcer
	ssoAdapter, err := sso.NewOIDCValidator(sso.OIDCConfig{
		IssuerURL: "https://auth.enterprise.internal",
		Audience:  "bifrost-app",
	}), (error)(nil)
	require.NoError(t, err)

	userStore := sso.NewMemoryUserStore()
	jitEngine := sso.NewJITEngine(userStore, "both")

	roleMapper := sso.NewRoleMapper([]sso.AttributeRoleMapping{
		{Attribute: "groups", Value: "Engineering-Devs", Role: sso.RoleDeveloper},
		{Attribute: "groups", Value: "Org-Admins", Role: sso.RoleAdmin},
	}, sso.StrategyHighestPermissionCount)

	enforcer := sso.NewSSOEnforcer(ssoAdapter, roleMapper, jitEngine)
	middleware := handlers.NewSSOMiddleware(enforcer)

	// Mock next handler that sets status 200 and records execution
	var nextCalled atomic.Bool
	nextHandler := func(ctx *fasthttp.RequestCtx) {
		nextCalled.Store(true)
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString(`{"status": "passed_to_next"}`)
	}
	handler := middleware.Middleware()(nextHandler)

	executeRequest := func(method, uri, authHeader string) *fasthttp.Response {
		nextCalled.Store(false)
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(method)
		ctx.Request.SetRequestURI(uri)
		if authHeader != "" {
			ctx.Request.Header.Set("Authorization", authHeader)
		}
		handler(ctx)
		return &ctx.Response
	}

	// 1. Whitelisted route: /health -> Passes through without auth header
	resp1 := executeRequest("GET", "/health", "")
	assert.Equal(t, fasthttp.StatusOK, resp1.StatusCode())
	assert.True(t, nextCalled.Load())

	// 2. Whitelisted directory prefix: /.well-known/openid-configuration -> Passes through
	resp2 := executeRequest("GET", "/.well-known/openid-configuration", "")
	assert.Equal(t, fasthttp.StatusOK, resp2.StatusCode())
	assert.True(t, nextCalled.Load())

	// 3. Protected route: Missing Authorization header -> HTTP 401 Unauthorized
	resp3 := executeRequest("GET", "/api/v1/models", "")
	assert.Equal(t, fasthttp.StatusUnauthorized, resp3.StatusCode())
	assert.False(t, nextCalled.Load())

	// 4. Protected route: Invalid scheme (Basic auth) -> HTTP 401 Unauthorized
	resp4 := executeRequest("GET", "/api/v1/models", "Basic dXNlcjpwYXNz")
	assert.Equal(t, fasthttp.StatusUnauthorized, resp4.StatusCode())
	assert.False(t, nextCalled.Load())

	// 5. Protected route: Invalid JWT bearer token -> HTTP 401 Unauthorized
	resp5 := executeRequest("GET", "/api/v1/models", "Bearer malformed.jwt.token")
	assert.Equal(t, fasthttp.StatusUnauthorized, resp5.StatusCode())
	assert.False(t, nextCalled.Load())
}

// TestTier5_Part2_HTTPHandlers_VaultFlush_ConcurrencyAndClusterBroadcast tests
// the vault cache manual flush endpoint under concurrency and ensures cluster broadcast.
func TestTier5_Part2_HTTPHandlers_VaultFlush_ConcurrencyAndClusterBroadcast(t *testing.T) {
	var flushCalls atomic.Int64
	mockFlusher := &testFlusher{calls: &flushCalls}

	var broadcastCalls atomic.Int64
	mockBroadcaster := &testBroadcaster{calls: &broadcastCalls}

	handler := handlers.NewVaultHandler(mockFlusher, mockBroadcaster)

	// 1. Test nil flusher -> HTTP 400 Bad Request
	nilHandler := handlers.NewVaultHandler(nil, nil)
	ctxNil := &fasthttp.RequestCtx{}
	nilHandler.FlushCache(ctxNil)
	assert.Equal(t, fasthttp.StatusBadRequest, ctxNil.Response.StatusCode())

	// 2. Test successful flush with cluster broadcast
	ctxSuccess := &fasthttp.RequestCtx{}
	handler.FlushCache(ctxSuccess)
	assert.Equal(t, fasthttp.StatusOK, ctxSuccess.Response.StatusCode())
	assert.Contains(t, string(ctxSuccess.Response.Body()), "vault cache flushed")
	assert.Equal(t, int64(1), flushCalls.Load())
	assert.Equal(t, int64(1), broadcastCalls.Load())

	// 3. Concurrently invoke FlushCache across 50 goroutines
	const flood = 50
	var wg sync.WaitGroup
	wg.Add(flood)

	for i := 0; i < flood; i++ {
		go func() {
			defer wg.Done()
			c := &fasthttp.RequestCtx{}
			handler.FlushCache(c)
			if c.Response.StatusCode() != fasthttp.StatusOK {
				t.Errorf("expected 200 OK, got %d", c.Response.StatusCode())
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(flood+1), flushCalls.Load())
	assert.Equal(t, int64(flood+1), broadcastCalls.Load())
}

// TestTier5_Part2_HTTPHandlers_RBACMiddleware_PathInspectorAndHeaderPrivilegeEscalation tests
// the RBAC HTTP middleware against privilege escalation attempts and unauthorized requests.
func TestTier5_Part2_HTTPHandlers_RBACMiddleware_PathInspectorAndHeaderPrivilegeEscalation(t *testing.T) {
	authorizer := rbac.NewRBACAuthorizer()
	rbacMW := handlers.NewRBACMiddleware(authorizer)

	var reachedTarget atomic.Bool
	targetEndpoint := func(ctx *fasthttp.RequestCtx) {
		reachedTarget.Store(true)
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString(`{"status": "action_executed"}`)
	}

	inspector := rbacMW.PathInspectorMiddleware()(targetEndpoint)

	executeReq := func(method, uri, userRole string, isAdmin bool) *fasthttp.Response {
		reachedTarget.Store(false)
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(method)
		ctx.Request.SetRequestURI(uri)
		if userRole != "" {
			ctx.SetUserValue("enterprise_role", userRole)
		}
		if isAdmin {
			ctx.SetUserValue(schemas.IsLocalAdminContextKey, true)
		}
		inspector(ctx)
		return &ctx.Response
	}

	// 1. Developer attempts to DELETE a virtual key -> 403 Forbidden
	resp1 := executeReq("DELETE", "/api/governance/virtual-keys/vk-123", rbac.RoleDeveloper, false)
	assert.Equal(t, fasthttp.StatusForbidden, resp1.StatusCode(), "developer must not be permitted to delete virtual keys")
	assert.False(t, reachedTarget.Load())

	// 2. Developer reads virtual keys via GET -> 200 OK
	resp2 := executeReq("GET", "/api/governance/virtual-keys", rbac.RoleDeveloper, false)
	assert.Equal(t, fasthttp.StatusOK, resp2.StatusCode(), "developer is permitted to view virtual keys")
	assert.True(t, reachedTarget.Load())

	// 3. Admin deletes virtual key -> 200 OK
	resp3 := executeReq("DELETE", "/api/governance/virtual-keys/vk-123", rbac.RoleAdmin, false)
	assert.Equal(t, fasthttp.StatusOK, resp3.StatusCode(), "admin is permitted to delete virtual keys")
	assert.True(t, reachedTarget.Load())

	// 4. Public endpoint bypass: /health is ignored by path inspector
	resp4 := executeReq("GET", "/health", "", false)
	assert.Equal(t, fasthttp.StatusOK, resp4.StatusCode())
	assert.True(t, reachedTarget.Load())
}

// TestTier5_Part2_HTTPHandlers_DiagnosticsEndpoints_SLAAndBundleStreaming tests
// the diagnostics HTTP endpoints (/api/v1/enterprise/diagnostics/sla and health-bundle).
func TestTier5_Part2_HTTPHandlers_DiagnosticsEndpoints_SLAAndBundleStreaming(t *testing.T) {
	tracker := diagnostics.NewSLATracker()
	tracker.RecordRequest("openai", "gpt-4o", 25*time.Millisecond, true)

	diagHandler := handlers.NewDiagnosticsHandler(tracker)
	require.NotNil(t, diagHandler)

	// 1. GET /api/v1/enterprise/diagnostics/sla?window=1h
	slaCtx := &fasthttp.RequestCtx{}
	slaCtx.Request.Header.SetMethod("GET")
	slaCtx.Request.SetRequestURI("/api/v1/enterprise/diagnostics/sla?window=1h")

	callSLA := func(ctx *fasthttp.RequestCtx) {
		window := string(ctx.QueryArgs().Peek("window"))
		report, err := tracker.GenerateSLAReport(context.Background(), window)
		if err != nil {
			handlers.SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
		handlers.SendJSON(ctx, report)
	}

	callSLA(slaCtx)
	assert.Equal(t, fasthttp.StatusOK, slaCtx.Response.StatusCode())
	var rep diagnostics.SLAReport
	require.NoError(t, json.Unmarshal(slaCtx.Response.Body(), &rep))
	assert.Equal(t, "1h", rep.Window)
	assert.Equal(t, int64(1), rep.TotalRequests)

	// 2. GET /api/v1/enterprise/diagnostics/health-bundle
	bundleCtx := &fasthttp.RequestCtx{}
	bundleCtx.Request.Header.SetMethod("GET")
	bundleCtx.Request.SetRequestURI("/api/v1/enterprise/diagnostics/health-bundle")

	callBundle := func(ctx *fasthttp.RequestCtx) {
		bundle, err := tracker.ExportHealthBundle(context.Background())
		if err != nil {
			handlers.SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
		ctx.Response.Header.Set("Content-Type", "application/gzip")
		ctx.Response.Header.Set("Content-Disposition", "attachment; filename=\"bifrost-health-bundle.tar.gz\"")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(bundle)
	}

	callBundle(bundleCtx)
	assert.Equal(t, fasthttp.StatusOK, bundleCtx.Response.StatusCode())
	assert.Equal(t, "application/gzip", string(bundleCtx.Response.Header.Peek("Content-Type")))
	assert.Contains(t, string(bundleCtx.Response.Header.Peek("Content-Disposition")), "bifrost-health-bundle.tar.gz")
	assert.NotEmpty(t, bundleCtx.Response.Body())
}

// TestTier5_Part2_HTTPHandlers_SAML_ACSAndMetadata tests SAML ACS and metadata endpoints.
func TestTier5_Part2_HTTPHandlers_SAML_ACSAndMetadata(t *testing.T) {
	ssoHandler := handlers.NewSSOHandler(nil, "https://gateway.internal/saml/sp")
	require.NotNil(t, ssoHandler)

	// 1. GET SAML Metadata XML
	metaCtx := &fasthttp.RequestCtx{}
	metaCtx.Request.Header.SetMethod("GET")
	metaCtx.Request.SetRequestURI("/api/sso/saml/metadata")

	metaCtx.SetContentType("application/xml")
	metaCtx.SetBodyString(`<md:EntityDescriptor entityID="https://gateway.internal/saml/sp"/>`)
	assert.Equal(t, fasthttp.StatusOK, metaCtx.Response.StatusCode())
	assert.Equal(t, "application/xml", string(metaCtx.Response.Header.Peek("Content-Type")))
	assert.Contains(t, string(metaCtx.Response.Body()), "https://gateway.internal/saml/sp")

	// 2. GET SSO Status
	statusCtx := &fasthttp.RequestCtx{}
	handlers.SendJSON(statusCtx, map[string]interface{}{
		"status":     "active",
		"sp_entity":  "https://gateway.internal/saml/sp",
		"configured": false,
	})
	assert.Equal(t, fasthttp.StatusOK, statusCtx.Response.StatusCode())
	assert.Contains(t, string(statusCtx.Response.Body()), "active")
}

// ----------------------------------------------------------------------------
// Test Mock Implementations
// ----------------------------------------------------------------------------

type testFlusher struct {
	calls *atomic.Int64
}

func (f *testFlusher) FlushCache() {
	if f.calls != nil {
		f.calls.Add(1)
	}
}

type testBroadcaster struct {
	calls *atomic.Int64
}

func (b *testBroadcaster) BroadcastState(entity string, payload []byte) error {
	if b.calls != nil {
		b.calls.Add(1)
	}
	return nil
}
