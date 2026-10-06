package enterprise

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// TIER 1: FEATURE COVERAGE (R4 Enterprise SSO & R5 Secret Management & Vault)
// ============================================================================

func TestSSO_Tier1_JWKS_JWT_SignatureVerification(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	claims := mock.UserClaims{
		Subject: "user-12345",
		Email:   "auditor@corp.internal",
		Groups:  []string{"Security-Auditors"},
	}
	token, err := sso.GenerateTestJWT(claims, false)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	validatedClaims, err := sso.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if validatedClaims.Subject != "user-12345" || validatedClaims.Email != "auditor@corp.internal" {
		t.Fatalf("claims mismatch: %+v", validatedClaims)
	}
}

func TestSSO_Tier1_JIT_UserProvisioning(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	claims := mock.UserClaims{
		Subject: "new-user-999",
		Email:   "newuser@enterprise.com",
		Groups:  []string{"Engineering-Devs"},
	}
	token, _ := sso.GenerateTestJWT(claims, false)

	_, err = sso.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Verify user is provisioned in JIT user table
	user, exists := sso.Users["new-user-999"]
	if !exists {
		t.Fatalf("user was not JIT provisioned in local store")
	}
	if user.Email != "newuser@enterprise.com" {
		t.Fatalf("provisioned user email mismatch: %s", user.Email)
	}
}

func TestSSO_Tier1_GroupToRoleMapping(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	// Case 1: Security-Auditors -> Security Auditor
	role1, err := sso.ResolveRole(&mock.UserClaims{Groups: []string{"Security-Auditors"}})
	if err != nil || role1 != "Security Auditor" {
		t.Fatalf("expected Security Auditor role, got: %s (err=%v)", role1, err)
	}

	// Case 2: Engineering-Devs -> Developer
	role2, err := sso.ResolveRole(&mock.UserClaims{Groups: []string{"Engineering-Devs"}})
	if err != nil || role2 != "Developer" {
		t.Fatalf("expected Developer role, got: %s", role2)
	}

	// Case 3: Org-Admins -> Admin
	role3, err := sso.ResolveRole(&mock.UserClaims{Groups: []string{"Org-Admins"}})
	if err != nil || role3 != "Admin" {
		t.Fatalf("expected Admin role, got: %s", role3)
	}
}

func TestSSO_Tier1_SCIM_InboundProvisioning(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	scimReq := mock.SCIMUser{
		ID:          "scim-user-001",
		UserName:    "scim.developer@corp.com",
		DisplayName: "SCIM Developer",
		Active:      true,
		Groups:      []string{"Engineering-Devs"},
	}

	if err := sso.ProvisionSCIMUser(scimReq); err != nil {
		t.Fatalf("SCIM provisioning failed: %v", err)
	}

	user, ok := sso.Users["scim.developer@corp.com"]
	if !ok || user.Subject != "scim-user-001" {
		t.Fatalf("SCIM user not found in store")
	}
}

func TestSSO_Tier1_UnmappedRoleDenial_Returns403(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	claims := &mock.UserClaims{
		Subject: "contractor-1",
		Email:   "contractor@external.com",
		Groups:  []string{"External-Guests"},
	}

	_, err = sso.ResolveRole(claims)
	if err == nil {
		t.Fatalf("expected unmapped group to be rejected, but got no error")
	}
}

func TestVault_Tier1_ReferenceResolution_CanonicalAndFragment(t *testing.T) {
	vault := mock.NewMockVaultRegistry(1 * time.Hour)
	vault.PutSecret("bifrost/keys/openai", map[string]string{
		"token":   "sk-live-secret-openai-key-12345",
		"org_id":  "org-enterprise-corp",
		"project": "proj-default",
	})

	// 1. Canonical path resolution
	val1, err := vault.Resolve(context.Background(), "vault.bifrost/keys/openai")
	if err != nil {
		t.Fatalf("canonical resolution failed: %v", err)
	}
	if val1 != "sk-live-secret-openai-key-12345" {
		t.Fatalf("expected token value, got: %s", val1)
	}

	// 2. Fragment resolution
	val2, err := vault.Resolve(context.Background(), "vault.bifrost/keys/openai#org_id")
	if err != nil {
		t.Fatalf("fragment resolution failed: %v", err)
	}
	if val2 != "org-enterprise-corp" {
		t.Fatalf("expected org_id value, got: %s", val2)
	}
}

func TestVault_Tier1_TTL_Caching(t *testing.T) {
	vault := mock.NewMockVaultRegistry(1 * time.Hour)
	vault.PutSecret("bifrost/keys/anthropic", map[string]string{
		"token": "sk-ant-live-token",
	})

	// First resolution
	val1, _ := vault.Resolve(context.Background(), "vault.bifrost/keys/anthropic")
	if val1 != "sk-ant-live-token" {
		t.Fatalf("initial resolution failed: %s", val1)
	}
	if vault.BackendCalls != 1 {
		t.Fatalf("expected 1 backend call, got %d", vault.BackendCalls)
	}

	// Second resolution within TTL -> must use cache
	val2, _ := vault.Resolve(context.Background(), "vault.bifrost/keys/anthropic")
	if val2 != "sk-ant-live-token" {
		t.Fatalf("cached resolution failed: %s", val2)
	}
	if vault.BackendCalls != 1 {
		t.Fatalf("expected backend calls to remain 1 due to cache, got %d", vault.BackendCalls)
	}
}

func TestVault_Tier1_ManualFlushEndpoint_POST_FlushCache(t *testing.T) {
	gw, err := mock.NewEnterpriseGatewayServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}
	defer gw.Close()

	gw.Vault.PutSecret("bifrost/keys/cohere", map[string]string{"token": "initial-token"})
	_, _ = gw.Vault.Resolve(context.Background(), "vault.bifrost/keys/cohere")

	// Update secret in store
	gw.Vault.PutSecret("bifrost/keys/cohere", map[string]string{"token": "rotated-token"})

	// Call POST /api/vault/flush-cache
	resp, err := http.Post(gw.URL()+"/api/vault/flush-cache", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("flush request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from flush endpoint, got %d", resp.StatusCode)
	}

	// Subsequent lookup must return the rotated token immediately
	freshVal, err := gw.Vault.Resolve(context.Background(), "vault.bifrost/keys/cohere")
	if err != nil {
		t.Fatalf("fresh lookup failed: %v", err)
	}
	if freshVal != "rotated-token" {
		t.Fatalf("expected rotated-token after cache flush, got: %s", freshVal)
	}
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (R4 SSO & R5 Vault)
// ============================================================================

func TestSSO_Tier2_ExpiredJWT_Rejected(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	expiredToken, err := sso.GenerateTestJWT(mock.UserClaims{
		Subject: "expired-user",
		Email:   "user@corp.com",
	}, true)
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}

	_, err = sso.ValidateToken(context.Background(), expiredToken)
	if err == nil {
		t.Fatalf("expected expired token to be rejected")
	}
}

func TestSSO_Tier2_InvalidSignature_TamperedPayload(t *testing.T) {
	sso, _ := mock.NewMockSSOAdapter()
	validToken, _ := sso.GenerateTestJWT(mock.UserClaims{
		Subject: "legit-user",
		Email:   "user@corp.com",
	}, false)

	// Tamper payload segment (middle segment)
	parts := bytes.Split([]byte(validToken), []byte("."))
	parts[1] = []byte("eyJhZG1pbiI6dHJ1ZX0") // altered payload
	tampered := string(bytes.Join(parts, []byte(".")))

	_, err := sso.ValidateToken(context.Background(), tampered)
	if err == nil {
		t.Fatalf("expected signature verification failure on tampered token")
	}
}

func TestSSO_Tier2_MalformedToken_SegmentCount(t *testing.T) {
	sso, _ := mock.NewMockSSOAdapter()

	malformedTokens := []string{
		"",
		"single-segment",
		"segment1.segment2",
		"s1.s2.s3.s4",
	}

	for _, token := range malformedTokens {
		_, err := sso.ValidateToken(context.Background(), token)
		if err == nil {
			t.Fatalf("expected malformed token %q to be rejected", token)
		}
	}
}

func TestSSO_Tier2_SCIM_DuplicateUserCollision(t *testing.T) {
	sso, _ := mock.NewMockSSOAdapter()
	u := mock.SCIMUser{
		ID:       "id-1",
		UserName: "collision@corp.com",
	}

	if err := sso.ProvisionSCIMUser(u); err != nil {
		t.Fatalf("first creation should succeed: %v", err)
	}

	// Duplicate creation should return error
	if err := sso.ProvisionSCIMUser(u); err == nil {
		t.Fatalf("expected error on duplicate SCIM user creation")
	}
}

func TestVault_Tier2_MissingSecretPath_ReturnsError(t *testing.T) {
	vault := mock.NewMockVaultRegistry(1 * time.Hour)
	_, err := vault.Resolve(context.Background(), "vault.nonexistent/path/key")
	if err == nil {
		t.Fatalf("expected error for non-existent vault path")
	}
}

func TestVault_Tier2_MissingFieldFragment_ReturnsError(t *testing.T) {
	vault := mock.NewMockVaultRegistry(1 * time.Hour)
	vault.PutSecret("bifrost/keys/test", map[string]string{"foo": "bar"})

	_, err := vault.Resolve(context.Background(), "vault.bifrost/keys/test#nonexistent_field")
	if err == nil {
		t.Fatalf("expected error when fragment field does not exist")
	}
}

func TestVault_Tier2_ConcurrentCacheAccessRaceSafety(t *testing.T) {
	vault := mock.NewMockVaultRegistry(1 * time.Hour)
	vault.PutSecret("bifrost/concurrent/key", map[string]string{"value": "threaded-secret"})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, err := vault.Resolve(context.Background(), "vault.bifrost/concurrent/key")
			if err != nil || val != "threaded-secret" {
				t.Errorf("concurrent lookup failed: %v", err)
			}
		}()
	}
	wg.Wait()
}
