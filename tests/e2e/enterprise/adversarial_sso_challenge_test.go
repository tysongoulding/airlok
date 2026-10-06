package enterprise

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/maximhq/bifrost/tests/e2e/enterprise/mock"
)

// ============================================================================
// ADVERSARIAL CHALLENGE: ENTERPRISE SSO & IDP INTEGRATION (R4 ACCEPTANCE)
// ============================================================================

// 1. Concurrency & Race Conditions: JIT Provisioning under 1000 Goroutines
func TestAdversarial_Enterprise_SSO_ConcurrentJITProvisioning_1000Goroutines(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	const swarmCount = 1000
	claims := mock.UserClaims{
		Subject: "e2e-swarm-subject-99",
		Email:   "e2e-swarm@enterprise.corp",
		Groups:  []string{"Engineering-Devs"},
	}
	token, err := sso.GenerateTestJWT(claims, false)
	if err != nil {
		t.Fatalf("failed to generate test JWT: %v", err)
	}

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var failCount atomic.Int64

	wg.Add(swarmCount)
	for i := 0; i < swarmCount; i++ {
		go func(gid int) {
			defer wg.Done()
			validated, err := sso.ValidateToken(context.Background(), token)
			if err != nil || validated == nil || validated.Subject != "e2e-swarm-subject-99" {
				failCount.Add(1)
				return
			}
			successCount.Add(1)
		}(i)
	}
	wg.Wait()

	if successCount.Load() != swarmCount {
		t.Fatalf("expected %d successful concurrent validations, got %d (failed: %d)",
			swarmCount, successCount.Load(), failCount.Load())
	}

	// Verify store state: Exactly 1 user in sso.Users
	if len(sso.Users) != 1 {
		t.Fatalf("CONCURRENCY INVARIANT VIOLATED: expected exactly 1 user in store, found %d", len(sso.Users))
	}
	user := sso.Users["e2e-swarm-subject-99"]
	if user == nil || user.Email != "e2e-swarm@enterprise.corp" {
		t.Fatalf("user record corrupted under concurrency: %+v", user)
	}
}

// 2. Concurrency: 500 Distinct Users Provisioned Simultaneously
func TestAdversarial_Enterprise_SSO_ConcurrentDistinctUsers_500Goroutines(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	const distinctCount = 500
	var wg sync.WaitGroup
	var successCount atomic.Int64

	wg.Add(distinctCount)
	for i := 0; i < distinctCount; i++ {
		go func(id int) {
			defer wg.Done()
			c := mock.UserClaims{
				Subject: fmt.Sprintf("distinct-sub-%04d", id),
				Email:   fmt.Sprintf("user-%04d@enterprise.corp", id),
				Groups:  []string{"Engineering-Devs"},
			}
			tok, genErr := sso.GenerateTestJWT(c, false)
			if genErr != nil {
				t.Errorf("token generation failed for %d: %v", id, genErr)
				return
			}
			_, valErr := sso.ValidateToken(context.Background(), tok)
			if valErr != nil {
				t.Errorf("token validation failed for %d: %v", id, valErr)
				return
			}
			successCount.Add(1)
		}(i)
	}
	wg.Wait()

	if successCount.Load() != distinctCount {
		t.Fatalf("expected %d distinct provisions, got %d", distinctCount, successCount.Load())
	}
	if len(sso.Users) != distinctCount {
		t.Fatalf("expected %d distinct users in store, found %d", distinctCount, len(sso.Users))
	}
}

// 3. Cryptographic Validation: Malformed, Tampered, and Expired Tokens
func TestAdversarial_Enterprise_SSO_Cryptographic_MalformedAndTamperedTokens(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	validClaims := mock.UserClaims{
		Subject: "crypto-victim",
		Email:   "victim@enterprise.corp",
		Groups:  []string{"Security-Auditors"},
	}
	validToken, _ := sso.GenerateTestJWT(validClaims, false)

	// 3.1 Truncated segment counts
	malformedSegmentCases := []string{
		"",
		"header-only",
		"header.payload",
		"header.payload.signature.extra",
		"a.b.c.d.e",
	}
	for _, mal := range malformedSegmentCases {
		_, err := sso.ValidateToken(context.Background(), mal)
		if err == nil {
			t.Errorf("expected malformed token %q to be rejected", mal)
		}
	}

	// 3.2 Corrupted / Tampered payload (privilege escalation attempt)
	parts := bytes.Split([]byte(validToken), []byte("."))
	// Tamper payload segment
	escalatedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"crypto-victim","groups":["Org-Admins"]}`))
	parts[1] = []byte(escalatedPayload)
	tamperedToken := string(bytes.Join(parts, []byte(".")))

	_, err = sso.ValidateToken(context.Background(), tamperedToken)
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: tampered payload was accepted without valid signature!")
	}

	// 3.3 Bit-flipped signature bytes
	sigBytes, _ := base64.RawURLEncoding.DecodeString(string(parts[2]))
	sigBytes[0] ^= 0xFF
	parts[2] = []byte(base64.RawURLEncoding.EncodeToString(sigBytes))
	flippedSigToken := string(bytes.Join(parts, []byte(".")))

	_, err = sso.ValidateToken(context.Background(), flippedSigToken)
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: bit-flipped signature was accepted!")
	}

	// 3.4 Key confusion / forged token with attacker RSA key
	attackerPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	attackerSigningInput := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ"
	h := sha256.Sum256([]byte(attackerSigningInput))
	attackerSig, _ := rsa.SignPKCS1v15(rand.Reader, attackerPrivKey, 0, h[:])
	forgedToken := fmt.Sprintf("%s.%s", attackerSigningInput, base64.RawURLEncoding.EncodeToString(attackerSig))

	_, err = sso.ValidateToken(context.Background(), forgedToken)
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: token signed by attacker key was accepted!")
	}

	// 3.5 Expired token (exp in past)
	expiredToken, _ := sso.GenerateTestJWT(validClaims, true)
	_, err = sso.ValidateToken(context.Background(), expiredToken)
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: expired token was accepted!")
	}
}

// 4. Strict Role Enforcement: 100% Rejection of Unmapped Groups
func TestAdversarial_Enterprise_SSO_StrictUnmappedGroup_100PercentDenial(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	unmappedScenarios := [][]string{
		{"External-Contractors"},
		{"Guests", "Anonymous"},
		{"Hacker-Role", "Root"},
		{},
		{"admin"},      // lowercase mismatch
		{"Developers"}, // case mismatch
		{"*.*"},
		{"Org-Admins-Fake"},
	}

	const concurrentRejections = 500
	var wg sync.WaitGroup
	var rejectionCount atomic.Int64
	var bypassCount atomic.Int64

	wg.Add(concurrentRejections)
	for i := 0; i < concurrentRejections; i++ {
		go func(iteration int) {
			defer wg.Done()
			scenario := unmappedScenarios[iteration%len(unmappedScenarios)]
			claims := &mock.UserClaims{
				Subject: fmt.Sprintf("unmapped-sub-%d", iteration),
				Email:   fmt.Sprintf("unmapped-%d@corp.com", iteration),
				Groups:  scenario,
			}
			role, err := sso.ResolveRole(claims)
			if err != nil && role == "" {
				rejectionCount.Add(1)
			} else {
				bypassCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if bypassCount.Load() > 0 {
		t.Fatalf("SECURITY VIOLATION: %d unmapped group attempts bypassed RBAC!", bypassCount.Load())
	}
	if rejectionCount.Load() != concurrentRejections {
		t.Fatalf("expected 100%% rejection rate (%d), got %d rejections", concurrentRejections, rejectionCount.Load())
	}
}

// 5. SCIM Concurrent Collision Prevention under 500 Goroutines
func TestAdversarial_Enterprise_SCIM_ConcurrentCollisionPrevention(t *testing.T) {
	sso, err := mock.NewMockSSOAdapter()
	if err != nil {
		t.Fatalf("failed to init mock SSO: %v", err)
	}

	scimUser := mock.SCIMUser{
		ID:          "scim-swarm-target-001",
		UserName:    "swarm.scim@enterprise.corp",
		DisplayName: "Swarm SCIM Target",
		Active:      true,
		Groups:      []string{"Engineering-Devs"},
	}

	const numGoroutines = 500
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var collisionCount atomic.Int64

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := sso.ProvisionSCIMUser(scimUser)
			if err == nil {
				successCount.Add(1)
			} else {
				collisionCount.Add(1)
			}
		}()
	}
	wg.Wait()

	// Exactly 1 must succeed; exactly 499 must fail with collision error
	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 successful SCIM creation, got %d", successCount.Load())
	}
	if collisionCount.Load() != numGoroutines-1 {
		t.Fatalf("expected %d collisions, got %d", numGoroutines-1, collisionCount.Load())
	}
}
