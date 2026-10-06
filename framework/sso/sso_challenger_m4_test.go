package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// CHALLENGER 1 EMPIRICAL ADVERSARIAL STRESS SUITE (M4 ITERATION 2)
// ============================================================================

// 1. Stress-test JIT user provisioning concurrency under 1000 goroutines with race detector
func TestChallenger_JITProvisioning_Concurrency_1000Goroutines(t *testing.T) {
	// 1.1 Swarm Attack: 1000 concurrent logins for the same user
	t.Run("Swarm1000_SameUser_IdempotencyAndNoRaces", func(t *testing.T) {
		store := NewMemoryUserStore()
		jit := NewJITEngine(store, "both")

		claims := &IdentityClaims{
			Subject: "concurrency-target-1",
			Email:   "target1@corp.internal",
			Name:    "Target One",
			Groups:  []string{"Engineering-Devs"},
		}

		const numGoroutines = 1000
		var wg sync.WaitGroup
		var successCount atomic.Int64
		var errCount atomic.Int64

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(iter int) {
				defer wg.Done()
				user, err := jit.ProvisionUser(context.Background(), claims, RoleDeveloper)
				if err != nil {
					errCount.Add(1)
					return
				}
				if user == nil || user.ID != "concurrency-target-1" {
					errCount.Add(1)
					return
				}
				successCount.Add(1)
			}(i)
		}
		wg.Wait()

		if errCount.Load() > 0 || successCount.Load() != numGoroutines {
			t.Fatalf("expected %d successes with 0 errors, got %d successes, %d errors",
				numGoroutines, successCount.Load(), errCount.Load())
		}

		users, err := store.ListUsers(context.Background())
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("INVARIANT VIOLATION: expected 1 user in store, found %d", len(users))
		}
	})

	// 1.2 Swarm Attack: 1000 concurrent distinct users created simultaneously
	t.Run("Swarm1000_DistinctUsers_AllCreatedSafely", func(t *testing.T) {
		store := NewMemoryUserStore()
		jit := NewJITEngine(store, "both")

		const numGoroutines = 1000
		var wg sync.WaitGroup
		var successCount atomic.Int64

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				c := &IdentityClaims{
					Subject: fmt.Sprintf("distinct-user-%04d", id),
					Email:   fmt.Sprintf("user-%04d@corp.internal", id),
					Name:    fmt.Sprintf("User %04d", id),
					Groups:  []string{"Engineering-Devs"},
				}
				user, err := jit.ProvisionUser(context.Background(), c, RoleDeveloper)
				if err == nil && user != nil {
					successCount.Add(1)
				}
			}(i)
		}
		wg.Wait()

		if successCount.Load() != numGoroutines {
			t.Fatalf("expected %d successful provisions, got %d", numGoroutines, successCount.Load())
		}

		users, err := store.ListUsers(context.Background())
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}
		if len(users) != numGoroutines {
			t.Fatalf("INVARIANT VIOLATION: expected %d users in store, found %d", numGoroutines, len(users))
		}
	})

	// 1.3 Mixed Swarm: Returning user mutations + New user creations + Concurrent Lookups & ListUsers
	t.Run("Swarm1000_MixedReturningAndNew_WithHeavyContention", func(t *testing.T) {
		store := NewMemoryUserStore()
		jit := NewJITEngine(store, "both")

		// Pre-populate 5 returning users
		for k := 0; k < 5; k++ {
			base := &IdentityClaims{
				Subject: fmt.Sprintf("returning-%d", k),
				Email:   fmt.Sprintf("ret-%d@corp.internal", k),
				Name:    fmt.Sprintf("Returning %d", k),
				Groups:  []string{"Engineering-Devs"},
			}
			_, err := jit.ProvisionUser(context.Background(), base, RoleDeveloper)
			if err != nil {
				t.Fatalf("failed to setup returning user %d: %v", k, err)
			}
		}

		const numGoroutines = 1000
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(iter int) {
				defer wg.Done()
				ctx := context.Background()

				switch iter % 4 {
				case 0:
					// Returning user update
					targetIdx := iter % 5
					c := &IdentityClaims{
						Subject: fmt.Sprintf("returning-%d", targetIdx),
						Email:   fmt.Sprintf("ret-%d-updated-%d@corp.internal", targetIdx, iter%10),
						Name:    fmt.Sprintf("Returning %d Updated", targetIdx),
						Groups:  []string{"Org-Admins"},
					}
					_, _ = jit.ProvisionUser(ctx, c, RoleAdmin)

				case 1:
					// New user creation
					c := &IdentityClaims{
						Subject: fmt.Sprintf("new-user-%04d", iter),
						Email:   fmt.Sprintf("new-%04d@corp.internal", iter),
						Name:    fmt.Sprintf("New User %04d", iter),
						Groups:  []string{"Engineering-Devs"},
					}
					_, _ = jit.ProvisionUser(ctx, c, RoleDeveloper)

				case 2:
					// Lookup user by ID and email
					targetIdx := iter % 5
					_, _ = store.GetUser(ctx, fmt.Sprintf("returning-%d", targetIdx))
					_, _ = store.GetUserByEmail(ctx, fmt.Sprintf("ret-%d@corp.internal", targetIdx))

				case 3:
					// Concurrent ListUsers inspection
					_, _ = store.ListUsers(ctx)
				}
			}(i)
		}
		wg.Wait()

		// Final check: All pre-existing users must still exist
		for k := 0; k < 5; k++ {
			u, err := store.GetUser(context.Background(), fmt.Sprintf("returning-%d", k))
			if err != nil || u == nil {
				t.Fatalf("returning user %d was lost under concurrent contention!", k)
			}
		}
	})
}

// 2. SAML 2.0 Security Adversarial Suite
func TestChallenger_SAML_AdversarialSecurity(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "idp.challenger.corp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	spEntityID := "https://gateway.enterprise.corp/saml/sp"
	validator := NewSAMLValidator(SAMLConfig{
		SPEntityID:         spEntityID,
		IdPCertificate:     cert,
		ClockSkewTolerance: 2 * time.Minute,
	})

	assertionID := "assert-valid-123"
	nowStr := time.Now().Format(time.RFC3339)
	notBefore := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := time.Now().Add(15 * time.Minute).Format(time.RFC3339)

	validSignedXML := buildTestSignedSAMLResponse(
		privKey,
		certB64,
		assertionID,
		nowStr,
		notBefore,
		notOnOrAfter,
		spEntityID,
		"challenger.user@corp.internal",
		"Engineering-Devs",
	)

	// 2.1 Baseline sanity: Authentic assertion must pass
	t.Run("AuthenticSignedAssertion_Passes", func(t *testing.T) {
		claims, err := validator.ValidateSAMLAssertion(context.Background(), validSignedXML)
		if err != nil {
			t.Fatalf("authentic signed assertion rejected: %v", err)
		}
		if claims.Subject != "challenger.user@corp.internal" {
			t.Fatalf("subject mismatch: %s", claims.Subject)
		}
	})

	// 2.2 Unsigned SAML assertion must be strictly rejected with ErrSAMLInvalidSig
	t.Run("UnsignedAssertion_Rejected", func(t *testing.T) {
		unsignedXML := `<Response ID="resp-unsigned" IssueInstant="2026-10-06T00:00:00Z">
			<Assertion ID="assert-unsigned" IssueInstant="2026-10-06T00:00:00Z">
				<Issuer>https://idp.enterprise.corp</Issuer>
				<Subject><NameID>attacker@corp.internal</NameID></Subject>
				<Conditions NotBefore="2026-10-05T00:00:00Z" NotOnOrAfter="2026-10-07T00:00:00Z">
					<AudienceRestriction><Audience>` + spEntityID + `</Audience></AudienceRestriction>
				</Conditions>
				<AttributeStatement>
					<Attribute Name="email"><AttributeValue>attacker@corp.internal</AttributeValue></Attribute>
					<Attribute Name="groups"><AttributeValue>Org-Admins</AttributeValue></Attribute>
				</AttributeStatement>
			</Assertion>
		</Response>`

		_, err := validator.ValidateSAMLAssertion(context.Background(), unsignedXML)
		if err != ErrSAMLInvalidSig {
			t.Fatalf("expected ErrSAMLInvalidSig for unsigned assertion, got: %v", err)
		}
	})

	// 2.3 Tampered XML assertion bodies must fail with ErrSAMLInvalidDigest
	t.Run("TamperedXMLAssertionBody_RejectedWithInvalidDigest", func(t *testing.T) {
		// Tamper 1: Privilege escalation in attribute statement
		tamperedGroupsXML := strings.Replace(validSignedXML, "Engineering-Devs", "Org-Admins", 1)
		_, err := validator.ValidateSAMLAssertion(context.Background(), tamperedGroupsXML)
		if err != ErrSAMLInvalidDigest {
			t.Fatalf("expected ErrSAMLInvalidDigest for tampered groups, got: %v", err)
		}

		// Tamper 2: Identity theft in Subject NameID
		tamperedSubjectXML := strings.Replace(validSignedXML, "challenger.user@corp.internal", "ceo@corp.internal", 1)
		_, err = validator.ValidateSAMLAssertion(context.Background(), tamperedSubjectXML)
		if err != ErrSAMLInvalidDigest {
			t.Fatalf("expected ErrSAMLInvalidDigest for tampered Subject, got: %v", err)
		}

		// Tamper 3: Issuer modification
		tamperedIssuerXML := strings.Replace(validSignedXML, "https://idp.enterprise.corp", "https://evil.idp.corp", 1)
		_, err = validator.ValidateSAMLAssertion(context.Background(), tamperedIssuerXML)
		if err != ErrSAMLInvalidDigest {
			t.Fatalf("expected ErrSAMLInvalidDigest for tampered Issuer, got: %v", err)
		}
	})

	// 2.4 Altered reference digests must fail with ErrSAMLInvalidDigest or ErrSAMLInvalidSig
	t.Run("AlteredReferenceDigest_Rejected", func(t *testing.T) {
		// Case A: Corrupted / forged digest in Reference without re-signing SignedInfo
		// Attacker changes DigestValue to some random base64
		fakeDigest := base64.StdEncoding.EncodeToString([]byte("totally-fake-digest-bytes-here!"))
		corruptedDigestXML := strings.Replace(validSignedXML, `<DigestValue>`, `<DigestValue>`+fakeDigest[:10], 1)
		_, err := validator.ValidateSAMLAssertion(context.Background(), corruptedDigestXML)
		if err != ErrSAMLInvalidDigest && err != ErrSAMLInvalidSig {
			t.Fatalf("expected ErrSAMLInvalidDigest or ErrSAMLInvalidSig, got: %v", err)
		}
	})

	// 2.5 XML Signature Wrapping (XSW) attacks
	t.Run("XSW_ReferenceURIMismatch_Rejected", func(t *testing.T) {
		// Attacker sets Reference URI to "#different-assertion" while Assertion ID is "assert-valid-123"
		xswXML := strings.Replace(validSignedXML, `URI="#assert-valid-123"`, `URI="#different-assertion"`, 1)
		_, err := validator.ValidateSAMLAssertion(context.Background(), xswXML)
		if err == nil {
			t.Fatalf("SECURITY FAILURE: XSW with mismatched Reference URI was accepted!")
		}
		if !strings.Contains(err.Error(), "does not match assertion id") && err != ErrSAMLInvalidSig {
			t.Fatalf("expected reference mismatch error, got: %v", err)
		}
	})

	// 2.6 Expired and Not-Yet-Valid SAML conditions
	t.Run("SAMLConditions_ExpiryAndNotBefore_Rejected", func(t *testing.T) {
		// Past expiration
		pastNOA := time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
		expiredXML := buildTestSignedSAMLResponse(
			privKey, certB64, "assert-exp", nowStr, notBefore, pastNOA, spEntityID, "u@corp.com", "Devs",
		)
		_, err := validator.ValidateSAMLAssertion(context.Background(), expiredXML)
		if err != ErrSAMLExpired {
			t.Fatalf("expected ErrSAMLExpired, got: %v", err)
		}

		// Future NotBefore
		futureNB := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
		futureXML := buildTestSignedSAMLResponse(
			privKey, certB64, "assert-future", nowStr, futureNB, notOnOrAfter, spEntityID, "u@corp.com", "Devs",
		)
		_, err = validator.ValidateSAMLAssertion(context.Background(), futureXML)
		if err != ErrSAMLNotYetValid {
			t.Fatalf("expected ErrSAMLNotYetValid, got: %v", err)
		}

		// Audience mismatch
		wrongAudXML := buildTestSignedSAMLResponse(
			privKey, certB64, "assert-aud", nowStr, notBefore, notOnOrAfter, "https://wrong.sp.entity/id", "u@corp.com", "Devs",
		)
		_, err = validator.ValidateSAMLAssertion(context.Background(), wrongAudXML)
		if err != ErrInvalidAudience {
			t.Fatalf("expected ErrInvalidAudience, got: %v", err)
		}
	})
}

// 3. OIDC Claims Strictness Suite
func TestChallenger_OIDC_ClaimsStrictness(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-oidc-chal", &privKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{
		IssuerURL: "https://auth.challenger.corp",
		Audience:  "bifrost-gateway",
	}, cache)

	// Helper to mint tokens
	mintToken := func(claims map[string]interface{}) string {
		return generateRSATestToken(t, privKey, "k-oidc-chal", claims)
	}

	baseClaims := func() map[string]interface{} {
		return map[string]interface{}{
			"sub":    "chal-user-1",
			"email":  "chal@corp.internal",
			"iss":    "https://auth.challenger.corp",
			"aud":    "bifrost-gateway",
			"exp":    time.Now().Add(10 * time.Minute).Unix(),
			"groups": []string{"Engineering-Devs"},
		}
	}

	// 3.1 Baseline: Valid token passes
	t.Run("ValidOIDCClaims_Passes", func(t *testing.T) {
		token := mintToken(baseClaims())
		claims, err := validator.ValidateToken(context.Background(), token)
		if err != nil {
			t.Fatalf("valid token rejected: %v", err)
		}
		if claims.Subject != "chal-user-1" {
			t.Fatalf("subject mismatch: %s", claims.Subject)
		}
	})

	// 3.2 Missing and invalid issuer
	t.Run("MissingAndInvalidIssuer_Rejected", func(t *testing.T) {
		// Missing issuer
		c := baseClaims()
		delete(c, "iss")
		_, err := validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrInvalidIssuer {
			t.Fatalf("expected ErrInvalidIssuer on missing iss, got: %v", err)
		}

		// Mismatched issuer
		c = baseClaims()
		c["iss"] = "https://rogue-issuer.corp"
		_, err = validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrInvalidIssuer {
			t.Fatalf("expected ErrInvalidIssuer on rogue iss, got: %v", err)
		}
	})

	// 3.3 Missing and invalid audience
	t.Run("MissingAndInvalidAudience_Rejected", func(t *testing.T) {
		// Missing audience
		c := baseClaims()
		delete(c, "aud")
		_, err := validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrInvalidAudience {
			t.Fatalf("expected ErrInvalidAudience on missing aud, got: %v", err)
		}

		// Empty audience array
		c = baseClaims()
		c["aud"] = []string{}
		_, err = validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrInvalidAudience {
			t.Fatalf("expected ErrInvalidAudience on empty aud, got: %v", err)
		}

		// Wrong audience
		c = baseClaims()
		c["aud"] = "other-service"
		_, err = validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrInvalidAudience {
			t.Fatalf("expected ErrInvalidAudience on wrong aud, got: %v", err)
		}
	})

	// 3.4 Missing and expired expiration
	t.Run("MissingAndExpired_Rejected", func(t *testing.T) {
		// Missing exp
		c := baseClaims()
		delete(c, "exp")
		_, err := validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrTokenExpired {
			t.Fatalf("expected ErrTokenExpired on missing exp, got: %v", err)
		}

		// Zero exp
		c = baseClaims()
		c["exp"] = 0
		_, err = validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrTokenExpired {
			t.Fatalf("expected ErrTokenExpired on zero exp, got: %v", err)
		}

		// Expired exp in past beyond clock skew (e.g. 5 minutes ago)
		c = baseClaims()
		c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
		_, err = validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrTokenExpired {
			t.Fatalf("expected ErrTokenExpired on past exp, got: %v", err)
		}

		// Future nbf beyond clock skew
		c = baseClaims()
		c["nbf"] = time.Now().Add(5 * time.Minute).Unix()
		_, err = validator.ValidateToken(context.Background(), mintToken(c))
		if err != ErrTokenExpired {
			t.Fatalf("expected ErrTokenExpired on future nbf, got: %v", err)
		}
	})
}
