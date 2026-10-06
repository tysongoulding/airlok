package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

// Helper to generate RSA test key pair and signed JWT
func generateRSATestToken(t *testing.T, privKey *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, payloadB64)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, 0, h[:])
	if err != nil {
		t.Fatalf("sign rsa: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s", signingInput, sigB64)
}

// Helper to generate ECDSA test key pair and signed JWT
func generateECDSATestToken(t *testing.T, privKey *ecdsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, payloadB64)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, h[:])
	if err != nil {
		t.Fatalf("sign ecdsa: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s", signingInput, sigB64)
}

func TestOIDC_RS256_SignatureAndClaims(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("key-1", &privKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{
		IssuerURL: "https://auth.enterprise.corp",
		Audience:  "bifrost-gateway",
	}, cache)

	claims := map[string]interface{}{
		"sub":    "user-100",
		"email":  "alice@enterprise.corp",
		"name":   "Alice Specialist",
		"groups": []string{"Security-Auditors"},
		"iss":    "https://auth.enterprise.corp",
		"aud":    "bifrost-gateway",
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	}
	token := generateRSATestToken(t, privKey, "key-1", claims)

	validated, err := validator.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("expected valid token, got err: %v", err)
	}
	if validated.Subject != "user-100" || validated.Email != "alice@enterprise.corp" {
		t.Errorf("claims mismatch: %+v", validated)
	}
	if len(validated.Groups) != 1 || validated.Groups[0] != "Security-Auditors" {
		t.Errorf("groups mismatch: %+v", validated.Groups)
	}
}

func TestOIDC_ES256_Signature(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec key: %v", err)
	}

	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("ec-key-1", &ecKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{}, cache)

	claims := map[string]interface{}{
		"sub":   "user-ec",
		"email": "ec@corp.com",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	}
	token := generateECDSATestToken(t, ecKey, "ec-key-1", claims)

	validated, err := validator.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("es256 validation failed: %v", err)
	}
	if validated.Subject != "user-ec" {
		t.Errorf("expected user-ec, got %s", validated.Subject)
	}
}

func TestOIDC_Rejections(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k1", &privKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{
		IssuerURL: "https://expected-issuer.com",
		Audience:  "expected-audience",
	}, cache)

	// 1. Expired token
	t.Run("expired token", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user-expired",
			"exp": time.Now().Add(-10 * time.Minute).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
	})

	// 2. Tampered signature
	t.Run("tampered payload", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user-valid",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		parts := strings.Split(token, ".")
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"tampered"}`))
		tampered := strings.Join(parts, ".")
		_, err := validator.ValidateToken(context.Background(), tampered)
		if err != ErrInvalidSignature {
			t.Errorf("expected ErrInvalidSignature, got %v", err)
		}
	})

	// 3. Malformed segment counts
	t.Run("malformed segments", func(t *testing.T) {
		badTokens := []string{"", "single", "part1.part2", "p1.p2.p3.p4"}
		for _, tok := range badTokens {
			_, err := validator.ValidateToken(context.Background(), tok)
			if err != ErrMalformedToken {
				t.Errorf("for token %q expected ErrMalformedToken, got %v", tok, err)
			}
		}
	})

	// 4. Invalid issuer
	t.Run("invalid issuer", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user",
			"iss": "https://wrong-issuer.com",
			"aud": "expected-audience",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrInvalidIssuer {
			t.Errorf("expected ErrInvalidIssuer, got %v", err)
		}
	})

	// 5. Invalid audience
	t.Run("invalid audience", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user",
			"iss": "https://expected-issuer.com",
			"aud": "wrong-audience",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrInvalidAudience {
			t.Errorf("expected ErrInvalidAudience, got %v", err)
		}
	})

	// 6. Missing issuer when configured
	t.Run("missing issuer", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user",
			"aud": "expected-audience",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrInvalidIssuer {
			t.Errorf("expected ErrInvalidIssuer on missing iss, got %v", err)
		}
	})

	// 7. Missing audience when configured
	t.Run("missing audience", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user",
			"iss": "https://expected-issuer.com",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrInvalidAudience {
			t.Errorf("expected ErrInvalidAudience on missing aud, got %v", err)
		}
	})

	// 8. Missing expiration
	t.Run("missing expiration", func(t *testing.T) {
		token := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
			"sub": "user",
			"iss": "https://expected-issuer.com",
			"aud": "expected-audience",
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired on missing exp, got %v", err)
		}
	})
}

func TestJWKSCache_FetchAndSingleflight(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nB64 := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	fetchCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetchCount++
		mu.Unlock()
		resp := JWKSResponse{
			Keys: []JWK{
				{Kty: "RSA", Kid: "test-kid", Alg: "RS256", N: nB64, E: eB64},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, server.Client(), 1*time.Hour)
	defer cache.Close()

	// Concurrent requests for key should trigger singleflight
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := cache.GetKey(context.Background(), "test-kid")
			if err != nil || key == nil {
				t.Errorf("failed to get key: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch under singleflight, got %d", fetchCount)
	}
}

func TestGroupRoleMapping_HighestPermissionCountAndOrder(t *testing.T) {
	mappings := []AttributeRoleMapping{
		{Attribute: "groups", Value: "Security-Auditors", Role: RoleSecurityAuditor}, // weight 5
		{Attribute: "groups", Value: "Engineering-Devs", Role: RoleDeveloper},        // weight 7
		{Attribute: "groups", Value: "Org-Admins", Role: RoleAdmin},                  // weight 54
		{Attribute: "groups", Value: "Infra-Operators", Role: RoleOperator},          // weight 4
	}

	mapper := NewRoleMapper(mappings, StrategyHighestPermissionCount)

	// Single match
	role, err := mapper.ResolveRole(&IdentityClaims{Groups: []string{"Security-Auditors"}})
	if err != nil || role != RoleSecurityAuditor {
		t.Fatalf("expected Security Auditor, got %s (err=%v)", role, err)
	}

	// Multiple matching groups -> highestPermissionCount wins (Admin: 54 vs Developer: 7)
	multiClaims := &IdentityClaims{
		Groups: []string{"Engineering-Devs", "Org-Admins"},
	}
	roleMulti, err := mapper.ResolveRole(multiClaims)
	if err != nil || roleMulti != RoleAdmin {
		t.Fatalf("expected Admin (54) to win over Developer (7), got %s", roleMulti)
	}

	// StrategyOrder -> first matching rule in mappings slice wins
	mapper.SetStrategy(StrategyOrder)
	roleOrder, err := mapper.ResolveRole(multiClaims)
	// In mappings, Engineering-Devs is index 1, Org-Admins is index 2. Engineering-Devs wins in order.
	if err != nil || roleOrder != RoleDeveloper {
		t.Fatalf("expected Developer to win under order strategy, got %s", roleOrder)
	}

	// Unmapped group -> returns ErrUnmappedRole
	unmappedClaims := &IdentityClaims{
		Groups: []string{"Contractor-Guests"},
	}
	_, err = mapper.ResolveRole(unmappedClaims)
	if err != ErrUnmappedRole {
		t.Fatalf("expected ErrUnmappedRole, got %v", err)
	}
}

func TestGroupRoleMapping_DotPathAndWildcard(t *testing.T) {
	mappings := []AttributeRoleMapping{
		{Attribute: "realm_access.roles", Value: "admin-role", Role: RoleAdmin},
		{Attribute: "groups", Value: "*", Role: RoleDeveloper},
	}

	mapper := NewRoleMapper(mappings, StrategyOrder)

	claims := &IdentityClaims{
		RawClaims: map[string]interface{}{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin-role"},
			},
		},
	}
	role, err := mapper.ResolveRole(claims)
	if err != nil || role != RoleAdmin {
		t.Fatalf("expected Admin via dot path, got %s (err=%v)", role, err)
	}

	// Wildcard match
	wildcardClaims := &IdentityClaims{
		Groups: []string{"Any-Group"},
	}
	roleWildcard, err := mapper.ResolveRole(wildcardClaims)
	if err != nil || roleWildcard != RoleDeveloper {
		t.Fatalf("expected Developer via wildcard, got %s", roleWildcard)
	}
}

func TestJITProvisioning_CreateAndSync(t *testing.T) {
	store := NewMemoryUserStore()
	jit := NewJITEngine(store, "both")

	claims := &IdentityClaims{
		Subject: "user-42",
		Email:   "user42@corp.com",
		Name:    "User 42",
		Groups:  []string{"Engineering-Devs"},
	}

	// 1. Initial creation
	user, err := jit.ProvisionUser(context.Background(), claims, RoleDeveloper)
	if err != nil {
		t.Fatalf("provision user: %v", err)
	}
	if user.ID != "user-42" || user.Role != RoleDeveloper || user.Email != "user42@corp.com" {
		t.Errorf("user mismatch: %+v", user)
	}

	// 2. Returning login: name update and role promotion
	updatedClaims := &IdentityClaims{
		Subject: "user-42",
		Email:   "user42@corp.com",
		Name:    "User 42 Renamed",
		Groups:  []string{"Engineering-Devs", "Org-Admins"},
	}
	updatedUser, err := jit.ProvisionUser(context.Background(), updatedClaims, RoleAdmin)
	if err != nil {
		t.Fatalf("update returning user: %v", err)
	}
	if updatedUser.Name != "User 42 Renamed" || updatedUser.Role != RoleAdmin {
		t.Errorf("returning user not updated: %+v", updatedUser)
	}

	// 3. Returning login with omitted role attribute preserves existing role
	omittedRoleClaims := &IdentityClaims{
		Subject: "user-42",
		Email:   "user42@corp.com",
	}
	keptUser, err := jit.ProvisionUser(context.Background(), omittedRoleClaims, "")
	if err != nil {
		t.Fatalf("login with omitted role: %v", err)
	}
	if keptUser.Role != RoleAdmin {
		t.Errorf("expected preserved role Admin, got %s", keptUser.Role)
	}
}

func TestJITProvisioning_SCIMFreezeMode(t *testing.T) {
	store := NewMemoryUserStore()
	jit := NewJITEngine(store, "scim") // SCIM-only freeze mode

	claims := &IdentityClaims{
		Subject: "brand-new-user",
		Email:   "brandnew@corp.com",
	}

	// New user login under SCIM freeze mode must be rejected
	_, err := jit.ProvisionUser(context.Background(), claims, RoleDeveloper)
	if err == nil {
		t.Fatalf("expected error provisioning new user in scim-only freeze mode")
	}

	// Provision via SCIM API first
	scimUser := SCIMUser{
		ID:       "brand-new-user",
		UserName: "brandnew@corp.com",
		Active:   true,
	}
	if err := store.CreateUser(context.Background(), &User{ID: scimUser.ID, Email: scimUser.UserName, Role: RoleDeveloper}); err != nil {
		t.Fatalf("create scim user: %v", err)
	}

	// Subsequent OIDC login succeeds
	user, err := jit.ProvisionUser(context.Background(), claims, RoleDeveloper)
	if err != nil || user.ID != "brand-new-user" {
		t.Fatalf("expected returning user to login, got err: %v", err)
	}
}

func buildTestSignedSAMLResponse(
	privKey *rsa.PrivateKey,
	certB64 string,
	assertionID string,
	issueInstant string,
	notBefore string,
	notOnOrAfter string,
	audience string,
	email string,
	group string,
) string {
	rawAssertion := fmt.Sprintf(`<Assertion ID="%s" IssueInstant="%s">
			<Issuer>https://idp.enterprise.corp</Issuer>
			<Subject>
				<NameID>%s</NameID>
			</Subject>
			<Conditions NotBefore="%s" NotOnOrAfter="%s">
				<AudienceRestriction>
					<Audience>%s</Audience>
				</AudienceRestriction>
			</Conditions>
			<AttributeStatement>
				<Attribute Name="email">
					<AttributeValue>%s</AttributeValue>
				</Attribute>
				<Attribute Name="groups">
					<AttributeValue>%s</AttributeValue>
				</Attribute>
			</AttributeStatement>
		</Assertion>`,
		assertionID, issueInstant, email, notBefore, notOnOrAfter, audience, email, group)

	h := sha256.Sum256(normalizeXMLWhitespace([]byte(rawAssertion)))
	digestB64 := base64.StdEncoding.EncodeToString(h[:])

	signedInfo := fmt.Sprintf(`<SignedInfo>
					<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
					<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
					<Reference URI="#%s">
						<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
						<DigestValue>%s</DigestValue>
					</Reference>
				</SignedInfo>`, assertionID, digestB64)

	hSI := sha256.Sum256([]byte(signedInfo))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hSI[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	signature := fmt.Sprintf(`<Signature>
				%s
				<SignatureValue>%s</SignatureValue>
				<KeyInfo>
					<X509Data>
						<X509Certificate>%s</X509Certificate>
					</X509Data>
				</KeyInfo>
			</Signature>`, signedInfo, sigB64, certB64)

	signedAssertion := fmt.Sprintf(`<Assertion ID="%s" IssueInstant="%s">
			<Issuer>https://idp.enterprise.corp</Issuer>
			<Subject>
				<NameID>%s</NameID>
			</Subject>
			<Conditions NotBefore="%s" NotOnOrAfter="%s">
				<AudienceRestriction>
					<Audience>%s</Audience>
				</AudienceRestriction>
			</Conditions>
			<AttributeStatement>
				<Attribute Name="email">
					<AttributeValue>%s</AttributeValue>
				</Attribute>
				<Attribute Name="groups">
					<AttributeValue>%s</AttributeValue>
				</Attribute>
			</AttributeStatement>
			%s
		</Assertion>`,
		assertionID, issueInstant, email, notBefore, notOnOrAfter, audience, email, group, signature)

	return fmt.Sprintf(`<Response ID="resp-1" IssueInstant="%s">
		%s
	</Response>`, issueInstant, signedAssertion)
}

func TestSAML_AssertionValidation(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.enterprise.corp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	validator := NewSAMLValidator(SAMLConfig{
		SPEntityID:     "https://gateway.enterprise.corp/saml/sp",
		IdPCertificate: cert,
	})

	assertionID := "assertion-uuid-12345"
	issueInstant := time.Now().Format(time.RFC3339)
	notBefore := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := time.Now().Add(15 * time.Minute).Format(time.RFC3339)

	signedXML := buildTestSignedSAMLResponse(
		privKey,
		certB64,
		assertionID,
		issueInstant,
		notBefore,
		notOnOrAfter,
		"https://gateway.enterprise.corp/saml/sp",
		"saml.auditor@corp.com",
		"Security-Auditors",
	)

	// Validate authentic SAML assertion
	claims, err := validator.ValidateSAMLAssertion(context.Background(), signedXML)
	if err != nil {
		t.Fatalf("validate authentic saml assertion failed: %v", err)
	}
	if claims.Subject != "saml.auditor@corp.com" || claims.Email != "saml.auditor@corp.com" {
		t.Errorf("claims mismatch: %+v", claims)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "Security-Auditors" {
		t.Errorf("groups mismatch: %+v", claims.Groups)
	}
}

func TestSAML_RejectUnsignedAssertion(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "idp.enterprise.corp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	validator := NewSAMLValidator(SAMLConfig{
		SPEntityID:     "https://gateway.enterprise.corp/saml/sp",
		IdPCertificate: cert,
	})

	unsignedXML := `<Response ID="resp-unsigned" IssueInstant="2026-10-06T00:00:00Z">
		<Assertion ID="assert-unsigned" IssueInstant="2026-10-06T00:00:00Z">
			<Issuer>https://idp.enterprise.corp</Issuer>
			<Subject>
				<NameID>attacker@corp.com</NameID>
			</Subject>
			<Conditions NotBefore="2026-10-05T00:00:00Z" NotOnOrAfter="2026-10-07T00:00:00Z">
				<AudienceRestriction>
					<Audience>https://gateway.enterprise.corp/saml/sp</Audience>
				</AudienceRestriction>
			</Conditions>
			<AttributeStatement>
				<Attribute Name="email">
					<AttributeValue>attacker@corp.com</AttributeValue>
				</Attribute>
				<Attribute Name="groups">
					<AttributeValue>Org-Admins</AttributeValue>
				</Attribute>
			</AttributeStatement>
		</Assertion>
	</Response>`

	_, err := validator.ValidateSAMLAssertion(context.Background(), unsignedXML)
	if err != ErrSAMLInvalidSig {
		t.Fatalf("expected ErrSAMLInvalidSig for unsigned assertion, got: %v", err)
	}
}

func TestSAML_TamperedAssertionBody_Rejected(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "idp.enterprise.corp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	validator := NewSAMLValidator(SAMLConfig{
		SPEntityID:     "https://gateway.enterprise.corp/saml/sp",
		IdPCertificate: cert,
	})

	signedXML := buildTestSignedSAMLResponse(
		privKey,
		certB64,
		"assert-tamper-target",
		time.Now().Format(time.RFC3339),
		time.Now().Add(-5*time.Minute).Format(time.RFC3339),
		time.Now().Add(15*time.Minute).Format(time.RFC3339),
		"https://gateway.enterprise.corp/saml/sp",
		"legit.user@corp.com",
		"Engineering-Devs",
	)

	// Tamper with assertion body after signing: escalate to Org-Admins
	tamperedXML := strings.Replace(signedXML, "Engineering-Devs", "Org-Admins", 1)

	_, err := validator.ValidateSAMLAssertion(context.Background(), tamperedXML)
	if err != ErrSAMLInvalidDigest {
		t.Fatalf("expected ErrSAMLInvalidDigest for tampered assertion body, got: %v", err)
	}
}

func TestSSOEnforcer_AuthenticateAndReject(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k1", &privKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{}, cache)
	mapper := NewRoleMapper([]AttributeRoleMapping{
		{Attribute: "groups", Value: "Org-Admins", Role: RoleAdmin},
	}, StrategyHighestPermissionCount)
	jit := NewJITEngine(NewMemoryUserStore(), "both")

	enforcer := NewSSOEnforcer(validator, mapper, jit)

	// 1. Authorized user
	validToken := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
		"sub":    "admin-user",
		"email":  "admin@corp.com",
		"groups": []string{"Org-Admins"},
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	})
	user, role, err := enforcer.AuthenticateToken(context.Background(), validToken)
	if err != nil || role != RoleAdmin || user == nil {
		t.Fatalf("expected admin authentication success: err=%v, role=%s", err, role)
	}

	// 2. Unmapped user
	unmappedToken := generateRSATestToken(t, privKey, "k1", map[string]interface{}{
		"sub":    "guest-user",
		"email":  "guest@corp.com",
		"groups": []string{"External-Guests"},
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	})
	_, _, err = enforcer.AuthenticateToken(context.Background(), unmappedToken)
	if err != ErrUnmappedRole {
		t.Fatalf("expected ErrUnmappedRole, got %v", err)
	}

	// 3. Verify FastHTTP 403 Response Writer
	var ctx fasthttp.RequestCtx
	WriteForbiddenUnmappedGroup(&ctx, "unmapped role")
	if ctx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Errorf("expected 403 status, got %d", ctx.Response.StatusCode())
	}
	var errBody map[string]map[string]interface{}
	_ = json.Unmarshal(ctx.Response.Body(), &errBody)
	if errBody["error"]["code"] != "sso_unmapped_group" {
		t.Errorf("expected sso_unmapped_group error code, got %+v", errBody)
	}
}
