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
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// ADVERSARIAL CHALLENGE: ENTERPRISE SSO & IDP INTEGRATION (FEATURES 21-25)
// ============================================================================

// --- Helper Functions ---

func makeAdversarialRSAToken(t *testing.T, privKey *rsa.PrivateKey, kid, alg string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{
		"alg": alg,
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
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

func makeAdversarialECDSAToken(t *testing.T, privKey *ecdsa.PrivateKey, kid, alg string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{
		"alg": alg,
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

// ----------------------------------------------------------------------------
// Challenge 1: Cryptographic Validation
// ----------------------------------------------------------------------------
func TestAdversarial_CryptographicValidation_RS256_ES256_TamperedAndMalformed(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("rsa-kid-1", &rsaKey.PublicKey)
	cache.AddKey("ec-kid-1", &ecKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{
		IssuerURL: "https://auth.enterprise.corp",
		Audience:  "bifrost-gateway",
	}, cache)

	validClaims := map[string]interface{}{
		"sub":    "attacker-target",
		"email":  "target@enterprise.corp",
		"groups": []string{"Engineering-Devs"},
		"iss":    "https://auth.enterprise.corp",
		"aud":    "bifrost-gateway",
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	}

	validRSAToken := makeAdversarialRSAToken(t, rsaKey, "rsa-kid-1", "RS256", validClaims)
	validECToken := makeAdversarialECDSAToken(t, ecKey, "ec-kid-1", "ES256", validClaims)

	// 1.1 Malformed segment counts (empty, 1 segment, 2 segments, 4 segments, 5 segments)
	t.Run("SegmentCountAttacks", func(t *testing.T) {
		attacks := []string{
			"",
			"   ",
			"single-segment-payload",
			"header.payload",
			"header.payload.sig.extra",
			"a.b.c.d.e",
			"...",
			"header..sig",
		}
		for _, atk := range attacks {
			_, err := validator.ValidateToken(context.Background(), atk)
			if err != ErrMalformedToken {
				t.Errorf("expected ErrMalformedToken for %q, got: %v", atk, err)
			}
		}
	})

	// 1.2 Corrupted Base64 in segments
	t.Run("CorruptedBase64Segments", func(t *testing.T) {
		parts := strings.Split(validRSAToken, ".")
		requireLen := len(parts) == 3
		if !requireLen {
			t.Fatalf("expected 3 parts")
		}

		// Bad base64 in header
		badHeader := "!!!not-base-64!!!" + "." + parts[1] + "." + parts[2]
		if _, err := validator.ValidateToken(context.Background(), badHeader); err != ErrMalformedToken {
			t.Errorf("expected ErrMalformedToken for invalid header base64, got: %v", err)
		}

		// Bad base64 in payload (unsigned / altered): rejected by signature verification
		badPayload := parts[0] + "." + "@@invalid-payload-base64@@" + "." + parts[2]
		if _, err := validator.ValidateToken(context.Background(), badPayload); err != ErrMalformedToken && err != ErrInvalidSignature {
			t.Errorf("expected rejection for invalid payload base64, got: %v", err)
		}

		// Bad base64 in payload that is signed: rejected by payload decoding
		badPayloadSignedInput := parts[0] + ".@@not-valid-b64@@"
		h := sha256.Sum256([]byte(badPayloadSignedInput))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, 0, h[:])
		signedBadB64Token := badPayloadSignedInput + "." + base64.RawURLEncoding.EncodeToString(sig)
		if _, err := validator.ValidateToken(context.Background(), signedBadB64Token); err != ErrMalformedToken {
			t.Errorf("expected ErrMalformedToken for signed invalid base64 payload, got: %v", err)
		}

		// Bad base64 in signature
		badSig := parts[0] + "." + parts[1] + "." + "###invalid-sig###"
		if _, err := validator.ValidateToken(context.Background(), badSig); err != ErrInvalidSignature {
			t.Errorf("expected ErrInvalidSignature for invalid signature base64, got: %v", err)
		}
	})

	// 1.3 Algorithm Confusion & Header Manipulation
	t.Run("AlgorithmConfusionAttacks", func(t *testing.T) {
		// "alg: none" attack
		noneToken := makeAdversarialRSAToken(t, rsaKey, "rsa-kid-1", "none", validClaims)
		if _, err := validator.ValidateToken(context.Background(), noneToken); err != ErrInvalidSignature {
			t.Errorf("expected rejection for alg: none, got: %v", err)
		}

		// "alg: HS256" attack (symmetric key confusion)
		hs256Token := makeAdversarialRSAToken(t, rsaKey, "rsa-kid-1", "HS256", validClaims)
		if _, err := validator.ValidateToken(context.Background(), hs256Token); err != ErrInvalidSignature {
			t.Errorf("expected rejection for alg: HS256, got: %v", err)
		}

		// Unknown kid attack
		unknownKidToken := makeAdversarialRSAToken(t, rsaKey, "unknown-kid-999", "RS256", validClaims)
		if _, err := validator.ValidateToken(context.Background(), unknownKidToken); err != ErrInvalidSignature {
			t.Errorf("expected rejection for unknown kid, got: %v", err)
		}

		// Non-JSON header
		corruptHeaderToken := base64.RawURLEncoding.EncodeToString([]byte("this is not json")) + "." + strings.Split(validRSAToken, ".")[1] + "." + strings.Split(validRSAToken, ".")[2]
		if _, err := validator.ValidateToken(context.Background(), corruptHeaderToken); err != ErrMalformedToken {
			t.Errorf("expected ErrMalformedToken for non-JSON header, got: %v", err)
		}
	})

	// 1.4 Payload Tampering & Privilege Escalation Attempt
	t.Run("PayloadTamperingAttacks", func(t *testing.T) {
		parts := strings.Split(validRSAToken, ".")
		// Attacker attempts to escalate privileges by injecting "Org-Admins" into payload
		tamperedClaims := map[string]interface{}{
			"sub":    "attacker-target",
			"email":  "target@enterprise.corp",
			"groups": []string{"Org-Admins"}, // ESCALATION
			"iss":    "https://auth.enterprise.corp",
			"aud":    "bifrost-gateway",
			"exp":    time.Now().Add(10 * time.Minute).Unix(),
		}
		tamperedPayloadBytes, _ := json.Marshal(tamperedClaims)
		tamperedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tamperedPayloadBytes) + "." + parts[2]

		_, err := validator.ValidateToken(context.Background(), tamperedToken)
		if err != ErrInvalidSignature {
			t.Fatalf("SECURITY VIOLATION: tampered payload was accepted! err: %v", err)
		}
	})

	// 1.5 Signature Bit-Flipping / Corruption
	t.Run("BitFlippedSignatureRejection", func(t *testing.T) {
		parts := strings.Split(validRSAToken, ".")
		sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
		// Flip first byte of RSA signature
		sigBytes[0] ^= 0xFF
		flippedSigToken := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

		if _, err := validator.ValidateToken(context.Background(), flippedSigToken); err != ErrInvalidSignature {
			t.Fatalf("expected ErrInvalidSignature for flipped signature byte, got: %v", err)
		}
	})

	// 1.6 ES256 Signature Attacks
	t.Run("ES256Attacks", func(t *testing.T) {
		// Valid ES256 token must pass
		claims, err := validator.ValidateToken(context.Background(), validECToken)
		if err != nil || claims.Subject != "attacker-target" {
			t.Fatalf("valid ES256 token failed: %v", err)
		}

		// Tampered payload with ES256 signature
		parts := strings.Split(validECToken, ".")
		tamperedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"spoofed"}`)) + "." + parts[2]
		if _, err := validator.ValidateToken(context.Background(), tamperedToken); err != ErrInvalidSignature {
			t.Errorf("expected ErrInvalidSignature for tampered ES256 payload, got: %v", err)
		}

		// Corrupted EC signature
		ecSigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
		ecSigBytes[len(ecSigBytes)-1] ^= 0xAA
		corruptECToken := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(ecSigBytes)
		if _, err := validator.ValidateToken(context.Background(), corruptECToken); err != ErrInvalidSignature {
			t.Errorf("expected ErrInvalidSignature for corrupted ES256 signature, got: %v", err)
		}

		// IEEE P1363 64-byte truncated signature
		truncatedSig := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // only 32 bytes instead of 64
		truncatedECToken := parts[0] + "." + parts[1] + "." + truncatedSig
		if _, err := validator.ValidateToken(context.Background(), truncatedECToken); err != ErrInvalidSignature {
			t.Errorf("expected ErrInvalidSignature for truncated ES256 signature, got: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// Challenge 2: Timing & Expired Tokens (exp, nbf, and Clock Skew Boundaries)
// ----------------------------------------------------------------------------
func TestAdversarial_Timing_ExpiryAndNotBefore_Boundaries(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-time", &rsaKey.PublicKey)

	tolerance := 30 * time.Second
	validator := NewOIDCValidatorWithCache(OIDCConfig{
		ClockSkewTolerance: tolerance,
	}, cache)

	now := time.Now().Unix()

	// 2.1 Expired in past beyond tolerance (now - 31s with 30s tolerance) -> MUST REJECT
	t.Run("ExpiredPastTolerance_Rejected", func(t *testing.T) {
		token := makeAdversarialRSAToken(t, rsaKey, "k-time", "RS256", map[string]interface{}{
			"sub": "user-exp",
			"exp": now - 35, // Expired 35 seconds ago (tolerance is 30s)
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired for token expired past skew, got: %v", err)
		}
	})

	// 2.2 Expired in past within tolerance (now - 15s with 30s tolerance) -> MUST ACCEPT
	t.Run("ExpiredWithinTolerance_Accepted", func(t *testing.T) {
		token := makeAdversarialRSAToken(t, rsaKey, "k-time", "RS256", map[string]interface{}{
			"sub": "user-exp-skew",
			"exp": now - 15, // Expired 15s ago, but within 30s tolerance
		})
		claims, err := validator.ValidateToken(context.Background(), token)
		if err != nil {
			t.Errorf("expected token within skew tolerance to be accepted, got: %v", err)
		}
		if claims != nil && claims.Subject != "user-exp-skew" {
			t.Errorf("claims mismatch: %+v", claims)
		}
	})

	// 2.3 Not Before (nbf) in future beyond tolerance (now + 35s with 30s tolerance) -> MUST REJECT
	t.Run("NotBeforeFutureBeyondTolerance_Rejected", func(t *testing.T) {
		token := makeAdversarialRSAToken(t, rsaKey, "k-time", "RS256", map[string]interface{}{
			"sub": "user-nbf-future",
			"nbf": now + 35,
			"exp": now + 600,
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired for future nbf past skew, got: %v", err)
		}
	})

	// 2.4 Not Before (nbf) in future within tolerance (now + 10s with 30s tolerance) -> MUST ACCEPT
	t.Run("NotBeforeFutureWithinTolerance_Accepted", func(t *testing.T) {
		token := makeAdversarialRSAToken(t, rsaKey, "k-time", "RS256", map[string]interface{}{
			"sub": "user-nbf-skew",
			"nbf": now + 10,
			"exp": now + 600,
		})
		claims, err := validator.ValidateToken(context.Background(), token)
		if err != nil {
			t.Errorf("expected token within nbf skew tolerance to be accepted, got: %v", err)
		}
		if claims != nil && claims.Subject != "user-nbf-skew" {
			t.Errorf("claims mismatch: %+v", claims)
		}
	})

	// 2.5 Expired far in past (1 year ago)
	t.Run("ExpiredFarInPast_Rejected", func(t *testing.T) {
		token := makeAdversarialRSAToken(t, rsaKey, "k-time", "RS256", map[string]interface{}{
			"sub": "user-ancient",
			"exp": now - 31536000,
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired for ancient token, got: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// Challenge 3: SAML 2.0 Adversarial Attacks (XSW, Tampered Digests, Conditions)
// ----------------------------------------------------------------------------
func TestAdversarial_SAML_XSW_TamperedDigests_AudienceMismatch(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject:      pkix.Name{CommonName: "idp.adversarial.corp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	spEntityID := "https://gateway.enterprise.corp/saml/sp"
	validator := NewSAMLValidator(SAMLConfig{
		SPEntityID:         spEntityID,
		IdPCertificate:     cert,
		ClockSkewTolerance: 2 * time.Minute,
	})

	makeSAMLPayload := func(assertionID, refURI, digestVal, notBefore, notOnOrAfter, audience, group string) string {
		nowStr := time.Now().Format(time.RFC3339)
		if digestVal == "" || digestVal == "dGVzdC1kaWdlc3Q=" {
			rawAssertion := fmt.Sprintf(`<Assertion ID="%s" IssueInstant="%s">
				<Issuer>https://idp.adversarial.corp</Issuer>
				<Subject>
					<NameID>saml.user@corp.com</NameID>
				</Subject>
				<Conditions NotBefore="%s" NotOnOrAfter="%s">
					<AudienceRestriction>
						<Audience>%s</Audience>
					</AudienceRestriction>
				</Conditions>
				<AttributeStatement>
					<Attribute Name="email">
						<AttributeValue>saml.user@corp.com</AttributeValue>
					</Attribute>
					<Attribute Name="groups">
						<AttributeValue>%s</AttributeValue>
					</Attribute>
				</AttributeStatement>
			</Assertion>`,
				assertionID, nowStr, notBefore, notOnOrAfter, audience, group)
			h := sha256.Sum256(normalizeXMLWhitespace([]byte(rawAssertion)))
			digestVal = base64.StdEncoding.EncodeToString(h[:])
		}

		signedInfo := fmt.Sprintf(`<SignedInfo>
						<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
						<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
						<Reference URI="%s">
							<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
							<DigestValue>%s</DigestValue>
						</Reference>
					</SignedInfo>`, refURI, digestVal)

		hSI := sha256.Sum256([]byte(signedInfo))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hSI[:])
		sigB64 := base64.StdEncoding.EncodeToString(sig)

		return fmt.Sprintf(`<Response ID="resp-1" IssueInstant="%s">
			<Assertion ID="%s" IssueInstant="%s">
				<Issuer>https://idp.adversarial.corp</Issuer>
				<Subject>
					<NameID>saml.user@corp.com</NameID>
				</Subject>
				<Conditions NotBefore="%s" NotOnOrAfter="%s">
					<AudienceRestriction>
						<Audience>%s</Audience>
					</AudienceRestriction>
				</Conditions>
				<AttributeStatement>
					<Attribute Name="email">
						<AttributeValue>saml.user@corp.com</AttributeValue>
					</Attribute>
					<Attribute Name="groups">
						<AttributeValue>%s</AttributeValue>
					</Attribute>
				</AttributeStatement>
				<Signature>
					%s
					<SignatureValue>%s</SignatureValue>
					<KeyInfo>
						<X509Data>
							<X509Certificate>%s</X509Certificate>
						</X509Data>
					</KeyInfo>
				</Signature>
			</Assertion>
		</Response>`,
			nowStr,
			assertionID,
			nowStr,
			notBefore,
			notOnOrAfter,
			audience,
			group,
			signedInfo,
			sigB64,
			certB64,
		)
	}

	validNB := time.Now().Add(-1 * time.Minute).Format(time.RFC3339)
	validNOA := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	validDigest := "dGVzdC1kaWdlc3Q="

	// 3.1 Legitimate SAML Assertion passes
	t.Run("LegitimateSAMLAssertion_Passes", func(t *testing.T) {
		validXML := makeSAMLPayload("assert-100", "#assert-100", validDigest, validNB, validNOA, spEntityID, "Engineering-Devs")
		claims, err := validator.ValidateSAMLAssertion(context.Background(), validXML)
		if err != nil {
			t.Fatalf("legitimate assertion failed: %v", err)
		}
		if claims.Subject != "saml.user@corp.com" {
			t.Errorf("subject mismatch: %s", claims.Subject)
		}
	})

	// 3.2 XML Signature Wrapping (XSW) Attack: Reference URI points to different assertion ID
	t.Run("XSW_ReferenceMismatch_Rejected", func(t *testing.T) {
		// Reference URI is #assert-original, but Assertion ID is assert-injected-malicious
		xswXML := makeSAMLPayload("assert-injected-malicious", "#assert-original", validDigest, validNB, validNOA, spEntityID, "Org-Admins")
		_, err := validator.ValidateSAMLAssertion(context.Background(), xswXML)
		if err == nil {
			t.Fatalf("SECURITY VIOLATION: XSW assertion with mismatched reference URI was accepted!")
		}
		if !strings.Contains(err.Error(), "does not match assertion id") {
			t.Errorf("expected reference mismatch error, got: %v", err)
		}
	})

	// 3.3 Altered Assertion ID in XML body after signing
	t.Run("AlteredAssertionID_Rejected", func(t *testing.T) {
		validXML := makeSAMLPayload("assert-100", "#assert-100", validDigest, validNB, validNOA, spEntityID, "Engineering-Devs")
		tamperedXML := strings.Replace(validXML, `Assertion ID="assert-100"`, `Assertion ID="assert-evil"`, 1)
		_, err := validator.ValidateSAMLAssertion(context.Background(), tamperedXML)
		if err == nil {
			t.Fatalf("SECURITY VIOLATION: altered assertion ID was accepted!")
		}
	})

	// 3.4 Tampered Digest Value in SignedInfo
	t.Run("TamperedDigest_Rejected", func(t *testing.T) {
		// Invalid base64 digest value
		badDigestXML := makeSAMLPayload("assert-100", "#assert-100", "not-base-64-digest!!!", validNB, validNOA, spEntityID, "Engineering-Devs")
		_, err := validator.ValidateSAMLAssertion(context.Background(), badDigestXML)
		if err != ErrSAMLInvalidDigest && err != ErrSAMLInvalidSig {
			t.Errorf("expected digest or signature failure, got: %v", err)
		}
	})

	// 3.5 Expired SAML Assertion (NotOnOrAfter in the past)
	t.Run("SAMLExpiredCondition_Rejected", func(t *testing.T) {
		pastNOA := time.Now().Add(-10 * time.Minute).Format(time.RFC3339) // expired past 2m skew
		expiredXML := makeSAMLPayload("assert-100", "#assert-100", validDigest, validNB, pastNOA, spEntityID, "Engineering-Devs")
		_, err := validator.ValidateSAMLAssertion(context.Background(), expiredXML)
		if err != ErrSAMLExpired {
			t.Errorf("expected ErrSAMLExpired, got: %v", err)
		}
	})

	// 3.6 Future SAML Assertion (NotBefore in the future)
	t.Run("SAMLNotYetValidCondition_Rejected", func(t *testing.T) {
		futureNB := time.Now().Add(10 * time.Minute).Format(time.RFC3339) // not valid for 10m (skew is 2m)
		futureXML := makeSAMLPayload("assert-100", "#assert-100", validDigest, futureNB, validNOA, spEntityID, "Engineering-Devs")
		_, err := validator.ValidateSAMLAssertion(context.Background(), futureXML)
		if err != ErrSAMLNotYetValid {
			t.Errorf("expected ErrSAMLNotYetValid, got: %v", err)
		}
	})

	// 3.7 Audience Mismatch
	t.Run("AudienceMismatch_Rejected", func(t *testing.T) {
		wrongAudienceXML := makeSAMLPayload("assert-100", "#assert-100", validDigest, validNB, validNOA, "https://wrong.audience.com/sp", "Engineering-Devs")
		_, err := validator.ValidateSAMLAssertion(context.Background(), wrongAudienceXML)
		if err != ErrInvalidAudience {
			t.Errorf("expected ErrInvalidAudience, got: %v", err)
		}
	})

	// 3.8 Base64 Encoded SAML Assertion Handling
	t.Run("Base64EncodedSAML_PassesAndRejects", func(t *testing.T) {
		validXML := makeSAMLPayload("assert-b64", "#assert-b64", validDigest, validNB, validNOA, spEntityID, "Engineering-Devs")
		b64Payload := base64.StdEncoding.EncodeToString([]byte(validXML))

		claims, err := validator.ValidateSAMLAssertion(context.Background(), b64Payload)
		if err != nil {
			t.Fatalf("failed to parse valid base64 SAML payload: %v", err)
		}
		if claims.Subject != "saml.user@corp.com" {
			t.Errorf("claims mismatch: %s", claims.Subject)
		}
	})
}

// ----------------------------------------------------------------------------
// Challenge 4: Concurrency & Race Conditions (500-1000 Goroutines)
// ----------------------------------------------------------------------------
func TestAdversarial_Concurrency_JITProvisioning_1000Goroutines(t *testing.T) {
	store := NewMemoryUserStore()
	jit := NewJITEngine(store, "both")

	const numGoroutines = 1000

	// 4.1 Swarm Attack: 1000 concurrent logins for the EXACT SAME user
	// Must result in EXACTLY 1 user record in store, zero duplicate collisions, zero races
	t.Run("ConcurrentLogins_SameUser_ZeroDuplicates", func(t *testing.T) {
		claims := &IdentityClaims{
			Subject: "concurrency-swarm-target",
			Email:   "swarm.target@enterprise.corp",
			Name:    "Swarm Target",
			Groups:  []string{"Engineering-Devs"},
		}

		var wg sync.WaitGroup
		var successCount atomic.Int64
		var errCount atomic.Int64

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(iteration int) {
				defer wg.Done()
				user, err := jit.ProvisionUser(context.Background(), claims, RoleDeveloper)
				if err != nil {
					errCount.Add(1)
					t.Errorf("provisioning failed in goroutine %d: %v", iteration, err)
					return
				}
				if user == nil || user.ID != "concurrency-swarm-target" {
					errCount.Add(1)
					t.Errorf("invalid user returned in goroutine %d", iteration)
					return
				}
				successCount.Add(1)
			}(i)
		}
		wg.Wait()

		if successCount.Load() != numGoroutines {
			t.Fatalf("expected %d successful provisions, got %d (errors: %d)", numGoroutines, successCount.Load(), errCount.Load())
		}

		// Verify store state: must have exactly 1 unique user
		users, err := store.ListUsers(context.Background())
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("CONCURRENCY FAILURE: expected exactly 1 user in store, found %d! Duplicate user creation occurred!", len(users))
		}
		if users[0].ID != "concurrency-swarm-target" || users[0].Email != "swarm.target@enterprise.corp" {
			t.Errorf("user attributes corrupted under concurrency: %+v", users[0])
		}
	})

	// 4.2 Swarm Attack: 500 concurrent logins for 500 DISTINCT users
	// Must result in EXACTLY 500 unique users provisioned, zero dropped, zero races
	t.Run("ConcurrentLogins_DistinctUsers_AllCreated", func(t *testing.T) {
		storeDistinct := NewMemoryUserStore()
		jitDistinct := NewJITEngine(storeDistinct, "both")

		const distinctCount = 500
		var wg sync.WaitGroup
		var successCount atomic.Int64

		wg.Add(distinctCount)
		for i := 0; i < distinctCount; i++ {
			go func(id int) {
				defer wg.Done()
				c := &IdentityClaims{
					Subject: fmt.Sprintf("distinct-user-%04d", id),
					Email:   fmt.Sprintf("user-%04d@enterprise.corp", id),
					Name:    fmt.Sprintf("User %04d", id),
					Groups:  []string{"Engineering-Devs"},
				}
				user, err := jitDistinct.ProvisionUser(context.Background(), c, RoleDeveloper)
				if err != nil || user == nil {
					t.Errorf("failed distinct provisioning for %d: %v", id, err)
					return
				}
				successCount.Add(1)
			}(i)
		}
		wg.Wait()

		if successCount.Load() != distinctCount {
			t.Fatalf("expected %d provisions, got %d", distinctCount, successCount.Load())
		}

		users, err := storeDistinct.ListUsers(context.Background())
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}
		if len(users) != distinctCount {
			t.Fatalf("expected %d distinct users in store, got %d", distinctCount, len(users))
		}
	})

	// 4.3 Concurrent Claim Reconciliation & Role Updates
	t.Run("ConcurrentRoleReconciliation", func(t *testing.T) {
		storeRecon := NewMemoryUserStore()
		jitRecon := NewJITEngine(storeRecon, "both")

		initialClaims := &IdentityClaims{
			Subject: "recon-user",
			Email:   "recon@corp.com",
			Name:    "Recon User",
		}
		_, err := jitRecon.ProvisionUser(context.Background(), initialClaims, RoleDeveloper)
		if err != nil {
			t.Fatalf("initial provision failed: %v", err)
		}

		const reconGoroutines = 500
		var wg sync.WaitGroup
		wg.Add(reconGoroutines)

		for i := 0; i < reconGoroutines; i++ {
			go func(iter int) {
				defer wg.Done()
				// Half update to Admin, half omit role
				if iter%2 == 0 {
					c := &IdentityClaims{Subject: "recon-user", Email: "recon@corp.com", Groups: []string{"Org-Admins"}}
					_, _ = jitRecon.ProvisionUser(context.Background(), c, RoleAdmin)
				} else {
					c := &IdentityClaims{Subject: "recon-user", Email: "recon@corp.com"}
					_, _ = jitRecon.ProvisionUser(context.Background(), c, "") // omitted role
				}
			}(i)
		}
		wg.Wait()

		// User must still be valid and active
		u, err := storeRecon.GetUser(context.Background(), "recon-user")
		if err != nil || u == nil {
			t.Fatalf("user lost during concurrent updates: %v", err)
		}
		if u.Role != RoleAdmin && u.Role != RoleDeveloper {
			t.Errorf("corrupted role state: %s", u.Role)
		}
	})

	// 4.4 Mixed Swarm: Concurrent returning user updates interleaved with concurrent new user creations
	// Demonstrates the shared state read/write collision between store.GetUser/CreateUser and in-place existing mutation
	t.Run("ConcurrentMixedReturningAndNewUsers_RaceDetection", func(t *testing.T) {
		storeMixed := NewMemoryUserStore()
		jitMixed := NewJITEngine(storeMixed, "both")

		// Create base user first
		baseUser := &IdentityClaims{
			Subject: "target-returning-user",
			Email:   "returning@enterprise.corp",
			Name:    "Returning User",
			Groups:  []string{"Engineering-Devs"},
		}
		_, err := jitMixed.ProvisionUser(context.Background(), baseUser, RoleDeveloper)
		if err != nil {
			t.Fatalf("initial provision failed: %v", err)
		}

		const mixedCount = 400
		var wg sync.WaitGroup
		wg.Add(mixedCount)

		for i := 0; i < mixedCount; i++ {
			go func(iter int) {
				defer wg.Done()
				if iter%2 == 0 {
					// Returning user login: mutates existing.Email, existing.LastLoginAt, etc.
					c := &IdentityClaims{
						Subject: "target-returning-user",
						Email:   fmt.Sprintf("returning-%d@enterprise.corp", iter%10),
						Groups:  []string{"Org-Admins"},
					}
					_, _ = jitMixed.ProvisionUser(context.Background(), c, RoleAdmin)
				} else {
					// New user login: iterates over store.users in GetUser and CreateUser
					c := &IdentityClaims{
						Subject: fmt.Sprintf("mixed-new-user-%04d", iter),
						Email:   fmt.Sprintf("new-%04d@enterprise.corp", iter),
						Groups:  []string{"Engineering-Devs"},
					}
					_, _ = jitMixed.ProvisionUser(context.Background(), c, RoleDeveloper)
				}
			}(i)
		}
		wg.Wait()
	})
}

// ----------------------------------------------------------------------------
// Challenge 4.4: JWKS Cache Stampede under 500 Goroutines
// ----------------------------------------------------------------------------
func TestAdversarial_JWKSCache_StampedeAndKeyRotation_500Goroutines(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nB64 := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
	eBytes := big.NewInt(int64(rsaKey.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	var httpFetchCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpFetchCount.Add(1)
		time.Sleep(20 * time.Millisecond) // Simulate slow IdP JWKS endpoint
		resp := JWKSResponse{
			Keys: []JWK{
				{Kty: "RSA", Kid: "swarm-kid", Alg: "RS256", N: nB64, E: eB64},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, server.Client(), 1*time.Hour)
	defer cache.Close()

	const numGoroutines = 500
	var wg sync.WaitGroup
	var successCount atomic.Int64

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			key, err := cache.GetKey(context.Background(), "swarm-kid")
			if err == nil && key != nil {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if successCount.Load() != numGoroutines {
		t.Fatalf("expected %d successful key fetches under singleflight, got %d", numGoroutines, successCount.Load())
	}

	// Singleflight must coalesce the concurrent storm to at most 1 (or 2 if timing split) HTTP backend hits
	fetches := httpFetchCount.Load()
	if fetches > 3 {
		t.Fatalf("CACHE STAMPEDE FAILURE: expected <= 3 backend fetches, got %d under 500 goroutines", fetches)
	}
}

// ----------------------------------------------------------------------------
// Challenge 5: Strict Role Enforcement (100% Rejection of Unmapped Groups)
// ----------------------------------------------------------------------------
func TestAdversarial_StrictRoleEnforcement_100PercentRejection(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewJWKSCache("", nil, time.Hour)
	cache.AddKey("k-rbac", &rsaKey.PublicKey)

	validator := NewOIDCValidatorWithCache(OIDCConfig{}, cache)
	mapper := NewRoleMapper([]AttributeRoleMapping{
		{Attribute: "groups", Value: "Security-Auditors", Role: RoleSecurityAuditor},
		{Attribute: "groups", Value: "Engineering-Devs", Role: RoleDeveloper},
		{Attribute: "groups", Value: "Org-Admins", Role: RoleAdmin},
	}, StrategyHighestPermissionCount)
	store := NewMemoryUserStore()
	jit := NewJITEngine(store, "both")

	enforcer := NewSSOEnforcer(validator, mapper, jit)

	// 5.1 Test a variety of unmapped and adversarial group combinations
	adversarialGroupSets := [][]string{
		{"External-Contractors"},
		{"Guests", "Anonymous"},
		{"Hacker-Role", "Root", "Wheel"},
		{},
		{"admin"},      // not Org-Admins
		{"developers"}, // not Engineering-Devs
		{"sec-audit"},  // not Security-Auditors
		{"*.*.*"},      // not wildcards unless explicitly configured
		{"Org-Admins-Fake"},
	}

	for idx, groups := range adversarialGroupSets {
		t.Run(fmt.Sprintf("AdversarialGroupSet_%d", idx), func(t *testing.T) {
			token := makeAdversarialRSAToken(t, rsaKey, "k-rbac", "RS256", map[string]interface{}{
				"sub":    fmt.Sprintf("unmapped-user-%d", idx),
				"email":  fmt.Sprintf("user-%d@unauthorized.com", idx),
				"groups": groups,
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
			})

			user, role, err := enforcer.AuthenticateToken(context.Background(), token)
			if err != ErrUnmappedRole {
				t.Fatalf("SECURITY VIOLATION: unmapped groups %+v did not return ErrUnmappedRole! err=%v, role=%s", groups, err, role)
			}
			if user != nil || role != "" {
				t.Fatalf("SECURITY VIOLATION: user or role created for unmapped groups: user=%+v, role=%s", user, role)
			}
		})
	}

	// 5.2 Verify that NO user accounts were provisioned in store for rejected attempts
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users failed: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("SECURITY VIOLATION: %d unauthorized users were provisioned in store after rejection!", len(users))
	}

	// 5.3 Pre-existing user whose group changes to unmapped must be rejected and denied
	t.Run("RevokedGroupMembership_Rejection", func(t *testing.T) {
		// 1. Initially provisioned with valid group
		validToken := makeAdversarialRSAToken(t, rsaKey, "k-rbac", "RS256", map[string]interface{}{
			"sub":    "former-developer",
			"email":  "former.dev@corp.com",
			"groups": []string{"Engineering-Devs"},
			"exp":    time.Now().Add(10 * time.Minute).Unix(),
		})
		user, role, err := enforcer.AuthenticateToken(context.Background(), validToken)
		if err != nil || user == nil || role != RoleDeveloper {
			t.Fatalf("initial provisioning failed: %v", err)
		}

		// 2. Subsequent login with removed/unmapped group
		revokedToken := makeAdversarialRSAToken(t, rsaKey, "k-rbac", "RS256", map[string]interface{}{
			"sub":    "former-developer",
			"email":  "former.dev@corp.com",
			"groups": []string{"Terminated-Contractors"}, // No longer valid
			"exp":    time.Now().Add(10 * time.Minute).Unix(),
		})
		_, _, err = enforcer.AuthenticateToken(context.Background(), revokedToken)
		if err != ErrUnmappedRole {
			t.Fatalf("SECURITY VIOLATION: revoked user with unmapped groups was not rejected with ErrUnmappedRole: %v", err)
		}
	})
}
