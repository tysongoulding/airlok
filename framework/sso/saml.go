package sso

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SAMLConfig configures the SAML 2.0 assertion validator.
type SAMLConfig struct {
	SPEntityID         string            // Expected Audience (SP Entity ID)
	IdPCertificate     *x509.Certificate // Pre-configured IdP signing certificate
	ClockSkewTolerance time.Duration     // Allowed clock skew tolerance (default 5m)
}

// SAMLResponseXML represents the root SAML Response XML document.
type SAMLResponseXML struct {
	XMLName      xml.Name          `xml:"Response"`
	ID           string            `xml:"ID,attr"`
	IssueInstant string            `xml:"IssueInstant,attr"`
	Status       SAMLStatusXML     `xml:"Status"`
	Assertion    SAMLAssertionXML  `xml:"Assertion"`
	Signature    *SAMLSignatureXML `xml:"Signature"`
}

// SAMLStatusXML represents the SAML response status.
type SAMLStatusXML struct {
	StatusCode SAMLStatusCodeXML `xml:"StatusCode"`
}

// SAMLStatusCodeXML represents the status code attribute.
type SAMLStatusCodeXML struct {
	Value string `xml:"Value,attr"`
}

// SAMLAssertionXML represents the core SAML 2.0 assertion.
type SAMLAssertionXML struct {
	XMLName            xml.Name                  `xml:"Assertion"`
	ID                 string                    `xml:"ID,attr"`
	IssueInstant       string                    `xml:"IssueInstant,attr"`
	Issuer             string                    `xml:"Issuer"`
	Subject            SAMLSubjectXML            `xml:"Subject"`
	Conditions         SAMLConditionsXML         `xml:"Conditions"`
	AttributeStatement SAMLAttributeStatementXML `xml:"AttributeStatement"`
	Signature          *SAMLSignatureXML         `xml:"Signature"`
}

// SAMLSubjectXML represents the SAML subject.
type SAMLSubjectXML struct {
	NameID string `xml:"NameID"`
}

// SAMLConditionsXML represents timing conditions and audience restrictions.
type SAMLConditionsXML struct {
	NotBefore           string                     `xml:"NotBefore,attr"`
	NotOnOrAfter        string                     `xml:"NotOnOrAfter,attr"`
	AudienceRestriction SAMLAudienceRestrictionXML `xml:"AudienceRestriction"`
}

// SAMLAudienceRestrictionXML represents allowed audience URIs.
type SAMLAudienceRestrictionXML struct {
	Audience []string `xml:"Audience"`
}

// SAMLAttributeStatementXML represents identity attributes.
type SAMLAttributeStatementXML struct {
	Attributes []SAMLAttributeXML `xml:"Attribute"`
}

// SAMLAttributeXML represents a single named attribute.
type SAMLAttributeXML struct {
	Name         string   `xml:"Name,attr"`
	FriendlyName string   `xml:"FriendlyName,attr"`
	Values       []string `xml:"AttributeValue"`
}

// SAMLSignatureXML represents the ds:Signature envelope.
type SAMLSignatureXML struct {
	SignedInfo     SAMLSignedInfoXML `xml:"SignedInfo"`
	SignatureValue string            `xml:"SignatureValue"`
	KeyInfo        SAMLKeyInfoXML    `xml:"KeyInfo"`
}

// SAMLSignedInfoXML represents the signed metadata.
type SAMLSignedInfoXML struct {
	CanonicalizationMethod SAMLAlgorithmXML `xml:"CanonicalizationMethod"`
	SignatureMethod        SAMLAlgorithmXML `xml:"SignatureMethod"`
	Reference              SAMLReferenceXML `xml:"Reference"`
}

// SAMLAlgorithmXML represents algorithm identifiers.
type SAMLAlgorithmXML struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLReferenceXML represents the signed assertion reference.
type SAMLReferenceXML struct {
	URI          string           `xml:"URI,attr"`
	DigestMethod SAMLAlgorithmXML `xml:"DigestMethod"`
	DigestValue  string           `xml:"DigestValue"`
}

// SAMLKeyInfoXML represents KeyInfo wrapper.
type SAMLKeyInfoXML struct {
	X509Data SAMLX509DataXML `xml:"X509Data"`
}

// SAMLX509DataXML represents the X.509 certificate payload.
type SAMLX509DataXML struct {
	X509Certificate string `xml:"X509Certificate"`
}

// SAMLValidator validates SAML 2.0 assertions.
type SAMLValidator struct {
	config SAMLConfig
}

// NewSAMLValidator creates a new SAMLValidator.
func NewSAMLValidator(cfg SAMLConfig) *SAMLValidator {
	if cfg.ClockSkewTolerance <= 0 {
		cfg.ClockSkewTolerance = 5 * time.Minute
	}
	return &SAMLValidator{config: cfg}
}

// ValidateSAMLAssertion validates a raw or Base64-encoded SAML Response / Assertion.
func (v *SAMLValidator) ValidateSAMLAssertion(ctx context.Context, rawPayload string) (*IdentityClaims, error) {
	rawPayload = strings.TrimSpace(rawPayload)
	if rawPayload == "" {
		return nil, fmt.Errorf("empty saml payload")
	}

	xmlData := []byte(rawPayload)
	if decoded, err := base64.StdEncoding.DecodeString(rawPayload); err == nil {
		xmlData = decoded
	}

	// 1. Unmarshal XML response or assertion
	var resp SAMLResponseXML
	if err := xml.Unmarshal(xmlData, &resp); err != nil {
		var assertion SAMLAssertionXML
		if err2 := xml.Unmarshal(xmlData, &assertion); err2 != nil {
			return nil, fmt.Errorf("failed to parse SAML XML: %w", err)
		}
		resp.Assertion = assertion
	}

	assertion := resp.Assertion
	if assertion.ID == "" && resp.ID != "" {
		// Response without separate assertion container
		assertion.ID = resp.ID
	}
	if assertion.ID == "" {
		return nil, fmt.Errorf("missing SAML assertion in payload")
	}

	// 2. Validate timing conditions
	now := time.Now()
	skew := v.config.ClockSkewTolerance

	if assertion.Conditions.NotBefore != "" {
		if nb, err := parseSAMLTime(assertion.Conditions.NotBefore); err == nil {
			if now.Add(skew).Before(nb) {
				return nil, ErrSAMLNotYetValid
			}
		}
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		if noa, err := parseSAMLTime(assertion.Conditions.NotOnOrAfter); err == nil {
			if now.Add(-skew).After(noa) {
				return nil, ErrSAMLExpired
			}
		}
	}

	// 3. Validate Audience Restriction
	if v.config.SPEntityID != "" && len(assertion.Conditions.AudienceRestriction.Audience) > 0 {
		matched := false
		for _, aud := range assertion.Conditions.AudienceRestriction.Audience {
			if aud == v.config.SPEntityID {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrInvalidAudience
		}
	}

	// 4. Verify Signature (Mandatory)
	sig := assertion.Signature
	if sig == nil {
		sig = resp.Signature
	}
	if sig == nil {
		return nil, ErrSAMLInvalidSig
	}
	if err := v.verifySignature(sig, xmlData, assertion.ID); err != nil {
		return nil, err
	}

	// 5. Extract Identity Claims
	claims := &IdentityClaims{
		Subject:   assertion.Subject.NameID,
		Issuer:    assertion.Issuer,
		Groups:    make([]string, 0),
		Roles:     make([]string, 0),
		Audience:  assertion.Conditions.AudienceRestriction.Audience,
		RawClaims: make(map[string]interface{}),
	}

	if assertion.Conditions.NotOnOrAfter != "" {
		if t, err := parseSAMLTime(assertion.Conditions.NotOnOrAfter); err == nil {
			claims.ExpiresAt = t.Unix()
		}
	}

	for _, attr := range assertion.AttributeStatement.Attributes {
		name := strings.ToLower(attr.Name)
		friendly := strings.ToLower(attr.FriendlyName)

		switch {
		case name == "email" || name == "mail" || friendly == "email" ||
			strings.HasSuffix(name, "/emailaddress") || strings.HasSuffix(name, "/claims/email"):
			if len(attr.Values) > 0 && claims.Email == "" {
				claims.Email = attr.Values[0]
			}
		case name == "name" || name == "displayname" || friendly == "displayname" ||
			strings.HasSuffix(name, "/displayname") || strings.HasSuffix(name, "/claims/name"):
			if len(attr.Values) > 0 && claims.Name == "" {
				claims.Name = attr.Values[0]
			}
		case name == "groups" || name == "memberof" || friendly == "groups" ||
			strings.HasSuffix(name, "/groups") || strings.HasSuffix(name, "/claims/groups"):
			claims.Groups = append(claims.Groups, attr.Values...)
		case name == "roles" || name == "role" || friendly == "roles" ||
			strings.HasSuffix(name, "/role") || strings.HasSuffix(name, "/claims/role"):
			claims.Roles = append(claims.Roles, attr.Values...)
		}

		if len(attr.Values) == 1 {
			claims.RawClaims[attr.Name] = attr.Values[0]
		} else {
			claims.RawClaims[attr.Name] = attr.Values
		}
	}

	if claims.Email == "" && strings.Contains(claims.Subject, "@") {
		claims.Email = claims.Subject
	}

	return claims, nil
}

// ValidateToken delegator for SSOProvider interface compliance.
func (v *SAMLValidator) ValidateToken(ctx context.Context, rawToken string) (*IdentityClaims, error) {
	return nil, fmt.Errorf("jwt token validation not supported by saml validator")
}

func (v *SAMLValidator) verifySignature(sig *SAMLSignatureXML, rawXML []byte, expectedAssertionID string) error {
	// XSW protection: Reference URI must target the expected assertion ID
	if sig.SignedInfo.Reference.URI != "" {
		ref := strings.TrimPrefix(sig.SignedInfo.Reference.URI, "#")
		if ref != "" && ref != expectedAssertionID {
			return fmt.Errorf("signature reference %q does not match assertion id %q", ref, expectedAssertionID)
		}
	}

	var pubKey *rsa.PublicKey
	if v.config.IdPCertificate != nil {
		if rsaK, ok := v.config.IdPCertificate.PublicKey.(*rsa.PublicKey); ok {
			pubKey = rsaK
		}
	} else if sig.KeyInfo.X509Data.X509Certificate != "" {
		certClean := strings.ReplaceAll(sig.KeyInfo.X509Data.X509Certificate, "\n", "")
		certClean = strings.ReplaceAll(certClean, " ", "")
		certDER, err := base64.StdEncoding.DecodeString(certClean)
		if err != nil {
			return ErrSAMLInvalidSig
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return ErrSAMLInvalidSig
		}
		if rsaK, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			pubKey = rsaK
		}
	}

	if pubKey == nil {
		return ErrSAMLInvalidSig
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.SignatureValue))
	if err != nil {
		return ErrSAMLInvalidSig
	}

	// 1. Decode expected DigestValue from Reference
	expectedDigestVal := strings.TrimSpace(sig.SignedInfo.Reference.DigestValue)
	if expectedDigestVal == "" {
		return ErrSAMLInvalidDigest
	}
	expectedDigestBytes, err := base64.StdEncoding.DecodeString(expectedDigestVal)
	if err != nil {
		return ErrSAMLInvalidDigest
	}

	// 2. Extract target Assertion XML element
	targetAssertionXML, err := extractAssertionXML(rawXML, expectedAssertionID)
	if err != nil {
		return fmt.Errorf("failed to extract assertion xml for id %q: %w", expectedAssertionID, ErrSAMLInvalidDigest)
	}

	// 3. Strip enveloped <Signature> if present
	strippedAssertion := stripEnvelopedSignature(targetAssertionXML)

	// 4. Verify Digest of the Assertion XML body
	digestAlgo := strings.ToLower(sig.SignedInfo.Reference.DigestMethod.Algorithm)
	if strings.Contains(digestAlgo, "sha1") {
		h := sha1.Sum(strippedAssertion)
		hNorm := sha1.Sum(normalizeXMLWhitespace(strippedAssertion))
		if !bytes.Equal(h[:], expectedDigestBytes) && !bytes.Equal(hNorm[:], expectedDigestBytes) {
			return ErrSAMLInvalidDigest
		}
	} else {
		// Default: SHA256
		h := sha256.Sum256(strippedAssertion)
		hNorm := sha256.Sum256(normalizeXMLWhitespace(strippedAssertion))
		if !bytes.Equal(h[:], expectedDigestBytes) && !bytes.Equal(hNorm[:], expectedDigestBytes) {
			return ErrSAMLInvalidDigest
		}
	}

	// 5. Extract <SignedInfo> XML element
	signedInfoXML, err := extractSignedInfoXML(rawXML)
	if err != nil {
		return fmt.Errorf("failed to extract signedinfo xml: %w", ErrSAMLInvalidSig)
	}

	// 6. Verify RSA Signature over the <SignedInfo> element
	sigAlgo := strings.ToLower(sig.SignedInfo.SignatureMethod.Algorithm)
	if strings.Contains(sigAlgo, "sha1") {
		hSI := sha1.Sum(signedInfoXML)
		hSINorm := sha1.Sum(normalizeXMLWhitespace(signedInfoXML))
		if rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hSI[:], sigBytes) != nil &&
			rsa.VerifyPKCS1v15(pubKey, 0, hSI[:], sigBytes) != nil &&
			rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hSINorm[:], sigBytes) != nil &&
			rsa.VerifyPKCS1v15(pubKey, 0, hSINorm[:], sigBytes) != nil {
			return ErrSAMLInvalidSig
		}
	} else {
		// Default: SHA256
		hSI := sha256.Sum256(signedInfoXML)
		hSINorm := sha256.Sum256(normalizeXMLWhitespace(signedInfoXML))
		if rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hSI[:], sigBytes) != nil &&
			rsa.VerifyPKCS1v15(pubKey, 0, hSI[:], sigBytes) != nil &&
			rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hSINorm[:], sigBytes) != nil &&
			rsa.VerifyPKCS1v15(pubKey, 0, hSINorm[:], sigBytes) != nil {
			return ErrSAMLInvalidSig
		}
	}

	return nil
}

// extractAssertionXML extracts the target Assertion XML element matching assertionID.
func extractAssertionXML(rawXML []byte, assertionID string) ([]byte, error) {
	idPatterns := []string{fmt.Sprintf(`ID="%s"`, assertionID), fmt.Sprintf(`ID='%s'`, assertionID)}
	var idIdx int = -1
	for _, p := range idPatterns {
		if idx := bytes.Index(rawXML, []byte(p)); idx != -1 {
			idIdx = idx
			break
		}
	}
	if idIdx == -1 {
		return nil, fmt.Errorf("assertion ID %q not found", assertionID)
	}

	start := bytes.LastIndex(rawXML[:idIdx], []byte("<"))
	if start == -1 {
		return nil, fmt.Errorf("malformed xml tag before assertion ID %q", assertionID)
	}

	tagContent := rawXML[start+1 : idIdx]
	spaceIdx := bytes.IndexAny(tagContent, " \t\r\n")
	var tagName string
	if spaceIdx != -1 {
		tagName = string(tagContent[:spaceIdx])
	} else {
		tagName = string(tagContent)
	}

	closeTag := []byte("</" + tagName + ">")
	closeIdx := bytes.Index(rawXML[idIdx:], closeTag)
	if closeIdx == -1 {
		return nil, fmt.Errorf("closing tag %s not found", string(closeTag))
	}
	end := idIdx + closeIdx + len(closeTag)

	return rawXML[start:end], nil
}

// stripEnvelopedSignature removes the enveloped <Signature> element from an Assertion XML block.
func stripEnvelopedSignature(elementXML []byte) []byte {
	sigPatterns := [][]byte{[]byte("<Signature"), []byte("<ds:Signature"), []byte("<dsig:Signature")}
	var sigStart int = -1
	var closeTag []byte
	for _, pat := range sigPatterns {
		if idx := bytes.Index(elementXML, pat); idx != -1 {
			sigStart = idx
			closeTag = []byte("</" + string(pat[1:]) + ">")
			break
		}
	}
	if sigStart == -1 {
		return elementXML
	}

	closeIdx := bytes.Index(elementXML[sigStart:], closeTag)
	if closeIdx == -1 {
		return elementXML
	}
	sigEnd := sigStart + closeIdx + len(closeTag)

	result := make([]byte, 0, len(elementXML)-(sigEnd-sigStart))
	result = append(result, elementXML[:sigStart]...)
	result = append(result, elementXML[sigEnd:]...)
	return result
}

// extractSignedInfoXML extracts the <SignedInfo> element from XML data.
func extractSignedInfoXML(rawXML []byte) ([]byte, error) {
	patterns := [][]byte{[]byte("<SignedInfo"), []byte("<ds:SignedInfo"), []byte("<dsig:SignedInfo")}
	var start int = -1
	var closeTag []byte
	for _, pat := range patterns {
		if idx := bytes.Index(rawXML, pat); idx != -1 {
			start = idx
			closeTag = []byte("</" + string(pat[1:]) + ">")
			break
		}
	}
	if start == -1 {
		return nil, fmt.Errorf("SignedInfo tag not found")
	}

	closeIdx := bytes.Index(rawXML[start:], closeTag)
	if closeIdx == -1 {
		return nil, fmt.Errorf("closing tag %s not found", string(closeTag))
	}
	end := start + closeIdx + len(closeTag)
	return rawXML[start:end], nil
}

// normalizeXMLWhitespace strips formatting whitespace between tags.
func normalizeXMLWhitespace(input []byte) []byte {
	re := regexp.MustCompile(`>\s+<`)
	return bytes.TrimSpace(re.ReplaceAll(input, []byte("><")))
}

func parseSAMLTime(tStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999Z",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, tStr); err == nil {
			return t, nil
		}
	}
	return time.Parse(time.RFC3339, tStr)
}
