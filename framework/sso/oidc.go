package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// OIDCConfig configures the OIDC JWT validator.
type OIDCConfig struct {
	IssuerURL          string
	ClientID           string
	Audience           string
	JWKSURI            string
	ClockSkewTolerance time.Duration
	KeyRefreshInterval time.Duration
	TeamIdsField       string // default: "groups"
	RolesField         string // default: "roles"
	HTTPClient         *http.Client
}

// OIDCValidator implements OIDC JWT token validation against JWKS public keys.
type OIDCValidator struct {
	config    OIDCConfig
	jwksCache *JWKSCache
}

// NewOIDCValidator creates a new OIDCValidator from configuration.
func NewOIDCValidator(cfg OIDCConfig) *OIDCValidator {
	if cfg.ClockSkewTolerance <= 0 {
		cfg.ClockSkewTolerance = 60 * time.Second
	}
	if cfg.TeamIdsField == "" {
		cfg.TeamIdsField = "groups"
	}
	if cfg.RolesField == "" {
		cfg.RolesField = "roles"
	}

	jwksCache := NewJWKSCache(cfg.JWKSURI, cfg.HTTPClient, cfg.KeyRefreshInterval)
	return &OIDCValidator{
		config:    cfg,
		jwksCache: jwksCache,
	}
}

// NewOIDCValidatorWithCache creates an OIDCValidator reusing an existing JWKSCache.
func NewOIDCValidatorWithCache(cfg OIDCConfig, cache *JWKSCache) *OIDCValidator {
	if cfg.ClockSkewTolerance <= 0 {
		cfg.ClockSkewTolerance = 60 * time.Second
	}
	if cfg.TeamIdsField == "" {
		cfg.TeamIdsField = "groups"
	}
	if cfg.RolesField == "" {
		cfg.RolesField = "roles"
	}
	return &OIDCValidator{
		config:    cfg,
		jwksCache: cache,
	}
}

// JWKSCache returns the underlying JWKS cache instance.
func (v *OIDCValidator) JWKSCache() *JWKSCache {
	return v.jwksCache
}

// ValidateToken verifies the authenticity, signature, expiration, and claims of a JWT bearer token.
func (v *OIDCValidator) ValidateToken(ctx context.Context, rawToken string) (*IdentityClaims, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, ErrMalformedToken
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	// 1. Decode and parse Header
	headerBytes, err := decodeBase64Segment(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedToken
	}

	alg := strings.ToUpper(header.Alg)
	if alg == "" {
		alg = "RS256"
	}

	// 2. Resolve Public Key from JWKS cache
	pubKey, err := v.jwksCache.GetKey(ctx, header.Kid)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	// 3. Verify Signature
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := decodeBase64Segment(parts[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}

	if err := verifySignature(pubKey, alg, []byte(signingInput), sigBytes); err != nil {
		return nil, ErrInvalidSignature
	}

	// 4. Decode Payload and Claims
	payloadBytes, err := decodeBase64Segment(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &rawMap); err != nil {
		return nil, ErrMalformedToken
	}

	claims := parseIdentityClaims(rawMap, v.config.TeamIdsField, v.config.RolesField)
	claims.RawClaims = rawMap

	// 5. Expiration and Timing Validation (Mandatory exp)
	now := time.Now().Unix()
	skew := int64(v.config.ClockSkewTolerance.Seconds())
	if claims.ExpiresAt <= 0 || now > (claims.ExpiresAt+skew) {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now < (claims.NotBefore-skew) {
		return nil, ErrTokenExpired
	}

	// 6. Issuer Validation (Mandatory when IssuerURL is configured)
	if v.config.IssuerURL != "" {
		expectedIss := strings.TrimSuffix(v.config.IssuerURL, "/")
		actualIss := strings.TrimSuffix(claims.Issuer, "/")
		if actualIss == "" || actualIss != expectedIss {
			return nil, ErrInvalidIssuer
		}
	}

	// 7. Audience Validation (Mandatory when Audience or ClientID is configured)
	if v.config.Audience != "" || v.config.ClientID != "" {
		if len(claims.Audience) == 0 {
			return nil, ErrInvalidAudience
		}
		matched := false
		for _, aud := range claims.Audience {
			if (v.config.Audience != "" && aud == v.config.Audience) ||
				(v.config.ClientID != "" && aud == v.config.ClientID) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrInvalidAudience
		}
	}

	return claims, nil
}

// ValidateSAMLAssertion delegator for SSOProvider interface compliance.
func (v *OIDCValidator) ValidateSAMLAssertion(ctx context.Context, rawAssertion string) (*IdentityClaims, error) {
	return nil, fmt.Errorf("saml validation not supported by oidc validator")
}

func verifySignature(pubKey crypto.PublicKey, alg string, signingInput []byte, sigBytes []byte) error {
	switch alg {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sigBytes); err != nil {
			if err2 := rsa.VerifyPKCS1v15(rsaPub, 0, h[:], sigBytes); err2 != nil {
				return ErrInvalidSignature
			}
		}
		return nil
	case "RS384":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		h := sha512.Sum384(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, h[:], sigBytes); err != nil {
			if err2 := rsa.VerifyPKCS1v15(rsaPub, 0, h[:], sigBytes); err2 != nil {
				return ErrInvalidSignature
			}
		}
		return nil
	case "RS512":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		h := sha512.Sum512(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, h[:], sigBytes); err != nil {
			if err2 := rsa.VerifyPKCS1v15(rsaPub, 0, h[:], sigBytes); err2 != nil {
				return ErrInvalidSignature
			}
		}
		return nil
	case "ES256":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		h := sha256.Sum256(signingInput)
		// Try ASN.1 signature verification first
		if ecdsa.VerifyASN1(ecPub, h[:], sigBytes) {
			return nil
		}
		// Try IEEE P1363 raw (r || s) signature format
		if len(sigBytes) == 64 {
			r := new(big.Int).SetBytes(sigBytes[:32])
			s := new(big.Int).SetBytes(sigBytes[32:])
			if ecdsa.Verify(ecPub, h[:], r, s) {
				return nil
			}
		}
		return ErrInvalidSignature
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func decodeBase64Segment(seg string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err == nil {
		return b, nil
	}
	b, err = base64.URLEncoding.DecodeString(seg)
	if err == nil {
		return b, nil
	}
	b, err = base64.RawStdEncoding.DecodeString(seg)
	if err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(seg)
}

func parseIdentityClaims(raw map[string]interface{}, teamIdsField, rolesField string) *IdentityClaims {
	claims := &IdentityClaims{
		Groups:    make([]string, 0),
		Roles:     make([]string, 0),
		Audience:  make([]string, 0),
		RawClaims: raw,
	}

	if v, ok := raw["sub"].(string); ok {
		claims.Subject = v
	}
	if v, ok := raw["email"].(string); ok {
		claims.Email = v
	}
	if v, ok := raw["name"].(string); ok {
		claims.Name = v
	}
	if v, ok := raw["preferred_username"].(string); ok {
		claims.PreferredUsername = v
	}
	if v, ok := raw["iss"].(string); ok {
		claims.Issuer = v
	}

	claims.ExpiresAt = toInt64(raw["exp"])
	claims.NotBefore = toInt64(raw["nbf"])
	claims.IssuedAt = toInt64(raw["iat"])

	// Audience
	if audRaw, ok := raw["aud"]; ok {
		claims.Audience = toStringSlice(audRaw)
	}

	// Groups / Team IDs
	if groupsRaw, ok := raw["groups"]; ok {
		claims.Groups = append(claims.Groups, toStringSlice(groupsRaw)...)
	}
	if teamIdsField != "" && teamIdsField != "groups" {
		if customGroupsRaw, ok := raw[teamIdsField]; ok {
			claims.Groups = append(claims.Groups, toStringSlice(customGroupsRaw)...)
		}
	}

	// Roles
	if rolesRaw, ok := raw["roles"]; ok {
		claims.Roles = append(claims.Roles, toStringSlice(rolesRaw)...)
	}
	if rolesField != "" && rolesField != "roles" {
		if customRolesRaw, ok := raw[rolesField]; ok {
			claims.Roles = append(claims.Roles, toStringSlice(customRolesRaw)...)
		}
	}

	// Fallback email from subject if subject looks like an email
	if claims.Email == "" && strings.Contains(claims.Subject, "@") {
		claims.Email = claims.Subject
	}

	return claims
}

func toStringSlice(val interface{}) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	default:
		return nil
	}
}

func toInt64(val interface{}) int64 {
	switch v := val.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}
