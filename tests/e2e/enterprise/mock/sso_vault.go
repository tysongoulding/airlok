package mock

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// UserClaims models identity claims extracted from OIDC/SAML assertions.
type UserClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
	ExpiresAt         int64    `json:"exp"`
}

type AttributeRoleMapping struct {
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
	Role      string `json:"role"`
}

// MockSSOAdapter provides OIDC/SAML token verification and role mapping.
type MockSSOAdapter struct {
	mu           sync.RWMutex
	PrivateKey   *rsa.PrivateKey
	PublicKey    *rsa.PublicKey
	RoleMappings []AttributeRoleMapping
	Users        map[string]*UserClaims
}

func NewMockSSOAdapter() (*MockSSOAdapter, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA test key: %w", err)
	}

	adapter := &MockSSOAdapter{
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		RoleMappings: []AttributeRoleMapping{
			{Attribute: "groups", Value: "Security-Auditors", Role: "Security Auditor"},
			{Attribute: "groups", Value: "Engineering-Devs", Role: "Developer"},
			{Attribute: "groups", Value: "Infra-Operators", Role: "Operator"},
			{Attribute: "groups", Value: "Org-Admins", Role: "Admin"},
		},
		Users: make(map[string]*UserClaims),
	}
	return adapter, nil
}

// GenerateTestJWT signs a test token using RSA-SHA256.
func (sso *MockSSOAdapter) GenerateTestJWT(claims UserClaims, expired bool) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	if expired {
		claims.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	} else if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
	}

	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, payloadB64)
	hash := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, sso.PrivateKey, 0, hash[:])
	if err != nil {
		return "", err
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s", signingInput, sigB64), nil
}

// ValidateToken verifies token signature and expiration.
func (sso *MockSSOAdapter) ValidateToken(ctx context.Context, rawToken string) (*UserClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token: invalid segment count")
	}

	// Verify signature
	signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
	hash := sha256.Sum256([]byte(signingInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}

	if err := rsa.VerifyPKCS1v15(sso.PublicKey, 0, hash[:], sigBytes); err != nil {
		return nil, fmt.Errorf("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}

	var claims UserClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token has expired")
	}

	// JIT Provisioning
	sso.mu.Lock()
	sso.Users[claims.Subject] = &claims
	sso.mu.Unlock()

	return &claims, nil
}

// ResolveRole maps user groups to Bifrost roles.
func (sso *MockSSOAdapter) ResolveRole(claims *UserClaims) (string, error) {
	sso.mu.RLock()
	defer sso.mu.RUnlock()

	for _, mapping := range sso.RoleMappings {
		for _, userGroup := range claims.Groups {
			if mapping.Attribute == "groups" && mapping.Value == userGroup {
				return mapping.Role, nil
			}
		}
	}
	return "", fmt.Errorf("no matching role mapped for user groups")
}

// SCIMUser represents SCIM 2.0 user representation.
type SCIMUser struct {
	ID          string   `json:"id"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      bool     `json:"active"`
	Groups      []string `json:"groups"`
}

func (sso *MockSSOAdapter) ProvisionSCIMUser(user SCIMUser) error {
	sso.mu.Lock()
	defer sso.mu.Unlock()

	if _, exists := sso.Users[user.UserName]; exists {
		return fmt.Errorf("user already exists")
	}
	sso.Users[user.UserName] = &UserClaims{
		Subject:           user.ID,
		Email:             user.UserName,
		Name:              user.DisplayName,
		PreferredUsername: user.UserName,
		Groups:            user.Groups,
	}
	return nil
}

// --- R5: Secret Management & Vault Integration ---

type VaultSecret struct {
	Path     string
	Data     map[string]string
	Version  int
	CachedAt time.Time
}

// MockVaultRegistry handles secret resolution from multiple providers.
type MockVaultRegistry struct {
	mu           sync.RWMutex
	CacheTTL     time.Duration
	Store        map[string]*VaultSecret // path -> secret
	Cache        map[string]string       // ref -> resolved value
	BackendCalls int
}

func NewMockVaultRegistry(cacheTTL time.Duration) *MockVaultRegistry {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Hour
	}
	return &MockVaultRegistry{
		CacheTTL: cacheTTL,
		Store:    make(map[string]*VaultSecret),
		Cache:    make(map[string]string),
	}
}

func (v *MockVaultRegistry) PutSecret(path string, fields map[string]string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Store[path] = &VaultSecret{
		Path:    path,
		Data:    fields,
		Version: 1,
	}
}

// Resolve resolves vault.<path> or vault.<path>#<field>.
func (v *MockVaultRegistry) Resolve(ctx context.Context, secretRef string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if cached, ok := v.Cache[secretRef]; ok {
		return cached, nil
	}

	if !strings.HasPrefix(secretRef, "vault.") {
		return secretRef, nil
	}

	refBody := strings.TrimPrefix(secretRef, "vault.")
	var path, field string
	if strings.Contains(refBody, "#") {
		parts := strings.SplitN(refBody, "#", 2)
		path = parts[0]
		field = parts[1]
	} else {
		path = refBody
	}

	v.BackendCalls++
	secret, exists := v.Store[path]
	if !exists {
		return "", fmt.Errorf("secret not found in vault: %s", path)
	}

	var resolved string
	if field != "" {
		val, ok := secret.Data[field]
		if !ok {
			return "", fmt.Errorf("field %s not found in secret %s", field, path)
		}
		resolved = val
	} else {
		// Default field is "token" or "value" or first available
		if val, ok := secret.Data["token"]; ok {
			resolved = val
		} else if val, ok := secret.Data["value"]; ok {
			resolved = val
		} else {
			for _, val := range secret.Data {
				resolved = val
				break
			}
		}
	}

	v.Cache[secretRef] = resolved
	return resolved, nil
}

// FlushCache invalidates cached secrets immediately.
func (v *MockVaultRegistry) FlushCache() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Cache = make(map[string]string)
}
