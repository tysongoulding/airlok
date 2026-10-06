package sso

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token has expired")
	ErrInvalidSignature  = errors.New("invalid token signature")
	ErrMalformedToken    = errors.New("malformed token: invalid segment count")
	ErrUnmappedRole      = errors.New("no matching role mapped for user groups")
	ErrInvalidAudience   = errors.New("token audience does not match this resource")
	ErrInvalidIssuer     = errors.New("token issuer does not match configuration")
	ErrSAMLInvalidDigest = errors.New("saml assertion digest verification failed")
	ErrSAMLInvalidSig    = errors.New("saml assertion signature verification failed")
	ErrSAMLExpired       = errors.New("saml assertion has expired")
	ErrSAMLNotYetValid   = errors.New("saml assertion is not yet valid")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
)

// Standard System Roles
const (
	RoleAdmin           = "Admin"
	RoleDeveloper       = "Developer"
	RoleSecurityAuditor = "Security Auditor"
	RoleOperator        = "Operator"
)

// IdentityClaims models normalized identity attributes from OIDC JWTs or SAML Assertions.
type IdentityClaims struct {
	Subject           string                 `json:"sub"`
	Email             string                 `json:"email"`
	Name              string                 `json:"name"`
	PreferredUsername string                 `json:"preferred_username"`
	Groups            []string               `json:"groups"`
	Roles             []string               `json:"roles"`
	Issuer            string                 `json:"iss,omitempty"`
	Audience          []string               `json:"aud,omitempty"`
	ExpiresAt         int64                  `json:"exp"`
	NotBefore         int64                  `json:"nbf,omitempty"`
	IssuedAt          int64                  `json:"iat,omitempty"`
	RawClaims         map[string]interface{} `json:"raw_claims,omitempty"`
}

// AttributeRoleMapping maps an IdP attribute/claim value to a Bifrost role.
type AttributeRoleMapping struct {
	Attribute string `json:"attribute"` // "groups", "roles", or dot-path e.g. "realm_access.roles"
	Value     string `json:"value"`     // Case-insensitive match value or "*"
	Role      string `json:"role"`      // Target role: "Admin", "Developer", "Security Auditor", "Operator"
}

// RoleResolutionStrategy defines how multiple matching roles are resolved.
type RoleResolutionStrategy string

const (
	StrategyHighestPermissionCount RoleResolutionStrategy = "highestPermissionCount"
	StrategyOrder                  RoleResolutionStrategy = "order"
)

// User represents an internal provisioned user account.
type User struct {
	ID                string              `json:"id"`
	Email             string              `json:"email"`
	Name              string              `json:"name"`
	PreferredUsername string              `json:"preferred_username"`
	Role              string              `json:"role"`
	Groups            []string            `json:"groups"`
	Teams             []string            `json:"teams"`
	BusinessUnits     []string            `json:"business_units"`
	Provider          string              `json:"provider"` // "oidc", "saml", "scim"
	Active            bool                `json:"active"`
	LastLoginAt       time.Time           `json:"last_login_at"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	ClaimMemory       map[string][]string `json:"claim_memory,omitempty"`
}

// SSOProvider defines authentication validation against OIDC and SAML IdPs.
type SSOProvider interface {
	ValidateToken(ctx context.Context, rawToken string) (*IdentityClaims, error)
	ValidateSAMLAssertion(ctx context.Context, rawAssertion string) (*IdentityClaims, error)
}

// GroupRoleMapper resolves identity claims into an authorized system role.
type GroupRoleMapper interface {
	ResolveRole(claims *IdentityClaims) (string, error)
	ResolveRoleFromGroups(groups []string) (string, error)
}

// JITProvisioner handles internal account creation and synchronization.
type JITProvisioner interface {
	ProvisionUser(ctx context.Context, claims *IdentityClaims, role string) (*User, error)
}

// UserStore specifies storage operations for provisioned user accounts.
type UserStore interface {
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context) ([]*User, error)
}
