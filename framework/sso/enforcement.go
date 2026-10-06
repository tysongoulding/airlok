package sso

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/valyala/fasthttp"
)

// SSOEnforcer coordinates token validation, role resolution, and JIT provisioning,
// enforcing strict rejection (HTTP 403 Forbidden) for unmapped roles.
type SSOEnforcer struct {
	validator SSOProvider
	mapper    GroupRoleMapper
	jit       JITProvisioner
}

// NewSSOEnforcer creates an SSOEnforcer.
func NewSSOEnforcer(val SSOProvider, mapper GroupRoleMapper, jit JITProvisioner) *SSOEnforcer {
	return &SSOEnforcer{
		validator: val,
		mapper:    mapper,
		jit:       jit,
	}
}

// AuthenticateToken verifies a JWT bearer token, resolves the user role, provisions
// or updates the user record, or strictly rejects with ErrUnmappedRole.
func (e *SSOEnforcer) AuthenticateToken(ctx context.Context, token string) (*User, string, error) {
	if e.validator == nil {
		return nil, "", ErrInvalidToken
	}

	claims, err := e.validator.ValidateToken(ctx, token)
	if err != nil {
		return nil, "", err
	}

	if e.mapper == nil {
		return nil, "", ErrUnmappedRole
	}

	role, err := e.mapper.ResolveRole(claims)
	if err != nil || role == "" {
		// Strict rejection: unmapped user groups map to zero roles
		return nil, "", ErrUnmappedRole
	}

	if e.jit != nil {
		user, err := e.jit.ProvisionUser(ctx, claims, role)
		if err != nil {
			return nil, "", err
		}
		return user, role, nil
	}

	// In the absence of a JIT provisioner, construct lightweight user
	user := &User{
		ID:     claims.Subject,
		Email:  claims.Email,
		Name:   claims.Name,
		Role:   role,
		Groups: claims.Groups,
		Active: true,
	}
	return user, role, nil
}

// AuthenticateSAML verifies a SAML assertion, resolves the user role, and provisions the user.
func (e *SSOEnforcer) AuthenticateSAML(ctx context.Context, rawAssertion string) (*User, string, error) {
	if e.validator == nil {
		return nil, "", ErrInvalidToken
	}

	claims, err := e.validator.ValidateSAMLAssertion(ctx, rawAssertion)
	if err != nil {
		return nil, "", err
	}

	if e.mapper == nil {
		return nil, "", ErrUnmappedRole
	}

	role, err := e.mapper.ResolveRole(claims)
	if err != nil || role == "" {
		return nil, "", ErrUnmappedRole
	}

	if e.jit != nil {
		user, err := e.jit.ProvisionUser(ctx, claims, role)
		if err != nil {
			return nil, "", err
		}
		return user, role, nil
	}

	user := &User{
		ID:     claims.Subject,
		Email:  claims.Email,
		Name:   claims.Name,
		Role:   role,
		Groups: claims.Groups,
		Active: true,
	}
	return user, role, nil
}

// WriteForbiddenUnmappedGroup sends an HTTP 403 Forbidden response using FastHTTP.
func WriteForbiddenUnmappedGroup(ctx *fasthttp.RequestCtx, reason string) {
	ctx.SetStatusCode(fasthttp.StatusForbidden)
	ctx.SetContentType("application/json")
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": "access denied: user groups do not map to any authorized gateway role",
			"type":    "forbidden",
			"code":    "sso_unmapped_group",
			"details": reason,
		},
	}
	_ = json.NewEncoder(ctx).Encode(resp)
}

// WriteForbiddenUnmappedGroupHTTP sends an HTTP 403 Forbidden response using net/http.
func WriteForbiddenUnmappedGroupHTTP(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": "access denied: user groups do not map to any authorized gateway role",
			"type":    "forbidden",
			"code":    "sso_unmapped_group",
			"details": reason,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}
