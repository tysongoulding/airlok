package handlers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// SSOMiddleware provides FastHTTP authentication and role enforcement using Enterprise SSO.
type SSOMiddleware struct {
	enforcer          *sso.SSOEnforcer
	whitelistedRoutes []string
}

// NewSSOMiddleware initializes an SSOMiddleware instance.
func NewSSOMiddleware(enforcer *sso.SSOEnforcer) *SSOMiddleware {
	return &SSOMiddleware{
		enforcer: enforcer,
		whitelistedRoutes: []string{
			"/.well-known/",
			"/health",
			"/login",
			"/api/session/is-auth-enabled",
			"/api/session/login",
			"/api/sso/callback",
			"/api/sso/saml/callback",
			"/api/sso/saml/acs",
			"/api/sso/saml/metadata",
			"/favicon.ico",
			"/assets/",
		},
	}
}

// Middleware returns the FastHTTP middleware function for enterprise authentication.
func (m *SSOMiddleware) Middleware() schemas.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			path := string(ctx.Request.URI().PathOriginal())

			// 1. Skip whitelisted public endpoints (exact match for discrete routes, prefix match for directory routes)
			for _, route := range m.whitelistedRoutes {
				if strings.HasSuffix(route, "/") {
					// Directory prefix (e.g. "/.well-known/", "/assets/")
					if strings.HasPrefix(path, route) || path == strings.TrimSuffix(route, "/") {
						next(ctx)
						return
					}
				} else {
					// Discrete endpoint (e.g. "/login", "/health", "/favicon.ico")
					if path == route || path == route+"/" {
						next(ctx)
						return
					}
				}
			}

			// 2. Extract Authorization Bearer Token
			authHeader := string(ctx.Request.Header.Peek("Authorization"))
			if authHeader == "" {
				SendJSONWithStatus(ctx, map[string]interface{}{
					"error": map[string]string{
						"code":    "unauthorized",
						"message": "Missing authorization token",
					},
				}, fasthttp.StatusUnauthorized)
				return
			}

			scheme, token, ok := strings.Cut(authHeader, " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
				SendJSONWithStatus(ctx, map[string]interface{}{
					"error": map[string]string{
						"code":    "invalid_scheme",
						"message": "Authorization header must use Bearer scheme",
					},
				}, fasthttp.StatusUnauthorized)
				return
			}

			if m.enforcer == nil {
				SendError(ctx, fasthttp.StatusInternalServerError, "SSO enforcer is not configured")
				return
			}

			// 3. Authenticate token, resolve roles, provision JIT user
			user, role, err := m.enforcer.AuthenticateToken(ctx, token)
			if err != nil {
				if errors.Is(err, sso.ErrUnmappedRole) {
					// HTTP 403 Forbidden: Authenticated user has zero mapped gateway roles
					sso.WriteForbiddenUnmappedGroup(ctx, "user groups do not map to any authorized gateway role")
					return
				}

				// HTTP 401 Unauthorized for expired or cryptographically invalid tokens
				SendJSONWithStatus(ctx, map[string]interface{}{
					"error": map[string]string{
						"code":    "invalid_token",
						"message": err.Error(),
					},
				}, fasthttp.StatusUnauthorized)
				return
			}

			// 4. Attach enterprise claims and role to context
			ctx.SetUserValue("enterprise_user", user)
			ctx.SetUserValue("enterprise_role", role)
			ctx.SetUserValue(schemas.BifrostContextKeyUserID, user.ID)
			ctx.SetUserValue(schemas.BifrostContextKeyUserRole, role)
			ctx.SetUserValue(schemas.IsLocalAdminContextKey, role == sso.RoleAdmin)
			ctx.SetUserValue(schemas.BifrostContextKeySessionToken, token)

			next(ctx)
		}
	}
}

// SSOHandler provides HTTP endpoints for SAML assertion consumer service and metadata.
type SSOHandler struct {
	enforcer   *sso.SSOEnforcer
	spEntityID string
}

// NewSSOHandler creates a new SSOHandler.
func NewSSOHandler(enforcer *sso.SSOEnforcer, spEntityID string) *SSOHandler {
	if spEntityID == "" {
		spEntityID = "https://bifrost.gateway/saml/sp"
	}
	return &SSOHandler{
		enforcer:   enforcer,
		spEntityID: spEntityID,
	}
}

// RegisterRoutes mounts SSO endpoints on the router.
func (h *SSOHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.POST("/api/sso/saml/acs", lib.ChainMiddlewares(h.handleSAMLACS, middlewares...))
	r.GET("/api/sso/saml/metadata", lib.ChainMiddlewares(h.handleSAMLMetadata, middlewares...))
	r.GET("/api/sso/claims", lib.ChainMiddlewares(h.handleGetClaims, middlewares...))
	r.GET("/api/sso/status", lib.ChainMiddlewares(h.handleSSOStatus, middlewares...))
}

func (h *SSOHandler) handleSAMLACS(ctx *fasthttp.RequestCtx) {
	var samlResponse string
	if ctx.IsPost() {
		samlResponse = string(ctx.PostArgs().Peek("SAMLResponse"))
		if samlResponse == "" {
			samlResponse = string(ctx.Request.Body())
		}
	}

	if samlResponse == "" {
		SendJSONWithStatus(ctx, map[string]string{
			"error": "missing SAMLResponse payload",
		}, fasthttp.StatusBadRequest)
		return
	}

	user, role, err := h.enforcer.AuthenticateSAML(ctx, samlResponse)
	if err != nil {
		if errors.Is(err, sso.ErrUnmappedRole) {
			sso.WriteForbiddenUnmappedGroup(ctx, "user groups do not map to any authorized gateway role")
			return
		}
		SendJSONWithStatus(ctx, map[string]string{
			"error": err.Error(),
		}, fasthttp.StatusUnauthorized)
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"status":  "ok",
		"user_id": user.ID,
		"role":    role,
		"email":   user.Email,
	})
}

func (h *SSOHandler) handleSAMLMetadata(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/xml")
	metadataXML := fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
    <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/api/sso/saml/acs" index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>`, h.spEntityID, h.spEntityID)
	ctx.SetBodyString(metadataXML)
}

func (h *SSOHandler) handleGetClaims(ctx *fasthttp.RequestCtx) {
	user := ctx.UserValue("enterprise_user")
	if user == nil {
		SendJSONWithStatus(ctx, map[string]string{
			"error": "no active enterprise session",
		}, fasthttp.StatusUnauthorized)
		return
	}
	SendJSON(ctx, user)
}

func (h *SSOHandler) handleSSOStatus(ctx *fasthttp.RequestCtx) {
	SendJSON(ctx, map[string]interface{}{
		"status":     "active",
		"sp_entity":  h.spEntityID,
		"configured": h.enforcer != nil,
	})
}
