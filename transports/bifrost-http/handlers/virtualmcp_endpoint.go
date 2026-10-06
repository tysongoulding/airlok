package handlers

import (
	"encoding/json"
	"strings"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// VirtualMCPEndpointHandler handles incoming /mcp/{slug} tool authorization requests.
type VirtualMCPEndpointHandler struct {
	registry *governance.VirtualMCPRegistry
}

// NewVirtualMCPEndpointHandler initializes an endpoint handler with the governance registry.
func NewVirtualMCPEndpointHandler(registry *governance.VirtualMCPRegistry) *VirtualMCPEndpointHandler {
	if registry == nil {
		registry = governance.NewVirtualMCPRegistry(nil)
	}
	return &VirtualMCPEndpointHandler{registry: registry}
}

// RegisterRoutes wires FastHTTP routes for /mcp/{slug}.
func (h *VirtualMCPEndpointHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/mcp/{slug}", lib.ChainMiddlewares(h.handleVirtualMCP, middlewares...))
	r.POST("/mcp/{slug}", lib.ChainMiddlewares(h.handleVirtualMCP, middlewares...))
}

func (h *VirtualMCPEndpointHandler) handleVirtualMCP(ctx *fasthttp.RequestCtx) {
	slug, _ := ctx.UserValue("slug").(string)
	if slug == "" {
		path := string(ctx.Request.URI().PathOriginal())
		slug = strings.TrimPrefix(path, "/mcp/")
		if idx := strings.Index(slug, "/"); idx != -1 {
			slug = slug[:idx]
		}
		if idx := strings.Index(slug, "?"); idx != -1 {
			slug = slug[:idx]
		}
	}

	user := string(ctx.Request.Header.Peek("X-User-ID"))
	tool := string(ctx.QueryArgs().Peek("tool"))
	connector := string(ctx.QueryArgs().Peek("connector"))

	// Non-existent or unauthorized slug check -> HTTP 403 Forbidden
	allowed, action, reason := h.registry.CheckToolAccess(slug, user, connector, tool)
	if !allowed {
		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		_ = json.NewEncoder(ctx).Encode(map[string]string{"error": reason})
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(map[string]interface{}{
		"status": "allowed",
		"action": action,
		"tool":   tool,
	})
}
