package handlers

import (
	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// VaultCacheFlusher specifies the cache invalidation contract.
type VaultCacheFlusher interface {
	FlushCache()
}

// ClusterBroadcaster allows broadcasting cache invalidation fleet-wide to cluster peers.
type ClusterBroadcaster interface {
	BroadcastState(entity string, payload []byte) error
}

// VaultHandler exposes management endpoints for external secret vaults.
type VaultHandler struct {
	flusher     VaultCacheFlusher
	broadcaster ClusterBroadcaster
}

// NewVaultHandler creates a new VaultHandler.
func NewVaultHandler(flusher VaultCacheFlusher, broadcaster ClusterBroadcaster) *VaultHandler {
	return &VaultHandler{
		flusher:     flusher,
		broadcaster: broadcaster,
	}
}

// RegisterRoutes registers Vault management routes on the FastHTTP router.
func (h *VaultHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.POST("/api/vault/flush-cache", lib.ChainMiddlewares(h.FlushCache, middlewares...))
}

// FlushCache purges cached secrets fleet-wide across all cluster nodes.
func (h *VaultHandler) FlushCache(ctx *fasthttp.RequestCtx) {
	if h.flusher == nil {
		SendJSONWithStatus(ctx, map[string]string{
			"error": "vault is not enabled",
		}, fasthttp.StatusBadRequest)
		return
	}

	h.flusher.FlushCache()

	// Broadcast to cluster peers if coordinator is present
	if h.broadcaster != nil {
		_ = h.broadcaster.BroadcastState("vault_flush", []byte("{}"))
	}

	SendJSON(ctx, map[string]string{
		"status":  "ok",
		"message": "vault cache flushed",
	})
}
