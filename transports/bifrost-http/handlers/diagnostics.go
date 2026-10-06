package handlers

import (
	"context"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// DiagnosticsHandler manages enterprise SLA reports and health bundle exports.
type DiagnosticsHandler struct {
	reporter diagnostics.DiagnosticsReporter
}

// NewDiagnosticsHandler creates a new DiagnosticsHandler.
func NewDiagnosticsHandler(reporter diagnostics.DiagnosticsReporter) *DiagnosticsHandler {
	return &DiagnosticsHandler{
		reporter: reporter,
	}
}

// RegisterRoutes registers SLA reporting and health bundle endpoints.
func (h *DiagnosticsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/v1/enterprise/diagnostics/sla", lib.ChainMiddlewares(h.handleSLA, middlewares...))
	r.GET("/api/v1/enterprise/diagnostics/health-bundle", lib.ChainMiddlewares(h.handleHealthBundle, middlewares...))
}

func (h *DiagnosticsHandler) handleSLA(ctx *fasthttp.RequestCtx) {
	window := string(ctx.QueryArgs().Peek("window"))
	report, err := h.reporter.GenerateSLAReport(context.Background(), window)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSON(ctx, report)
}

func (h *DiagnosticsHandler) handleHealthBundle(ctx *fasthttp.RequestCtx) {
	bundle, err := h.reporter.ExportHealthBundle(context.Background())
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "failed to generate health bundle: "+err.Error())
		return
	}

	ctx.Response.Header.Set("Content-Type", "application/gzip")
	ctx.Response.Header.Set("Content-Disposition", "attachment; filename=\"bifrost-health-bundle.tar.gz\"")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(bundle)
}
