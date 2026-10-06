package diagnostics

import (
	"context"
	"time"
)

// SLAReport represents aggregated performance and reliability metrics.
type SLAReport struct {
	Window             string                     `json:"window"`
	Status             string                     `json:"status"` // "HEALTHY", "DEGRADED", "CRITICAL"
	UptimePct          float64                    `json:"uptime_pct"`
	P50LatencyMs       float64                    `json:"p50_latency"`
	P95LatencyMs       float64                    `json:"p95_latency"`
	P99LatencyMs       float64                    `json:"p99_latency"`
	TotalRequests      int64                      `json:"total_requests"`
	SuccessfulRequests int64                      `json:"successful_requests"`
	FailedRequests     int64                      `json:"failed_requests"`
	ProviderMetrics    map[string]*ProviderMetric `json:"provider_metrics,omitempty"`
}

// ProviderMetric breaks down latency and uptime by LLM provider.
type ProviderMetric struct {
	P50LatencyMs float64 `json:"p50_latency"`
	P95LatencyMs float64 `json:"p95_latency"`
	P99LatencyMs float64 `json:"p99_latency"`
	UptimePct    float64 `json:"uptime_pct"`
	TotalCount   int64   `json:"total_requests"`
}

// DiagnosticsReporter defines SLA reporting and health bundle export interfaces.
type DiagnosticsReporter interface {
	RecordRequest(provider, model string, duration time.Duration, success bool)
	GenerateSLAReport(ctx context.Context, window string) (*SLAReport, error)
	ExportHealthBundle(ctx context.Context) ([]byte, error)
}
