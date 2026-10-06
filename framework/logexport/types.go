package logexport

import (
	"time"

	"github.com/maximhq/bifrost/framework/objectstore"
)

// BackpressureStrategy dictates how Enqueue behaves when the internal buffer is saturated.
type BackpressureStrategy string

const (
	BackpressureDrop  BackpressureStrategy = "drop"
	BackpressureBlock BackpressureStrategy = "block"
)

// Config configures the log exporter, payload offloader, and datadog streamer.
type Config struct {
	QueueCapacity        int                  `json:"queue_capacity"`          // default: 10000
	BatchSize            int                  `json:"batch_size"`              // default: 100
	MaxBatchBytes        int                  `json:"max_batch_bytes"`         // default: 1048576 (1MB)
	FlushInterval        time.Duration        `json:"flush_interval"`          // default: 1s
	Backpressure         BackpressureStrategy `json:"backpressure"`            // default: drop
	OffloadThresholdByte int                  `json:"offload_threshold_bytes"` // default: 32768 (32KB)
	ObjectStoreConfig    *objectstore.Config  `json:"object_storage,omitempty"`
	DatadogConfig        *DatadogConfig       `json:"datadog,omitempty"`
}

// DatadogConfig specifies settings for Datadog APM and LLM Observability streaming.
type DatadogConfig struct {
	Enabled               bool              `json:"enabled"`
	ServiceName           string            `json:"service_name"`             // default: "bifrost"
	MLApp                 string            `json:"ml_app"`                   // default: same as ServiceName
	AgentAddr             string            `json:"agent_addr"`               // default: "localhost:8126"
	DogStatsDAddr         string            `json:"dogstatsd_addr"`           // default: "localhost:8125"
	Agentless             bool              `json:"agentless"`                // default: false
	APIKey                string            `json:"api_key,omitempty"`
	Site                  string            `json:"site,omitempty"`           // default: "datadoghq.com"
	Env                   string            `json:"env,omitempty"`
	Version               string            `json:"version,omitempty"`
	CustomTags            map[string]string `json:"custom_tags,omitempty"`
	DisableContentLogging bool              `json:"disable_content_logging"`
}

// ArchiveConfig configures windowed time-based archival to S3/GCS.
type ArchiveConfig struct {
	Interval       time.Duration `json:"interval"`         // default: 24h, min: 5m
	GracePeriod    time.Duration `json:"grace_period"`      // default: 15m
	MaxObjectBytes int64         `json:"max_object_bytes"`  // default: 134217728 (128 MiB)
	Compress       bool          `json:"compress"`          // default: true
	Prefix         string        `json:"prefix"`            // default: "bifrost"
	TargetPrefix   string        `json:"target_prefix"`     // "audit-logs" or "logs"
}

// LogEntry represents an exported gateway log record.
type LogEntry struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Provider         string                 `json:"provider,omitempty"`
	Model            string                 `json:"model,omitempty"`
	Status           string                 `json:"status,omitempty"`
	StatusCode       int                    `json:"status_code,omitempty"`
	PromptLen        int                    `json:"prompt_len,omitempty"`
	LatencyMs        float64                `json:"latency_ms,omitempty"`
	PromptTokens     int                    `json:"prompt_tokens,omitempty"`
	CompletionTokens int                    `json:"completion_tokens,omitempty"`
	TotalTokens      int                    `json:"total_tokens,omitempty"`
	CostUSD          float64                `json:"cost_usd,omitempty"`
	VirtualKeyID     string                 `json:"virtual_key_id,omitempty"`
	SelectedKeyID    string                 `json:"selected_key_id,omitempty"`
	UserID           string                 `json:"user_id,omitempty"`
	TeamID           string                 `json:"team_id,omitempty"`
	RawRequest       string                 `json:"raw_request,omitempty"`
	RawResponse      string                 `json:"raw_response,omitempty"`
	InputHistory     string                 `json:"input_history,omitempty"`
	OutputMessage    string                 `json:"output_message,omitempty"`
	Offloaded        bool                   `json:"offloaded,omitempty"`
	OffloadedRefs    map[string]string      `json:"offloaded_refs,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// ManifestPart describes a single part in a windowed archive.
type ManifestPart struct {
	Key        string `json:"key"`
	EventCount int    `json:"event_count"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256,omitempty"`
}

// ArchiveManifest defines the authoritative commit record for an archival window.
type ArchiveManifest struct {
	Version     int            `json:"version"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
	EventCount  int            `json:"event_count"`
	Compressed  bool           `json:"compressed"`
	CompletedAt time.Time      `json:"completed_at"`
	Parts       []ManifestPart `json:"parts"`
}
