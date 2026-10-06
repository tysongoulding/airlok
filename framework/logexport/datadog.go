package logexport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// DDSpan represents an APM trace span sent to Datadog agent.
type DDSpan struct {
	TraceID  uint64             `json:"trace_id"`
	SpanID   uint64             `json:"span_id"`
	ParentID uint64             `json:"parent_id,omitempty"`
	Name     string             `json:"name"`
	Resource string             `json:"resource"`
	Service  string             `json:"service"`
	Type     string             `json:"type"`
	Start    int64              `json:"start"`
	Duration int64              `json:"duration"`
	Error    int32              `json:"error"`
	Meta     map[string]string  `json:"meta"`
	Metrics  map[string]float64 `json:"metrics"`
}

// DatadogStreamer implements schemas.ObservabilityPlugin to stream spans to Datadog.
type DatadogStreamer struct {
	config        DatadogConfig
	client        *http.Client
	emittedSpans  atomic.Int64
	failedSpans   atomic.Int64
	capturedSpans []*DDSpan
	capMu         sync.Mutex
}

// NewDatadogStreamer constructs a DatadogStreamer.
func NewDatadogStreamer(cfg DatadogConfig) *DatadogStreamer {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "bifrost"
	}
	if cfg.MLApp == "" {
		cfg.MLApp = cfg.ServiceName
	}
	if cfg.AgentAddr == "" {
		cfg.AgentAddr = "localhost:8126"
	}
	if cfg.DogStatsDAddr == "" {
		cfg.DogStatsDAddr = "localhost:8125"
	}
	if cfg.Site == "" {
		cfg.Site = "datadoghq.com"
	}

	return &DatadogStreamer{
		config:        cfg,
		client:        &http.Client{Timeout: 5 * time.Second},
		capturedSpans: make([]*DDSpan, 0),
	}
}

// SetHTTPClient sets custom http client for testing.
func (d *DatadogStreamer) SetHTTPClient(client *http.Client) {
	d.capMu.Lock()
	defer d.capMu.Unlock()
	d.client = client
}

// GetName implements schemas.BasePlugin.
func (d *DatadogStreamer) GetName() string {
	return "datadog"
}

// Inject implements schemas.ObservabilityPlugin.
// Complies with the zero-retention requirement: extracts and copies all fields synchronously before returning.
func (d *DatadogStreamer) Inject(ctx context.Context, trace *schemas.Trace) error {
	if !d.config.Enabled || trace == nil {
		return nil
	}

	// 1. Convert trace to Datadog spans synchronously
	spans := d.convertTraceToSpans(trace)
	if len(spans) == 0 {
		return nil
	}

	d.capMu.Lock()
	d.capturedSpans = append(d.capturedSpans, spans...)
	client := d.client
	d.capMu.Unlock()
	d.emittedSpans.Add(int64(len(spans)))

	// 2. Dispatch payload to Agent or Intake API
	var err error
	if d.config.Agentless {
		err = d.sendAgentless(ctx, client, spans)
	} else {
		err = d.sendAgent(ctx, client, spans)
	}

	if err != nil {
		// Observability plugins handle errors gracefully without failing request pipelines
		d.failedSpans.Add(int64(len(spans)))
		return nil
	}
	return nil
}

func (d *DatadogStreamer) convertTraceToSpans(t *schemas.Trace) []*DDSpan {
	spans := make([]*DDSpan, 0, len(t.Spans)+1)

	rootStart := t.StartTime.UnixNano()
	rootDuration := t.EndTime.Sub(t.StartTime).Nanoseconds()
	if rootDuration <= 0 {
		rootDuration = 1000
	}

	meta := make(map[string]string)
	for k, v := range d.config.CustomTags {
		meta[k] = v
	}
	meta["service"] = d.config.ServiceName
	meta["ml_app"] = d.config.MLApp
	if d.config.Env != "" {
		meta["env"] = d.config.Env
	}
	if d.config.Version != "" {
		meta["version"] = d.config.Version
	}

	metrics := make(map[string]float64)

	// Extract attributes from root span
	if t.RootSpan != nil && t.RootSpan.Attributes != nil {
		for k, v := range t.RootSpan.Attributes {
			switch val := v.(type) {
			case string:
				meta[k] = val
			case int:
				metrics[k] = float64(val)
			case int64:
				metrics[k] = float64(val)
			case float64:
				metrics[k] = val
			}
		}
	}

	// Extract token metrics from trace attributes if present
	if pt := schemas.GetIntAttr(t.Attributes, "gen_ai.usage.input_tokens"); pt > 0 {
		metrics["llm.prompt_tokens"] = float64(pt)
	}
	if ct := schemas.GetIntAttr(t.Attributes, "gen_ai.usage.output_tokens"); ct > 0 {
		metrics["llm.completion_tokens"] = float64(ct)
	}
	if tt := schemas.GetIntAttr(t.Attributes, "gen_ai.usage.total_tokens"); tt > 0 {
		metrics["llm.total_tokens"] = float64(tt)
	}

	// Fallback check root span attributes for token metrics
	if t.RootSpan != nil && t.RootSpan.Attributes != nil {
		if _, ok := metrics["llm.prompt_tokens"]; !ok {
			if pt := schemas.GetIntAttr(t.RootSpan.Attributes, "gen_ai.usage.input_tokens"); pt > 0 {
				metrics["llm.prompt_tokens"] = float64(pt)
			}
		}
		if _, ok := metrics["llm.completion_tokens"]; !ok {
			if ct := schemas.GetIntAttr(t.RootSpan.Attributes, "gen_ai.usage.output_tokens"); ct > 0 {
				metrics["llm.completion_tokens"] = float64(ct)
			}
		}
		if _, ok := metrics["llm.total_tokens"]; !ok {
			if tt := schemas.GetIntAttr(t.RootSpan.Attributes, "gen_ai.usage.total_tokens"); tt > 0 {
				metrics["llm.total_tokens"] = float64(tt)
			}
		}
	}

	metrics["llm.latency_ms"] = float64(rootDuration) / 1e6

	model := meta["model"]
	if model == "" {
		model = meta["gen_ai.request.model"]
	}

	rootSpan := &DDSpan{
		TraceID:  hashStringToUint64(t.TraceID),
		SpanID:   hashStringToUint64(t.InternalID),
		Name:     "bifrost.llm.request",
		Resource: fmt.Sprintf("llm:%s", model),
		Service:  d.config.ServiceName,
		Type:     "llm",
		Start:    rootStart,
		Duration: rootDuration,
		Meta:     meta,
		Metrics:  metrics,
	}
	spans = append(spans, rootSpan)

	return spans
}

func (d *DatadogStreamer) sendAgent(ctx context.Context, client *http.Client, spans []*DDSpan) error {
	payload, err := json.Marshal([][]*DDSpan{spans})
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/v0.4/traces", d.config.AgentAddr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (d *DatadogStreamer) sendAgentless(ctx context.Context, client *http.Client, spans []*DDSpan) error {
	payload, err := json.Marshal(spans)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://api.%s/api/intake/llm-obs/v1/trace/spans", d.config.Site)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", d.config.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// GetCapturedSpans returns spans captured for testing.
func (d *DatadogStreamer) GetCapturedSpans() []*DDSpan {
	d.capMu.Lock()
	defer d.capMu.Unlock()
	res := make([]*DDSpan, len(d.capturedSpans))
	for i, s := range d.capturedSpans {
		if s != nil {
			cp := *s
			if s.Meta != nil {
				cp.Meta = make(map[string]string, len(s.Meta))
				for k, v := range s.Meta {
					cp.Meta[k] = v
				}
			}
			if s.Metrics != nil {
				cp.Metrics = make(map[string]float64, len(s.Metrics))
				for k, v := range s.Metrics {
					cp.Metrics[k] = v
				}
			}
			res[i] = &cp
		}
	}
	return res
}

func hashStringToUint64(s string) uint64 {
	if s == "" {
		return 1
	}
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	if h == 0 {
		return 1
	}
	return h
}
