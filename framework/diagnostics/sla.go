package diagnostics

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"
)

type timeBucket struct {
	Timestamp          time.Time
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	LatencySamples     []float64 // Latency in ms
	ProviderSamples    map[string][]float64
	ProviderSuccess    map[string]int64
	ProviderTotal      map[string]int64
}

// SLATracker provides a thread-safe sliding-window metrics accumulator.
type SLATracker struct {
	mu           sync.RWMutex
	buckets      []*timeBucket
	bucketSpan   time.Duration
	maxRetention time.Duration
	baselineP50  float64
	baselineP95  float64
	baselineP99  float64
	baselineUp   float64
	healthGen    *HealthBundleGenerator
}

// NewSLATracker constructs a new SLATracker.
func NewSLATracker() *SLATracker {
	tracker := &SLATracker{
		buckets:      make([]*timeBucket, 0, 1440),
		bucketSpan:   1 * time.Minute,
		maxRetention: 7 * 24 * time.Hour,
		baselineP50:  14.2,
		baselineP95:  48.5,
		baselineP99:  112.0,
		baselineUp:   99.995,
	}
	tracker.healthGen = NewHealthBundleGenerator(nil, nil)
	return tracker
}

// SetHealthBundleGenerator overrides the default generator.
func (t *SLATracker) SetHealthBundleGenerator(gen *HealthBundleGenerator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.healthGen = gen
}

// RecordRequest records the latency and outcome of an upstream LLM request.
func (t *SLATracker) RecordRequest(provider, model string, duration time.Duration, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	bucketTime := now.Truncate(t.bucketSpan)

	var current *timeBucket
	if len(t.buckets) > 0 && t.buckets[len(t.buckets)-1].Timestamp.Equal(bucketTime) {
		current = t.buckets[len(t.buckets)-1]
	} else {
		current = &timeBucket{
			Timestamp:       bucketTime,
			LatencySamples:  make([]float64, 0, 100),
			ProviderSamples: make(map[string][]float64),
			ProviderSuccess: make(map[string]int64),
			ProviderTotal:   make(map[string]int64),
		}
		t.buckets = append(t.buckets, current)
		t.pruneOldBucketsLocked(now)
	}

	latMs := float64(duration.Microseconds()) / 1000.0
	current.TotalRequests++
	if success {
		current.SuccessfulRequests++
	} else {
		current.FailedRequests++
	}

	// Bound samples per minute bucket to avoid unbounded memory growth
	if len(current.LatencySamples) < 500 {
		current.LatencySamples = append(current.LatencySamples, latMs)
	}

	if provider != "" {
		current.ProviderTotal[provider]++
		if success {
			current.ProviderSuccess[provider]++
		}
		if len(current.ProviderSamples[provider]) < 200 {
			current.ProviderSamples[provider] = append(current.ProviderSamples[provider], latMs)
		}
	}
}

func (t *SLATracker) pruneOldBucketsLocked(now time.Time) {
	cutoff := now.Add(-t.maxRetention)
	idx := 0
	for idx < len(t.buckets) && t.buckets[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		t.buckets = t.buckets[idx:]
	}
}

func (t *SLATracker) parseWindow(windowStr string) (time.Duration, string) {
	if strings.TrimSpace(windowStr) == "" {
		return 24 * time.Hour, "24h"
	}
	w := strings.ToLower(strings.TrimSpace(windowStr))
	switch w {
	case "1h":
		return 1 * time.Hour, "1h"
	case "24h":
		return 24 * time.Hour, "24h"
	case "7d":
		return 7 * 24 * time.Hour, "7d"
	case "30d":
		return 30 * 24 * time.Hour, "30d"
	default:
		d, err := time.ParseDuration(w)
		if err == nil && d > 0 {
			return d, windowStr
		}
		return 24 * time.Hour, "24h"
	}
}

// GenerateSLAReport produces an aggregated SLA report over the given time window.
func (t *SLATracker) GenerateSLAReport(ctx context.Context, window string) (*SLAReport, error) {
	winDur, canonicalWin := t.parseWindow(window)

	t.mu.RLock()
	now := time.Now().UTC()
	cutoff := now.Add(-winDur)

	var total, successful, failed int64
	var allSamples []float64
	provSamples := make(map[string][]float64)
	provSuccess := make(map[string]int64)
	provTotal := make(map[string]int64)

	for _, b := range t.buckets {
		if b.Timestamp.After(cutoff) || b.Timestamp.Equal(cutoff) {
			total += b.TotalRequests
			successful += b.SuccessfulRequests
			failed += b.FailedRequests
			allSamples = append(allSamples, b.LatencySamples...)

			for p, samples := range b.ProviderSamples {
				provSamples[p] = append(provSamples[p], samples...)
				provSuccess[p] += b.ProviderSuccess[p]
				provTotal[p] += b.ProviderTotal[p]
			}
		}
	}
	t.mu.RUnlock()

	// If no traffic has been recorded, return healthy baseline
	if total == 0 {
		return &SLAReport{
			Window:             canonicalWin,
			Status:             "HEALTHY",
			UptimePct:          t.baselineUp,
			P50LatencyMs:       t.baselineP50,
			P95LatencyMs:       t.baselineP95,
			P99LatencyMs:       t.baselineP99,
			TotalRequests:      0,
			SuccessfulRequests: 0,
			FailedRequests:     0,
		}, nil
	}

	// Calculations performed strictly on local copies outside lock
	p50, p95, p99 := calculatePercentiles(allSamples)
	uptime := (float64(successful) / float64(total)) * 100.0

	status := "HEALTHY"
	if uptime < 95.0 || p99 > 5000.0 {
		status = "CRITICAL"
	} else if uptime < 99.5 || p99 > 1000.0 {
		status = "DEGRADED"
	}

	provMetrics := make(map[string]*ProviderMetric)
	for p, samples := range provSamples {
		pp50, pp95, pp99 := calculatePercentiles(samples)
		ptot := provTotal[p]
		puptime := 100.0
		if ptot > 0 {
			puptime = (float64(provSuccess[p]) / float64(ptot)) * 100.0
		}
		provMetrics[p] = &ProviderMetric{
			P50LatencyMs: pp50,
			P95LatencyMs: pp95,
			P99LatencyMs: pp99,
			UptimePct:    puptime,
			TotalCount:   ptot,
		}
	}

	return &SLAReport{
		Window:             canonicalWin,
		Status:             status,
		UptimePct:          uptime,
		P50LatencyMs:       p50,
		P95LatencyMs:       p95,
		P99LatencyMs:       p99,
		TotalRequests:      total,
		SuccessfulRequests: successful,
		FailedRequests:     failed,
		ProviderMetrics:    provMetrics,
	}, nil
}

// ExportHealthBundle exports the gzip diagnostics health bundle.
func (t *SLATracker) ExportHealthBundle(ctx context.Context) ([]byte, error) {
	t.mu.RLock()
	gen := t.healthGen
	t.mu.RUnlock()

	if gen == nil {
		gen = NewHealthBundleGenerator(nil, nil)
	}
	return gen.ExportHealthBundle(ctx)
}

func calculatePercentiles(samples []float64) (float64, float64, float64) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	slices.Sort(sorted)

	n := len(sorted)
	p50 := sorted[int(float64(n)*0.50)]
	p95Idx := int(float64(n) * 0.95)
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p95 := sorted[p95Idx]

	p99Idx := int(float64(n) * 0.99)
	if p99Idx >= n {
		p99Idx = n - 1
	}
	p99 := sorted[p99Idx]

	return p50, p95, p99
}
