package mock

import (
	"context"
	"sync"
	"time"

	"github.com/maximhq/bifrost/framework/audit"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/maximhq/bifrost/framework/logexport"
	"github.com/maximhq/bifrost/framework/rbac"
)

// --- R7: Log Exports & Audit Trail Pipeline ---

// AuditEvent aliases the production audit.AuditEvent.
type AuditEvent = audit.AuditEvent

// MockAuditLedger bridges to the genuine framework/audit.Ledger.
type MockAuditLedger struct {
	mu              sync.RWMutex
	ledger          *audit.Ledger
	HMACKey         []byte
	OmitIPAddresses bool
	Events          []*AuditEvent
}

// NewMockAuditLedger initializes an audit ledger backed by genuine framework/audit.
func NewMockAuditLedger(hmacKey string, omitIP bool) (*MockAuditLedger, error) {
	cfg := audit.Config{
		HMACKey:         hmacKey,
		OmitIPAddresses: omitIP,
	}
	realLedger, err := audit.NewLedger(cfg)
	if err != nil {
		return nil, err
	}

	return &MockAuditLedger{
		ledger:          realLedger,
		HMACKey:         []byte(hmacKey),
		OmitIPAddresses: omitIP,
		Events:          make([]*AuditEvent, 0),
	}, nil
}

func (a *MockAuditLedger) RecordEvent(action, targetType, targetID, initiatorID, clientIP, payload string) (*AuditEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.ledger.SetOmitIPAddresses(a.OmitIPAddresses)

	event, err := a.ledger.RecordEvent(action, targetType, targetID, initiatorID, clientIP, payload)
	if err != nil {
		return nil, err
	}

	a.Events = append(a.Events, event)
	return event, nil
}

func (a *MockAuditLedger) VerifySignature(event *AuditEvent) bool {
	return a.ledger.VerifySignature(event)
}

// MockLogExporter bridges to the genuine framework/logexport.BatchedLogQueue and PayloadOffloader.
type MockLogExporter struct {
	mu             sync.Mutex
	queue          *logexport.BatchedLogQueue
	offloader      *logexport.PayloadOffloader
	BatchSize      int
	FlushTimeout   time.Duration
	Queue          []map[string]interface{}
	FlushedBatches [][]map[string]interface{}
	OffloadedS3    map[string][]byte
}

func NewMockLogExporter(batchSize int, timeout time.Duration) *MockLogExporter {
	offloader := logexport.NewPayloadOffloader(nil, 32768, "bifrost", false)
	cfg := logexport.Config{
		BatchSize:     batchSize,
		FlushInterval: timeout,
	}
	queue := logexport.NewBatchedLogQueue(cfg, offloader)

	return &MockLogExporter{
		queue:          queue,
		offloader:      offloader,
		BatchSize:      batchSize,
		FlushTimeout:   timeout,
		Queue:          make([]map[string]interface{}, 0),
		FlushedBatches: make([][]map[string]interface{}, 0),
		OffloadedS3:    make(map[string][]byte),
	}
}

func (e *MockLogExporter) Enqueue(logEntry map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Queue = append(e.Queue, logEntry)
	_ = e.queue.EnqueueMap(logEntry)

	if len(e.Queue) >= e.BatchSize {
		e.queue.Flush()
		e.FlushedBatches = e.queue.GetFlushedBatchMaps()
		e.Queue = e.Queue[:0]
	}
}

func (e *MockLogExporter) Flush() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.queue.Flush()
	e.FlushedBatches = e.queue.GetFlushedBatchMaps()
	e.Queue = e.Queue[:0]
}

func (e *MockLogExporter) OffloadPayloadToS3(objectKey string, payload []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.offloader.OffloadPayloadToS3(objectKey, payload); err != nil {
		return err
	}
	e.OffloadedS3[objectKey] = append([]byte(nil), payload...)
	return nil
}

// --- R8: Role-Based Access Control (RBAC) & Diagnostics ---

type Resource = rbac.Resource

const (
	ResourceLogs             Resource = rbac.ResourceLogs
	ResourceModelProvider    Resource = rbac.ResourceModelProvider
	ResourceVirtualKeys      Resource = rbac.ResourceVirtualKeys
	ResourceAuditLogs        Resource = rbac.ResourceAuditLogs
	ResourceGuardrailsConfig Resource = rbac.ResourceGuardrailsConfig
	ResourceCluster          Resource = rbac.ResourceCluster
	ResourceVirtualMCPs      Resource = rbac.ResourceVirtualMCPs
	ResourceAdaptiveRouter   Resource = rbac.ResourceAdaptiveRouter
	ResourceRoles            Resource = rbac.ResourceRoles
)

type Operation = rbac.Operation

const (
	OpView      Operation = rbac.OpView
	OpCreate    Operation = rbac.OpCreate
	OpUpdate    Operation = rbac.OpUpdate
	OpDelete    Operation = rbac.OpDelete
	OpDownload  Operation = rbac.OpDownload
	OpInference Operation = rbac.OpInference
)

// MockRBACAuthorizer bridges to the genuine framework/rbac.RBACAuthorizer.
type MockRBACAuthorizer struct {
	authorizer      *rbac.RBACAuthorizer
	RolePermissions map[string]map[string]bool // compatibility mirror
}

func NewMockRBACAuthorizer() *MockRBACAuthorizer {
	realAuthorizer := rbac.NewRBACAuthorizer()
	roles := realAuthorizer.ListRoles()
	rolePerms := make(map[string]map[string]bool, len(roles))
	for _, r := range roles {
		rolePerms[r.Name] = r.Permissions
	}

	return &MockRBACAuthorizer{
		authorizer:      realAuthorizer,
		RolePermissions: rolePerms,
	}
}

func (r *MockRBACAuthorizer) Authorize(role string, res Resource, op Operation) (bool, error) {
	return r.authorizer.Authorize(role, res, op)
}

// MockDiagnosticsReporter bridges to the genuine framework/diagnostics.SLATracker.
type MockDiagnosticsReporter struct {
	tracker      *diagnostics.SLATracker
	P50LatencyMs float64
	P95LatencyMs float64
	P99LatencyMs float64
	UptimePct    float64
}

func NewMockDiagnosticsReporter() *MockDiagnosticsReporter {
	tracker := diagnostics.NewSLATracker()
	return &MockDiagnosticsReporter{
		tracker:      tracker,
		P50LatencyMs: 14.2,
		P95LatencyMs: 48.5,
		P99LatencyMs: 112.0,
		UptimePct:    99.995,
	}
}

func (d *MockDiagnosticsReporter) GenerateSLAReport(ctx context.Context, window string) (map[string]interface{}, error) {
	report, err := d.tracker.GenerateSLAReport(ctx, window)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"window":      report.Window,
		"uptime_pct":  report.UptimePct,
		"p50_latency": report.P50LatencyMs,
		"p95_latency": report.P95LatencyMs,
		"p99_latency": report.P99LatencyMs,
		"status":      report.Status,
	}, nil
}

func (d *MockDiagnosticsReporter) ExportHealthBundle(ctx context.Context) ([]byte, error) {
	return d.tracker.ExportHealthBundle(ctx)
}
