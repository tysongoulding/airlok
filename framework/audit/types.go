package audit

import (
	"time"

	"github.com/maximhq/bifrost/framework/objectstore"
)

// GenesisPrevHash is the canonical PrevHash for SequenceID = 1.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditEvent represents a single cryptographically signed, hash-chained audit record.
type AuditEvent struct {
	ID            string    `json:"id"`
	SequenceID    int64     `json:"sequence_id"`
	Timestamp     time.Time `json:"timestamp"`
	Action        string    `json:"action"`
	TargetType    string    `json:"target_type"` // e.g. virtual_key, role, provider, config
	TargetID      string    `json:"target_id"`
	InitiatorID   string    `json:"initiator_id"` // ActorID
	ClientIP      string    `json:"client_ip,omitempty"`
	Payload       string    `json:"payload"`
	PayloadHash   string    `json:"payload_hash"`
	PrevHash      string    `json:"prev_hash"`
	HMACSignature string    `json:"hmac_signature"`
	KeyID         string    `json:"key_id,omitempty"` // Key version for rotation
}

// Clone creates a deep copy of the AuditEvent to prevent data races.
func (e *AuditEvent) Clone() *AuditEvent {
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}

// IPSanitizationMode controls how IP addresses are handled.
type IPSanitizationMode string

const (
	IPSanitizationNone IPSanitizationMode = "none"
	IPSanitizationOmit IPSanitizationMode = "omit"
	IPSanitizationMask IPSanitizationMode = "mask"
	IPSanitizationHash IPSanitizationMode = "hash"
)

// Config configures the audit ledger, sanitization, and archival.
type Config struct {
	Disabled              bool                `json:"disabled"`
	HMACKey               string              `json:"hmac_key"`               // Minimum 32 bytes
	KeyRegistry           map[string]string   `json:"key_registry,omitempty"` // key_id -> secret
	ActiveKeyID           string              `json:"active_key_id,omitempty"`
	RetentionDays         int                 `json:"retention_days"`
	OmitIPAddresses       bool                `json:"omit_ip_addresses"`
	IPMode                IPSanitizationMode  `json:"ip_mode"`
	IPHashSalt            string              `json:"ip_hash_salt"`
	ArchiveInterval       time.Duration       `json:"archive_interval"`         // Default 24h, min 5m
	ArchiveGracePeriod    time.Duration       `json:"archive_grace_period"`     // Default 15m, < Interval
	ArchiveMaxObjectBytes int64               `json:"archive_max_object_bytes"` // Default 128MB
	ObjectStorage         *objectstore.Config `json:"object_storage,omitempty"`
}

// ArchiveManifest commits a closed window of audit events.
type ArchiveManifest struct {
	Version         int           `json:"version"`
	WindowStart     time.Time     `json:"window_start"`
	WindowEnd       time.Time     `json:"window_end"`
	EventCount      int64         `json:"event_count"`
	Compressed      bool          `json:"compressed"`
	CompletedAt     time.Time     `json:"completed_at"`
	FirstSequenceID int64         `json:"first_sequence_id,omitempty"`
	LastSequenceID  int64         `json:"last_sequence_id,omitempty"`
	ChainValid      bool          `json:"chain_valid"`
	Parts           []ArchivePart `json:"parts"`
}

// ArchivePart represents a single part file in object storage.
type ArchivePart struct {
	Key        string `json:"key"`
	EventCount int64  `json:"event_count"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}
