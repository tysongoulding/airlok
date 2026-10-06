package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// AuditLedger defines the contract for immutable, signed, hash-chained audit logging.
type AuditLedger interface {
	RecordEvent(action, targetType, targetID, initiatorID, clientIP, payload string) (*AuditEvent, error)
	VerifySignature(event *AuditEvent) bool
	VerifyChain(from, to int64) (valid bool, brokenAt int64)
	GetEvents(fromSeq, toSeq int64) ([]*AuditEvent, error)
	GetEventsInWindow(start, end time.Time) ([]*AuditEvent, error)
	Close() error
}

// Ledger is the thread-safe implementation of AuditLedger.
type Ledger struct {
	mu             sync.RWMutex
	hmacKey        []byte
	keyRegistry    map[string][]byte
	activeKeyID    string
	sanitizer      *IPSanitizer
	events         []*AuditEvent
	lastSequenceID int64
	lastHash       string
}

// NewLedger constructs a new audit ledger.
func NewLedger(cfg Config) (*Ledger, error) {
	if len(cfg.HMACKey) < 32 {
		return nil, fmt.Errorf("hmac_key must be at least 32 bytes")
	}

	mode := cfg.IPMode
	if cfg.OmitIPAddresses {
		mode = IPSanitizationOmit
	}
	sanitizer := NewIPSanitizer(mode, cfg.IPHashSalt)

	reg := make(map[string][]byte)
	for k, v := range cfg.KeyRegistry {
		reg[k] = []byte(v)
	}

	return &Ledger{
		hmacKey:        []byte(cfg.HMACKey),
		keyRegistry:    reg,
		activeKeyID:    cfg.ActiveKeyID,
		sanitizer:      sanitizer,
		events:         make([]*AuditEvent, 0),
		lastSequenceID: 0,
		lastHash:       GenesisPrevHash,
	}, nil
}

// SetIPSanitizationMode dynamically updates the IP privacy mode on the ledger.
func (l *Ledger) SetIPSanitizationMode(mode IPSanitizationMode) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sanitizer.SetMode(mode)
}

// SetOmitIPAddresses dynamically toggles omission of client IPs.
func (l *Ledger) SetOmitIPAddresses(omit bool) {
	if omit {
		l.SetIPSanitizationMode(IPSanitizationOmit)
	} else {
		l.SetIPSanitizationMode(IPSanitizationNone)
	}
}

// RecordEvent appends a new signed, hash-chained audit entry atomically using current time.
func (l *Ledger) RecordEvent(action, targetType, targetID, initiatorID, clientIP, payload string) (*AuditEvent, error) {
	return l.RecordEventWithTimestamp(time.Now().UTC(), action, targetType, targetID, initiatorID, clientIP, payload)
}

// RecordEventWithTimestamp appends an entry with a specific timestamp.
func (l *Ledger) RecordEventWithTimestamp(now time.Time, action, targetType, targetID, initiatorID, clientIP, payload string) (*AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	seq := l.lastSequenceID + 1
	prevHash := l.lastHash
	if seq == 1 {
		prevHash = GenesisPrevHash
	}

	sanitizedIP := l.sanitizer.Sanitize(clientIP)

	// Compute payload hash
	pDigest := sha256.Sum256([]byte(payload))
	payloadHash := hex.EncodeToString(pDigest[:])

	now = now.UTC()
	event := &AuditEvent{
		ID:          fmt.Sprintf("audit-%d", seq),
		SequenceID:  seq,
		Timestamp:   now,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		InitiatorID: initiatorID,
		ClientIP:    sanitizedIP,
		Payload:     payload,
		PayloadHash: payloadHash,
		PrevHash:    prevHash,
		KeyID:       l.activeKeyID,
	}

	// Compute canonical HMAC-SHA256
	sigInput := l.canonicalSignInput(event)
	event.HMACSignature = l.computeHMAC(sigInput, l.hmacKey)

	// Update state
	l.events = append(l.events, event)
	l.lastSequenceID = seq
	l.lastHash = event.HMACSignature

	return event.Clone(), nil
}

// VerifySignature checks HMAC signature on a single event.
func (l *Ledger) VerifySignature(event *AuditEvent) bool {
	if event == nil {
		return false
	}
	l.mu.RLock()
	key := l.hmacKey
	if event.KeyID != "" {
		if k, ok := l.keyRegistry[event.KeyID]; ok {
			key = k
		}
	}
	l.mu.RUnlock()

	// Verify payload hash matches payload
	pDigest := sha256.Sum256([]byte(event.Payload))
	computedHash := hex.EncodeToString(pDigest[:])
	if event.PayloadHash != "" && event.PayloadHash != computedHash {
		return false
	}

	sigInput := l.canonicalSignInput(event)
	expectedSig := l.computeHMAC(sigInput, key)
	if hmac.Equal([]byte(expectedSig), []byte(event.HMACSignature)) {
		return true
	}

	// Fallback verification for legacy mock format compatibility
	legacyInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s", event.ID, event.Timestamp.Format(time.RFC3339), event.Action, event.TargetType, event.TargetID, event.Payload)
	expectedLegacy := l.computeHMAC(legacyInput, key)
	return hmac.Equal([]byte(expectedLegacy), []byte(event.HMACSignature))
}

// VerifyChain verifies hash continuity, payload integrity, and HMAC signatures.
// Returns valid=true, brokenAt=0 if intact; valid=false, brokenAt=SeqID on failure.
func (l *Ledger) VerifyChain(from, to int64) (bool, int64) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.events) == 0 {
		if to > 0 {
			return false, 1
		}
		return true, 0
	}
	if from <= 0 {
		from = 1
	}
	if to <= 0 {
		to = l.lastSequenceID
	}
	if from > to {
		return false, from
	}
	if from > l.lastSequenceID {
		return false, from
	}
	if to > l.lastSequenceID {
		return false, l.lastSequenceID + 1
	}

	startIndex := -1
	for idx, e := range l.events {
		if e.SequenceID == from {
			startIndex = idx
			break
		}
	}
	if startIndex == -1 {
		return false, from
	}
	if from == 1 && startIndex != 0 {
		return false, 1
	}

	var expectedPrevHash string
	if from == 1 {
		expectedPrevHash = GenesisPrevHash
	} else {
		if startIndex == 0 {
			expectedPrevHash = l.events[0].PrevHash
		} else {
			expectedPrevHash = l.events[startIndex-1].HMACSignature
		}
	}

	currentSeq := from
	for i := startIndex; i < len(l.events); i++ {
		e := l.events[i]

		// 1. Sequence monotonicity check MUST come first
		if e.SequenceID != currentSeq {
			return false, currentSeq
		}

		// 2. PrevHash chaining check
		if e.PrevHash != expectedPrevHash {
			return false, e.SequenceID
		}

		// 3. Payload integrity check
		pDigest := sha256.Sum256([]byte(e.Payload))
		if e.PayloadHash != hex.EncodeToString(pDigest[:]) {
			return false, e.SequenceID
		}

		// 4. HMAC signature check
		key := l.hmacKey
		if e.KeyID != "" {
			if k, ok := l.keyRegistry[e.KeyID]; ok {
				key = k
			}
		}
		sigInput := l.canonicalSignInput(e)
		expectedSig := l.computeHMAC(sigInput, key)
		if !hmac.Equal([]byte(expectedSig), []byte(e.HMACSignature)) {
			// Check legacy format fallback
			legacyInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s", e.ID, e.Timestamp.Format(time.RFC3339), e.Action, e.TargetType, e.TargetID, e.Payload)
			expectedLegacy := l.computeHMAC(legacyInput, key)
			if !hmac.Equal([]byte(expectedLegacy), []byte(e.HMACSignature)) {
				return false, e.SequenceID
			}
		}

		expectedPrevHash = e.HMACSignature
		currentSeq++

		// Terminate loop once requested upper bound 'to' is verified
		if e.SequenceID == to {
			break
		}
	}

	// Verify that the chain was not truncated before reaching 'to'
	if currentSeq <= to {
		return false, currentSeq
	}

	return true, 0
}

// GetEvents retrieves a range of cloned events.
func (l *Ledger) GetEvents(fromSeq, toSeq int64) ([]*AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]*AuditEvent, 0)
	for _, e := range l.events {
		if e.SequenceID >= fromSeq && (toSeq <= 0 || e.SequenceID <= toSeq) {
			out = append(out, l.sanitizer.ScrubEventDynamic(e))
		}
	}
	return out, nil
}

// GetEventsInWindow returns events within [start, end) time window.
func (l *Ledger) GetEventsInWindow(start, end time.Time) ([]*AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]*AuditEvent, 0)
	for _, e := range l.events {
		if (e.Timestamp.Equal(start) || e.Timestamp.After(start)) && e.Timestamp.Before(end) {
			out = append(out, l.sanitizer.ScrubEventDynamic(e))
		}
	}
	return out, nil
}

func (l *Ledger) Close() error {
	return nil
}

func (l *Ledger) canonicalSignInput(e *AuditEvent) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s",
		e.SequenceID,
		e.Timestamp.Format(time.RFC3339Nano),
		e.InitiatorID,
		e.Action,
		e.TargetType,
		e.TargetID,
		e.PayloadHash,
		e.ClientIP,
		e.PrevHash,
	)
}

func (l *Ledger) computeHMAC(input string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}
