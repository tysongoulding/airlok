package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

const challengerSecretKey = "adversarial-stress-key-at-least-32-bytes-long!"

// ============================================================================
// 1. TAMPER DETECTION: BIT-FLIPS, INSERTIONS, DELETIONS, PREVHASH BREAKS
// ============================================================================

func setupTestChain(t *testing.T, count int) (*Ledger, []*AuditEvent) {
	t.Helper()
	ledger, err := NewLedger(Config{HMACKey: challengerSecretKey})
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	events := make([]*AuditEvent, count)
	for i := 1; i <= count; i++ {
		e, err := ledger.RecordEvent(
			"mutate",
			"config",
			fmt.Sprintf("cfg-%d", i),
			fmt.Sprintf("user-%d", i),
			"192.168.1.10",
			fmt.Sprintf(`{"index": %d, "data": "payload-%d"}`, i, i),
		)
		if err != nil {
			t.Fatalf("failed to record event %d: %v", i, err)
		}
		events[i-1] = e
	}

	// Verify intact chain first
	valid, brokenAt := ledger.VerifyChain(1, int64(count))
	if !valid || brokenAt != 0 {
		t.Fatalf("initial chain failed verification: valid=%v, brokenAt=%d", valid, brokenAt)
	}
	return ledger, events
}

// TestAudit_Tamper_BitFlipPayload tests altering a single bit/byte in payload.
func TestAudit_Tamper_BitFlipPayload(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	// Bit-flip payload at seq 5 (index 4)
	ledger.mu.Lock()
	ledger.events[4].Payload = `{"index": 5, "data": "payload-5-corrupted"}`
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on bit-flipped payload")
	}
	if brokenAt != 5 {
		t.Fatalf("expected brokenAt=5, got %d", brokenAt)
	}
}

// TestAudit_Tamper_BitFlipPayloadDigest tests altering payload hash while payload stays same.
func TestAudit_Tamper_BitFlipPayloadDigest(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	// Tamper PayloadHash directly
	ledger.mu.Lock()
	ledger.events[2].PayloadHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid || brokenAt != 3 {
		t.Fatalf("expected brokenAt=3 on altered payload digest, got valid=%v, brokenAt=%d", valid, brokenAt)
	}
}

// TestAudit_Tamper_AlterPrevHash tests altering PrevHash at sequence 6.
func TestAudit_Tamper_AlterPrevHash(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	ledger.mu.Lock()
	ledger.events[5].PrevHash = "bad0000000000000000000000000000000000000000000000000000000000000"
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on altered PrevHash")
	}
	if brokenAt != 6 {
		t.Fatalf("expected brokenAt=6, got %d", brokenAt)
	}
}

// TestAudit_Tamper_AlterGenesisPrevHash tests altering Genesis PrevHash at seq 1.
func TestAudit_Tamper_AlterGenesisPrevHash(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	ledger.mu.Lock()
	ledger.events[0].PrevHash = "bad0000000000000000000000000000000000000000000000000000000000000"
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid || brokenAt != 1 {
		t.Fatalf("expected brokenAt=1 on genesis prevhash tampering, got valid=%v, brokenAt=%d", valid, brokenAt)
	}
}

// TestAudit_Tamper_ReorderEntries tests swapping entry 4 and entry 5.
func TestAudit_Tamper_ReorderEntries(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	ledger.mu.Lock()
	ledger.events[3], ledger.events[4] = ledger.events[4], ledger.events[3]
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on reordered entries")
	}
	// At index 3, the event has SequenceID 5 instead of expected 4
	if brokenAt != 4 {
		t.Fatalf("expected brokenAt=4 on reordering, got %d", brokenAt)
	}
}

// TestAudit_Tamper_InsertFakeEntry_MatchingSeq tests inserting a fabricated entry with SequenceID=5.
func TestAudit_Tamper_InsertFakeEntry_MatchingSeq(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	fakeEvent := &AuditEvent{
		ID:          "audit-fake",
		SequenceID:  5,
		Timestamp:   time.Now().UTC(),
		Action:      "hack",
		TargetType:  "role",
		TargetID:    "admin",
		InitiatorID: "attacker",
		ClientIP:    "1.2.3.4",
		Payload:     `{"root": true}`,
		PrevHash:    ledger.events[3].HMACSignature,
	}
	pDigest := sha256.Sum256([]byte(fakeEvent.Payload))
	fakeEvent.PayloadHash = hex.EncodeToString(pDigest[:])
	fakeEvent.HMACSignature = "fake-sig-1234567890abcdef"

	ledger.mu.Lock()
	// Insert fakeEvent between index 3 and 4
	newEvents := make([]*AuditEvent, 0, 11)
	newEvents = append(newEvents, ledger.events[:4]...)
	newEvents = append(newEvents, fakeEvent)
	newEvents = append(newEvents, ledger.events[4:]...)
	ledger.events = newEvents
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on fake entry insertion with SequenceID=5")
	}
	if brokenAt != 5 {
		t.Fatalf("expected brokenAt=5 on fake insertion, got %d", brokenAt)
	}
}

// TestAudit_Tamper_InsertFakeEntry_EarlyBreakBypass demonstrates that inserting an entry
// with SequenceID > to (e.g. 999) causes VerifyChain to break early and falsely return valid=true.
func TestAudit_Tamper_InsertFakeEntry_EarlyBreakBypass(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	fakeEvent := &AuditEvent{
		ID:          "audit-fake-bypass",
		SequenceID:  999,
		Timestamp:   time.Now().UTC(),
		Action:      "hack",
		TargetType:  "role",
		TargetID:    "admin",
		InitiatorID: "attacker",
		ClientIP:    "1.2.3.4",
		Payload:     `{"root": true}`,
		PrevHash:    ledger.events[3].HMACSignature,
	}
	pDigest := sha256.Sum256([]byte(fakeEvent.Payload))
	fakeEvent.PayloadHash = hex.EncodeToString(pDigest[:])
	fakeEvent.HMACSignature = "fake-sig-1234567890abcdef"

	ledger.mu.Lock()
	// Insert fakeEvent between index 3 and 4
	newEvents := make([]*AuditEvent, 0, 11)
	newEvents = append(newEvents, ledger.events[:4]...)
	newEvents = append(newEvents, fakeEvent)
	newEvents = append(newEvents, ledger.events[4:]...)
	ledger.events = newEvents
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on fake entry with SequenceID > to, got valid=true")
	}
	if brokenAt != 5 {
		t.Fatalf("expected brokenAt=5 on fake entry with SequenceID=999, got %d", brokenAt)
	}
}

// TestAudit_Tamper_TruncatedChain verifies that truncating the chain before reaching
// the target 'to' sequence is detected and reports the missing sequence ID.
func TestAudit_Tamper_TruncatedChain(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	ledger.mu.Lock()
	// Truncate events from 10 to 5 while lastSequenceID remains 10
	ledger.events = ledger.events[:5]
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on truncated chain, got valid=true")
	}
	if brokenAt != 6 {
		t.Fatalf("expected brokenAt=6 on truncated chain (first missing event), got %d", brokenAt)
	}
}

// TestAudit_Tamper_PrependFakeEntry verifies that inserting an entry before genesis sequence 1 fails.
func TestAudit_Tamper_PrependFakeEntry(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	fakeEvent := &AuditEvent{
		ID:            "audit-fake-prepend",
		SequenceID:    999,
		Timestamp:     time.Now().UTC(),
		Action:        "hack",
		TargetType:    "role",
		TargetID:      "admin",
		InitiatorID:   "attacker",
		ClientIP:      "1.2.3.4",
		Payload:       `{"root": true}`,
		PrevHash:      GenesisPrevHash,
		HMACSignature: "fake-sig-prepend",
	}

	ledger.mu.Lock()
	ledger.events = append([]*AuditEvent{fakeEvent}, ledger.events...)
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on prepended fake entry")
	}
	if brokenAt != 1 {
		t.Fatalf("expected brokenAt=1 on prepended fake entry, got %d", brokenAt)
	}
}

// TestAudit_Tamper_DeleteEntry tests deleting an entry from the middle of the chain.
func TestAudit_Tamper_DeleteEntry(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	ledger.mu.Lock()
	// Remove entry at index 4 (SequenceID 5)
	ledger.events = append(ledger.events[:4], ledger.events[5:]...)
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on deleted entry")
	}
	// Expected seq at index 4 is 5, but following item has SequenceID 6
	if brokenAt != 5 {
		t.Fatalf("expected brokenAt=5 on deletion, got %d", brokenAt)
	}
}

// TestAudit_Tamper_AlterHMACSignature tests flipping bits in the HMAC signature.
func TestAudit_Tamper_AlterHMACSignature(t *testing.T) {
	ledger, _ := setupTestChain(t, 10)

	ledger.mu.Lock()
	sigBytes := []byte(ledger.events[2].HMACSignature)
	if sigBytes[0] == 'a' {
		sigBytes[0] = 'b'
	} else {
		sigBytes[0] = 'a'
	}
	ledger.events[2].HMACSignature = string(sigBytes)
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid || brokenAt != 3 {
		t.Fatalf("expected brokenAt=3 on altered signature, got valid=%v, brokenAt=%d", valid, brokenAt)
	}
}

// TestAudit_Tamper_AlterMetadataFields tests altering Timestamp, Action, TargetID, InitiatorID.
func TestAudit_Tamper_AlterMetadataFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(e *AuditEvent)
		targetSeq int64
	}{
		{
			name: "alter timestamp",
			mutate: func(e *AuditEvent) {
				e.Timestamp = e.Timestamp.Add(5 * time.Minute)
			},
			targetSeq: 4,
		},
		{
			name: "alter action",
			mutate: func(e *AuditEvent) {
				e.Action = "unauthorized_action"
			},
			targetSeq: 4,
		},
		{
			name: "alter initiator",
			mutate: func(e *AuditEvent) {
				e.InitiatorID = "hacker"
			},
			targetSeq: 4,
		},
		{
			name: "alter target_type",
			mutate: func(e *AuditEvent) {
				e.TargetType = "super_admin"
			},
			targetSeq: 4,
		},
		{
			name: "alter target_id",
			mutate: func(e *AuditEvent) {
				e.TargetID = "compromised-target"
			},
			targetSeq: 4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ledger, _ := setupTestChain(t, 10)
			idx := tc.targetSeq - 1

			ledger.mu.Lock()
			tc.mutate(ledger.events[idx])
			ledger.mu.Unlock()

			valid, brokenAt := ledger.VerifyChain(1, 10)
			if valid || brokenAt != tc.targetSeq {
				t.Fatalf("expected brokenAt=%d on %s, got valid=%v, brokenAt=%d", tc.targetSeq, tc.name, valid, brokenAt)
			}
		})
	}
}

// ============================================================================
// 2. HEAVY CONCURRENCY STRESS TEST: 500 GOROUTINES UNDER -RACE
// ============================================================================

func TestAudit_HeavyConcurrency_500Goroutines(t *testing.T) {
	ledger, err := NewLedger(Config{HMACKey: challengerSecretKey})
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}

	const totalGoroutines = 500
	const eventsPerGoroutine = 10
	const totalExpectedEvents = totalGoroutines * eventsPerGoroutine // 5000 events

	var wg sync.WaitGroup
	wg.Add(totalGoroutines)

	startBarrier := make(chan struct{})

	for g := 0; g < totalGoroutines; g++ {
		go func(routineID int) {
			defer wg.Done()
			<-startBarrier // synchronize high-pressure burst

			for i := 0; i < eventsPerGoroutine; i++ {
				_, err := ledger.RecordEvent(
					"burst_action",
					"virtual_key",
					fmt.Sprintf("vk-g%d-%d", routineID, i),
					fmt.Sprintf("user-g%d", routineID),
					"10.0.1.5",
					fmt.Sprintf(`{"g": %d, "i": %d, "ts": "%s"}`, routineID, i, time.Now().UTC().Format(time.RFC3339Nano)),
				)
				if err != nil {
					t.Errorf("routine %d event %d error: %v", routineID, i, err)
					return
				}
			}
		}(g)
	}

	// Release all 500 goroutines simultaneously
	close(startBarrier)
	wg.Wait()

	// 1. Verify sequence count
	ledger.mu.RLock()
	actualCount := int64(len(ledger.events))
	lastSeq := ledger.lastSequenceID
	ledger.mu.RUnlock()

	if actualCount != totalExpectedEvents {
		t.Fatalf("expected %d events in ledger, got %d", totalExpectedEvents, actualCount)
	}
	if lastSeq != totalExpectedEvents {
		t.Fatalf("expected lastSequenceID=%d, got %d", totalExpectedEvents, lastSeq)
	}

	// 2. Verify monotonic sequential sequence continuity
	ledger.mu.RLock()
	for i := int64(0); i < actualCount; i++ {
		expectedSeq := i + 1
		if ledger.events[i].SequenceID != expectedSeq {
			ledger.mu.RUnlock()
			t.Fatalf("sequence discontinuity at index %d: expected %d, got %d", i, expectedSeq, ledger.events[i].SequenceID)
		}
	}
	ledger.mu.RUnlock()

	// 3. Verify complete chain integrity from sequence 1 to 5000
	valid, brokenAt := ledger.VerifyChain(1, totalExpectedEvents)
	if !valid || brokenAt != 0 {
		t.Fatalf("chain verification failed after 500 concurrent goroutines: valid=%v, brokenAt=%d", valid, brokenAt)
	}
}

// ============================================================================
// 3. IP SANITIZER EDGE CASES & QUERY-TIME SCRUBBING
// ============================================================================

func TestAudit_IPSanitizer_AllEdgeCases(t *testing.T) {
	salt := "test-salt-12345"
	maskSanitizer := NewIPSanitizer(IPSanitizationMask, salt)
	hashSanitizer := NewIPSanitizer(IPSanitizationHash, salt)
	omitSanitizer := NewIPSanitizer(IPSanitizationOmit, salt)
	noneSanitizer := NewIPSanitizer(IPSanitizationNone, salt)

	tests := []struct {
		input        string
		expectMask   string
		expectOmit   string
		expectNone   string
		validateHash func(t *testing.T, res string)
	}{
		{
			input:      "192.168.1.50",
			expectMask: "192.168.1.0", // /24 CIDR
			expectOmit: "",
			expectNone: "192.168.1.50",
			validateHash: func(t *testing.T, res string) {
				if len(res) < 10 || res[:8] != "anon-ip-" {
					t.Fatalf("invalid hash pseudonym: %s", res)
				}
			},
		},
		{
			input:      "10.200.30.99",
			expectMask: "10.200.30.0",
			expectOmit: "",
			expectNone: "10.200.30.99",
		},
		{
			input:      "127.0.0.1",
			expectMask: "127.0.0.0", // loopback IPv4
			expectOmit: "",
			expectNone: "127.0.0.1",
		},
		{
			input:      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expectMask: "2001:db8:85a3::", // /48 CIDR
			expectOmit: "",
			expectNone: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			validateHash: func(t *testing.T, res string) {
				if len(res) < 10 || res[:8] != "anon-ip-" {
					t.Fatalf("invalid IPv6 hash: %s", res)
				}
			},
		},
		{
			input:      "::1",
			expectMask: "::", // IPv6 loopback masked with /48
			expectOmit: "",
			expectNone: "::1",
		},
		{
			input:      "fe80::1",
			expectMask: "fe80::", // IPv6 link-local
			expectOmit: "",
			expectNone: "fe80::1",
		},
		{
			input:      "::ffff:192.0.2.128", // IPv4-mapped IPv6
			expectMask: "192.0.2.0",
			expectOmit: "",
			expectNone: "::ffff:192.0.2.128",
		},
		{
			input:      "invalid-ip-string",
			expectMask: "", // invalid IPs produce empty under mask
			expectOmit: "",
			expectNone: "invalid-ip-string",
		},
		{
			input:      "999.999.999.999",
			expectMask: "",
			expectOmit: "",
			expectNone: "999.999.999.999",
		},
		{
			input:      "",
			expectMask: "",
			expectOmit: "",
			expectNone: "",
		},
		{
			input:      "   192.168.1.1   ",
			expectMask: "192.168.1.0", // whitespace trimmed
			expectOmit: "",
			expectNone: "192.168.1.1",
		},
	}

	for _, tc := range tests {
		t.Run("input="+tc.input, func(t *testing.T) {
			mRes := maskSanitizer.Sanitize(tc.input)
			if mRes != tc.expectMask {
				t.Errorf("mask mismatch for %q: expected %q, got %q", tc.input, tc.expectMask, mRes)
			}

			oRes := omitSanitizer.Sanitize(tc.input)
			if oRes != tc.expectOmit {
				t.Errorf("omit mismatch for %q: expected %q, got %q", tc.input, tc.expectOmit, oRes)
			}

			nRes := noneSanitizer.Sanitize(tc.input)
			if nRes != tc.expectNone {
				t.Errorf("none mismatch for %q: expected %q, got %q", tc.input, tc.expectNone, nRes)
			}

			if tc.validateHash != nil {
				hRes := hashSanitizer.Sanitize(tc.input)
				tc.validateHash(t, hRes)
			}
		})
	}
}

// TestAudit_QueryTimeScrubbing_DynamicWithoutBreakingChain verifies that
// GetEvents dynamically scrubs IPs when omit is enabled without mutating
// the internal ledger records or breaking chain cryptographic validity.
func TestAudit_QueryTimeScrubbing_DynamicWithoutBreakingChain(t *testing.T) {
	ledger, err := NewLedger(Config{
		HMACKey:         challengerSecretKey,
		OmitIPAddresses: false, // Initially record real client IPs
	})
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}

	ips := []string{"192.168.1.1", "10.0.0.2", "172.16.5.9", "100.64.0.1"}
	for i, ip := range ips {
		_, err := ledger.RecordEvent("login", "user", fmt.Sprintf("u-%d", i), "admin", ip, `{"action": "test"}`)
		if err != nil {
			t.Fatalf("failed to record: %v", err)
		}
	}

	// 1. Initial query: real IPs returned
	initialEvents, err := ledger.GetEvents(1, 4)
	if err != nil {
		t.Fatalf("GetEvents error: %v", err)
	}
	for i, e := range initialEvents {
		if e.ClientIP != ips[i] {
			t.Fatalf("expected real IP %s, got %s", ips[i], e.ClientIP)
		}
		if !ledger.VerifySignature(e) {
			t.Fatalf("initial event %d signature must verify", e.SequenceID)
		}
	}

	// 2. Dynamically toggle IP omission (compliance mode activated)
	ledger.SetOmitIPAddresses(true)

	// 3. Query events again: returned copies MUST have ClientIP scrubbed
	scrubbedEvents, err := ledger.GetEvents(1, 4)
	if err != nil {
		t.Fatalf("GetEvents scrubbed error: %v", err)
	}
	for _, e := range scrubbedEvents {
		if e.ClientIP != "" {
			t.Fatalf("expected scrubbed ClientIP='', got: %s", e.ClientIP)
		}
	}

	// 4. Assert stored internal ledger records are UNTOUCHED
	ledger.mu.RLock()
	for i, stored := range ledger.events {
		if stored.ClientIP != ips[i] {
			ledger.mu.RUnlock()
			t.Fatalf("stored ledger event %d ClientIP was mutated! expected %s, got %s", stored.SequenceID, ips[i], stored.ClientIP)
		}
	}
	ledger.mu.RUnlock()

	// 5. Assert 100% chain validity is PRESERVED (cryptographic chain remains intact)
	valid, brokenAt := ledger.VerifyChain(1, 4)
	if !valid || brokenAt != 0 {
		t.Fatalf("VerifyChain failed after query scrubbing! brokenAt=%d", brokenAt)
	}

	// 6. Dynamically toggle IP omission OFF again
	ledger.SetOmitIPAddresses(false)
	restoredEvents, err := ledger.GetEvents(1, 4)
	if err != nil {
		t.Fatalf("GetEvents restored error: %v", err)
	}
	for i, e := range restoredEvents {
		if e.ClientIP != ips[i] {
			t.Fatalf("expected restored IP %s, got %s", ips[i], e.ClientIP)
		}
		if !ledger.VerifySignature(e) {
			t.Fatalf("restored event signature failed verification: seq=%d", e.SequenceID)
		}
	}
}

// TestAudit_KeyRotationRegistry verifies key rotation support with KeyID.
func TestAudit_KeyRotationRegistry(t *testing.T) {
	keyV1 := "key-version-1-at-least-32-bytes-long!"
	keyV2 := "key-version-2-at-least-32-bytes-long!"

	reg := map[string]string{
		"v1": keyV1,
		"v2": keyV2,
	}

	cfg := Config{
		HMACKey:     keyV1,
		KeyRegistry: reg,
		ActiveKeyID: "v1",
	}
	ledger, err := NewLedger(cfg)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}

	// Record with v1
	e1, err := ledger.RecordEvent("create", "key", "k1", "admin", "127.0.0.1", `{"k": 1}`)
	if err != nil || e1.KeyID != "v1" {
		t.Fatalf("expected KeyID v1, got %v", e1.KeyID)
	}

	// Rotate active key to v2
	ledger.mu.Lock()
	ledger.hmacKey = []byte(keyV2)
	ledger.activeKeyID = "v2"
	ledger.mu.Unlock()

	// Record with v2
	e2, err := ledger.RecordEvent("create", "key", "k2", "admin", "127.0.0.1", `{"k": 2}`)
	if err != nil || e2.KeyID != "v2" {
		t.Fatalf("expected KeyID v2, got %v", e2.KeyID)
	}

	// Both signatures verify with registry
	if !ledger.VerifySignature(e1) {
		t.Fatalf("e1 signed with v1 must verify using registry")
	}
	if !ledger.VerifySignature(e2) {
		t.Fatalf("e2 signed with v2 must verify using registry")
	}

	// Chain verification across rotated keys succeeds
	valid, brokenAt := ledger.VerifyChain(1, 2)
	if !valid || brokenAt != 0 {
		t.Fatalf("chain across rotated keys failed verification: brokenAt=%d", brokenAt)
	}
}
