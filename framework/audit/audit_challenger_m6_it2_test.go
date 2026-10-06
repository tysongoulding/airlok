package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/objectstore"
)

const adversarialKeyM6It2 = "m6-it2-adversarial-secret-key-32bytes-min!"

// TestChallenger_VerifyChain_InjectedFakeEntries tests injecting fake entries
// at various positions with various sequence IDs to ensure VerifyChain always catches them.
func TestChallenger_VerifyChain_InjectedFakeEntries(t *testing.T) {
	ledger, err := NewLedger(Config{HMACKey: adversarialKeyM6It2})
	if err != nil {
		t.Fatalf("NewLedger error: %v", err)
	}

	for i := 1; i <= 10; i++ {
		_, err := ledger.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
		if err != nil {
			t.Fatalf("RecordEvent %d: %v", i, err)
		}
	}

	// Baseline check: intact chain
	valid, brokenAt := ledger.VerifyChain(1, 10)
	if !valid || brokenAt != 0 {
		t.Fatalf("expected intact chain to pass, got valid=%v, brokenAt=%d", valid, brokenAt)
	}

	// Scenario 1: Seq 999 injected at index 4 (between seq 4 and seq 5)
	t.Run("inject_seq999_at_index4", func(t *testing.T) {
		ledgerCopy, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
		for i := 1; i <= 10; i++ {
			_, _ = ledgerCopy.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
		}

		fake := &AuditEvent{
			ID:          "audit-fake-999",
			SequenceID:  999,
			Timestamp:   time.Now().UTC(),
			Action:      "hack",
			TargetType:  "role",
			TargetID:    "admin",
			InitiatorID: "hacker",
			ClientIP:    "1.2.3.4",
			Payload:     `{"root":true}`,
			PrevHash:    ledgerCopy.events[3].HMACSignature,
		}
		pDigest := sha256.Sum256([]byte(fake.Payload))
		fake.PayloadHash = hex.EncodeToString(pDigest[:])
		fake.HMACSignature = "fake-sig-999"

		ledgerCopy.mu.Lock()
		newEvents := make([]*AuditEvent, 0, 11)
		newEvents = append(newEvents, ledgerCopy.events[:4]...)
		newEvents = append(newEvents, fake)
		newEvents = append(newEvents, ledgerCopy.events[4:]...)
		ledgerCopy.events = newEvents
		ledgerCopy.mu.Unlock()

		v, b := ledgerCopy.VerifyChain(1, 10)
		if v {
			t.Fatalf("expected VerifyChain to fail on injected seq 999 at index 4")
		}
		if b != 5 {
			t.Fatalf("expected brokenAt=5, got %d", b)
		}
	})

	// Scenario 2: Duplicate seq 4 injected at index 4
	t.Run("inject_duplicate_seq4_at_index4", func(t *testing.T) {
		ledgerCopy, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
		for i := 1; i <= 10; i++ {
			_, _ = ledgerCopy.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
		}

		fake := ledgerCopy.events[3].Clone()
		ledgerCopy.mu.Lock()
		newEvents := make([]*AuditEvent, 0, 11)
		newEvents = append(newEvents, ledgerCopy.events[:4]...)
		newEvents = append(newEvents, fake)
		newEvents = append(newEvents, ledgerCopy.events[4:]...)
		ledgerCopy.events = newEvents
		ledgerCopy.mu.Unlock()

		v, b := ledgerCopy.VerifyChain(1, 10)
		if v {
			t.Fatalf("expected VerifyChain to fail on duplicate seq 4 at index 4")
		}
		if b != 5 {
			t.Fatalf("expected brokenAt=5, got %d", b)
		}
	})

	// Scenario 3: Injected seq 0 at index 4
	t.Run("inject_seq0_at_index4", func(t *testing.T) {
		ledgerCopy, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
		for i := 1; i <= 10; i++ {
			_, _ = ledgerCopy.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
		}

		fake := ledgerCopy.events[3].Clone()
		fake.SequenceID = 0

		ledgerCopy.mu.Lock()
		newEvents := make([]*AuditEvent, 0, 11)
		newEvents = append(newEvents, ledgerCopy.events[:4]...)
		newEvents = append(newEvents, fake)
		newEvents = append(newEvents, ledgerCopy.events[4:]...)
		ledgerCopy.events = newEvents
		ledgerCopy.mu.Unlock()

		v, b := ledgerCopy.VerifyChain(1, 10)
		if v {
			t.Fatalf("expected VerifyChain to fail on seq 0 at index 4")
		}
		if b != 5 {
			t.Fatalf("expected brokenAt=5, got %d", b)
		}
	})
}

// TestChallenger_VerifyChain_TruncatedChainExhaustive tests truncating chains at every prefix.
func TestChallenger_VerifyChain_TruncatedChainExhaustive(t *testing.T) {
	for truncLen := 1; truncLen < 10; truncLen++ {
		t.Run(fmt.Sprintf("truncate_at_%d", truncLen), func(t *testing.T) {
			ledger, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
			for i := 1; i <= 10; i++ {
				_, _ = ledger.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
			}

			ledger.mu.Lock()
			ledger.events = ledger.events[:truncLen]
			ledger.mu.Unlock()

			valid, brokenAt := ledger.VerifyChain(1, 10)
			if valid {
				t.Fatalf("expected VerifyChain to fail on chain truncated to %d events", truncLen)
			}
			expectedBroken := int64(truncLen + 1)
			if brokenAt != expectedBroken {
				t.Fatalf("expected brokenAt=%d, got %d", expectedBroken, brokenAt)
			}
		})
	}
}

// TestChallenger_VerifyChain_PrependedFakeEntry tests prepending an unauthenticated
// event before sequence 1.
func TestChallenger_VerifyChain_PrependedFakeEntry(t *testing.T) {
	ledger, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
	for i := 1; i <= 10; i++ {
		_, _ = ledger.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
	}

	fake := &AuditEvent{
		ID:            "audit-fake-0",
		SequenceID:    0,
		Timestamp:     time.Now().UTC(),
		Action:        "prepended",
		TargetType:    "sys",
		TargetID:      "sys1",
		InitiatorID:   "hacker",
		ClientIP:      "1.2.3.4",
		Payload:       "{}",
		PrevHash:      GenesisPrevHash,
		HMACSignature: "fake-sig-prepend",
	}

	ledger.mu.Lock()
	ledger.events = append([]*AuditEvent{fake}, ledger.events...)
	ledger.mu.Unlock()

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if valid {
		t.Fatalf("expected VerifyChain to fail on prepended event")
	}
	if brokenAt != 1 {
		t.Fatalf("expected brokenAt=1, got %d", brokenAt)
	}
}

// TestChallenger_VerifyChain_BoundaryClamping verifies boundary normalization and clamping.
func TestChallenger_VerifyChain_BoundaryClamping(t *testing.T) {
	ledger, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
	for i := 1; i <= 50; i++ {
		_, _ = ledger.RecordEvent("action", "target", fmt.Sprintf("t-%d", i), "admin", "10.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
	}

	// 1. VerifyChain(40, 100) -> to > lastSequenceID, detects missing tail, valid = false, brokenAt = 51
	v, b := ledger.VerifyChain(40, 100)
	if v || b != 51 {
		t.Fatalf("VerifyChain(40, 100) should detect tail truncation at 51: v=%v, b=%d", v, b)
	}

	// VerifyChain(40, 0) defaults to head (50) and passes
	vHead, bHead := ledger.VerifyChain(40, 0)
	if !vHead || bHead != 0 {
		t.Fatalf("VerifyChain(40, 0) should verify to head and pass: v=%v, b=%d", vHead, bHead)
	}

	// 2. VerifyChain(0, 10) -> from normalized to 1, passes
	v, b = ledger.VerifyChain(0, 10)
	if !v || b != 0 {
		t.Fatalf("VerifyChain(0, 10) should normalize from=1 and pass: v=%v, b=%d", v, b)
	}

	// 3. VerifyChain(-10, -5) -> from=1, to=50, passes
	v, b = ledger.VerifyChain(-10, -5)
	if !v || b != 0 {
		t.Fatalf("VerifyChain(-10, -5) should normalize to 1..50 and pass: v=%v, b=%d", v, b)
	}

	// 4. VerifyChain(10, 5) -> from > to, fails with brokenAt=10
	v, b = ledger.VerifyChain(10, 5)
	if v || b != 10 {
		t.Fatalf("VerifyChain(10, 5) should fail with brokenAt=10: v=%v, b=%d", v, b)
	}

	// 5. VerifyChain(1, 1) -> single event passes
	v, b = ledger.VerifyChain(1, 1)
	if !v || b != 0 {
		t.Fatalf("VerifyChain(1, 1) should pass: v=%v, b=%d", v, b)
	}

	// 6. VerifyChain(50, 50) -> last single event passes
	v, b = ledger.VerifyChain(50, 50)
	if !v || b != 0 {
		t.Fatalf("VerifyChain(50, 50) should pass: v=%v, b=%d", v, b)
	}

	// 7. VerifyChain(51, 60) -> out of bounds from, fails
	v, b = ledger.VerifyChain(51, 60)
	if v {
		t.Fatalf("VerifyChain(51, 60) should fail: v=%v, b=%d", v, b)
	}

	// 8. Empty ledger VerifyChain: to=10 fails because records are missing, to=0 passes
	emptyLedger, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})
	v, b = emptyLedger.VerifyChain(1, 10)
	if v || b != 1 {
		t.Fatalf("empty ledger VerifyChain(1, 10) should return (false, 1): v=%v, b=%d", v, b)
	}
	v0, b0 := emptyLedger.VerifyChain(1, 0)
	if !v0 || b0 != 0 {
		t.Fatalf("empty ledger VerifyChain(1, 0) should return (true, 0): v=%v, b=%d", v0, b0)
	}
}

// TestChallenger_ConcurrentLedgerAndVerification_500Goroutines exercises
// 500 concurrent goroutines performing writes, reads, and chain verifications simultaneously.
func TestChallenger_ConcurrentLedgerAndVerification_500Goroutines(t *testing.T) {
	ledger, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})

	const totalGoroutines = 500
	var wg sync.WaitGroup
	wg.Add(totalGoroutines)

	startBarrier := make(chan struct{})

	for g := 0; g < totalGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			<-startBarrier

			if id%3 == 0 {
				// Reader: GetEvents
				for i := 0; i < 5; i++ {
					_, _ = ledger.GetEvents(1, 100)
					time.Sleep(1 * time.Millisecond)
				}
			} else if id%3 == 1 {
				// Verifier: VerifyChain
				for i := 0; i < 5; i++ {
					_, _ = ledger.VerifyChain(1, 50)
					time.Sleep(1 * time.Millisecond)
				}
			} else {
				// Writer: RecordEvent
				for i := 0; i < 5; i++ {
					_, err := ledger.RecordEvent(
						"concurrent_op",
						"resource",
						fmt.Sprintf("res-%d-%d", id, i),
						fmt.Sprintf("user-%d", id),
						"10.0.0.1",
						fmt.Sprintf(`{"g":%d,"i":%d}`, id, i),
					)
					if err != nil {
						t.Errorf("routine %d write %d error: %v", id, i, err)
					}
				}
			}
		}(g)
	}

	close(startBarrier)
	wg.Wait()

	ledger.mu.RLock()
	totalEvents := int64(len(ledger.events))
	ledger.mu.RUnlock()

	if totalEvents == 0 {
		t.Fatalf("expected events recorded")
	}

	valid, brokenAt := ledger.VerifyChain(1, totalEvents)
	if !valid || brokenAt != 0 {
		t.Fatalf("chain failed verification after 500 concurrent goroutines: v=%v, brokenAt=%d", valid, brokenAt)
	}
}

// TestChallenger_Archiver_DetectsTamperedChainInWindow verifies that
// ArchiveWindow detects when a chain inside the window has been tampered with
// and flags ChainValid = false in the resulting manifest.
func TestChallenger_Archiver_DetectsTamperedChainInWindow(t *testing.T) {
	store := objectstore.NewInMemoryObjectStore()
	ledger, _ := NewLedger(Config{HMACKey: adversarialKeyM6It2})

	windowStart := time.Now().UTC().Add(-2 * time.Hour)
	windowEnd := windowStart.Add(1 * time.Hour)
	eventTime := windowStart.Add(20 * time.Minute)

	for i := 1; i <= 5; i++ {
		_, _ = ledger.RecordEventWithTimestamp(eventTime, "action", "target", fmt.Sprintf("t-%d", i), "admin", "127.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
	}

	// Tamper event 3 in ledger
	ledger.mu.Lock()
	ledger.events[2].Payload = `{"tampered":true}`
	ledger.mu.Unlock()

	archiver, err := NewArchiver(ledger, store, Config{
		ArchiveInterval:    1 * time.Hour,
		ArchiveGracePeriod: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewArchiver error: %v", err)
	}

	manifest, err := archiver.ArchiveWindow(context.Background(), windowStart, windowEnd)
	if err != nil {
		t.Fatalf("ArchiveWindow error: %v", err)
	}

	if manifest.ChainValid {
		t.Fatalf("expected manifest.ChainValid to be false for tampered chain in window!")
	}
}
