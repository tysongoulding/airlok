package audit_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/audit"
	"github.com/maximhq/bifrost/framework/objectstore"
)

const testSecretKey = "super-secret-hmac-key-that-is-at-least-32-bytes!"

func TestAudit_HMAC_ChainIntegrity(t *testing.T) {
	ledger, err := audit.NewLedger(audit.Config{HMACKey: testSecretKey})
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}

	for i := 1; i <= 10; i++ {
		event, err := ledger.RecordEvent("create", "virtual_key", fmt.Sprintf("vk-%d", i), "admin", "192.168.1.1", "{}")
		if err != nil {
			t.Fatalf("failed to record: %v", err)
		}
		if event.HMACSignature == "" {
			t.Fatalf("HMAC signature must be non-empty")
		}
		if !ledger.VerifySignature(event) {
			t.Fatalf("signature verification failed on newly recorded event")
		}
	}

	valid, brokenAt := ledger.VerifyChain(1, 10)
	if !valid || brokenAt != 0 {
		t.Fatalf("expected valid chain, got brokenAt=%d", brokenAt)
	}
}

func TestAudit_TamperDetection_PayloadAndPrevHash(t *testing.T) {
	ledger, _ := audit.NewLedger(audit.Config{HMACKey: testSecretKey})
	e1, _ := ledger.RecordEvent("create", "role", "role-1", "admin", "127.0.0.1", `{"read": true}`)
	e2, _ := ledger.RecordEvent("update", "role", "role-1", "admin", "127.0.0.1", `{"write": true}`)

	// Untampered
	if !ledger.VerifySignature(e1) || !ledger.VerifySignature(e2) {
		t.Fatalf("valid signatures must verify")
	}

	// Tamper payload on e1
	e1Tampered := e1.Clone()
	e1Tampered.Payload = `{"admin": true}`
	if ledger.VerifySignature(e1Tampered) {
		t.Fatalf("tampered payload must fail signature verification")
	}

	// Tamper PrevHash on e2
	e2Tampered := e2.Clone()
	e2Tampered.PrevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if ledger.VerifySignature(e2Tampered) {
		t.Fatalf("tampered prev_hash must fail verification")
	}
}

func TestAudit_IPSanitization_OmitMaskHash(t *testing.T) {
	// 1. Omit
	ledgerOmit, _ := audit.NewLedger(audit.Config{HMACKey: testSecretKey, OmitIPAddresses: true})
	eOmit, _ := ledgerOmit.RecordEvent("login", "user", "u1", "u1", "192.168.1.50", "{}")
	if eOmit.ClientIP != "" {
		t.Fatalf("expected omitted IP, got %s", eOmit.ClientIP)
	}
	if !ledgerOmit.VerifySignature(eOmit) {
		t.Fatalf("signature on IP-omitted event must verify")
	}

	// 2. Mask
	ledgerMask, _ := audit.NewLedger(audit.Config{HMACKey: testSecretKey, IPMode: audit.IPSanitizationMask})
	eMask, _ := ledgerMask.RecordEvent("login", "user", "u1", "u1", "192.168.1.50", "{}")
	if eMask.ClientIP != "192.168.1.0" {
		t.Fatalf("expected masked IP 192.168.1.0, got %s", eMask.ClientIP)
	}

	// 3. Hash
	ledgerHash, _ := audit.NewLedger(audit.Config{HMACKey: testSecretKey, IPMode: audit.IPSanitizationHash, IPHashSalt: "audit-salt"})
	eHash, _ := ledgerHash.RecordEvent("login", "user", "u1", "u1", "192.168.1.50", "{}")
	if eHash.ClientIP == "192.168.1.50" || eHash.ClientIP == "" {
		t.Fatalf("expected hashed IP pseudonym, got %s", eHash.ClientIP)
	}
}

func TestAudit_HMACKeyLengthRejection(t *testing.T) {
	shortKey := "short-key-16-bytes"
	_, err := audit.NewLedger(audit.Config{HMACKey: shortKey})
	if err == nil {
		t.Fatalf("expected error when HMAC key is shorter than 32 bytes")
	}
}

func TestAudit_WindowedArchival_PartRollingAndManifest(t *testing.T) {
	ledger, _ := audit.NewLedger(audit.Config{HMACKey: testSecretKey})
	store := objectstore.NewInMemoryObjectStore()

	windowStart := time.Now().UTC().Add(-2 * time.Hour)
	windowEnd := windowStart.Add(1 * time.Hour)
	eventTime := windowStart.Add(10 * time.Minute)

	// Record events in window
	for i := 0; i < 20; i++ {
		_, _ = ledger.RecordEventWithTimestamp(eventTime, "update", "policy", fmt.Sprintf("p-%d", i), "admin", "10.0.0.1", `{"rules": ["block"]}`)
	}

	archiver, err := audit.NewArchiver(ledger, store, audit.Config{
		ArchiveInterval:       1 * time.Hour,
		ArchiveGracePeriod:    5 * time.Minute,
		ArchiveMaxObjectBytes: 500, // Small limit forces multiple parts
		ObjectStorage: &objectstore.Config{
			Prefix:   "compliance",
			Compress: false,
		},
	})
	if err != nil {
		t.Fatalf("failed to init archiver: %v", err)
	}

	manifest, err := archiver.ArchiveWindow(context.Background(), windowStart, windowEnd)
	if err != nil {
		t.Fatalf("archival failed: %v", err)
	}

	if manifest.EventCount != 20 {
		t.Fatalf("expected 20 events in manifest, got %d", manifest.EventCount)
	}
	if len(manifest.Parts) < 2 {
		t.Fatalf("expected part rolling (>1 part), got %d parts", len(manifest.Parts))
	}
}

func TestAudit_ConcurrentAppends_RaceDetector(t *testing.T) {
	ledger, _ := audit.NewLedger(audit.Config{HMACKey: testSecretKey})

	workers := 20
	eventsPerWorker := 30
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWorker; i++ {
				_, err := ledger.RecordEvent(
					"create", "virtual_key",
					fmt.Sprintf("vk-w%d-%d", workerID, i),
					fmt.Sprintf("user-%d", workerID),
					"10.0.0.1",
					`{"action": "test"}`,
				)
				if err != nil {
					t.Errorf("worker %d append error: %v", workerID, err)
				}
			}
		}(w)
	}

	wg.Wait()

	totalExpected := int64(workers * eventsPerWorker)
	valid, brokenAt := ledger.VerifyChain(1, totalExpected)
	if !valid || brokenAt != 0 {
		t.Fatalf("concurrent chain verification failed: brokenAt=%d", brokenAt)
	}
}
