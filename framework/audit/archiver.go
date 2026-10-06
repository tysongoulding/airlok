package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/maximhq/bifrost/framework/objectstore"
)

// Archiver manages windowed packaging of audit rows into JSONL objects in S3/GCS.
type Archiver struct {
	mu           sync.RWMutex
	ledger       AuditLedger
	store        objectstore.ObjectStore
	prefix       string
	compress     bool
	interval     time.Duration
	gracePeriod  time.Duration
	maxPartBytes int64
	watermark    time.Time
}

// NewArchiver instantiates a new windowed archiver.
func NewArchiver(ledger AuditLedger, store objectstore.ObjectStore, cfg Config) (*Archiver, error) {
	if ledger == nil || store == nil {
		return nil, fmt.Errorf("ledger and object store are required")
	}

	interval := cfg.ArchiveInterval
	if interval < 5*time.Minute {
		interval = 24 * time.Hour
	}
	grace := cfg.ArchiveGracePeriod
	if grace <= 0 || grace >= interval {
		grace = 15 * time.Minute
	}
	maxBytes := cfg.ArchiveMaxObjectBytes
	if maxBytes <= 0 {
		maxBytes = 134217728 // 128 MiB default
	}

	prefix := "bifrost"
	compress := false
	if cfg.ObjectStorage != nil {
		if cfg.ObjectStorage.Prefix != "" {
			prefix = cfg.ObjectStorage.Prefix
		}
		compress = cfg.ObjectStorage.Compress
	}

	return &Archiver{
		ledger:       ledger,
		store:        store,
		prefix:       prefix,
		compress:     compress,
		interval:     interval,
		gracePeriod:  grace,
		maxPartBytes: maxBytes,
	}, nil
}

// ArchiveWindow packages a closed window [start, end) into parts and writes a manifest.
func (a *Archiver) ArchiveWindow(ctx context.Context, start, end time.Time) (*ArchiveManifest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().UTC()
	if now.Before(end.Add(a.gracePeriod)) {
		return nil, fmt.Errorf("window [%s, %s) is within grace period until %s",
			start.Format(time.RFC3339), end.Format(time.RFC3339), end.Add(a.gracePeriod).Format(time.RFC3339))
	}

	startCompact := start.Format("20060102T150405Z")
	endCompact := end.Format("20060102T150405Z")
	windowDir := fmt.Sprintf("%s/audit-logs/%s/%s-%s",
		a.prefix, start.Format("2006/01/02"), startCompact, endCompact)

	manifestKey := fmt.Sprintf("%s/manifest.json", windowDir)
	if a.compress {
		manifestKey += ".gz"
	}

	// Idempotency: First complete write wins
	if existingData, err := a.store.Get(ctx, manifestKey); err == nil && len(existingData) > 0 {
		var manifest ArchiveManifest
		if err := json.Unmarshal(existingData, &manifest); err == nil {
			a.watermark = end
			return &manifest, nil
		}
	}

	events, err := a.ledger.GetEventsInWindow(start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch window events: %w", err)
	}

	parts := make([]ArchivePart, 0)
	var currentBuf bytes.Buffer
	partIndex := 0
	partEventCount := int64(0)
	totalEvents := int64(len(events))

	flushPart := func() error {
		if currentBuf.Len() == 0 {
			return nil
		}
		partKey := fmt.Sprintf("%s/part-%05d.jsonl", windowDir, partIndex)
		if a.compress {
			partKey += ".gz"
		}

		rawBytes := currentBuf.Bytes()
		uncompressedLen := int64(len(rawBytes))
		var uploadPayload []byte

		if a.compress {
			var gzBuf bytes.Buffer
			gw := gzip.NewWriter(&gzBuf)
			if _, err := gw.Write(rawBytes); err != nil {
				return err
			}
			if err := gw.Close(); err != nil {
				return err
			}
			uploadPayload = gzBuf.Bytes()
		} else {
			uploadPayload = rawBytes
		}

		digest := sha256.Sum256(uploadPayload)
		shaStr := hex.EncodeToString(digest[:])

		tags := map[string]string{
			"type":         "audit-logs",
			"window_start": start.Format(time.RFC3339),
			"window_end":   end.Format(time.RFC3339),
			"part":         fmt.Sprintf("%d", partIndex),
			"count":        fmt.Sprintf("%d", partEventCount),
		}

		if err := a.store.Put(ctx, partKey, uploadPayload, tags); err != nil {
			return fmt.Errorf("failed to put part %s: %w", partKey, err)
		}

		parts = append(parts, ArchivePart{
			Key:        partKey,
			EventCount: partEventCount,
			Bytes:      uncompressedLen,
			SHA256:     shaStr,
		})

		currentBuf.Reset()
		partIndex++
		partEventCount = 0
		return nil
	}

	for _, event := range events {
		line, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		line = append(line, '\n')

		// If adding line crosses maxPartBytes and buffer has events, roll to new part
		if int64(currentBuf.Len()+len(line)) > a.maxPartBytes && currentBuf.Len() > 0 {
			if err := flushPart(); err != nil {
				return nil, err
			}
		}

		currentBuf.Write(line)
		partEventCount++
	}

	if currentBuf.Len() > 0 {
		if err := flushPart(); err != nil {
			return nil, err
		}
	}

	// Verify chain inside window if events exist
	chainValid := true
	var firstSeq, lastSeq int64
	if totalEvents > 0 {
		firstSeq = events[0].SequenceID
		lastSeq = events[len(events)-1].SequenceID
		chainValid, _ = a.ledger.VerifyChain(firstSeq, lastSeq)
	}

	manifest := ArchiveManifest{
		Version:         1,
		WindowStart:     start,
		WindowEnd:       end,
		EventCount:      totalEvents,
		Compressed:      a.compress,
		CompletedAt:     time.Now().UTC(),
		FirstSequenceID: firstSeq,
		LastSequenceID:  lastSeq,
		ChainValid:      chainValid,
		Parts:           parts,
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	var manifestPayload []byte
	if a.compress {
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		if _, err := gw.Write(manifestJSON); err != nil {
			return nil, err
		}
		if err := gw.Close(); err != nil {
			return nil, err
		}
		manifestPayload = gzBuf.Bytes()
	} else {
		manifestPayload = manifestJSON
	}

	manifestTags := map[string]string{
		"type":         "audit-logs-manifest",
		"window_start": start.Format(time.RFC3339),
		"window_end":   end.Format(time.RFC3339),
		"count":        fmt.Sprintf("%d", totalEvents),
	}

	// Commit point: only once manifest is stored does watermark advance
	if err := a.store.Put(ctx, manifestKey, manifestPayload, manifestTags); err != nil {
		return nil, fmt.Errorf("failed to commit manifest %s: %w", manifestKey, err)
	}

	a.watermark = end
	return &manifest, nil
}

// GetWatermark returns the current committed archive window end.
func (a *Archiver) GetWatermark() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.watermark
}
