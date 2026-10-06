package logexport

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

// WindowedArchiver periodically archives rows into time-windowed JSONL objects sealed by a manifest.
type WindowedArchiver struct {
	config    ArchiveConfig
	store     objectstore.ObjectStore
	watermark time.Time
	mu        sync.RWMutex
	manifests []*ArchiveManifest
}

// NewWindowedArchiver creates an archiver.
func NewWindowedArchiver(cfg ArchiveConfig, store objectstore.ObjectStore, startWatermark time.Time) *WindowedArchiver {
	if cfg.Interval < 5*time.Minute {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.GracePeriod <= 0 || cfg.GracePeriod >= cfg.Interval {
		cfg.GracePeriod = 15 * time.Minute
	}
	if cfg.MaxObjectBytes <= 0 {
		cfg.MaxObjectBytes = 134217728 // 128 MiB
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "bifrost"
	}
	if cfg.TargetPrefix == "" {
		cfg.TargetPrefix = "audit-logs"
	}

	return &WindowedArchiver{
		config:    cfg,
		store:     store,
		watermark: startWatermark.UTC(),
		manifests: make([]*ArchiveManifest, 0),
	}
}

// ArchiveWindow archives rows belonging to [windowStart, windowEnd).
func (a *WindowedArchiver) ArchiveWindow(ctx context.Context, windowStart, windowEnd time.Time, rows [][]byte) (*ArchiveManifest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	start := windowStart.UTC()
	end := windowEnd.UTC()

	// Verify grace period
	if time.Now().UTC().Before(end.Add(a.config.GracePeriod)) {
		return nil, fmt.Errorf("window [%s, %s) is within grace period %s", start, end, a.config.GracePeriod)
	}

	startStr := start.Format("20060102T150405Z")
	endStr := end.Format("20060102T150405Z")
	dirPrefix := fmt.Sprintf("%s/%s/%04d/%02d/%02d/%s-%s",
		a.config.Prefix, a.config.TargetPrefix, start.Year(), start.Month(), start.Day(), startStr, endStr)

	manifest := &ArchiveManifest{
		Version:     1,
		WindowStart: start,
		WindowEnd:   end,
		EventCount:  len(rows),
		Compressed:  a.config.Compress,
		CompletedAt: time.Now().UTC(),
		Parts:       make([]ManifestPart, 0),
	}

	// 1. Partition rows into parts bounded by MaxObjectBytes
	var currentBuf bytes.Buffer
	partIndex := 0
	partEvents := 0

	uploadPart := func() error {
		if currentBuf.Len() == 0 {
			return nil
		}
		ext := "jsonl"
		data := currentBuf.Bytes()
		uncompressedLen := int64(len(data))
		uploadPayload := data

		if a.config.Compress {
			ext = "jsonl.gz"
			var gzBuf bytes.Buffer
			gw := gzip.NewWriter(&gzBuf)
			if _, err := gw.Write(data); err != nil {
				return err
			}
			if err := gw.Close(); err != nil {
				return err
			}
			uploadPayload = gzBuf.Bytes()
		}

		partKey := fmt.Sprintf("%s/part-%05d.%s", dirPrefix, partIndex, ext)
		if a.store != nil {
			if err := a.store.Put(ctx, partKey, uploadPayload, map[string]string{
				"type":        a.config.TargetPrefix,
				"part":        fmt.Sprintf("%d", partIndex),
				"event_count": fmt.Sprintf("%d", partEvents),
			}); err != nil {
				return fmt.Errorf("failed to upload part %s: %w", partKey, err)
			}
		}

		digest := sha256.Sum256(uploadPayload)
		manifest.Parts = append(manifest.Parts, ManifestPart{
			Key:        partKey,
			EventCount: partEvents,
			Bytes:      uncompressedLen,
			SHA256:     hex.EncodeToString(digest[:]),
		})

		partIndex++
		partEvents = 0
		currentBuf.Reset()
		return nil
	}

	for _, row := range rows {
		if int64(currentBuf.Len()+len(row)+1) > a.config.MaxObjectBytes && currentBuf.Len() > 0 {
			if err := uploadPart(); err != nil {
				return nil, err
			}
		}
		currentBuf.Write(row)
		currentBuf.WriteByte('\n')
		partEvents++
	}

	if err := uploadPart(); err != nil {
		return nil, err
	}

	// 2. Commit Manifest
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestKey := fmt.Sprintf("%s/manifest.json", dirPrefix)
	manifestData := manifestJSON
	if a.config.Compress {
		manifestKey += ".gz"
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		if _, err := gw.Write(manifestJSON); err != nil {
			return nil, err
		}
		if err := gw.Close(); err != nil {
			return nil, err
		}
		manifestData = gzBuf.Bytes()
	}

	if a.store != nil {
		if err := a.store.Put(ctx, manifestKey, manifestData, map[string]string{
			"type": fmt.Sprintf("%s-manifest", a.config.TargetPrefix),
		}); err != nil {
			return nil, fmt.Errorf("failed to commit manifest %s: %w", manifestKey, err)
		}
	}

	// 3. Advance watermark to end of window
	a.watermark = end
	a.manifests = append(a.manifests, manifest)
	return manifest, nil
}

// GetWatermark returns the current committed watermark.
func (a *WindowedArchiver) GetWatermark() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.watermark
}
