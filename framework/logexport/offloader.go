package logexport

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/framework/objectstore"
)

// PayloadOffloader handles streaming large request/response payloads to S3/GCS.
type PayloadOffloader struct {
	store          objectstore.ObjectStore
	thresholdBytes int
	prefix         string
	compress       bool
	mu             sync.RWMutex
	offloadedMem   map[string][]byte // local storage / mock cache
}

// NewPayloadOffloader constructs an offloader backed by objectstore.ObjectStore.
func NewPayloadOffloader(store objectstore.ObjectStore, thresholdBytes int, prefix string, compress bool) *PayloadOffloader {
	if thresholdBytes <= 0 {
		thresholdBytes = 32768 // 32KB
	}
	if prefix == "" {
		prefix = "bifrost"
	}
	return &PayloadOffloader{
		store:          store,
		thresholdBytes: thresholdBytes,
		prefix:         prefix,
		compress:       compress,
		offloadedMem:   make(map[string][]byte),
	}
}

// OffloadPayloadToS3 stores a payload at the given S3 object key.
// Compatible with tests/e2e/enterprise/mock/MockLogExporter.OffloadPayloadToS3.
func (p *PayloadOffloader) OffloadPayloadToS3(objectKey string, payload []byte) error {
	return p.OffloadDirect(context.Background(), objectKey, payload)
}

// OffloadPayloadToGCS stores a payload at the given GCS object key.
func (p *PayloadOffloader) OffloadPayloadToGCS(objectKey string, payload []byte) error {
	return p.OffloadDirect(context.Background(), objectKey, payload)
}

// OffloadDirect writes a payload directly to the underlying object store by key.
func (p *PayloadOffloader) OffloadDirect(ctx context.Context, key string, payload []byte) error {
	p.mu.Lock()
	p.offloadedMem[key] = append([]byte(nil), payload...)
	p.mu.Unlock()

	if p.store != nil {
		cleanKey := normalizeObjectKey(key)
		return p.store.Put(ctx, cleanKey, payload, map[string]string{
			"type": "offloaded_payload",
		})
	}
	return nil
}

// OffloadIfLarge inspects payload size: if >= thresholdBytes, uploads to store and returns URI pointer.
func (p *PayloadOffloader) OffloadIfLarge(ctx context.Context, storeType string, timestamp time.Time, id, fieldName string, data []byte) (bool, string, error) {
	if len(data) < p.thresholdBytes {
		return false, string(data), nil
	}

	ts := timestamp.UTC()
	ext := "json"
	uploadBytes := data

	if p.compress {
		ext = "json.gz"
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(data); err != nil {
			return false, "", fmt.Errorf("gzip compress error: %w", err)
		}
		if err := gw.Close(); err != nil {
			return false, "", fmt.Errorf("gzip close error: %w", err)
		}
		uploadBytes = buf.Bytes()
	}

	rawKey := fmt.Sprintf("%s/payloads/%04d/%02d/%02d/%02d/%s_%s.%s",
		p.prefix, ts.Year(), ts.Month(), ts.Day(), ts.Hour(), id, fieldName, ext)

	scheme := "s3"
	if strings.EqualFold(storeType, "gcs") {
		scheme = "gs"
	}
	uri := fmt.Sprintf("%s://%s", scheme, rawKey)

	if err := p.OffloadDirect(ctx, uri, uploadBytes); err != nil {
		return false, "", err
	}
	return true, uri, nil
}

// FetchOffloadedPayload retrieves and decompresses an offloaded payload from URI pointer.
func (p *PayloadOffloader) FetchOffloadedPayload(ctx context.Context, uri string) ([]byte, error) {
	p.mu.RLock()
	val, ok := p.offloadedMem[uri]
	p.mu.RUnlock()

	if ok {
		return decompressIfNeeded(val)
	}

	if p.store == nil {
		return nil, fmt.Errorf("object store not configured for uri: %s", uri)
	}

	cleanKey := normalizeObjectKey(uri)
	data, err := p.store.Get(ctx, cleanKey)
	if err != nil {
		return nil, err
	}
	return decompressIfNeeded(data)
}

// GetOffloadedMap returns a defensive copy of all offloaded payloads stored in memory.
func (p *PayloadOffloader) GetOffloadedMap() map[string][]byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make(map[string][]byte, len(p.offloadedMem))
	for k, v := range p.offloadedMem {
		res[k] = append([]byte(nil), v...)
	}
	return res
}

func normalizeObjectKey(uri string) string {
	s := strings.TrimPrefix(uri, "s3://")
	s = strings.TrimPrefix(s, "gs://")
	return s
}

func decompressIfNeeded(data []byte) ([]byte, error) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	}
	return append([]byte(nil), data...), nil
}
