package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

type mockFlusher struct {
	mu     sync.Mutex
	called int
}

func (m *mockFlusher) FlushCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.called++
}

type mockBroadcaster struct {
	mu       sync.Mutex
	entities []string
}

func (m *mockBroadcaster) BroadcastState(entity string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entities = append(m.entities, entity)
	return nil
}

func TestVaultHandler_FlushCache_Success(t *testing.T) {
	flusher := &mockFlusher{}
	broadcaster := &mockBroadcaster{}
	handler := NewVaultHandler(flusher, broadcaster)

	r := router.New()
	handler.RegisterRoutes(r)

	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/api/vault/flush-cache")

	r.Handler(&ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", ctx.Response.StatusCode())
	}

	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["message"] != "vault cache flushed" {
		t.Errorf("expected 'vault cache flushed', got %s", resp["message"])
	}

	flusher.mu.Lock()
	if flusher.called != 1 {
		t.Errorf("expected flusher called 1 time, got %d", flusher.called)
	}
	flusher.mu.Unlock()

	broadcaster.mu.Lock()
	if len(broadcaster.entities) != 1 || broadcaster.entities[0] != "vault_flush" {
		t.Errorf("expected broadcast vault_flush, got %v", broadcaster.entities)
	}
	broadcaster.mu.Unlock()
}

func TestVaultHandler_FlushCache_Disabled(t *testing.T) {
	handler := NewVaultHandler(nil, nil)

	r := router.New()
	handler.RegisterRoutes(r)

	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/api/vault/flush-cache")

	r.Handler(&ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected HTTP 400 when disabled, got %d", ctx.Response.StatusCode())
	}

	var resp map[string]string
	_ = json.Unmarshal(ctx.Response.Body(), &resp)
	if resp["error"] != "vault is not enabled" {
		t.Errorf("expected 'vault is not enabled', got %s", resp["error"])
	}
}

func TestVaultHandler_FlushCache_Concurrent(t *testing.T) {
	flusher := &mockFlusher{}
	broadcaster := &mockBroadcaster{}
	handler := NewVaultHandler(flusher, broadcaster)

	r := router.New()
	handler.RegisterRoutes(r)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var ctx fasthttp.RequestCtx
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/api/vault/flush-cache")
			r.Handler(&ctx)
			if ctx.Response.StatusCode() != fasthttp.StatusOK {
				t.Errorf("unexpected status code: %d", ctx.Response.StatusCode())
			}
		}()
	}
	wg.Wait()

	flusher.mu.Lock()
	defer flusher.mu.Unlock()
	if flusher.called != 20 {
		t.Errorf("expected 20 calls, got %d", flusher.called)
	}
}
